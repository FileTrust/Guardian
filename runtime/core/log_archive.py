"""Keep one entity's log folder from growing forever.

Every entity carries its own copy of this file on purpose. An entity has to be
deployable on its own -- someone running only a Vault Keeper has no FileTrust
root to import a shared helper from -- so there is no shared parent package
here and there never should be.

What a pass does, in order:

  1. Rotate.  A log that is bigger than ``max_mb``, or that belongs to a day
     other than today, is closed off and gzipped.
  2. Age out.  Archives older than ``keep_days`` are deleted.
  3. Cap.      While the folder is still over ``max_total_mb``, the oldest
     archive is deleted until it fits.

Two file-naming styles are handled, because the entities use both:

  ``do_2026-08-24.log``  -- already dated. Any day but today is finished, so it
                           is gzipped and the original removed.
  ``vk.log``             -- one growing file. It is copied out and then
                           *truncated* rather than renamed, so a process
                           holding it open keeps writing to the same inode.
                           This is what logrotate calls copytruncate.

Nothing here raises: a failure to tidy logs must never take an entity down.
"""

from __future__ import annotations

import gzip
import os
import re
import shutil
import threading
import time
from datetime import date, datetime, timedelta
from pathlib import Path

__all__ = ["archive_logs", "start_daily", "DEFAULTS"]

DEFAULTS = {
    "log_max_mb": 50,
    "log_keep_days": 14,
    "log_max_total_mb": 1000,
}

# do_2026-08-24.log / discovery-1.log / vk-2026-08-24.log.gz
_DATE_IN_NAME = re.compile(r"(\d{4}-\d{2}-\d{2})")
_LOG_SUFFIXES = (".log", ".jsonl")
_MB = 1024 * 1024


def _dated(path: Path) -> date | None:
    """The calendar day baked into a filename, if there is one."""
    match = _DATE_IN_NAME.search(path.name)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%Y-%m-%d").date()
    except ValueError:
        return None


def _gzip_to(src: Path, dest: Path) -> bool:
    """Compress *src* to *dest*. Returns False instead of raising."""
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        with src.open("rb") as raw, gzip.open(tmp, "wb", compresslevel=6) as gz:
            shutil.copyfileobj(raw, gz, length=1 << 20)
        tmp.replace(dest)
        return True
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        return False


def _archive_name(path: Path, stamp: str) -> Path:
    """vk.log + 2026-08-24 -> vk-2026-08-24.log.gz (deduped if it exists)."""
    base, ext = path.stem, path.suffix
    if _dated(path):                       # already dated: keep the name as-is
        candidate = path.with_suffix(ext + ".gz")
    else:
        candidate = path.with_name(f"{base}-{stamp}{ext}.gz")
    n = 1
    while candidate.exists():
        candidate = candidate.with_name(
            candidate.name.replace(".gz", f".{n}.gz", 1) if n == 1
            else re.sub(r"\.\d+\.gz$", f".{n}.gz", candidate.name)
        )
        n += 1
    return candidate


def _rotate(path: Path, max_bytes: int, today: date) -> bool:
    """Gzip *path* if it is finished or oversized. True if it was archived."""
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size == 0:
        return False

    day = _dated(path)
    finished = day is not None and day != today
    oversized = size >= max_bytes
    if not (finished or oversized):
        return False

    stamp = (day or today).isoformat()
    dest = _archive_name(path, stamp)
    if not _gzip_to(path, dest):
        return False

    if finished:
        # Nothing is writing to a past day's file -- safe to remove outright.
        try:
            path.unlink()
        except OSError:
            pass
    else:
        # Live file: truncate in place so an open append handle survives.
        try:
            with path.open("r+b") as handle:
                handle.truncate(0)
        except OSError:
            pass
    return True


def _age_days(path: Path) -> float:
    """How old a log's *contents* are, in days.

    The date in the filename wins over mtime. An archive named 2026-01-01 holds
    January's log no matter when it was gzipped, and mtime is easily disturbed
    by copying or restoring files, which would silently spare or destroy the
    wrong archive.
    """
    day = _dated(path)
    if day is not None:
        return (date.today() - day).days
    try:
        return (time.time() - path.stat().st_mtime) / 86400
    except OSError:
        return 0.0


def _prune_by_age(archives: list[Path], keep_days: int, keep_days_by_name: dict) -> list[Path]:
    """Delete archives past their retention. Returns the survivors."""
    survivors = []
    for arc in archives:
        limit = keep_days
        for fragment, override in (keep_days_by_name or {}).items():
            if fragment in arc.name:
                limit = override
                break
        if _age_days(arc) > limit:
            try:
                arc.unlink()
                continue
            except OSError:
                pass
        survivors.append(arc)
    return survivors


def _prune_by_size(archives: list[Path], log_dir: Path, max_total_bytes: int) -> int:
    """Delete oldest archives until the folder fits. Returns how many went."""
    def total() -> int:
        return sum(
            f.stat().st_size
            for f in log_dir.rglob("*")
            if f.is_file() and not f.is_symlink()
        )

    removed = 0
    try:
        current = total()
    except OSError:
        return 0
    oldest_first = sorted(archives, key=_age_days, reverse=True)
    for arc in oldest_first:
        if current <= max_total_bytes:
            break
        try:
            size = arc.stat().st_size
            arc.unlink()
            current -= size
            removed += 1
        except OSError:
            continue
    return removed


def archive_logs(
    log_dir,
    *,
    max_mb: int = DEFAULTS["log_max_mb"],
    keep_days: int = DEFAULTS["log_keep_days"],
    max_total_mb: int = DEFAULTS["log_max_total_mb"],
    keep_days_by_name: dict | None = None,
    exclude: tuple = (),
) -> dict:
    """Run one tidy-up pass over *log_dir*. Never raises.

    ``keep_days_by_name`` lets one file outlive the rest, e.g.
    ``{"transactions": 90}`` keeps transaction records for 90 days while
    ordinary logs still go after 14.

    Returns a small summary dict, handy for logging or tests.
    """
    result = {"rotated": 0, "deleted_old": 0, "deleted_for_size": 0, "error": None}
    try:
        log_dir = Path(log_dir)
        if not log_dir.is_dir():
            return result

        today = date.today()
        max_bytes = max(1, int(max_mb)) * _MB

        for path in sorted(log_dir.iterdir()):
            if not path.is_file() or path.is_symlink():
                continue
            if path.suffix not in _LOG_SUFFIXES:
                continue
            if any(fragment in path.name for fragment in exclude):
                continue
            if _rotate(path, max_bytes, today):
                result["rotated"] += 1

        archives = [
            p for p in log_dir.iterdir()
            if p.is_file() and not p.is_symlink() and p.name.endswith(".gz")
        ]
        before = len(archives)
        archives = _prune_by_age(archives, int(keep_days), keep_days_by_name or {})
        result["deleted_old"] = before - len(archives)
        result["deleted_for_size"] = _prune_by_size(
            archives, log_dir, max(1, int(max_total_mb)) * _MB
        )
    except Exception as exc:  # tidying logs must never stop an entity
        result["error"] = str(exc)
    return result


def _seconds_until_next_run(hour: int) -> float:
    now = datetime.now()
    nxt = now.replace(hour=hour, minute=5, second=0, microsecond=0)
    if nxt <= now:
        nxt += timedelta(days=1)
    return max(60.0, (nxt - now).total_seconds())


def start_daily(log_dir, *, hour: int = 3, on_done=None, **options) -> threading.Thread:
    """Tidy *log_dir* now, then again every day at *hour*.

    Runs on a daemon thread, so it never holds the entity open on shutdown.
    """
    def loop() -> None:
        summary = archive_logs(log_dir, **options)
        if on_done:
            try:
                on_done(summary)
            except Exception:
                pass
        while True:
            time.sleep(_seconds_until_next_run(hour))
            summary = archive_logs(log_dir, **options)
            if on_done:
                try:
                    on_done(summary)
                except Exception:
                    pass

    thread = threading.Thread(target=loop, name="log-archive", daemon=True)
    thread.start()
    return thread


class _Tee:
    """Write to the original stream and to a file at the same time."""

    def __init__(self, stream, handle):
        self._stream = stream
        self._handle = handle

    def write(self, text):
        self._stream.write(text)
        try:
            self._handle.write(text)
        except (OSError, ValueError):
            pass
        return len(text)

    def flush(self):
        self._stream.flush()
        try:
            self._handle.flush()
        except (OSError, ValueError):
            pass

    def isatty(self):
        return getattr(self._stream, "isatty", lambda: False)()

    def __getattr__(self, name):
        return getattr(self._stream, name)


def tee_stdout(log_dir, prefix: str):
    """Also write stdout and stderr into ``log_dir/<prefix>_<date>.log``.

    For entities that only ``print``. Their log file is otherwise created by
    whatever runner redirects their output, which means it lands outside the
    entity -- no good for something meant to run standalone.

    Returns the log path, or None if it could not be opened.
    """
    import sys

    try:
        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        path = log_dir / f"{prefix}_{date.today().isoformat()}.log"
        handle = open(path, "a", encoding="utf-8", buffering=1)
        sys.stdout = _Tee(sys.stdout, handle)
        sys.stderr = _Tee(sys.stderr, handle)
        return path
    except OSError:
        return None


def options_from_config(config, prefix: str = "") -> dict:
    """Pull the three knobs out of an entity's config.

    Accepts a dict or any object with attributes, so it suits every entity
    regardless of how it loads config.json. Missing keys fall back to DEFAULTS.
    """
    def read(key: str, fallback):
        name = f"{prefix}{key}"
        if isinstance(config, dict):
            value = config.get(name, fallback)
        else:
            value = getattr(config, name, getattr(config, name.upper(), fallback))
        try:
            return int(value)
        except (TypeError, ValueError):
            return fallback

    return {
        "max_mb": read("log_max_mb", DEFAULTS["log_max_mb"]),
        "keep_days": read("log_keep_days", DEFAULTS["log_keep_days"]),
        "max_total_mb": read("log_max_total_mb", DEFAULTS["log_max_total_mb"]),
    }
