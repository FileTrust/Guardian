#!/usr/bin/env python3
"""Remove the standard Guardian server installation using Python's standard library."""
import argparse
import fcntl
import os
from pathlib import Path
import shutil
import subprocess
import sys

APP = Path("/opt/filetrust-guardian")
STATE = Path("/var/lib/filetrust-guardian")
CREDENTIALS = Path("/etc/filetrust-guardian")
UNIT = Path("/etc/systemd/system/filetrust-guardian.service")
UPDATE_OVERRIDE = Path("/etc/systemd/system/filetrust-guardian.service.d/application-updates.conf")
SERVICE = "filetrust-guardian.service"


def check_path(path):
    # Refuse redirected installation paths before stopping or deleting anything.
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError(f"Refusing symbolic-link installation path: {path}")


def uninstall(purge=False):
    check_path(APP)
    lock_path = APP / ".filetrust-updates/update.lock"
    lock = None
    try:
        if lock_path.exists():
            check_path(lock_path)
            lock = lock_path.open("rb")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("An update is in progress; wait before uninstalling") from None
        return _uninstall(purge)
    finally:
        if lock:
            lock.close()


def _uninstall(purge=False):
    if os.geteuid() != 0:
        raise PermissionError("Run sudo python3 uninstall.py")
    if not Path("/run/systemd/system").is_dir():
        raise ValueError("This uninstaller requires Linux with systemd")
    targets = [APP, STATE, CREDENTIALS, UNIT, UPDATE_OVERRIDE]
    for path in targets:
        check_path(path)
    if purge:
        print("This permanently deletes the wallet, unlock key, shares, proof files and download cache.", flush=True)
        print("Retire this Guardian's network duties and save any required backups first.", flush=True)
        if not sys.stdin.isatty() or input("Type DELETE to delete all Guardian data: ") != "DELETE":
            raise ValueError("Cancelled; nothing changed")
    load_state = subprocess.run(
        ["systemctl", "show", "--property=LoadState", "--value", SERVICE],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if load_state != "not-found":
        # A failure must leave the installation and custody files intact.
        subprocess.run(["systemctl", "disable", "--now", SERVICE], check=True)
    # A manually launched instance may be outside the systemd unit.
    locks = []
    for path in (APP / ".filetrust-updates/run.lock", STATE / ".run.lock"):
        if path.exists():
            check_path(path)
            lock = path.open("rb")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                lock.close()
                raise ValueError("A Guardian process is still running; stop it normally before uninstalling") from None
            locks.append(lock)
    if APP.exists():
        shutil.rmtree(APP)
    UNIT.unlink(missing_ok=True)
    UPDATE_OVERRIDE.unlink(missing_ok=True)
    if UPDATE_OVERRIDE.parent.exists() and not any(UPDATE_OVERRIDE.parent.iterdir()):
        UPDATE_OVERRIDE.parent.rmdir()
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    if purge:
        for path in (STATE, CREDENTIALS):
            if path.exists():
                shutil.rmtree(path)
        print("Guardian application and all local Guardian data removed.")
    else:
        print(f"Guardian removed. Data kept in {STATE}; unlock credential kept in {CREDENTIALS}.")
    print("Your source clone and the inactive ftguardian system account are kept.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--purge", action="store_true", help="Also delete wallet, shares, unlock key and downloads; requires typing DELETE")
    args = parser.parse_args()
    try:
        uninstall(args.purge)
    except (OSError, ValueError, subprocess.CalledProcessError, KeyboardInterrupt, EOFError) as exc:
        print(f"Uninstall stopped: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
