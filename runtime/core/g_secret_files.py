"""Key material on disk.

Kept free of configuration so it can be tested without a Guardian identity --
importing the config module requires a real private key, which a permissions
test has no business needing.
"""
from __future__ import annotations

import os
import stat
import contextlib
import io
import json
import tempfile
from pathlib import Path


SECRET_FILE_MODE = 0o600
SECRET_DIR_MODE = 0o700


def secret_file_is_private(path) -> tuple[bool, str]:
    """Is this file readable only by the account running the Guardian?

    The mode is read back rather than inferred from chmod returning cleanly. On
    a filesystem that cannot store permissions -- NTFS or exFAT, ordinary when an
    application lives on a second drive -- chmod succeeds and changes nothing, so
    trusting its return value would report every share on such a disk as safe.
    """
    p = Path(path)
    try:
        mode = stat.S_IMODE(os.stat(p).st_mode)
    except OSError as exc:
        return False, f"cannot read the permissions of {p}: {exc}"
    if mode & 0o077:
        return False, (
            f"{p} is mode {mode:04o}: other accounts on this machine can read "
            f"this key share. Move the Guardian's material to a filesystem that "
            f"keeps permissions."
        )
    return True, "ok"


def secret_dir_is_private(path) -> tuple[bool, str]:
    """A closed file in an open directory still leaks its name.

    Share filenames carry the file id, the key epoch and which Guardian dealt to
    whom -- a map of what to steal and from where.
    """
    p = Path(path)
    try:
        mode = stat.S_IMODE(os.stat(p).st_mode)
    except OSError as exc:
        return False, f"cannot read the permissions of {p}: {exc}"
    if mode & 0o077:
        return False, (
            f"{p} is mode {mode:04o}: other accounts on this machine can list "
            f"the Guardian's key material."
        )
    return True, "ok"


def make_secret_dir(path) -> Path:
    """Create a directory for key material, closed to everyone else."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, SECRET_DIR_MODE)
    except OSError:
        pass  # reported by secret_dir_is_private, with the mode that resulted
    return p


@contextlib.contextmanager
def open_secret_file(path):
    """Open a file for writing that is never, even briefly, readable by others.

    The mode is given to the kernel at creation rather than applied afterwards:
    a file created open and tightened later is readable for the moment in
    between, and that moment is exactly when it holds the share.
    """
    from . import g_vault
    path = Path(path)
    buffer = io.StringIO()
    yield buffer
    text = buffer.getvalue()
    if g_vault.enabled():
        text = g_vault.encrypt(path, text)
    make_secret_dir(path.parent)
    fd, temporary = tempfile.mkstemp(prefix=".secret-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        Path(temporary).unlink(missing_ok=True)


def read_secret_json(path):
    from . import g_vault
    path = Path(path)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or (g_vault.enabled() and (info.st_mode & 0o077 or (os.getuid() != 0 and info.st_uid != os.getuid()))):
        os.close(fd)
        raise PermissionError("Guardian material must be an owner-only regular file")
    with os.fdopen(fd, encoding="utf-8") as source:
        text = source.read()
    if g_vault.enabled():
        text = g_vault.decrypt(path, text)
    return json.loads(text)


def load_wallet_config(path):
    """Public config holds only a wallet reference; legacy G remains supported."""
    path = Path(path)
    config = json.loads(path.read_text(encoding="utf-8"))
    from . import g_vault
    if g_vault.enabled() and (config.get("wallet_file") != "wallet.json" or "private_key" in config):
        raise ValueError("Public Guardian requires protected wallet storage")
    if config.get("wallet_file"):
        if not g_vault.enabled() or "private_key" in config:
            raise ValueError("Public Guardian requires protected wallet storage")
        wallet = read_secret_json(path.parent / config["wallet_file"])
        config["private_key"] = wallet["private_key"]
    return config


def write_json_atomic(path, data: dict) -> None:
    """Write key material so it is never, at any instant, readable by others.

    The mode is given at creation and re-asserted before the rename, not applied
    to a file that already exists open: a temp file created at the default mode
    and tightened afterwards is readable for the moment in between, and that
    moment is precisely when it holds the share.
    """
    path = Path(path)
    with open_secret_file(path) as f:
        json.dump(data, f, indent=2)


def restrict_secret_file(path) -> tuple[bool, str]:
    """Ask for 0600 on an existing secret file, then check it was granted."""
    try:
        os.chmod(Path(path), SECRET_FILE_MODE)
    except OSError:
        pass  # reported by the read-back below, with the mode that resulted
    return secret_file_is_private(path)
