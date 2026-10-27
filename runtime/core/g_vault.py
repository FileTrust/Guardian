"""Software-only authenticated storage for the public Guardian service.

The credential contains a unique random 256-bit key, not an OS login password.
It must be backed up separately from the encrypted state. Full host/root
compromise remains outside this at-rest protection.
"""
from __future__ import annotations

import base64
import functools
import json
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT = "filetrust-guardian-aesgcm-v1"
_CREDENTIAL_ROOT = Path("/run/credentials")


def enabled() -> bool:
    return bool(os.environ.get("FILETRUST_GUARDIAN_STATE"))


@functools.lru_cache(maxsize=1)
def _key() -> bytes:
    credentials = os.environ.get("CREDENTIALS_DIRECTORY")
    if credentials:
        folder = Path(credentials)
        if (not folder.is_absolute() or ".." in folder.parts or
                not folder.is_relative_to(_CREDENTIAL_ROOT) or folder.resolve() != folder):
            raise PermissionError("Unexpected systemd credential directory")
        directory = folder.lstat()
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid not in (0, os.getuid()) or
                directory.st_mode & 0o022):
            raise PermissionError("Guardian systemd credential directory must be protected")
    filename = (folder / "unlock.key" if credentials else
                Path(os.environ.get("FILETRUST_GUARDIAN_KEY_FILE", "/etc/filetrust-guardian/unlock.key")))
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        owner_only = not info.st_mode & 0o077 and info.st_uid in (0, os.getuid())
        # LoadCredential may expose a root-owned 0440 file to the service.
        # Ordinary key files retain the owner-only rule above.
        managed = credentials and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o440
        if not stat.S_ISREG(info.st_mode) or not (owner_only or managed):
            raise PermissionError("Guardian unlock credential must be an owner-only regular file")
        raw = os.read(fd, 33)
        if len(raw) != 32:
            raise ValueError("Guardian unlock credential must contain exactly 32 bytes")
        return raw
    finally:
        os.close(fd)


def _aad(path: Path) -> bytes:
    root = Path(os.environ["FILETRUST_GUARDIAN_STATE"]).resolve()
    relative = path.resolve().relative_to(root).as_posix()
    return f"{FORMAT}|{relative}".encode()


def encrypt(path: Path, value: str) -> str:
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key()).encrypt(nonce, value.encode(), _aad(path))
    return json.dumps({"format": FORMAT, "nonce": base64.b64encode(nonce).decode(),
                       "ciphertext": base64.b64encode(ciphertext).decode()})


def decrypt(path: Path, value: str) -> str:
    try:
        data = json.loads(value)
        if data.get("format") != FORMAT:
            raise ValueError("Plaintext material is not accepted by the public Guardian")
        return AESGCM(_key()).decrypt(base64.b64decode(data["nonce"], validate=True),
                                    base64.b64decode(data["ciphertext"], validate=True), _aad(path)).decode()
    except Exception:
        # Never put ciphertext, plaintext, or an offending JSON fragment in logs.
        raise ValueError("Cannot unlock Guardian material; restore the matching key and state backup") from None
