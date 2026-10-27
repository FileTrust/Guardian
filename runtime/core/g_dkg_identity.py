"""Persistent Baby Jubjub encryption identity for accepted DKG duties.

Independent of configuration and wallet loading. A missing registered secret
must be restored, never silently replaced. Existing X25519 keys are separate.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import fcntl
import os
from pathlib import Path
import stat

from .g_crypto import BABY_L, baby_mul, baby_rand_scalar
from .g_dkg_cipher import checked_public_key
from .g_secret_files import make_secret_dir, read_secret_json, write_json_atomic, secret_dir_is_private
from web3 import Web3


@dataclass(frozen=True)
class DkgIdentity:
    secret: int = field(repr=False)
    public: tuple[int, int]


@contextmanager
def private_lock(directory: Path):
    directory = Path(directory)
    if directory.is_symlink():
        raise PermissionError('DKG private state cannot be a symlink')
    make_secret_dir(directory)
    if not secret_dir_is_private(directory)[0]:
        raise PermissionError('DKG state needs a filesystem with owner-only permissions')
    descriptor = os.open(directory / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PermissionError('DKG state lock must be an owner-only regular file')
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def read_private_json(path: Path):
    info = Path(path).lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise PermissionError('DKG secret state must be an owner-only regular file')
    try:
        return read_secret_json(path)
    except Exception:
        raise RuntimeError('Cannot read protected DKG state; restore the matching backup') from None


def load_identity(root: Path, registered_public) -> DkgIdentity:
    """Create only for an unregistered key; otherwise require a matching backup.

    The caller obtains registered_public from the exact bound registry. This
    function never infers an empty registration from an RPC exception.
    """
    registered = tuple(int(v) for v in registered_public)
    if len(registered) != 2:
        raise ValueError('Invalid encryption-key registration')
    if registered != (0, 0):
        checked_public_key(registered)
    directory = Path(root) / 'identity'
    with private_lock(directory):
        path = directory / 'babyjubjub.json'
        if path.exists() or path.is_symlink():
            data = read_private_json(path)
            try:
                secret = int(data['secret'])
                public = tuple(int(v) for v in data['public'])
                if data.get('format') != 1 or not 0 < secret < BABY_L or baby_mul(secret) != public:
                    raise ValueError()
                checked_public_key(public)
            except (KeyError, TypeError, ValueError):
                raise RuntimeError('Saved DKG identity is invalid; restore its backup') from None
        else:
            if registered != (0, 0):
                raise RuntimeError('Registered DKG identity is missing; restore its matching backup')
            secret = baby_rand_scalar()
            public = checked_public_key(baby_mul(secret))
            write_json_atomic(path, {'format': 1, 'curve': 'BabyJubjub', 'secret': str(secret), 'public': list(public)})
        if registered != (0, 0) and public != registered:
            raise RuntimeError('Saved DKG identity differs from registration; restore the matching backup')
        return DkgIdentity(secret, public)


def ensure_registered_identity(root: Path, address: str, guardian_registry, dispute_manager, submit) -> DkgIdentity:
    """Register/validate a public identity before accepting any recovery duty.

    `submit(fn, label)` must submit through the node's protected wallet/nonce
    path and return a confirmed receipt. Only public coordinates go on chain.
    Propagate uncertain RPC/receipts; never interpret them as no registration.
    """
    with private_lock(Path(root) / 'registration'):
        return _register_identity(root, address, guardian_registry, dispute_manager, submit)


def _register_identity(root, address, guardian_registry, dispute_manager, submit):
    if not guardian_registry.functions.isRegisteredGuardian(address).call():
        raise RuntimeError('Register the Guardian wallet before preparing its DKG identity')
    registered = guardian_registry.functions.getGuardianDkgBabyJubjubPublicKey(address).call()
    identity = load_identity(root, registered)
    if tuple(int(v) for v in registered) == (0, 0):
        receipt = submit(guardian_registry.functions.setDkgBabyJubjubPublicKey(*identity.public), 'Register DKG public identity')
        if receipt is None or int(receipt['status']) != 1:
            raise RuntimeError('DKG identity registration was not confirmed')
    actual = guardian_registry.functions.getGuardianDkgBabyJubjubPublicKey(address).call()
    if tuple(int(v) for v in actual) != identity.public:
        raise RuntimeError('DKG encryption registration differs from the protected local identity')
    digest = Web3.keccak(b''.join(v.to_bytes(32, 'big') for v in identity.public))
    if not dispute_manager.functions.validatedEncryptionKeys(digest).call():
        receipt = submit(dispute_manager.functions.validateEncryptionKey(*identity.public), 'Validate DKG public identity')
        if receipt is None or int(receipt['status']) != 1:
            raise RuntimeError('DKG public-key validation was not confirmed')
    if not dispute_manager.functions.validatedEncryptionKeys(digest).call():
        raise RuntimeError('DKG public-key validation is not available on chain')
    return identity
