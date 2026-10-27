"""Attempt-bound scalar encryption for the existing zkDKG dispute circuit.

This module is independent of node configuration and wallets. It does not
replace the X25519 format used by legacy DKG. The recovery protocol uses the
same scalar ciphertext for delivery and for the circuit's public input hash.
"""
from __future__ import annotations

from functools import lru_cache

from web3 import Web3

from .g_crypto import BABY_G, BABY_L, BABY_P, baby_add, baby_is_on_curve, baby_mul
from .g_poseidon import poseidon2

RECEIVER_DOMAIN = b"FileTrust-DKG-receiver-v1"


def _identity(point) -> bool:
    return point is None or point == (0, 1)


def _raw_mul(scalar, point):
    """Subgroup check must NOT reduce scalar mod L as baby_mul does."""
    result = None
    while scalar:
        if scalar & 1:
            result = baby_add(result, point)
        point = baby_add(point, point)
        scalar >>= 1
    return result


@lru_cache(maxsize=128)
def _checked_point(x: int, y: int):
    point = (x, y)
    if not (0 <= x < BABY_P and 0 <= y < BABY_P) or not baby_is_on_curve(point) or _identity(point):
        raise ValueError("Invalid Baby Jubjub encryption public key")
    if not _identity(_raw_mul(BABY_L, point)):
        raise ValueError("Encryption public key is outside the prime-order subgroup")
    return point


def checked_public_key(point):
    if not isinstance(point, (tuple, list)) or len(point) != 2:
        raise ValueError("Expected a Baby Jubjub encryption public key")
    if any(type(value) is not int for value in point):
        raise ValueError("Public key coordinates must be integers")
    return _checked_point(*point)


def _secret(secret: int) -> int:
    if type(secret) is not int or not 0 < secret < BABY_L:
        raise ValueError("Expected a nonzero canonical Baby Jubjub secret scalar")
    return secret


def material_id_bytes(material_id) -> bytes:
    if isinstance(material_id, str):
        material_id = bytes.fromhex(material_id.removeprefix('0x'))
    if not isinstance(material_id, bytes) or len(material_id) != 32 or material_id == bytes(32):
        raise ValueError("Expected a nonzero 32-byte material identity")
    return material_id


def receiver_key_tweak(material_id) -> int:
    digest = Web3.keccak(RECEIVER_DOMAIN + material_id_bytes(material_id))
    return int.from_bytes(digest, 'big') % (BABY_L - 1) + 1


def receiver_public_key(public_key, material_id):
    original = checked_public_key(public_key)
    derived = baby_add(original, baby_mul(receiver_key_tweak(material_id), BABY_G))
    return checked_public_key(derived)


def receiver_secret_key(secret: int, material_id) -> int:
    return _secret((_secret(secret) + receiver_key_tweak(material_id)) % BABY_L)


def compress_commitment(point) -> int:
    if point is None:
        point = (0, 1)
    x, y = point
    if not (0 <= x < BABY_P and 0 <= y < BABY_P) or not baby_is_on_curve(point):
        raise ValueError("Invalid Baby Jubjub commitment")
    return y | ((x & 1) << 255)


def _mask(secret, public_key, constant_commitment):
    shared = baby_mul(_secret(secret), checked_public_key(public_key))
    if _identity(shared):
        raise ValueError("Invalid identity DH shared point")
    compress_commitment(constant_commitment)
    # Identity is a valid zero coefficient commitment, unlike encryption keys.
    constant_x = 0 if constant_commitment is None else constant_commitment[0]
    return poseidon2(shared[0], constant_x)


def encrypt_share(share: int, dealer_secret: int, receiver_public, constant_commitment) -> int:
    if type(share) is not int or not 0 <= share < BABY_L:
        raise ValueError("Expected a canonical DKG share")
    return (share + _mask(dealer_secret, receiver_public, constant_commitment)) % BABY_P


def decrypt_share(ciphertext: int, receiver_secret: int, dealer_public, constant_commitment) -> int:
    if type(ciphertext) is not int or not 0 <= ciphertext < BABY_P:
        raise ValueError("Expected a canonical scalar ciphertext")
    share = (ciphertext - _mask(receiver_secret, dealer_public, constant_commitment)) % BABY_P
    if share >= BABY_L:
        raise ValueError("Decrypted value is not a canonical DKG share")
    return share


def scalar_payload(ciphertext: int) -> bytes:
    if type(ciphertext) is not int or not 0 <= ciphertext < BABY_P:
        raise ValueError("Expected a canonical scalar ciphertext")
    return ciphertext.to_bytes(32, 'big')


def read_scalar_payload(payload: bytes) -> int:
    if not isinstance(payload, bytes) or len(payload) != 32:
        raise ValueError("Expected a 32-byte scalar ciphertext")
    value = int.from_bytes(payload, 'big')
    scalar_payload(value)
    return value


def justification_hash(commitments, dealer_public, receiver_public, receiver_index, ciphertext) -> int:
    dealer = checked_public_key(dealer_public)
    receiver = checked_public_key(receiver_public)
    if not commitments or type(receiver_index) is not int or not 1 <= receiver_index <= 20:
        raise ValueError("Invalid dispute public inputs")
    packed = b''.join(compress_commitment(p).to_bytes(32, 'big') for p in commitments)
    words = [*dealer, *receiver, receiver_index]
    envelope = Web3.keccak(packed) + b''.join(v.to_bytes(32, 'big') for v in words) + scalar_payload(ciphertext)
    return int.from_bytes(Web3.keccak(envelope), 'big') % BABY_P
