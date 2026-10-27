"""X25519 + HKDF + AES-GCM share encryption / decryption.

Each Guardian has one long-term X25519 keypair stored in the instance root.
DKG shares sent to other Guardians are encrypted with their X25519 public key
(fetched from the on-chain GuardianRegistry) using ephemeral ECDH + HKDF +
AES-256-GCM.
"""
from __future__ import annotations

from core.g_secret_files import read_secret_json

import json
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from core.g_share_payload import parse_share_payload
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core.g_config import ROOT, SH_INDEX

_KEY_PATH = ROOT / "guardian_encryption_key.json"


# ---------------------------------------------------------------------------
# Local key management
# ---------------------------------------------------------------------------

def load_local_guardian_encryption_private_key() -> bytes:
    if not _KEY_PATH.exists():
        raise FileNotFoundError(f"Missing Guardian encryption key: {_KEY_PATH}")
    data = read_secret_json(_KEY_PATH)
    if data.get("curve") != "X25519":
        raise ValueError("Guardian encryption key must be X25519")
    private_hex = data["private_key_hex"].replace("0x", "")
    private_bytes = bytes.fromhex(private_hex)
    if len(private_bytes) != 32:
        raise ValueError(f"Invalid X25519 private key length: {len(private_bytes)}")
    return private_bytes


# ---------------------------------------------------------------------------
# Decryption
# ---------------------------------------------------------------------------

def decrypt_dkg_share_payload(payload: bytes, my_index: int, expected_from_index: int) -> int:
    """Decrypt an X25519-HKDF-AES-GCM-encrypted DKG share payload.

    Supports two wire formats:
      v1 (legacy JSON): starts with '{', payload is a JSON object
      v2 (binary):      starts with 0x02, layout = [0x02 | epk(32) | nonce(12) | ct(48)]
    """
    private_bytes = load_local_guardian_encryption_private_key()
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)

    # Shape first, before any key is involved, so a malformed payload is refused
    # by name rather than by whatever happens to trip over it.
    kind, parsed = parse_share_payload(payload)
    aad = f"DKG|{expected_from_index}|{my_index}".encode("utf-8")

    if kind == "v1":
        data = parsed
        eph_public_bytes = bytes.fromhex(data["epk"])
        nonce = bytes.fromhex(data["nonce"])
        ct = bytes.fromhex(data["ct"])
        aad = data["aad"].encode("utf-8")
        eph_public = x25519.X25519PublicKey.from_public_bytes(eph_public_bytes)
        shared_secret = private_key.exchange(eph_public)
        aes_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b"FileTrust-DKG-share-v1",
        ).derive(shared_secret)
        plaintext = AESGCM(aes_key).decrypt(nonce, ct, aad)
        share_data = json.loads(plaintext.decode("utf-8"))
        if int(share_data["from"]) != int(expected_from_index):
            raise ValueError(f"Wrong decrypted fromIndex: {share_data['from']}")
        if int(share_data["to"]) != int(my_index):
            raise ValueError(f"Wrong decrypted toIndex: {share_data['to']}")
        return int(share_data["s_ij"])

    epk_bytes, nonce, ct = parsed
    eph_public = x25519.X25519PublicKey.from_public_bytes(epk_bytes)
    shared_secret = private_key.exchange(eph_public)
    aes_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"FileTrust-DKG-share-v1",
    ).derive(shared_secret)
    plaintext = AESGCM(aes_key).decrypt(nonce, ct, aad)
    return int.from_bytes(plaintext, "big")


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def encrypt_dkg_share_for_guardian(
    recipient_public_key_bytes: bytes,
    from_index: int,
    to_index: int,
    s_ij: int,
) -> bytes:
    """Encrypt a DKG share scalar. Wire format v2: [0x02 | epk(32) | nonce(12) | ct(48)]"""
    recipient_public_key = x25519.X25519PublicKey.from_public_bytes(recipient_public_key_bytes)

    eph_private = x25519.X25519PrivateKey.generate()
    eph_public = eph_private.public_key()
    shared_secret = eph_private.exchange(recipient_public_key)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"FileTrust-DKG-share-v1",
    ).derive(shared_secret)

    nonce = secrets.token_bytes(12)
    plaintext = s_ij.to_bytes(32, "big")
    aad = f"DKG|{from_index}|{to_index}".encode("utf-8")
    ct = AESGCM(aes_key).encrypt(nonce, plaintext, aad)

    eph_public_bytes = eph_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b'\x02' + eph_public_bytes + nonce + ct
