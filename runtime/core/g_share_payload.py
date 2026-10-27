"""The shape of an encrypted DKG share, before any key is involved.

This payload arrives from another Guardian through the chain, so it is hostile
input in the ordinary case rather than the exceptional one. Reading it must fail
by saying what was wrong -- an IndexError on an empty payload surfaces in a poll
loop as an unexplained crash, when the true statement is "that dealer sent
nonsense", and the difference decides whether anyone can act on it.

Kept free of configuration so it can be tested without a Guardian identity, for
the same reason as g_chain_logs.py, g_secret_files.py and g_policy.py.
"""
from __future__ import annotations

import json

# [0x02 | ephemeral public key (32) | nonce (12) | ciphertext (48)]
V2_EPK_BYTES = 32
V2_NONCE_BYTES = 12
V2_CT_BYTES = 48
V2_PAYLOAD_LENGTH = 1 + V2_EPK_BYTES + V2_NONCE_BYTES + V2_CT_BYTES

V1_REQUIRED_FIELDS = ("epk", "nonce", "ct", "aad", "from", "to", "s_ij")


def parse_share_payload(payload: bytes):
    """Return ("v1", dict) or ("v2", (epk, nonce, ct)), or raise ValueError.

    Every refusal names the payload rather than the code that tripped over it.
    """
    raw = bytes(payload)
    if len(raw) < 2:
        raise ValueError(f"DKG share payload is too short: {len(raw)} bytes")

    if raw[0] == ord("{"):
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"DKG share payload is not readable JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("DKG share payload is not an object")
        for field in V1_REQUIRED_FIELDS:
            if field not in data:
                raise ValueError(f"DKG share payload is missing {field}")
        # Decoded here, not left to the caller. A parser that reports a missing
        # field but passes an unusable one through has drawn its boundary in an
        # odd place: what it returns should be usable, or it should have said no.
        for field in ("epk", "nonce", "ct"):
            try:
                bytes.fromhex(str(data[field]))
            except ValueError as exc:
                raise ValueError(f"DKG share payload has unreadable {field}: {exc}") from exc
        return "v1", data

    if raw[0] != 2:
        raise ValueError(f"Unknown DKG share payload version: {raw[0]}")

    # Measured before it is cut up: Python slices short input silently, so a
    # truncated payload would otherwise reach the curve as a shorter key and the
    # cipher as a shorter nonce, and fail somewhere that does not name the cause.
    if len(raw) != V2_PAYLOAD_LENGTH:
        raise ValueError(
            f"DKG share payload has wrong length: {len(raw)} bytes, "
            f"expected {V2_PAYLOAD_LENGTH}"
        )
    return "v2", (
        raw[1:1 + V2_EPK_BYTES],
        raw[1 + V2_EPK_BYTES:1 + V2_EPK_BYTES + V2_NONCE_BYTES],
        raw[1 + V2_EPK_BYTES + V2_NONCE_BYTES:],
    )
