"""All cryptographic math for Guardian nodes.

Covers:
  - secp256k1 elliptic-curve operations (used by legacy DKG and PRE DLEQ)
  - Baby Jubjub curve operations (used by ZKDKG_V2)
  - V2 ElGamal encryption / decryption over Baby Jubjub
  - Shamir polynomial evaluation
  - PRE DLEQ proof generation (secp256k1)
  - V2 share verification and Lagrange interpolation helpers

No I/O, no blockchain calls, no config imports.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import List, Optional, Tuple

from web3 import Web3

# ---------------------------------------------------------------------------
# secp256k1 parameters
# ---------------------------------------------------------------------------

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_A = 0
_B = 7

_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (_Gx, _Gy)

n_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

Point = Optional[Tuple[int, int]]

# ---------------------------------------------------------------------------
# secp256k1 field / curve operations
# ---------------------------------------------------------------------------

def mod_inv(x: int, m: int) -> int:
    return pow(x, m - 2, m)


def is_on_curve(P: Point) -> bool:
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + _A * x + _B)) % _P == 0


def point_add(P: Point, Q: Point) -> Point:
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return None
    if P == Q:
        if y1 == 0:
            return None
        s = (3 * x1 * x1 + _A) * mod_inv(2 * y1 % _P, _P) % _P
    else:
        if x1 == x2:
            return None
        s = (y2 - y1) * mod_inv((x2 - x1) % _P, _P) % _P
    x3 = (s * s - x1 - x2) % _P
    y3 = (s * (x1 - x3) - y1) % _P
    return (x3, y3)


def scalar_mult(k: int, P: Point) -> Point:
    if k % n_order == 0 or P is None:
        return None
    k = k % n_order
    result: Point = None
    addend = P
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def rand_scalar() -> int:
    return secrets.randbelow(n_order - 1) + 1


def poly_eval(coeffs: List[int], x: int, mod: int) -> int:
    res = 0
    pow_x = 1
    x = x % mod
    for c in coeffs:
        res = (res + c * pow_x) % mod
        pow_x = (pow_x * x) % mod
    return res


def lagrange_coeff_at_zero(i: int, indices: List[int], mod: int = n_order) -> int:
    """L_i(0) Lagrange coefficient for the given index set."""
    i = int(i)
    num = 1
    den = 1
    for j in indices:
        j = int(j)
        if j == i:
            continue
        num = (num * (-j)) % mod
        den = (den * (i - j)) % mod
    return (num * mod_inv(den % mod, mod)) % mod


def find_address_index(addresses: List[str], target: str) -> Optional[int]:
    target_cs = Web3.to_checksum_address(target).lower()
    for i, addr in enumerate(addresses, start=1):
        if Web3.to_checksum_address(addr).lower() == target_cs:
            return i
    return None


# ---------------------------------------------------------------------------
# secp256k1 DKG — polynomial-based share generation
# ---------------------------------------------------------------------------

def dkg_generate_local(t: int, n: int, my_index: int):
    """Generate secp256k1 DKG dealer material (legacy DKG protocol)."""
    if not (1 < t <= n):
        raise ValueError("Need 1 < t <= n")
    coeffs = [rand_scalar() for _ in range(t)]
    commitments_i = [scalar_mult(a_l, G) for a_l in coeffs]
    for P in commitments_i:
        assert is_on_curve(P)
    shares_row = [poly_eval(coeffs, j, n_order) for j in range(1, n + 1)]
    return commitments_i, shares_row


def dkg_generate_refresh_local(weighted_old_share: int, t_new: int, n_new: int):
    """Generate secp256k1 same-PK refresh dealer material."""
    if not (1 < t_new <= n_new):
        raise ValueError("Need 1 < t_new <= n_new")
    coeffs = [int(weighted_old_share) % n_order]
    coeffs.extend(rand_scalar() for _ in range(t_new - 1))
    commitments_i = [scalar_mult(a_l, G) for a_l in coeffs]
    for P in commitments_i:
        assert is_on_curve(P)
    shares_row = [poly_eval(coeffs, j, n_order) for j in range(1, n_new + 1)]
    return commitments_i, shares_row


# ---------------------------------------------------------------------------
# PRE DLEQ proof (secp256k1)
# ---------------------------------------------------------------------------

def make_pre_dleq_proof(
    request_id: int,
    share_version: int,
    share_index: int,
    sk: int,
    C1: Point,
    share_public_key: Point,
) -> dict:
    """Fiat-Shamir DLEQ proof: D = sk*C1 and share_public_key = sk*G."""
    if C1 is None or share_public_key is None:
        raise ValueError("Cannot prove DLEQ for point at infinity")
    D = scalar_mult(sk, C1)
    if D is None:
        raise ValueError("PRE partial is point at infinity")
    r = secrets.randbelow(n_order - 1) + 1
    a1 = scalar_mult(r, G)
    a2 = scalar_mult(r, C1)
    if a1 is None or a2 is None:
        raise ValueError("DLEQ nonce produced point at infinity")
    c = Web3.solidityKeccak(
        [
            "uint256", "uint32", "uint8",
            "uint256", "uint256",
            "uint256", "uint256",
            "uint256", "uint256",
            "uint256", "uint256",
            "uint256", "uint256",
        ],
        [
            int(request_id), int(share_version), int(share_index),
            int(C1[0]), int(C1[1]),
            int(share_public_key[0]), int(share_public_key[1]),
            int(D[0]), int(D[1]),
            int(a1[0]), int(a1[1]),
            int(a2[0]), int(a2[1]),
        ],
    )
    c_int = int.from_bytes(c, "big") % n_order
    s_int = (r + c_int * (int(sk) % n_order)) % n_order
    return {"D": D, "a1": a1, "a2": a2, "s": s_int, "c": c_int}


# ---------------------------------------------------------------------------
# Baby Jubjub parameters and curve operations
# ---------------------------------------------------------------------------

BABY_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
BABY_Q = 21888242871839275222246405745257275088614511777268538073601725287587578984328
BABY_L = BABY_Q // 8
BABY_A = 168700
BABY_D = 168696
BABY_G = (
    16540640123574156134436876038791482806971768689494387082833631921987005038935,
    20819045374670962167435360035096875258406992893633759881276124905556507972311,
)

BabyPoint = Optional[Tuple[int, int]]


def _keccak(data: bytes) -> bytes:
    return bytes(Web3.keccak(data))


def _bmod(x: int) -> int:
    return x % BABY_P


def _binv(x: int) -> int:
    return pow(x % BABY_P, BABY_P - 2, BABY_P)


def baby_is_on_curve(point: BabyPoint) -> bool:
    if point is None:
        return True
    x, y = point
    return (BABY_A * x * x + y * y - 1 - BABY_D * x * x * y * y) % BABY_P == 0


def baby_add(p: BabyPoint, q: BabyPoint) -> BabyPoint:
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    x1x2 = _bmod(x1 * x2)
    y1y2 = _bmod(y1 * y2)
    dxxyy = _bmod(BABY_D * x1x2 * y1y2)
    x3 = _bmod((_bmod(x1 * y2) + _bmod(y1 * x2)) * _binv(1 + dxxyy))
    y3 = _bmod((y1y2 - _bmod(BABY_A * x1x2)) * _binv(1 - dxxyy))
    return x3, y3


def baby_mul(scalar: int, point: BabyPoint = BABY_G) -> BabyPoint:
    if point is None:
        return None
    k = int(scalar) % BABY_L
    if k == 0:
        return None
    result: BabyPoint = None
    addend: BabyPoint = point
    while k:
        if k & 1:
            result = baby_add(result, addend)
        k >>= 1
        if k:
            addend = baby_add(addend, addend)
    return result


def baby_rand_scalar() -> int:
    return secrets.randbelow(BABY_L - 1) + 1


# ---------------------------------------------------------------------------
# Baby Jubjub DKG — polynomial-based share generation (ZKDKG_V2)
# ---------------------------------------------------------------------------

def v2_dkg_generate_local(t: int, n: int):
    if not (1 < t <= n):
        raise ValueError("Need 1 < t <= n")
    coeffs = [baby_rand_scalar() for _ in range(t)]
    commitments = [baby_mul(c, BABY_G) for c in coeffs]
    for point in commitments:
        if point is None or not baby_is_on_curve(point):
            raise ValueError("invalid Baby Jubjub commitment")
    shares_row = [poly_eval(coeffs, j, BABY_L) for j in range(1, n + 1)]
    return coeffs, commitments, shares_row


def v2_dkg_generate_refresh_local(old_share: int, t_new: int, n_new: int):
    if not (1 < int(t_new) <= int(n_new)):
        raise ValueError("Need 1 < t_new <= n_new")
    coeffs = [int(old_share) % BABY_L]
    coeffs.extend(baby_rand_scalar() for _ in range(int(t_new) - 1))
    commitments = [baby_mul(c, BABY_G) for c in coeffs]
    for point in commitments:
        if point is None or not baby_is_on_curve(point):
            raise ValueError("invalid Baby Jubjub refresh commitment")
    shares_row = [poly_eval(coeffs, j, BABY_L) for j in range(1, int(n_new) + 1)]
    return coeffs, commitments, shares_row


# ---------------------------------------------------------------------------
# V2 Baby Jubjub serialisation helpers
# ---------------------------------------------------------------------------

def _baby_points_to_json(points) -> list:
    return [[str(int(p[0])), str(int(p[1]))] for p in points]


def _baby_points_from_json(values) -> list:
    out = []
    for x, y in values:
        pnt = (int(x), int(y))
        if not baby_is_on_curve(pnt):
            raise ValueError("saved Baby Jubjub point is not on curve")
        out.append(pnt)
    return out


# ---------------------------------------------------------------------------
# V2 ElGamal encryption / decryption over Baby Jubjub
# ---------------------------------------------------------------------------

def _point_bytes(point: BabyPoint) -> bytes:
    if point is None:
        raise ValueError("point at infinity is not supported")
    return int(point[0]).to_bytes(32, "big") + int(point[1]).to_bytes(32, "big")


def xor_stream(data: bytes, key_material: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        out.extend(hashlib.sha256(key_material + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(a ^ b for a, b in zip(data, out[: len(data)]))


def v2_mask_key(shared: BabyPoint, context: bytes = b"") -> bytes:
    return hashlib.sha256(b"FileTrust-ZKDKG-V2-ElGamal" + _point_bytes(shared) + context).digest()


def v2_encrypt_to_pk(public_key: BabyPoint, plaintext: bytes, context: bytes = b""):
    if not baby_is_on_curve(public_key):
        raise ValueError("V2 public key is not on Baby Jubjub")
    r = secrets.randbelow(BABY_L - 1) + 1
    c1 = baby_mul(r, BABY_G)
    shared = baby_mul(r, public_key)
    if c1 is None or shared is None:
        raise RuntimeError("V2 encryption produced point at infinity")
    c2 = xor_stream(plaintext, v2_mask_key(shared, context))
    return c1, c2


def v2_batch_encryption_secret(public_key: BabyPoint):
    if not baby_is_on_curve(public_key):
        raise ValueError("V2 public key is not on Baby Jubjub")
    r = secrets.randbelow(BABY_L - 1) + 1
    c1 = baby_mul(r, BABY_G)
    shared = baby_mul(r, public_key)
    if c1 is None or shared is None:
        raise RuntimeError("V2 batch encryption produced point at infinity")
    return c1, shared


def v2_encrypt_with_shared(shared: BabyPoint, plaintext: bytes, context: bytes = b"") -> bytes:
    if shared is None:
        raise ValueError("missing V2 shared point")
    return xor_stream(plaintext, v2_mask_key(shared, context))


def v2_decrypt_with_shared(shared: BabyPoint, c2: bytes, context: bytes = b"") -> bytes:
    if shared is None:
        raise ValueError("missing V2 shared point")
    return xor_stream(bytes(c2), v2_mask_key(shared, context))


# ---------------------------------------------------------------------------
# V2 context hashing (Solidity-compatible keccak256)
# ---------------------------------------------------------------------------

def v2_context_hash(
    request_id: int,
    share_version: int,
    share_index: int,
    cid_index: int,
    c1: BabyPoint,
    share_pub: BabyPoint,
    d: BabyPoint,
) -> int:
    if c1 is None or share_pub is None or d is None:
        raise ValueError("V2 context points must not be infinity")
    encoded = b"".join(
        int(x).to_bytes(32, "big")
        for x in [
            request_id, share_version, share_index, cid_index,
            c1[0], c1[1], share_pub[0], share_pub[1], d[0], d[1],
        ]
    )
    return int.from_bytes(_keccak(encoded), "big") % BABY_P


def v2_batch_context_hash(
    request_id: int,
    batch_id: int,
    file_id: bytes | str,
    key_epoch: int,
    share_version: int,
    share_index: int,
    batch_c1: BabyPoint,
    share_pub: BabyPoint,
    e1: BabyPoint,
    e2: BabyPoint,
    pk_req: BabyPoint,
) -> int:
    """Context hash for the V2 batch PRE proof.

    Binds all public inputs: share key, C1, ElGamal ciphertext (E1, E2),
    and requester's Baby Jubjub public key.  D is NOT included — it is private.
    Must match _computeBatchDleqChallenge in TElGv2.sol exactly.
    """
    if batch_c1 is None or share_pub is None or e1 is None or e2 is None or pk_req is None:
        raise ValueError("V2 batch context points must not be infinity")
    if isinstance(file_id, str):
        h = file_id[2:] if file_id.startswith("0x") else file_id
        file_id_bytes = bytes.fromhex(h)
    else:
        file_id_bytes = bytes(file_id)
    if len(file_id_bytes) != 32:
        raise ValueError("fileId must be 32 bytes")
    encoded = b"".join([
        int(request_id).to_bytes(32, "big"),
        int(batch_id).to_bytes(32, "big"),
        file_id_bytes,
        int(key_epoch).to_bytes(32, "big"),
        int(share_version).to_bytes(32, "big"),
        int(share_index).to_bytes(32, "big"),
        int(batch_c1[0]).to_bytes(32, "big"),
        int(batch_c1[1]).to_bytes(32, "big"),
        int(share_pub[0]).to_bytes(32, "big"),
        int(share_pub[1]).to_bytes(32, "big"),
        int(e1[0]).to_bytes(32, "big"),
        int(e1[1]).to_bytes(32, "big"),
        int(e2[0]).to_bytes(32, "big"),
        int(e2[1]).to_bytes(32, "big"),
        int(pk_req[0]).to_bytes(32, "big"),
        int(pk_req[1]).to_bytes(32, "big"),
    ])
    return int.from_bytes(_keccak(encoded), "big") % BABY_P


# ---------------------------------------------------------------------------
# V2 Lagrange / threshold helpers
# ---------------------------------------------------------------------------

def v2_lagrange_coeff(x_j: int, x_set: list) -> int:
    xj = int(x_j) % BABY_L
    num = 1
    den = 1
    for xm in x_set:
        xm = int(xm) % BABY_L
        if xm == xj:
            continue
        num = (num * (-xm)) % BABY_L
        den = (den * (xj - xm)) % BABY_L
    return (num * pow(den, BABY_L - 2, BABY_L)) % BABY_L


def v2_combine_partials(partials: list) -> BabyPoint:
    indices = [int(i) for i, _ in partials]
    acc: BabyPoint = None
    for idx, point in partials:
        lam = v2_lagrange_coeff(int(idx), indices)
        acc = baby_add(acc, baby_mul(lam, point))
    return acc


def verify_v2_share_against_commitments(share: int, receiver_index: int, commitments) -> bool:
    """Verify share s against Baby Jubjub dealer commitments."""
    left = baby_mul(int(share) % BABY_L, BABY_G)
    if left is None:
        return False
    acc = None
    power = 1
    x = int(receiver_index) % BABY_L
    for commitment in commitments:
        term = baby_mul(power, commitment)
        acc = baby_add(acc, term)
        power = (power * x) % BABY_L
    return acc == left
