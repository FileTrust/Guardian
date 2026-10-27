"""Dealer material persistence and local share file I/O.

Handles everything that touches the instance's local filesystem:
  - File ID normalisation helpers
  - Atomic JSON writes (safe against partial-write crashes)
  - Path builders for every kind of dealer / share file
  - Load-or-create functions that guarantee one-shot randomness
  - File I/O for local share computation (secp256k1 legacy DKG)
  - Epoch metadata persistence

No blockchain calls, no config side-effects at import time.
"""
from __future__ import annotations

from core.g_secret_files import read_secret_json

import json
import os
import time
from pathlib import Path
from typing import List, Optional, Tuple

from web3 import Web3

from .g_secret_files import (
    SECRET_DIR_MODE,
    SECRET_FILE_MODE,
    make_secret_dir,
    open_secret_file,
    write_json_atomic,
    secret_dir_is_private,
    secret_file_is_private,
)

from core.g_config import (
    DEALER_MATERIAL_DIR,
    DKG_LOCAL_DIR,
    SH_INDEX,
    ROOT,
)
from core.g_crypto import (
    BABY_G,
    BABY_L,
    G,
    Point,
    _baby_points_from_json,
    _baby_points_to_json,
    baby_is_on_curve,
    baby_mul,
    dkg_generate_local,
    dkg_generate_refresh_local,
    is_on_curve,
    n_order,
    point_add,
    poly_eval,
    scalar_mult,
    v2_dkg_generate_local,
    v2_dkg_generate_refresh_local,
)

# ---------------------------------------------------------------------------
# File-ID helpers
# ---------------------------------------------------------------------------

def normalize_file_id_hex(value) -> str:
    if value is None:
        raise ValueError("FILE_ID is not set")
    if isinstance(value, (bytes, bytearray)):
        return Web3.to_hex(value)
    s = str(value).strip()
    if not s.startswith("0x"):
        s = "0x" + s
    if len(s) != 66:
        raise ValueError(f"Bad fileId length: {s}")
    return Web3.to_hex(Web3.to_bytes(hexstr=s))


def file_id_hex_to_bytes(file_id_hex: str) -> bytes:
    return Web3.to_bytes(hexstr=normalize_file_id_hex(file_id_hex))


def make_base_prefix(file_id_hex: str, n: int, t: int) -> str:
    short_id = normalize_file_id_hex(file_id_hex)[2:18]
    return f"dkg_ec_file_{short_id}_n{n}_t{t}"


# ---------------------------------------------------------------------------
# Atomic JSON write
# ---------------------------------------------------------------------------


# Re-exported so existing callers in this module keep working.
_write_json_atomic = write_json_atomic


# ---------------------------------------------------------------------------
# secp256k1 commitment serialisation helpers
# ---------------------------------------------------------------------------

def _points_to_xy(commitments_i: List[Point]):
    Cx, Cy = [], []
    for P in commitments_i:
        if P is None or not is_on_curve(P):
            raise ValueError("Invalid commitment point")
        Cx.append(str(P[0]))
        Cy.append(str(P[1]))
    return Cx, Cy


def _xy_to_points(Cx, Cy, expected_len: int) -> List[Point]:
    if len(Cx) != expected_len or len(Cy) != expected_len:
        raise ValueError("Invalid saved commitment length")
    out: List[Point] = []
    for x, y in zip(Cx, Cy):
        P = (int(x), int(y))
        if not is_on_curve(P):
            raise ValueError("Saved commitment is not on curve")
        out.append(P)
    return out


# Baby Jubjub commitment helpers (used by chain publish functions)
def _commitments_xy(commitments):
    xs, ys = [], []
    for point in commitments:
        if point is None or not baby_is_on_curve(point):
            raise ValueError("invalid Baby Jubjub commitment")
        xs.append(int(point[0]))
        ys.append(int(point[1]))
    return xs, ys


# ---------------------------------------------------------------------------
# Path builders
# ---------------------------------------------------------------------------

def fresh_dkg_material_path(file_id_hex: str, key_epoch: int, n: int, t: int, guardian_index: int) -> Path:
    short_id = normalize_file_id_hex(file_id_hex)[2:18]
    return DEALER_MATERIAL_DIR / (
        f"fresh_dkg_{short_id}_k{int(key_epoch)}_n{int(n)}_t{int(t)}_sh{int(guardian_index)}.json"
    )


def refresh_dealer_material_path(
    file_id_hex: str, key_epoch: int, share_version: int,
    old_index: int, new_n: int, new_t: int,
) -> Path:
    short_id = normalize_file_id_hex(file_id_hex)[2:18]
    return DEALER_MATERIAL_DIR / (
        f"refresh_{short_id}_k{int(key_epoch)}_v{int(share_version)}_"
        f"old{int(old_index)}_newn{int(new_n)}_newt{int(new_t)}.json"
    )


def v2_fresh_material_path(file_id_hex: str, key_epoch: int, n: int, t: int, guardian_index: int) -> Path:
    short_id = normalize_file_id_hex(file_id_hex)[2:18]
    return DEALER_MATERIAL_DIR / (
        f"v2_fresh_dkg_{short_id}_k{int(key_epoch)}_n{int(n)}_t{int(t)}_G{int(guardian_index)}.json"
    )


def v2_final_share_path(
    file_id_hex: str, key_epoch: int, share_version: int,
    n: int, t: int, share_index: int,
) -> Path:
    from . import g_config as cfg
    if getattr(cfg,'DKG_ATTEMPT_PROTOCOL',0)==1:
        from .g_dkg_custody import active_share_path
        return active_share_path(cfg,file_id_hex,key_epoch,share_version,n,t,share_index)
    short_id = normalize_file_id_hex(file_id_hex)[2:18]
    return DKG_LOCAL_DIR / (
        f"v2_dkg_file_{short_id}_n{int(n)}_t{int(t)}_k{int(key_epoch)}_v{int(share_version)}_final_share_{int(share_index)}.json"
    )


def v2_refresh_material_path(
    file_id_hex: str, key_epoch: int, share_version: int,
    old_index: int, new_n: int, new_t: int,
) -> Path:
    short_id = normalize_file_id_hex(file_id_hex)[2:18]
    return DEALER_MATERIAL_DIR / (
        f"v2_refresh_{short_id}_k{int(key_epoch)}_v{int(share_version)}_"
        f"old{int(old_index)}_newn{int(new_n)}_newt{int(new_t)}.json"
    )


def refresh_base_prefix(file_id_hex: str, n: int, t: int, key_epoch: int, share_version: int) -> str:
    base = f"{make_base_prefix(file_id_hex, n, t)}_k{int(key_epoch)}"
    if int(share_version) > 1:
        base = f"{base}_v{int(share_version)}"
    return base


def final_share_path_for_version(
    file_id_hex: str, n: int, t: int,
    key_epoch: int, share_version: int, share_index: int,
) -> Path:
    base = refresh_base_prefix(file_id_hex, n, t, key_epoch, share_version)
    return ROOT / f"{base}_final_share_{int(share_index)}.json"


# ---------------------------------------------------------------------------
# Load-or-create V2 (Baby Jubjub) fresh dealer material
# Critical: never regenerate after any material has been published on-chain.
# ---------------------------------------------------------------------------

def load_or_create_v2_fresh_material(
    file_id_hex: str, key_epoch: int, n: int, t: int, guardian_index: int,
):
    path = v2_fresh_material_path(file_id_hex, key_epoch, n, t, guardian_index)
    if path.exists():
        data = read_secret_json(path)
        if normalize_file_id_hex(data.get("fileId", "")) != normalize_file_id_hex(file_id_hex):
            raise ValueError(f"Saved V2 DKG material has wrong fileId: {path}")
        if int(data.get("keyEpoch", -1)) != int(key_epoch):
            raise ValueError(f"Saved V2 DKG material has wrong keyEpoch: {path}")
        if int(data.get("shareVersion", 1)) != 1:
            raise ValueError(f"Saved V2 DKG material has unsupported shareVersion: {path}")
        if int(data.get("guardianIndex", -1)) != int(guardian_index):
            raise ValueError(f"Saved V2 DKG material has wrong guardianIndex: {path}")
        if int(data.get("n", -1)) != int(n) or int(data.get("t", -1)) != int(t):
            raise ValueError(f"Saved V2 DKG material has wrong n/t: {path}")
        coeffs = [int(x) for x in data["coeffs"]]
        commitments = _baby_points_from_json(data["commitments"])
        shares_row = [int(x) for x in data["shares_row"]]
        if len(coeffs) != int(t) or len(commitments) != int(t) or len(shares_row) != int(n):
            raise ValueError(f"Saved V2 DKG material has wrong lengths: {path}")
        print(f"  -> V2 G {guardian_index}: reused saved Baby Jubjub DKG material: {path}")
        return coeffs, commitments, shares_row

    coeffs, commitments, shares_row = v2_dkg_generate_local(int(t), int(n))
    data = {
        "kind": "zkdkg_v2_dealer_material",
        "curve": "BabyJubjub",
        "fileId": normalize_file_id_hex(file_id_hex),
        "keyEpoch": int(key_epoch),
        "shareVersion": 1,
        "guardianIndex": int(guardian_index),
        "n": int(n),
        "t": int(t),
        "coeffs": [str(x) for x in coeffs],
        "commitments": _baby_points_to_json(commitments),
        "shares_row": [str(x) for x in shares_row],
    }
    _write_json_atomic(path, data)
    print(f"  -> V2 G {guardian_index}: created Baby Jubjub DKG material: {path}")
    return coeffs, commitments, shares_row


def load_v2_final_share_for_version(
    file_id_hex: str, key_epoch: int, share_version: int,
    n: int, t: int, share_index: int,
) -> Tuple[int, int]:
    from . import g_config as cfg
    if getattr(cfg,'DKG_ATTEMPT_PROTOCOL',0)==1:
        from .g_dkg_custody import load_active_share
        return load_active_share(cfg,file_id_hex,key_epoch,share_version,n,t,share_index)
    path = v2_final_share_path(file_id_hex, key_epoch, share_version, n, t, share_index)
    if not path.exists():
        raise FileNotFoundError(f"Missing local ZKDKG_V2 share for refresh: {path}")
    data = read_secret_json(path)
    return int(data.get("index", data.get("shareIndex", share_index))), int(data.get("share", data.get("sk")))


def load_or_create_v2_refresh_material(
    file_id_hex: str, key_epoch: int, share_version: int,
    old_index: int, old_share: int, new_t: int, new_n: int,
):
    path = v2_refresh_material_path(file_id_hex, key_epoch, share_version, old_index, new_n, new_t)
    if path.exists():
        data = read_secret_json(path)
        if normalize_file_id_hex(data.get("fileId", "")) != normalize_file_id_hex(file_id_hex):
            raise ValueError(f"Saved V2 refresh material has wrong fileId: {path}")
        if int(data.get("keyEpoch", -1)) != int(key_epoch):
            raise ValueError(f"Saved V2 refresh material has wrong keyEpoch: {path}")
        if int(data.get("shareVersion", -1)) != int(share_version):
            raise ValueError(f"Saved V2 refresh material has wrong shareVersion: {path}")
        if int(data.get("oldIndex", -1)) != int(old_index):
            raise ValueError(f"Saved V2 refresh material has wrong oldIndex: {path}")
        if int(data.get("newN", -1)) != int(new_n) or int(data.get("newT", -1)) != int(new_t):
            raise ValueError(f"Saved V2 refresh material has wrong new n/t: {path}")
        coeffs = [int(x) for x in data["coeffs"]]
        commitments = _baby_points_from_json(data["commitments"])
        shares_row = [int(x) for x in data["shares_row"]]
        expected_c0 = baby_mul(int(old_share) % BABY_L, BABY_G)
        if commitments[0] != expected_c0:
            raise ValueError(
                "Saved V2 refresh material does not match this Guardian's old V2 share. "
                "Do not reuse this folder with a different chain/key epoch/share version."
            )
        print(f"[ZKDKG_V2 refresh] old participant {old_index}: reused saved material: {path}")
        return coeffs, commitments, shares_row

    coeffs, commitments, shares_row = v2_dkg_generate_refresh_local(old_share, int(new_t), int(new_n))
    data = {
        "kind": "zkdkg_v2_same_pk_refresh_material",
        "curve": "BabyJubjub",
        "fileId": normalize_file_id_hex(file_id_hex),
        "keyEpoch": int(key_epoch),
        "shareVersion": int(share_version),
        "oldIndex": int(old_index),
        "newN": int(new_n),
        "newT": int(new_t),
        "coeffs": [str(x) for x in coeffs],
        "commitments": _baby_points_to_json(commitments),
        "shares_row": [str(x) for x in shares_row],
    }
    _write_json_atomic(path, data)
    print(f"[ZKDKG_V2 refresh] old participant {old_index}: created material: {path}")
    return coeffs, commitments, shares_row


# ---------------------------------------------------------------------------
# Load-or-create secp256k1 (legacy) dealer material
# ---------------------------------------------------------------------------

def load_or_create_fresh_dkg_material(
    file_id_hex: str, key_epoch: int, n: int, t: int, guardian_index: int,
):
    path = fresh_dkg_material_path(file_id_hex, key_epoch, n, t, guardian_index)
    if path.exists():
        data = read_secret_json(path)
        commitments_i = _xy_to_points(data["Cx"], data["Cy"], int(t))
        shares_row = [int(x) for x in data["shares_row"]]
        if len(shares_row) != int(n):
            raise ValueError("Invalid saved DKG shares_row length")
        print(f"  -> SH {guardian_index}: reused saved fresh DKG material: {path}")
        return commitments_i, shares_row

    commitments_i, shares_row = dkg_generate_local(int(t), int(n), int(guardian_index))
    Cx, Cy = _points_to_xy(commitments_i)
    data = {
        "kind": "fresh_dkg_dealer_material",
        "fileId": normalize_file_id_hex(file_id_hex),
        "keyEpoch": int(key_epoch),
        "guardianIndex": int(guardian_index),
        "n": int(n),
        "t": int(t),
        "Cx": Cx,
        "Cy": Cy,
        "shares_row": [str(x) for x in shares_row],
    }
    _write_json_atomic(path, data)
    print(f"  -> SH {guardian_index}: created and saved fresh DKG material: {path}")
    return commitments_i, shares_row


def load_or_create_refresh_dealer_material(
    file_id_hex: str, key_epoch: int, share_version: int,
    old_index: int, old_sk: int, new_t: int, new_n: int,
):
    path = refresh_dealer_material_path(file_id_hex, key_epoch, share_version, old_index, new_n, new_t)
    if path.exists():
        data = read_secret_json(path)
        commitments_i = _xy_to_points(data["Cx"], data["Cy"], int(new_t))
        shares_row = [int(x) for x in data["shares_row"]]
        if len(shares_row) != int(new_n):
            raise ValueError("Invalid saved refresh shares_row length")
        expected_c0 = scalar_mult(int(old_sk), G)
        if commitments_i[0] != expected_c0:
            raise ValueError(
                "Saved refresh material does not match this Guardian's old share. "
                "Do not reuse this folder with a different chain/key epoch."
            )
        print(f"[refresh] old participant {old_index}: reused saved refresh material: {path}")
        return commitments_i, shares_row

    commitments_i, shares_row = dkg_generate_refresh_local(int(old_sk), int(new_t), int(new_n))
    Cx, Cy = _points_to_xy(commitments_i)
    data = {
        "kind": "same_pk_refresh_dealer_material",
        "fileId": normalize_file_id_hex(file_id_hex),
        "keyEpoch": int(key_epoch),
        "shareVersion": int(share_version),
        "oldIndex": int(old_index),
        "newN": int(new_n),
        "newT": int(new_t),
        "Cx": Cx,
        "Cy": Cy,
        "shares_row": [str(x) for x in shares_row],
    }
    _write_json_atomic(path, data)
    print(f"[refresh] old participant {old_index}: created and saved refresh material: {path}")
    return commitments_i, shares_row


def load_final_share_for_version(
    file_id_hex: str, n: int, t: int,
    key_epoch: int, share_version: int, share_index: int,
) -> Tuple[int, int]:
    path = final_share_path_for_version(file_id_hex, n, t, key_epoch, share_version, share_index)
    if not path.exists():
        raise FileNotFoundError(f"Missing local share for refresh: {path}")
    data = read_secret_json(path)
    return int(data["index"]), int(data["sk"])


# ---------------------------------------------------------------------------
# Local file I/O — legacy secp256k1 share coordination files
# ---------------------------------------------------------------------------

_SHARED_DIR = DKG_LOCAL_DIR


def write_local_commitments_file(base_prefix: str, idx: int, n: int, t: int, commitments_i: List[Point]) -> None:
    Cx = [str(P[0]) for P in commitments_i]
    Cy = [str(P[1]) for P in commitments_i]
    data = {"index": idx, "n": n, "t": t, "Cx": Cx, "Cy": Cy}
    filename = _SHARED_DIR / f"{base_prefix}_commitments_{idx}.json"
    with open_secret_file(filename) as f:
        json.dump(data, f, indent=2)
    print(f"  -> Commitments of SH {idx} written to {filename}")


def write_outgoing_shares_files(base_prefix: str, idx: int, shares_row: List[int]) -> None:
    for j, s_ij in enumerate(shares_row, start=1):
        data = {"from": idx, "to": j, "s_ij": str(s_ij)}
        filename = _SHARED_DIR / f"{base_prefix}_share_from_{idx}_to_{j}.json"
        with open_secret_file(filename) as f:
            json.dump(data, f, indent=2)
    print(f"  -> Outgoing shares of SH {idx} written for all recipients.")


def read_all_commitments(base_prefix: str, n: int, t: int) -> List[List[Point]]:
    all_commitments: List[List[Point]] = []
    for i in range(1, n + 1):
        filename = _SHARED_DIR / f"{base_prefix}_commitments_{i}.json"
        if not filename.exists():
            raise FileNotFoundError(f"Missing commitments file: {filename}")
        data = read_secret_json(filename)
        Cx, Cy = data["Cx"], data["Cy"]
        if len(Cx) != t or len(Cy) != t:
            raise ValueError("Invalid commitments length")
        Ci: List[Point] = []
        for x_str, y_str in zip(Cx, Cy):
            P = (int(x_str), int(y_str))
            assert is_on_curve(P)
            Ci.append(P)
        all_commitments.append(Ci)
    return all_commitments


def read_incoming_shares_for_index(base_prefix: str, my_index: int, n: int) -> List[int]:
    shares_for_j: List[int] = []
    for i in range(1, n + 1):
        filename = _SHARED_DIR / f"{base_prefix}_share_from_{i}_to_{my_index}.json"
        if not filename.exists():
            raise FileNotFoundError(f"Missing share file: {filename}")
        data = read_secret_json(filename)
        shares_for_j.append(int(data["s_ij"]))
    return shares_for_j


def wait_for_files(paths: List[Path], poll_interval: int = 2) -> None:
    while True:
        if all(path.exists() for path in paths):
            return
        time.sleep(poll_interval)


def write_final_share_json(
    base_prefix: str, idx: int, n: int, t: int, sk_j: int, vk_j: Point,
) -> None:
    if vk_j is None:
        raise ValueError("vk_j is INF")
    vkx, vky = vk_j
    data = {"index": idx, "n": n, "t": t, "sk": str(sk_j), "vkx": str(vkx), "vky": str(vky)}
    filename = ROOT / f"{base_prefix}_final_share_{idx}.json"
    with open_secret_file(filename) as f:
        json.dump(data, f, indent=2)
    print(f"  -> Final share of SH {idx} written to {filename}")


def write_final_share_json_for_version(
    file_id_hex: str, n: int, t: int,
    key_epoch: int, share_version: int, idx: int, sk_j: int, vk_j: Point,
) -> None:
    if vk_j is None:
        raise ValueError("vk_j is INF")
    vkx, vky = vk_j
    data = {
        "fileId": normalize_file_id_hex(file_id_hex),
        "keyEpoch": int(key_epoch),
        "shareVersion": int(share_version),
        "index": int(idx),
        "n": int(n),
        "t": int(t),
        "sk": str(sk_j),
        "vkx": str(vkx),
        "vky": str(vky),
    }
    path = final_share_path_for_version(file_id_hex, n, t, key_epoch, share_version, idx)
    with open_secret_file(path) as f:
        json.dump(data, f, indent=2)
    print(f"  -> Refreshed final share written to {path}")


def write_global_json(
    filename: Path, file_id_hex: str, n: int, t: int, PK: Point, agg_commitments: List[Point],
) -> None:
    if PK is None:
        raise ValueError("PK is INF")
    PKx, PKy = PK
    Cx = [str(P[0]) for P in agg_commitments]
    Cy = [str(P[1]) for P in agg_commitments]
    data = {
        "fileId": normalize_file_id_hex(file_id_hex),
        "n": n, "t": t,
        "PKx": str(PKx), "PKy": str(PKy),
        "Cx": Cx, "Cy": Cy,
    }
    with open_secret_file(filename) as f:
        json.dump(data, f, indent=2)


def write_epoch_metadata_json(
    file_id_hex: str, key_epoch: int, n: int, t: int, guardians: List[str],
) -> None:
    short_id = normalize_file_id_hex(file_id_hex)[2:18]
    path = _SHARED_DIR / f"dkg_epoch_{short_id}_k{key_epoch}.json"
    data = {
        "fileId": normalize_file_id_hex(file_id_hex),
        "keyEpoch": int(key_epoch),
        "dkgN": int(n),
        "dkgT": int(t),
        "guardians": [Web3.to_checksum_address(g) for g in guardians],
    }
    with open_secret_file(path) as f:
        json.dump(data, f, indent=2)
    print(f"DKG epoch metadata saved to {path}")


def load_epoch_metadata(file_id_hex: str, key_epoch: int) -> dict:
    file_id_hex = normalize_file_id_hex(file_id_hex)
    short_id = file_id_hex[2:18]
    path = _SHARED_DIR / f"dkg_epoch_{short_id}_k{int(key_epoch)}.json"
    if not path.exists():
        raise FileNotFoundError(f"Missing DKG epoch metadata: {path}")
    return read_secret_json(path)


# ---------------------------------------------------------------------------
# Local share computation — secp256k1 legacy DKG
# ---------------------------------------------------------------------------

def compute_local_share_after_collecting(
    base_prefix: str, my_index: int, n: int, t: int,
):
    commit_files = [_SHARED_DIR / f"{base_prefix}_commitments_{i}.json" for i in range(1, n + 1)]
    share_files = [_SHARED_DIR / f"{base_prefix}_share_from_{i}_to_{my_index}.json" for i in range(1, n + 1)]
    print(f"SH {my_index}: waiting for all commitments and incoming shares...")
    wait_for_files(commit_files + share_files)

    commitments = read_all_commitments(base_prefix, n, t)
    shares_for_j = read_incoming_shares_for_index(base_prefix, my_index, n)

    j = my_index
    for i in range(n):
        Ci = commitments[i]
        s_ij = shares_for_j[i]
        left = scalar_mult(s_ij, G)
        acc: Point = None
        pow_j = 1
        for C_l in Ci:
            term = scalar_mult(pow_j, C_l)
            acc = point_add(acc, term)
            pow_j = (pow_j * j) % n_order
        if left != acc:
            raise ValueError(f"Share verification failed for i={i + 1}, j={j}")

    sk_j = sum(shares_for_j) % n_order
    vk_j = scalar_mult(sk_j, G)
    return sk_j, vk_j
