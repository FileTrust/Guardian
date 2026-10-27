"""All blockchain interactions for Guardian nodes.

Covers:
  - Contract loaders (ACL, DKG, TElG, ZKDKG_V2, GuardianRegistry, …)
  - On-chain reads: commitments, encrypted shares, PRE job state
  - On-chain writes: DKG material, PRE partials, disputes, pricing
  - Share public key publishing
  - Same-PK refresh discovery and processing (secp256k1 and Baby Jubjub)
  - ZKDKG_V2 policy processing
  - PRE job build from chain
"""
from __future__ import annotations

from core.g_secret_files import read_secret_json

import json
import time
from pathlib import Path
from typing import List, Optional, Tuple

from web3 import Web3

from .g_policy import get_current_policy_info as _get_current_policy_info

import core.g_config as cfg
from core.g_log import log_every, log_once, log_state, preview_list
from core.g_crypto import (
    BABY_G,
    BABY_L,
    G,
    Point,
    baby_add,
    baby_is_on_curve,
    baby_mul,
    find_address_index,
    is_on_curve,
    lagrange_coeff_at_zero,
    n_order,
    point_add,
    poly_eval,
    scalar_mult,
    verify_v2_share_against_commitments,
)
from core.g_material import (
    _commitments_xy,
    _write_json_atomic,
    final_share_path_for_version,
    load_epoch_metadata,
    load_final_share_for_version,
    load_or_create_fresh_dkg_material,
    load_or_create_refresh_dealer_material,
    load_or_create_v2_fresh_material,
    load_or_create_v2_refresh_material,
    load_v2_final_share_for_version,
    make_base_prefix,
    normalize_file_id_hex,
    refresh_dealer_material_path,
    v2_final_share_path,
    v2_fresh_material_path,
    v2_refresh_material_path,
    write_final_share_json_for_version,
)
from core.g_share_crypto import decrypt_dkg_share_payload, encrypt_dkg_share_for_guardian
from core.g_tx import PreTxOutcome, is_terminal_v2_pre_error, send_contract_transaction
from core.g_zk import generate_zkdkg_dispute_justification_proof, proof_tuple_from_zokrates_json

try:
    from core import g_txlog as TXLOG
except Exception:
    TXLOG = None

# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------

_SCAN_SKIP_UNTIL: dict[tuple, float] = {}
_POLICY_ID_CACHE: dict[str, tuple[float, tuple[bytes, ...]]] = {}
_EVENT_CURSOR_CACHE: dict[str, int] | None = None
_POLICY_ID_CACHE_SECONDS = 20.0

_SHORT_SCAN_SKIP_SECONDS = 60.0
_COMPLETE_SCAN_SKIP_SECONDS = 300.0
_EVENT_CURSOR_LOOKBACK_BLOCKS = 100

# How far behind the event cursor may fall before it is moved to the head
# instead of walked forward. About fourteen hours on a one-second chain.
#
# Walking back further than this buys nothing and risks something. Nothing,
# because the events are only used to notice work sooner: the periodic scan
# reads the authoritative state -- every access request, every policy -- and
# finds the same work whether or not a single log was ever read. And something,
# because an RPC node that prunes history cannot answer for blocks that old, so
# a Guardian returning after a long absence would fail every pass, never advance
# the cursor, and stall permanently for a second reason after the first was
# fixed.
_EVENT_CURSOR_MAX_CATCHUP_BLOCKS = 50_000


def _scan_skip_active(key: tuple) -> bool:
    until = _SCAN_SKIP_UNTIL.get(key)
    if until is None:
        return False
    if until <= time.monotonic():
        _SCAN_SKIP_UNTIL.pop(key, None)
        return False
    return True


def _remember_scan_skip(key: tuple, seconds: float) -> None:
    _SCAN_SKIP_UNTIL[key] = time.monotonic() + max(1.0, float(seconds))


def _contract_cache_key(contract) -> str:
    address = getattr(contract, "address", None) or getattr(contract, "contract_address", None)
    return str(address or id(contract)).lower()


def _policy_ids(acl) -> tuple[bytes, ...]:
    key = _contract_cache_key(acl)
    now = time.monotonic()
    cached = _POLICY_ID_CACHE.get(key)
    if cached is not None and cached[0] > now:
        return cached[1]

    count = acl.functions.getFilePolicyCount().call()
    file_ids = tuple(acl.functions.getFileIdAt(i).call() for i in range(count))
    _POLICY_ID_CACHE[key] = (now + _POLICY_ID_CACHE_SECONDS, file_ids)
    return file_ids


def _event_cursor_path() -> Path:
    return cfg.ROOT / "state" / "guardian_event_cursors.json"


def _load_event_cursors() -> dict[str, int]:
    global _EVENT_CURSOR_CACHE
    if _EVENT_CURSOR_CACHE is not None:
        return _EVENT_CURSOR_CACHE
    path = _event_cursor_path()
    try:
        raw = read_secret_json(path)
        _EVENT_CURSOR_CACHE = {str(k): int(v) for k, v in raw.items()}
    except Exception:
        _EVENT_CURSOR_CACHE = {}
    return _EVENT_CURSOR_CACHE


def _save_event_cursors() -> None:
    if _EVENT_CURSOR_CACHE is None:
        return
    path = _event_cursor_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        _write_json_atomic(path, _EVENT_CURSOR_CACHE)
    except Exception:
        pass


def _event_cursor_key(name: str, *contracts) -> str:
    parts = [name]
    parts.extend(_contract_cache_key(contract) for contract in contracts if contract is not None)
    return ":".join(parts)


def _event_file_id(value) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        data = value
    elif isinstance(value, str):
        try:
            data = Web3.to_bytes(hexstr=value)
        except Exception:
            return None
    else:
        try:
            data = bytes(value)
        except Exception:
            return None
    return data if len(data) == 32 else None


def _event_uint(value) -> int | None:
    try:
        return int(value)
    except Exception:
        return None


def _collect_event_file_ids(w3: Web3, cursor_name: str, event_specs: list[tuple[object, tuple[str, ...]]]) -> tuple[bytes, ...]:
    cursors = _load_event_cursors()
    contracts = [contract for contract, _names in event_specs]
    key = _event_cursor_key(cursor_name, *contracts)
    try:
        latest = int(w3.eth.block_number)
    except Exception:
        return tuple()
    last_seen = int(cursors.get(key, max(0, latest - _EVENT_CURSOR_LOOKBACK_BLOCKS)))
    if latest <= last_seen:
        return tuple()

    if latest - last_seen > _EVENT_CURSOR_MAX_CATCHUP_BLOCKS:
        # Skipped, not lost: the state scan covers the gap.
        last_seen = max(0, latest - LOG_WINDOW_BLOCKS)

    from_block = max(0, last_seen + 1)
    # Bounded span, not just a bounded start. The cursor keeps the beginning
    # close to the head while the Guardian is running, but says nothing about
    # how far behind it can fall: after a few hours offline this asked for every
    # block since, and a chain that caps a log query -- Cosmos refuses more than
    # 10,000 blocks -- rejects the whole request. The Guardian would then fail on
    # every poll, permanently, having done nothing wrong except stop for a while.
    #
    # Reading one window per pass catches up over several passes instead.
    latest = min(latest, from_block + LOG_WINDOW_BLOCKS - 1)
    if latest < from_block:
        return tuple()
    found: list[bytes] = []
    seen: set[bytes] = set()
    try:
        for contract, event_names in event_specs:
            for event_name in event_names:
                event_factory = getattr(contract.events, event_name, None)
                if event_factory is None:
                    continue
                for entry in event_factory().get_logs(from_block=from_block, to_block=latest):
                    file_id = _event_file_id(entry.get("args", {}).get("fileId"))
                    if file_id is None or file_id in seen:
                        continue
                    seen.add(file_id)
                    found.append(file_id)
        cursors[key] = latest
        _save_event_cursors()
    except Exception:
        return tuple()
    return tuple(found)


def _collect_event_request_ids(w3: Web3, cursor_name: str, event_specs: list[tuple[object, tuple[str, ...]]]) -> tuple[int, ...]:
    cursors = _load_event_cursors()
    contracts = [contract for contract, _names in event_specs]
    key = _event_cursor_key(cursor_name, *contracts)
    try:
        latest = int(w3.eth.block_number)
    except Exception:
        return tuple()
    last_seen = int(cursors.get(key, max(0, latest - _EVENT_CURSOR_LOOKBACK_BLOCKS)))
    if latest <= last_seen:
        return tuple()

    from_block = max(0, last_seen + 1)
    found: list[int] = []
    seen: set[int] = set()
    try:
        for contract, event_names in event_specs:
            for event_name in event_names:
                event_factory = getattr(contract.events, event_name, None)
                if event_factory is None:
                    continue
                for entry in event_factory().get_logs(from_block=from_block, to_block=latest):
                    request_id = _event_uint(entry.get("args", {}).get("requestId"))
                    if request_id is None or request_id in seen:
                        continue
                    seen.add(request_id)
                    found.append(request_id)
        cursors[key] = latest
        _save_event_cursors()
    except Exception:
        return tuple()
    return tuple(found)


def collect_dkg_event_file_ids(w3: Web3, acl, coordinator_v2=None) -> tuple[bytes, ...]:
    specs: list[tuple[object, tuple[str, ...]]] = [
        (acl, (
            "KeyGenRequestedForFile",
        )),
    ]
    if coordinator_v2 is not None:
        specs.append((coordinator_v2, (
            "ZkDkgV2SamePkRefreshRequested",
            "ZkDkgV2Finalized",
        )))
    file_ids = _collect_event_file_ids(w3, "dkg", specs)
    if file_ids:
        _POLICY_ID_CACHE.pop(_contract_cache_key(acl), None)
    return file_ids


def collect_pre_event_request_ids(w3: Web3, dv, telg_v2=None) -> tuple[int, ...]:
    specs: list[tuple[object, tuple[str, ...]]] = [
        (dv, ("DataAccessRequestedV2",)),
    ]
    return _collect_event_request_ids(w3, "pre", specs)


def is_no_pending_refresh_error(exc: Exception) -> bool:
    return "no pending refresh" in str(exc).lower()


def short_addr(addr: str) -> str:
    addr = str(addr)
    if len(addr) <= 12:
        return addr
    return addr[:6] + "..." + addr[-4:]


def normalize_uint_list(values) -> List[int]:
    return [int(x) for x in list(values or [])]


# ---------------------------------------------------------------------------
# Generic contract loader
# ---------------------------------------------------------------------------

def load_contract(w3: Web3, address: str, json_path: str):
    with open(json_path, "r", encoding="utf-8") as f:
        artifact = json.load(f)
    checksum = Web3.to_checksum_address(address)
    code = w3.eth.get_code(checksum)
    if len(code) == 0:
        raise RuntimeError(
            f"No contract code at {checksum}. "
            f"Check the configured address for artifact {json_path}."
        )
    return w3.eth.contract(address=checksum, abi=artifact["abi"])


def _load_contract_opt(w3: Web3, address: str | None, json_path: str | None):
    """Return contract or None when address/path not configured."""
    if not address or not json_path:
        return None
    resolved = cfg.resolve_artifact_path(json_path)
    if resolved is None or not resolved.is_file():
        return None
    try:
        return load_contract(w3, address, str(resolved))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Named contract loaders
# ---------------------------------------------------------------------------

def load_guardian_registry(w3: Web3):
    resolved = cfg.resolve_artifact_path(cfg.GUARDIAN_REGISTRY_JSON)
    if not cfg.GUARDIAN_REGISTRY_ADDRESS or resolved is None or not resolved.is_file():
        raise RuntimeError("GuardianRegistry not configured")
    artifact = json.loads(resolved.read_text(encoding="utf-8"))
    return w3.eth.contract(
        address=Web3.to_checksum_address(cfg.GUARDIAN_REGISTRY_ADDRESS),
        abi=artifact["abi"],
    )


def load_zkdkg_dispute_manager(w3: Web3):
    resolved = cfg.resolve_artifact_path(cfg.ZKDKG_DISPUTE_MANAGER_JSON)
    if not cfg.ZKDKG_DISPUTE_MANAGER_ADDRESS or resolved is None or not resolved.is_file():
        raise ValueError("ZkDkgDisputeManager address/artifact is not configured")
    artifact = json.loads(resolved.read_text(encoding="utf-8"))
    return w3.eth.contract(
        address=Web3.to_checksum_address(cfg.ZKDKG_DISPUTE_MANAGER_ADDRESS),
        abi=artifact["abi"],
    )


def load_zkdkg_coordinator_v2(w3: Web3):
    resolved = cfg.resolve_artifact_path(cfg.ZKDKG_COORDINATOR_V2_JSON)
    if not cfg.ZKDKG_COORDINATOR_V2_ADDRESS or resolved is None or not resolved.is_file():
        raise ValueError("ZkDkgCoordinatorV2 address/artifact is not configured")
    artifact = json.loads(resolved.read_text(encoding="utf-8"))
    return w3.eth.contract(
        address=Web3.to_checksum_address(cfg.ZKDKG_COORDINATOR_V2_ADDRESS),
        abi=artifact["abi"],
    )


def load_acl(w3: Web3):
    resolved = cfg.resolve_artifact_path(cfg.ACL_JSON)
    if not cfg.ACL_ADDRESS or resolved is None or not resolved.is_file():
        raise RuntimeError("AccessControlFT not configured")
    artifact = json.loads(resolved.read_text(encoding="utf-8"))
    return w3.eth.contract(
        address=Web3.to_checksum_address(cfg.ACL_ADDRESS),
        abi=artifact["abi"],
    )


def load_reputation_manager(w3: Web3):
    return _load_contract_opt(w3, cfg.REPUTATION_MANAGER_ADDRESS, cfg.REPUTATION_MANAGER_JSON)


def load_reward_manager(w3: Web3):
    return _load_contract_opt(w3, cfg.REWARD_MANAGER_ADDRESS, cfg.REWARD_MANAGER_JSON)


def poll_serious_penalties(rep_contract, from_block: int = 0) -> list:
    if rep_contract is None:
        return []
    try:
        event_filter = rep_contract.events.SeriousPenaltyTriggered.createFilter(fromBlock=from_block)
        entries = event_filter.get_all_entries()
        for e in entries:
            print("[Reputation] SeriousPenaltyTriggered:", e)
        return entries
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Guardian registry helpers
# ---------------------------------------------------------------------------

def get_guardian_encryption_public_key(guardian_registry, guardian_addr: str) -> bytes:
    guardian_addr = Web3.to_checksum_address(guardian_addr)
    g = guardian_registry.functions.getGuardian(guardian_addr).call()
    pubkey = bytes(g[1])
    if len(pubkey) != 32:
        raise ValueError(
            f"Guardian {guardian_addr} has invalid encryption public key length: {len(pubkey)}"
        )
    return pubkey


# ---------------------------------------------------------------------------
# On-chain DKG reads
# ---------------------------------------------------------------------------

def wait_for_onchain_dkg_material(dkg, file_id_bytes: bytes, key_epoch: int, my_index: int, n: int) -> None:
    print(f"SH {my_index}: waiting for on-chain commitments and encrypted shares...")
    while True:
        ok_commitments = all(
            dkg.functions.hasGuardianCommitments(file_id_bytes, int(key_epoch), int(i)).call()
            for i in range(1, n + 1)
        )
        ok_shares = all(
            dkg.functions.hasEncryptedDkgShare(file_id_bytes, int(key_epoch), int(i), int(my_index)).call()
            for i in range(1, n + 1)
        )
        if ok_commitments and ok_shares:
            return
        time.sleep(cfg.POLL_INTERVAL)


def read_all_commitments_from_chain(dkg, file_id_bytes: bytes, key_epoch: int, n: int, t: int) -> List[List[Point]]:
    all_commitments: List[List[Point]] = []
    for i in range(1, n + 1):
        exists, guardian, Cx, Cy = dkg.functions.getGuardianCommitments(
            file_id_bytes, int(key_epoch), int(i),
        ).call()
        if not exists:
            raise ValueError(f"Missing on-chain commitments for SH {i}")
        if len(Cx) != t or len(Cy) != t:
            raise ValueError(f"Invalid commitment length for SH {i}")
        Ci: List[Point] = []
        for x, y in zip(Cx, Cy):
            P = (int(x), int(y))
            assert is_on_curve(P)
            Ci.append(P)
        all_commitments.append(Ci)
    return all_commitments


def read_incoming_shares_from_chain(
    dkg, sh_account, file_id_bytes: bytes, key_epoch: int, my_index: int, n: int,
) -> List[int]:
    shares_for_j: List[int] = []
    for from_index in range(1, n + 1):
        exists, sender, recipient, payload = dkg.functions.getEncryptedDkgShare(
            file_id_bytes, int(key_epoch), int(from_index), int(my_index),
        ).call({"from": sh_account.address})
        if not exists:
            raise ValueError(f"Missing encrypted share from SH {from_index} to SH {my_index}")
        s_ij = decrypt_dkg_share_payload(
            payload, my_index=my_index, expected_from_index=from_index,
        )
        shares_for_j.append(s_ij)
    return shares_for_j


def _read_v2_dealer_commitments(coordinator_v2, file_id_bytes: bytes, key_epoch: int, dealer_index: int, t: int, share_version: int = 1):
    exists, _dealer, _stored_index, xs, ys = coordinator_v2.functions.getV2DealerCommitments(
        file_id_bytes, int(key_epoch), int(share_version), int(dealer_index),
    ).call()
    if not exists:
        raise ValueError(f"missing V2 dealer commitments for dealerIndex={dealer_index}, shareVersion={share_version}")
    if len(xs) != int(t) or len(ys) != int(t):
        raise ValueError(f"invalid V2 dealer commitment count for dealerIndex={dealer_index}")
    out = []
    for x, y in zip(xs, ys):
        point = (int(x), int(y))
        if not baby_is_on_curve(point):
            raise ValueError(f"invalid Baby Jubjub commitment for dealerIndex={dealer_index}")
        out.append(point)
    return out


def read_refresh_commitments_from_chain(dkg, job: dict, old_index: int) -> List[Point]:
    exists, guardian, Cx, Cy = dkg.functions.getRefreshGuardianCommitments(
        job["fileIdBytes"], int(job["keyEpoch"]), int(job["shareVersion"]), int(old_index),
    ).call()
    if not exists:
        raise ValueError(f"Missing refresh commitments from old index {old_index}")
    if len(Cx) != int(job["newT"]) or len(Cy) != int(job["newT"]):
        raise ValueError(f"Invalid refresh commitment length from old index {old_index}")
    out: List[Point] = []
    for x, y in zip(Cx, Cy):
        P = (int(x), int(y))
        assert is_on_curve(P)
        out.append(P)
    return out


# ---------------------------------------------------------------------------
# On-chain existence checks
# ---------------------------------------------------------------------------

def any_fresh_dkg_material_onchain(dkg, file_id_bytes: bytes, key_epoch: int, guardian_index: int, n: int) -> bool:
    if dkg.functions.hasGuardianCommitments(file_id_bytes, int(key_epoch), int(guardian_index)).call():
        return True
    return any(
        dkg.functions.hasEncryptedDkgShare(file_id_bytes, int(key_epoch), int(guardian_index), int(to_index)).call()
        for to_index in range(1, int(n) + 1)
    )


def any_refresh_material_onchain(dkg, file_id_bytes: bytes, key_epoch: int, share_version: int, old_index: int, new_n: int) -> bool:
    if dkg.functions.hasRefreshGuardianCommitments(file_id_bytes, int(key_epoch), int(share_version), int(old_index)).call():
        return True
    return any(
        dkg.functions.hasEncryptedRefreshShare(file_id_bytes, int(key_epoch), int(share_version), int(old_index), int(new_index)).call()
        for new_index in range(1, int(new_n) + 1)
    )


def any_v2_refresh_material_onchain(coordinator_v2, file_id_bytes: bytes, key_epoch: int, share_version: int, old_index: int, new_n: int) -> bool:
    try:
        if coordinator_v2.functions.hasV2DealerCommitments(file_id_bytes, int(key_epoch), int(share_version), int(old_index)).call():
            return True
    except Exception:
        pass
    for new_index in range(1, int(new_n) + 1):
        try:
            if coordinator_v2.functions.hasV2EncryptedShare(file_id_bytes, int(key_epoch), int(share_version), int(old_index), int(new_index)).call():
                return True
        except Exception:
            pass
    return False


from core.g_chain_logs import (  # noqa: E402
    LOG_WINDOW_BLOCKS,
    logs_backward as _logs_backward,
    logs_forward as _logs_forward,
)

# Highest block already searched for opened disputes, so the poll reads only
# new blocks instead of the whole chain on every pass.
_ZKDKG_DISPUTE_SCANNED_TO: int | None = None


def zkdkg_babyjubjub_material_exists(
    dispute_manager, file_id_bytes: bytes,
    key_epoch: int, share_version: int, is_refresh: bool, dealer_index: int,
) -> bool:
    try:
        events = _logs_backward(
            dispute_manager.events.ZkDkgBabyJubjubMaterialPublished(),
            {
                "fileId": file_id_bytes,
                "keyEpoch": int(key_epoch),
                "shareVersion": int(share_version),
            },
        )
    except Exception as exc:
        log_every(
            ("zkdkg-v2-material-exists-error", int(dealer_index)),
            f"  -> Could not query V2 material events for SH {dealer_index}: {exc}",
            60,
        )
        return False
    for ev in events:
        args = ev["args"]
        if bytes(args["fileId"]) != bytes(file_id_bytes):
            continue
        if int(args["keyEpoch"]) != int(key_epoch):
            continue
        if int(args["shareVersion"]) != int(share_version):
            continue
        if bool(args["isRefresh"]) != bool(is_refresh):
            continue
        if int(args["dealerIndex"]) == int(dealer_index):
            return True
    return False


# ---------------------------------------------------------------------------
# On-chain DKG writes
# ---------------------------------------------------------------------------

def _send_tx(w3: Web3, sh_account, fn, label: str, extra_gas: int = 80_000) -> dict:
    if TXLOG is not None:
        TXLOG.set_current_transaction_label(label)
    try:
        gas_est = fn.estimate_gas({"from": sh_account.address})
        tx_hash, receipt, _tx = send_contract_transaction(
            w3,
            sh_account,
            fn,
            gas=gas_est + extra_gas,
            gas_price=cfg.FIXED_GAS_PRICE_WEI,
        )
        print(f"  -> {label} tx: {tx_hash.hex()}")
        print(f"  -> {label} status: {receipt.status}")
        return receipt
    finally:
        if TXLOG is not None:
            TXLOG.set_current_transaction_label("")


_LAST_REWARD_CLAIM_AT = 0.0


def claim_guardian_rewards_if_available(w3: Web3, sh_account, label: str = "") -> bool:
    """Withdraw already-credited Guardian rewards as a separate on-chain transaction."""
    global _LAST_REWARD_CLAIM_AT
    if not cfg.AUTO_CLAIM_REWARDS:
        return False
    now = time.time()
    cooldown = max(0, int(cfg.REWARD_CLAIM_COOLDOWN_SECONDS))
    if cooldown and _LAST_REWARD_CLAIM_AT and now - _LAST_REWARD_CLAIM_AT < cooldown:
        return False
    reward_manager = load_reward_manager(w3)
    if reward_manager is None:
        return False
    try:
        claimable = int(reward_manager.functions.claimableReward(sh_account.address).call())
    except Exception as exc:
        log_every(
            ("reward-claim-check-error", str(exc)),
            f"[Rewards] claimableReward check failed: {exc}",
            seconds=120,
        )
        return False
    if claimable <= int(cfg.MIN_REWARD_CLAIM_WEI):
        return False
    try:
        receipt = _send_tx(
            w3,
            sh_account,
            reward_manager.functions.claimRewards(),
            label or f"claimRewards amount={claimable} wei",
            extra_gas=60_000,
        )
        if int(receipt.status) == 1:
            _LAST_REWARD_CLAIM_AT = now
            print(f"[Rewards] Guardian claimed {claimable} wei")
            return True
    except Exception as exc:
        log_every(
            ("reward-claim-error", str(exc)),
            f"[Rewards] claimRewards skipped: {exc}",
            seconds=120,
        )
    return False


def upload_guardian_commitments(
    w3, dkg, sh_account, file_id_bytes, do_checksum, key_epoch, guardian_index, commitments_i,
) -> bool:
    Cx = [int(P[0]) for P in commitments_i]
    Cy = [int(P[1]) for P in commitments_i]
    already = dkg.functions.hasGuardianCommitments(file_id_bytes, int(key_epoch), int(guardian_index)).call()
    if already:
        log_state(
            ("dkg-commitments-exist", int(key_epoch), int(guardian_index)), True,
            f"  -> On-chain commitments already exist for SH {guardian_index}, epoch={key_epoch}. Skipping publish."
        )
        return True
    fn = dkg.functions.publishGuardianCommitments(
        file_id_bytes, do_checksum, int(key_epoch), int(guardian_index), Cx, Cy,
    )
    try:
        receipt = _send_tx(w3, sh_account, fn, "publishGuardianCommitments", extra_gas=50_000)
        return receipt.status == 1
    except Exception as e:
        print(f"  -> publishGuardianCommitments failed: {e}")
        return False


def upload_encrypted_dkg_shares(
    w3, dkg, guardian_registry, sh_account,
    file_id_bytes, do_checksum, key_epoch, from_index, policy_guardians, shares_row,
) -> bool:
    print(f"  -> SH {from_index}: publishing {len(shares_row)} encrypted DKG share(s) for epoch={key_epoch}.")
    for to_index, s_ij in enumerate(shares_row, start=1):
        already = dkg.functions.hasEncryptedDkgShare(file_id_bytes, int(key_epoch), int(from_index), int(to_index)).call()
        if already:
            log_state(
                ("dkg-encrypted-share-exists", int(key_epoch), int(from_index), int(to_index)), True,
                f"  -> Encrypted DKG share already exists: from {from_index} to {to_index}. Skipping."
            )
            continue
        recipient_addr = Web3.to_checksum_address(policy_guardians[to_index - 1])
        recipient_pubkey = get_guardian_encryption_public_key(guardian_registry, recipient_addr)
        payload = encrypt_dkg_share_for_guardian(recipient_pubkey, from_index, to_index, s_ij)
        fn = dkg.functions.publishEncryptedDkgShare(
            file_id_bytes, do_checksum, int(key_epoch), int(from_index), int(to_index), payload,
        )
        try:
            gas_est = fn.estimate_gas({"from": sh_account.address})
        except Exception as e:
            print(f"  -> publishEncryptedDkgShare gas estimate failed from {from_index} to {to_index}: {e}")
            return False
        tx_hash, receipt, _tx = send_contract_transaction(
            w3, sh_account, fn,
            gas=gas_est + 80_000,
            gas_price=cfg.FIXED_GAS_PRICE_WEI,
        )
        print(f"  -> publishEncryptedDkgShare from {from_index} to {to_index} tx:", tx_hash.hex())
        print(f"  -> publishEncryptedDkgShare from {from_index} to {to_index} status:", receipt.status)
        if receipt.status != 1:
            return False
    return True


def publish_share_public_key(
    w3, dkg, sh_account, file_id_bytes, do_checksum,
    key_epoch, share_version, share_index, vk_j,
) -> bool:
    if vk_j is None:
        raise ValueError("Cannot publish point at infinity as share public key")
    vkx, vky = vk_j
    try:
        already = dkg.functions.hasSharePublicKey(file_id_bytes, int(key_epoch), int(share_version), int(share_index)).call()
    except Exception:
        already = False
    if already:
        log_state(
            ("share-pk-exists", int(key_epoch), int(share_version), int(share_index)), True,
            f"  -> Share public key already exists for epoch={key_epoch}, shareVersion={share_version}, shareIndex={share_index}.",
        )
        return True
    fn = dkg.functions.publishSharePublicKey(
        file_id_bytes, do_checksum, int(key_epoch), int(share_version), int(share_index), int(vkx), int(vky),
    )
    try:
        gas_est = fn.estimate_gas({"from": sh_account.address})
    except Exception as e:
        print(f"  -> publishSharePublicKey gas estimate failed: {e}")
        return False
    tx_hash, receipt, _tx = send_contract_transaction(
        w3, sh_account, fn,
        gas=gas_est + 120_000,
        gas_price=cfg.FIXED_GAS_PRICE_WEI,
    )
    print(f"  -> publishSharePublicKey epoch={key_epoch}, shareVersion={share_version}, shareIndex={share_index} tx: {tx_hash.hex()}")
    print(f"  -> publishSharePublicKey status: {receipt.status}")
    return receipt.status == 1


def upload_pk_and_commitments(w3, dkg, sh_account, file_id_bytes, do_checksum, n, t, PK, agg_commitments) -> bool:
    PKx, PKy = PK
    Cx = [int(P[0]) for P in agg_commitments]
    Cy = [int(P[1]) for P in agg_commitments]
    fn = dkg.functions.storeKeyAndCommitmentsForFile(
        file_id_bytes, do_checksum, t, n, PKx, PKy, Cx, Cy,
    )
    tx_hash, receipt, _tx = send_contract_transaction(
        w3, sh_account, fn,
        gas=900_000,
        gas_price=cfg.FIXED_GAS_PRICE_WEI,
    )
    print("storeKeyAndCommitmentsForFile tx:", tx_hash.hex())
    print("Tx status:", receipt.status)
    return receipt.status == 1


# ---------------------------------------------------------------------------
# V2 DKG on-chain writes
# ---------------------------------------------------------------------------

def _field_hash(value: bytes) -> int:
    return int.from_bytes(Web3.keccak(value), "big") % BABY_L


def publish_v2_dkg_material(
    w3, dispute_manager, coordinator_v2, sh_account,
    file_id_bytes, file_id_hex, key_epoch, guardian_index, n, t, commitments, shares_row,
) -> bool:
    compressed_commitments = [int(p[0]) for p in commitments]
    encrypted_shares = []
    for to_index, share in enumerate(shares_row, start=1):
        if to_index == guardian_index:
            continue
        encrypted_shares.append(
            _field_hash(
                b"FileTrust-ZKDKG-V2-local-transport"
                + int(guardian_index).to_bytes(2, "big")
                + int(to_index).to_bytes(2, "big")
                + int(share).to_bytes(32, "big")
            )
        )
    exists = zkdkg_babyjubjub_material_exists(dispute_manager, file_id_bytes, int(key_epoch), 1, False, int(guardian_index))
    if not exists:
        if hasattr(dispute_manager.functions, "publishAndAcknowledgeV2Material"):
            fn = dispute_manager.functions.publishAndAcknowledgeV2Material(
                file_id_bytes, int(key_epoch), 1, False, int(guardian_index),
                compressed_commitments, encrypted_shares, int(compressed_commitments[0]),
            )
            label = "publishAndAcknowledgeV2Material"
        else:
            fn = dispute_manager.functions.publishZkDkgBabyJubjubMaterial(
                file_id_bytes, int(key_epoch), 1, False, int(guardian_index),
                compressed_commitments, encrypted_shares, int(compressed_commitments[0]),
            )
            label = "publishZkDkgBabyJubjubMaterial"
        try:
            gas_est = fn.estimate_gas({"from": sh_account.address})
        except Exception as e:
            print(f"  -> {label} gas estimate failed: {e}")
            return False
        tx_hash, receipt, _tx = send_contract_transaction(
            w3, sh_account, fn,
            gas=gas_est + 120_000,
            gas_price=cfg.FIXED_GAS_PRICE_WEI,
        )
        print(f"  -> {label} tx:", tx_hash.hex())
        print(f"  -> {label} status:", receipt.status)
        if receipt.status != 1:
            return False
        if label == "publishAndAcknowledgeV2Material":
            return True
    else:
        print(f"  -> V2 Baby Jubjub material already published for SH {guardian_index}")

    try:
        already_ack = coordinator_v2.functions.dealerMaterialSubmitted(file_id_bytes, int(key_epoch), int(guardian_index)).call()
    except Exception:
        already_ack = False

    if not already_ack:
        fn = coordinator_v2.functions.acknowledgeDealerMaterial(file_id_bytes, int(key_epoch), int(guardian_index))
        try:
            gas_est = fn.estimate_gas({"from": sh_account.address})
        except Exception as e:
            print(f"  -> acknowledgeDealerMaterial gas estimate failed: {e}")
            return False
        tx_hash, receipt, _tx = send_contract_transaction(
            w3, sh_account, fn,
            gas=gas_est + 80_000,
            gas_price=cfg.FIXED_GAS_PRICE_WEI,
        )
        print("  -> acknowledgeDealerMaterial tx:", tx_hash.hex())
        print("  -> acknowledgeDealerMaterial status:", receipt.status)
        return receipt.status == 1
    return True


def publish_v2_dealer_commitments(
    w3, coordinator_v2, sh_account, file_id_bytes, key_epoch, guardian_index, commitments, share_version: int = 1,
) -> bool:
    try:
        already = coordinator_v2.functions.hasV2DealerCommitments(file_id_bytes, int(key_epoch), int(share_version), int(guardian_index)).call()
    except Exception:
        already = False
    if already:
        print(f"[ZKDKG_V2] V2 dealer commitments already published: shareVersion={share_version}, dealerIndex={guardian_index}")
        return True
    xs, ys = _commitments_xy(commitments)
    fn = coordinator_v2.functions.publishV2DealerCommitments(file_id_bytes, int(key_epoch), int(share_version), int(guardian_index), xs, ys)
    try:
        gas_est = fn.estimate_gas({"from": sh_account.address})
    except Exception as e:
        print(f"  -> publishV2DealerCommitments gas estimate failed: {e}")
        return False
    tx_hash, receipt, _tx = send_contract_transaction(
        w3, sh_account, fn,
        gas=gas_est + 120_000,
        gas_price=cfg.FIXED_GAS_PRICE_WEI,
    )
    print("  -> publishV2DealerCommitments tx:", tx_hash.hex())
    print("  -> publishV2DealerCommitments status:", receipt.status)
    return receipt.status == 1


def publish_v2_encrypted_shares_onchain(
    w3, coordinator_v2, guardian_registry, sh_account,
    file_id_bytes, key_epoch, from_index, policy_guardians, shares_row, share_version: int = 1,
) -> bool:
    print(f"  -> G {from_index}: publishing {len(shares_row)} encrypted V2 DKG share(s) for epoch={key_epoch}, shareVersion={share_version}.")
    for to_index, s_ij in enumerate(shares_row, start=1):
        try:
            already = coordinator_v2.functions.hasV2EncryptedShare(
                file_id_bytes, int(key_epoch), int(share_version), int(from_index), int(to_index),
            ).call()
        except Exception:
            already = False
        if already:
            log_state(
                ("v2-encrypted-share-exists", int(key_epoch), int(share_version), int(from_index), int(to_index)), True,
                f"  -> V2 encrypted DKG share already exists: shareVersion={share_version}, from {from_index} to {to_index}. Skipping.",
            )
            continue
        recipient_addr = Web3.to_checksum_address(policy_guardians[to_index - 1])
        recipient_pubkey = get_guardian_encryption_public_key(guardian_registry, recipient_addr)
        payload = encrypt_dkg_share_for_guardian(recipient_pubkey, from_index, to_index, s_ij)
        fn = coordinator_v2.functions.publishV2EncryptedShare(
            file_id_bytes, int(key_epoch), int(share_version), int(from_index), int(to_index), payload,
        )
        try:
            gas_est = fn.estimate_gas({"from": sh_account.address})
        except Exception as e:
            print(f"  -> publishV2EncryptedShare gas estimate failed from {from_index} to {to_index}: {e}")
            return False
        tx_hash, receipt, _tx = send_contract_transaction(
            w3, sh_account, fn,
            gas=gas_est + 100_000,
            gas_price=cfg.FIXED_GAS_PRICE_WEI,
        )
        print(f"  -> publishV2EncryptedShare {from_index}->{to_index} tx:", tx_hash.hex())
        print(f"  -> publishV2EncryptedShare {from_index}->{to_index} status:", receipt.status)
        if receipt.status != 1:
            return False
    return True


def publish_v2_share_public_key(
    w3, coordinator_v2, sh_account, file_id_bytes, key_epoch, share_index, vk, share_version: int = 1,
) -> bool:
    try:
        exists, _x, _y = coordinator_v2.functions.getV2SharePublicKey(
            file_id_bytes, int(key_epoch), int(share_version), int(share_index),
        ).call()
        if exists:
            existing_vk = (int(_x), int(_y))
            local_vk = (int(vk[0]), int(vk[1]))
            if existing_vk != local_vk:
                print(
                    f"[ZKDKG_V2] SAFETY STOP: on-chain V2 share public key for "
                    f"shareVersion={share_version}, shareIndex={share_index} does not match local.\n"
                    f"[ZKDKG_V2] Existing on-chain vk=({existing_vk[0]}, {existing_vk[1]})\n"
                    f"[ZKDKG_V2] Local computed vk=({local_vk[0]}, {local_vk[1]})"
                )
                return False
            print(f"[ZKDKG_V2] V2 share public key already published and matches local: shareVersion={share_version}, shareIndex={share_index}")
            return True
    except Exception:
        pass
    fn = coordinator_v2.functions.publishV2SharePublicKey(
        file_id_bytes, int(key_epoch), int(share_index), int(vk[0]), int(vk[1]),
    )
    try:
        gas_est = fn.estimate_gas({"from": sh_account.address})
    except Exception as e:
        print(f"  -> publishV2SharePublicKey gas estimate failed: {e}")
        return False
    tx_hash, receipt, _tx = send_contract_transaction(
        w3, sh_account, fn,
        gas=gas_est + 80_000,
        gas_price=cfg.FIXED_GAS_PRICE_WEI,
    )
    print("  -> publishV2SharePublicKey tx:", tx_hash.hex())
    print("  -> publishV2SharePublicKey status:", receipt.status)
    if receipt.status == 1:
        print(f"[ZKDKG_V2] Published V2 share public key on-chain: shareVersion={share_version}, shareIndex={share_index}")
    return receipt.status == 1


# ---------------------------------------------------------------------------
# Dispute handling
# ---------------------------------------------------------------------------

def open_zkdkg_invalid_share_dispute(
    w3, dkg, sh_account, file_id_bytes, key_epoch, share_version,
    accused_dealer_index, receiver_index, is_refresh: bool = False,
) -> bool:
    if not cfg.ENABLE_ZKDKG_MIGRATION:
        return False
    try:
        dispute_manager = load_zkdkg_dispute_manager(w3)
    except Exception as e:
        print(f"  -> zkDKG dispute manager not configured; cannot open dispute: {e}")
        return False
    fn = dispute_manager.functions.openZkDkgEncryptedShareDispute(
        file_id_bytes, int(key_epoch), int(share_version), bool(is_refresh),
        int(accused_dealer_index), int(receiver_index),
    )
    try:
        gas_est = fn.estimate_gas({"from": sh_account.address})
    except Exception as e:
        print(f"  -> zkDKG dispute open gas estimate failed dealer={accused_dealer_index} receiver={receiver_index}: {e}")
        return False
    tx_hash, receipt, _tx = send_contract_transaction(
        w3, sh_account, fn,
        gas=gas_est + 80_000,
        gas_price=cfg.FIXED_GAS_PRICE_WEI,
    )
    print(f"  -> openZkDkgEncryptedShareDispute dealer={accused_dealer_index} receiver={receiver_index} tx:", tx_hash.hex())
    print(f"  -> openZkDkgEncryptedShareDispute dealer={accused_dealer_index} receiver={receiver_index} status:", receipt.status)
    return receipt.status == 1


def submit_zkdkg_dispute_justification(
    w3, dispute_manager, sh_account, dispute_id, proof_json_path: str,
) -> bool:
    with open(Path(proof_json_path).expanduser().resolve(), "r", encoding="utf-8") as f:
        proof_json = json.load(f)
    proof = proof_tuple_from_zokrates_json(proof_json)
    fn = dispute_manager.functions.justifyZkDkgEncryptedShareDispute(dispute_id, proof)
    try:
        gas_est = fn.estimate_gas({"from": sh_account.address})
    except Exception as e:
        print(f"  -> zkDKG justification gas estimate failed: {e}")
        return False
    tx_hash, receipt, _tx = send_contract_transaction(
        w3, sh_account, fn,
        gas=gas_est + 120_000,
        gas_price=cfg.FIXED_GAS_PRICE_WEI,
    )
    print("  -> justifyZkDkgEncryptedShareDispute tx:", tx_hash.hex())
    print("  -> justifyZkDkgEncryptedShareDispute status:", receipt.status)
    return receipt.status == 1


def finalize_expired_zkdkg_dispute(w3, dispute_manager, sh_account, dispute_id) -> bool:
    fn = dispute_manager.functions.finalizeExpiredZkDkgEncryptedShareDispute(dispute_id)
    try:
        gas_est = fn.estimate_gas({"from": sh_account.address})
    except Exception as e:
        print(f"  -> zkDKG dispute finalize gas estimate failed: {e}")
        return False
    tx_hash, receipt, _tx = send_contract_transaction(
        w3, sh_account, fn,
        gas=gas_est + 120_000,
        gas_price=cfg.FIXED_GAS_PRICE_WEI,
    )
    print("  -> finalizeExpiredZkDkgEncryptedShareDispute tx:", tx_hash.hex())
    print("  -> finalizeExpiredZkDkgEncryptedShareDispute status:", receipt.status)
    return receipt.status == 1


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if parent.name == "FileTrust":
            return parent
    return cfg.ROOT


def _zkdkg_dispute_build_dir(participant_count: int, threshold: int) -> Path:
    participant_count = int(participant_count)
    threshold = int(threshold)
    local_dir = cfg.ZK_BUILD_ROOT / "zkdkg" / str(participant_count) / f"t{threshold}" / "poly_eval"
    if (local_dir / "out").is_file() and (local_dir / "proving.key").is_file():
        return local_dir
    repo_dir = _repo_root() / "build" / "zkdkg" / str(participant_count) / f"t{threshold}" / "poly_eval"
    if (repo_dir / "out").is_file() and (repo_dir / "proving.key").is_file():
        return repo_dir
    # Backward-compatible path for the old majority-threshold N-only build.
    if threshold == (participant_count // 2) + 1:
        legacy_local = cfg.ZK_BUILD_ROOT / "zkdkg" / str(participant_count) / "poly_eval"
        if (legacy_local / "out").is_file() and (legacy_local / "proving.key").is_file():
            return legacy_local
        return _repo_root() / "build" / "zkdkg" / str(participant_count) / "poly_eval"
    return repo_dir


def _load_zkdkg_v2_dealer_material_for_dispute(acl, coordinator_v2, dispute_record) -> tuple[int, int, list, list, Path]:
    is_refresh = bool(dispute_record[3])
    file_id_bytes = bytes(dispute_record[4])
    file_id_hex = normalize_file_id_hex(Web3.to_hex(file_id_bytes))
    key_epoch = int(dispute_record[5])
    share_version = int(dispute_record[6])
    dealer_index = int(dispute_record[7])

    if is_refresh:
        (
            refresh_exists, _refresh_finalized, _stored_share_version,
            _old_share_version, _old_t, _old_n, new_t, new_n,
            _old_guardians, _new_guardians, _old_participant_indices,
        ) = coordinator_v2.functions.getPendingV2Refresh(file_id_bytes, key_epoch).call()
        if not refresh_exists:
            raise RuntimeError("zkDKG dispute refresh metadata is not available")
        material_path = v2_refresh_material_path(file_id_hex, key_epoch, share_version, dealer_index, int(new_n), int(new_t))
        participant_count = int(new_n)
        threshold = int(new_t)
    else:
        exists, active, _owner, threshold, guardians = acl.functions.getFilePolicy(file_id_bytes).call()
        if not (exists and active):
            raise RuntimeError("zkDKG dispute policy is not active")
        material_path = v2_fresh_material_path(file_id_hex, key_epoch, len(guardians), int(threshold), dealer_index)
        participant_count = len(guardians)
        threshold = int(threshold)

    if not material_path.is_file():
        raise FileNotFoundError(f"Missing local zkDKG dealer material for dispute: {material_path}")
    data = read_secret_json(material_path)
    coeffs = [int(x) for x in data["coeffs"]]
    commitments = [(int(p[0]), int(p[1])) for p in data["commitments"]]
    if len(coeffs) < 1 or len(commitments) != threshold:
        raise ValueError(f"Invalid zkDKG dealer material for dispute: {material_path}")
    return participant_count, threshold, coeffs, commitments, material_path


def build_zkdkg_dispute_justification_proof(w3, dispute_manager, dispute_record) -> dict:
    acl = load_acl(w3)
    coordinator_v2 = load_zkdkg_coordinator_v2(w3)
    guardian_registry = load_guardian_registry(w3)
    participant_count, threshold, coeffs, commitments, material_path = _load_zkdkg_v2_dealer_material_for_dispute(
        acl, coordinator_v2, dispute_record,
    )
    dealer = Web3.to_checksum_address(dispute_record[9])
    receiver = Web3.to_checksum_address(dispute_record[10])
    receiver_index = int(dispute_record[8])
    encrypted_share = int(dispute_record[13])
    dealer_pub = guardian_registry.functions.getGuardianDkgBabyJubjubPublicKey(dealer).call()
    receiver_pub = guardian_registry.functions.getGuardianDkgBabyJubjubPublicKey(receiver).call()
    dispute_id = dispute_manager.functions.disputeIdFor(
        dispute_record[4],
        int(dispute_record[5]),
        int(dispute_record[6]),
        bool(dispute_record[3]),
        int(dispute_record[7]),
        int(dispute_record[8]),
    ).call()
    public_input_hash = int(dispute_manager.functions.justificationPublicInputHash(dispute_id).call())
    build_dir = _zkdkg_dispute_build_dir(participant_count, threshold)
    log_state(
        ("zkdkg-justify-build", dispute_id.hex() if hasattr(dispute_id, "hex") else str(dispute_id)),
        str(build_dir),
        f"  -> zkDKG dispute justification using material {material_path} and build {build_dir}",
    )
    return generate_zkdkg_dispute_justification_proof(
        build_dir,
        commitments,
        int(coeffs[0]),
        dealer_pub,
        receiver_pub,
        receiver_index,
        encrypted_share,
        public_input_hash,
        cfg.ZOKRATES_BIN,
    )


# ---------------------------------------------------------------------------
# Composite: compute local share from on-chain data (secp256k1)
# ---------------------------------------------------------------------------

def compute_local_share_from_onchain(dkg, sh_account, file_id_bytes, key_epoch, my_index, n, t):
    wait_for_onchain_dkg_material(dkg, file_id_bytes, key_epoch, my_index, n)
    commitments = read_all_commitments_from_chain(dkg, file_id_bytes, key_epoch, n, t)
    shares_for_j = read_incoming_shares_from_chain(dkg, sh_account, file_id_bytes, key_epoch, my_index, n)
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
            open_zkdkg_invalid_share_dispute(
                Web3(Web3.HTTPProvider(cfg.RPC_URL)), dkg, sh_account,
                file_id_bytes, key_epoch, 1, i + 1, j, False,
            )
            raise ValueError(f"On-chain decrypted share verification failed for i={i + 1}, j={j}")
    sk_j = sum(shares_for_j) % n_order
    vk_j = scalar_mult(sk_j, G)
    print(f"SH {my_index}: final share computed from on-chain encrypted shares.")
    return sk_j, vk_j


# ---------------------------------------------------------------------------
# Composite: compute and store V2 final share from chain
# ---------------------------------------------------------------------------

def try_compute_and_store_v2_final_share_from_chain(
    coordinator_v2, sh_account,
    file_id_bytes, file_id_hex, key_epoch, n, t, my_index, share_version: int = 1,
    w3=None,
):
    missing = []
    for from_index in range(1, int(n) + 1):
        try:
            has_commitments = coordinator_v2.functions.hasV2DealerCommitments(
                file_id_bytes, int(key_epoch), int(share_version), int(from_index)
            ).call()
            has_share = coordinator_v2.functions.hasV2EncryptedShare(
                file_id_bytes, int(key_epoch), int(share_version), int(from_index), int(my_index)
            ).call()
        except Exception as exc:
            print(f"[ZKDKG_V2] could not check on-chain V2 DKG material: {exc}")
            return None, None
        if not has_commitments or not has_share:
            missing.append(from_index)

    if missing:
        log_state(
            ("v2-wait-incoming", normalize_file_id_hex(file_id_hex), int(key_epoch), int(share_version), int(my_index)),
            tuple(missing),
            f"[ZKDKG_V2] G {my_index}: waiting for on-chain encrypted V2 shares/commitments "
            f"from dealers {missing} for shareVersion={share_version}",
        )
        return None, None

    sk = 0
    for from_index in range(1, int(n) + 1):
        exists, _dealer, recipient, payload = coordinator_v2.functions.getV2EncryptedShare(
            file_id_bytes, int(key_epoch), int(share_version), int(from_index), int(my_index),
        ).call({"from": sh_account.address})
        if not exists:
            raise ValueError(f"missing V2 encrypted share from {from_index} to {my_index}")
        if Web3.to_checksum_address(recipient) != Web3.to_checksum_address(sh_account.address):
            raise ValueError(f"wrong V2 encrypted share recipient from {from_index} to {my_index}")
        s_ij = decrypt_dkg_share_payload(payload, my_index=my_index, expected_from_index=from_index) % BABY_L
        commitments = _read_v2_dealer_commitments(coordinator_v2, file_id_bytes, key_epoch, from_index, t, share_version)
        if not verify_v2_share_against_commitments(s_ij, my_index, commitments):
            print(f"[ZKDKG_V2] invalid encrypted share from dealerIndex={from_index} to receiverIndex={my_index}")
            if w3 is not None:
                try:
                    open_zkdkg_invalid_share_dispute(
                        w3, None, sh_account,
                        file_id_bytes, key_epoch, int(share_version),
                        int(from_index), int(my_index), False,
                    )
                except Exception as _dispute_exc:
                    print(f"[ZKDKG_V2] failed to open dispute for dealerIndex={from_index}: {_dispute_exc}")
            return None, None
        sk = (sk + s_ij) % BABY_L

    vk = baby_mul(sk, BABY_G)
    if vk is None or not baby_is_on_curve(vk):
        raise ValueError("invalid V2 final share public key")

    out = v2_final_share_path(file_id_hex, key_epoch, share_version, n, t, my_index)
    data = {
        "kind": "zkdkg_v2_final_share",
        "curve": "BabyJubjub",
        "fileId": normalize_file_id_hex(file_id_hex),
        "keyEpoch": int(key_epoch),
        "shareVersion": int(share_version),
        "index": int(my_index),
        "n": int(n),
        "t": int(t),
        "share": str(int(sk)),
        "sk": str(int(sk)),
        "vkx": str(int(vk[0])),
        "vky": str(int(vk[1])),
    }
    _write_json_atomic(out, data)
    print(f"  -> V2 final Baby Jubjub share written to {out}")
    return sk, vk


# ---------------------------------------------------------------------------
# Composite: refresh helpers (secp256k1)
# ---------------------------------------------------------------------------

def refresh_material_ready_for_new_guardian(dkg, job: dict) -> bool:
    file_id_bytes = job["fileIdBytes"]
    key_epoch = int(job["keyEpoch"])
    share_version = int(job["shareVersion"])
    new_index = int(job["newIndex"])
    participants = job.get("finalizedParticipantIndices") or []
    if not participants:
        return False
    for old_index in participants:
        if not dkg.functions.hasRefreshGuardianCommitments(file_id_bytes, key_epoch, share_version, int(old_index)).call():
            return False
        if not dkg.functions.hasEncryptedRefreshShare(file_id_bytes, key_epoch, share_version, int(old_index), new_index).call():
            return False
    return True


def compute_refreshed_local_share_from_onchain(dkg, sh_account, job: dict):
    new_index = int(job["newIndex"])
    key_epoch = int(job["keyEpoch"])
    share_version = int(job["shareVersion"])
    file_id_bytes = job["fileIdBytes"]
    participants = job.get("finalizedParticipantIndices") or job["oldParticipantIndices"]
    sk_j = 0
    for old_index in participants:
        commitments = read_refresh_commitments_from_chain(dkg, job, int(old_index))
        exists, sender, recipient, payload = dkg.functions.getEncryptedRefreshShare(
            file_id_bytes, key_epoch, share_version, int(old_index), new_index,
        ).call({"from": sh_account.address})
        if not exists:
            raise ValueError(f"Missing encrypted refresh share from old index {old_index} to new index {new_index}")
        s_ij = decrypt_dkg_share_payload(payload, my_index=new_index, expected_from_index=int(old_index))
        left = scalar_mult(s_ij, G)
        acc: Point = None
        pow_j = 1
        for C_l in commitments:
            term = scalar_mult(pow_j, C_l)
            acc = point_add(acc, term)
            pow_j = (pow_j * new_index) % n_order
        if left != acc:
            raise ValueError(f"Refresh share verification failed for old index {old_index}, new index {new_index}")
        coeff = lagrange_coeff_at_zero(int(old_index), [int(x) for x in participants])
        sk_j = (sk_j + (int(coeff) * int(s_ij))) % n_order
    vk_j = scalar_mult(sk_j, G)
    return sk_j, vk_j


def upload_refresh_guardian_commitments(
    w3, dkg, sh_account, file_id_bytes, key_epoch, share_version, old_index, commitments_i,
) -> bool:
    Cx = [int(P[0]) for P in commitments_i]
    Cy = [int(P[1]) for P in commitments_i]
    already = dkg.functions.hasRefreshGuardianCommitments(file_id_bytes, int(key_epoch), int(share_version), int(old_index)).call()
    if already:
        log_state(
            ("refresh-commitments-exist", int(key_epoch), int(share_version), int(old_index)), True,
            f"  -> Refresh commitments already exist for old index {old_index}. Skipping."
        )
        return True
    fn = dkg.functions.publishRefreshGuardianCommitments(file_id_bytes, int(key_epoch), int(share_version), int(old_index), Cx, Cy)
    try:
        gas_est = fn.estimate_gas({"from": sh_account.address})
    except Exception as e:
        if is_no_pending_refresh_error(e):
            log_state(
                ("refresh-already-finalized", int(key_epoch), int(share_version), int(old_index)), True,
                f"  -> Refresh already finalized for shareVersion={share_version}; no more refresh commitments needed."
            )
            return True
        print(f"  -> publishRefreshGuardianCommitments gas estimate failed: {e}")
        return False
    try:
        tx_hash, receipt, _tx = send_contract_transaction(
            w3, sh_account, fn,
            gas=gas_est + 50_000,
            gas_price=cfg.FIXED_GAS_PRICE_WEI,
        )
    except Exception as e:
        if is_no_pending_refresh_error(e):
            log_state(
                ("refresh-already-finalized", int(key_epoch), int(share_version), int(old_index)), True,
                f"  -> Refresh already finalized for shareVersion={share_version}; no more refresh commitments needed."
            )
            return True
        raise
    print("  -> publishRefreshGuardianCommitments tx:", tx_hash.hex())
    print("  -> publishRefreshGuardianCommitments status:", receipt.status)
    return receipt.status == 1


def upload_encrypted_refresh_shares(
    w3, dkg, guardian_registry, sh_account,
    file_id_bytes, key_epoch, share_version, old_index, new_guardians, shares_row,
) -> bool:
    print(f"  -> Old Guardian index {old_index}: publishing {len(shares_row)} encrypted refresh share(s) for shareVersion={share_version}.")
    for new_index, s_ij in enumerate(shares_row, start=1):
        already = dkg.functions.hasEncryptedRefreshShare(file_id_bytes, int(key_epoch), int(share_version), int(old_index), int(new_index)).call()
        if already:
            log_state(
                ("refresh-share-exists", int(key_epoch), int(share_version), int(old_index), int(new_index)), True,
                f"  -> Encrypted refresh share already exists: old {old_index} to new {new_index}. Skipping."
            )
            continue
        recipient_addr = Web3.to_checksum_address(new_guardians[new_index - 1])
        recipient_pubkey = get_guardian_encryption_public_key(guardian_registry, recipient_addr)
        payload = encrypt_dkg_share_for_guardian(recipient_pubkey, old_index, new_index, s_ij)
        fn = dkg.functions.publishEncryptedRefreshShare(file_id_bytes, int(key_epoch), int(share_version), int(old_index), int(new_index), payload)
        try:
            gas_est = fn.estimate_gas({"from": sh_account.address})
        except Exception as e:
            if is_no_pending_refresh_error(e):
                log_state(
                    ("refresh-already-finalized", int(key_epoch), int(share_version), int(old_index)), True,
                    f"  -> Refresh already finalized for shareVersion={share_version}; no more refresh shares needed."
                )
                return True
            print(f"  -> publishEncryptedRefreshShare gas estimate failed old {old_index} to new {new_index}: {e}")
            return False
        try:
            tx_hash, receipt, _tx = send_contract_transaction(
                w3, sh_account, fn,
                gas=gas_est + 80_000,
                gas_price=cfg.FIXED_GAS_PRICE_WEI,
            )
        except Exception as e:
            if is_no_pending_refresh_error(e):
                log_state(
                    ("refresh-already-finalized", int(key_epoch), int(share_version), int(old_index)), True,
                    f"  -> Refresh already finalized for shareVersion={share_version}; no more refresh shares needed."
                )
                return True
            raise
        print(f"  -> publishEncryptedRefreshShare old {old_index} to new {new_index} tx:", tx_hash.hex())
        print(f"  -> publishEncryptedRefreshShare old {old_index} to new {new_index} status:", receipt.status)
        if receipt.status != 1:
            return False
    return True


# ---------------------------------------------------------------------------
# Discovery: fresh DKG policies
# ---------------------------------------------------------------------------

def discover_file_policy(
    acl,
    sh_address: str,
    skip_file_ids: set[str] | None = None,
    priority_file_ids: tuple[bytes, ...] | None = None,
    allow_full_scan: bool = True,
):
    def build_result(file_id_bytes, file_id_hex, owner, threshold, guardians):
        guardians_cs = [Web3.to_checksum_address(g) for g in guardians]
        sh_cs = Web3.to_checksum_address(sh_address)
        dynamic_index = next(
            (i for i, g in enumerate(guardians_cs, start=1) if g.lower() == sh_cs.lower()),
            None,
        )
        if dynamic_index is None:
            return None, None, None, None, None, None, None
        return (
            file_id_bytes,
            file_id_hex,
            Web3.to_checksum_address(owner),
            int(threshold),
            len(guardians_cs),
            int(dynamic_index),
            guardians_cs,
        )

    if cfg.CONFIG_FILE_ID:
        from core.g_material import file_id_hex_to_bytes
        file_id_hex = normalize_file_id_hex(cfg.CONFIG_FILE_ID)
        file_id_bytes = file_id_hex_to_bytes(file_id_hex)
        exists, active, owner, threshold, guardians = acl.functions.getFilePolicy(file_id_bytes).call()
        if not exists or not active:
            raise RuntimeError(f"Configured fileId policy is not active: {file_id_hex}")
        if not acl.functions.isGuardianForFile(file_id_bytes, sh_address).call():
            raise RuntimeError(f"This Guardian is not selected for configured fileId: {file_id_hex}")
        return build_result(file_id_bytes, file_id_hex, owner, threshold, guardians)

    skip_file_ids = skip_file_ids or set()
    seen_file_ids: set[str] = set()
    all_file_ids: list[bytes] = []
    for file_id_bytes in priority_file_ids or tuple():
        normalized = normalize_file_id_hex(Web3.to_hex(file_id_bytes))
        if normalized in seen_file_ids:
            continue
        seen_file_ids.add(normalized)
        all_file_ids.append(file_id_bytes)
    if allow_full_scan:
        for file_id_bytes in _policy_ids(acl):
            normalized = normalize_file_id_hex(Web3.to_hex(file_id_bytes))
            if normalized in seen_file_ids:
                continue
            seen_file_ids.add(normalized)
            all_file_ids.append(file_id_bytes)

    for file_id_bytes in all_file_ids:
        file_id_hex = Web3.to_hex(file_id_bytes)
        if normalize_file_id_hex(file_id_hex) in skip_file_ids:
            continue
        exists, active, owner, threshold, guardians = acl.functions.getFilePolicy(file_id_bytes).call()
        if not exists or not active:
            continue
        if not acl.functions.isGuardianForFile(file_id_bytes, sh_address).call():
            continue
        if not acl.functions.hasRequestedKeyGenForFile(file_id_bytes).call():
            continue
        return build_result(file_id_bytes, file_id_hex, owner, threshold, guardians)

    return None, None, None, None, None, None, None


def discover_file_policies(
    acl,
    sh_address: str,
    skip_file_ids: set[str] | None = None,
    priority_file_ids: tuple[bytes, ...] | None = None,
    allow_full_scan: bool = True,
    limit: int = 3,
):
    results = []
    skip_file_ids = skip_file_ids or set()
    seen_file_ids: set[str] = set()
    all_file_ids: list[bytes] = []
    for file_id_bytes in priority_file_ids or tuple():
        normalized = normalize_file_id_hex(Web3.to_hex(file_id_bytes))
        if normalized in seen_file_ids:
            continue
        seen_file_ids.add(normalized)
        all_file_ids.append(file_id_bytes)
    if allow_full_scan:
        for file_id_bytes in _policy_ids(acl):
            normalized = normalize_file_id_hex(Web3.to_hex(file_id_bytes))
            if normalized in seen_file_ids:
                continue
            seen_file_ids.add(normalized)
            all_file_ids.append(file_id_bytes)

    for file_id_bytes in all_file_ids:
        file_id_hex = Web3.to_hex(file_id_bytes)
        if normalize_file_id_hex(file_id_hex) in skip_file_ids:
            continue
        try:
            exists, active, owner, threshold, guardians = acl.functions.getFilePolicy(file_id_bytes).call()
        except Exception:
            continue
        if not exists or not active:
            continue
        if not acl.functions.isGuardianForFile(file_id_bytes, sh_address).call():
            continue
        if not acl.functions.hasRequestedKeyGenForFile(file_id_bytes).call():
            continue
        single = discover_file_policy(
            acl,
            sh_address,
            skip_file_ids=skip_file_ids,
            priority_file_ids=(file_id_bytes,),
            allow_full_scan=False,
        )
        if single[0] is None:
            continue
        results.append(single)
        if len(results) >= max(1, int(limit)):
            break
    return results


def find_finalized_v2_policy_with_missing_share(acl, coordinator_v2, sh_address: str):
    """
    Scan all policies for a finalized V2 DKG key where this Guardian is a member
    but has not yet published its share public key.

    This handles the race condition where DKG finalization happened before the
    Guardian could read all incoming encrypted shares and publish its share key.
    The contract does not block share key publication after finalization.

    Returns (file_id_bytes, file_id_hex, owner, t, n, my_index, guardians) or None.
    """
    sh_cs = Web3.to_checksum_address(sh_address)
    try:
        file_ids = _policy_ids(acl)
    except Exception:
        return None

    for file_id_bytes in file_ids:
        try:
            file_id_hex = Web3.to_hex(file_id_bytes)
            if _scan_skip_active(("v2-share-pk-present", normalize_file_id_hex(file_id_hex), sh_cs.lower())):
                continue
            exists, active, owner, threshold, guardians = acl.functions.getFilePolicy(file_id_bytes).call()
        except Exception:
            continue
        if not exists or not active:
            continue

        guardians_cs = [Web3.to_checksum_address(g) for g in guardians]
        my_index = next(
            (idx for idx, g in enumerate(guardians_cs, start=1) if g.lower() == sh_cs.lower()),
            None,
        )
        if my_index is None:
            continue

        try:
            mode = int(acl.functions.getFilePolicyMode(file_id_bytes).call())
        except Exception:
            continue
        if mode != 1:  # ZKDKG_V2 only
            continue

        try:
            key = coordinator_v2.functions.getV2Key(file_id_bytes).call()
            key_exists    = bool(key[0])
            key_finalized = bool(key[1])
            key_epoch     = int(key[5])
            share_version = int(key[6])
        except Exception:
            continue
        if not key_exists or not key_finalized or key_epoch == 0:
            continue

        try:
            pk_exists, _, _ = coordinator_v2.functions.getV2SharePublicKey(
                file_id_bytes, key_epoch, share_version, my_index,
            ).call()
        except Exception:
            continue
        if pk_exists:
            _remember_scan_skip(
                ("v2-share-pk-present", normalize_file_id_hex(file_id_hex), sh_cs.lower()),
                _COMPLETE_SCAN_SKIP_SECONDS,
            )
            continue

        return (
            file_id_bytes, file_id_hex,
            Web3.to_checksum_address(owner),
            int(threshold), len(guardians_cs), my_index, guardians_cs,
        )

    return None


# ---------------------------------------------------------------------------
# Discovery: same-PK refresh (secp256k1)
# ---------------------------------------------------------------------------

def discover_pending_same_pk_refresh(dkg, acl, sh_address: str) -> Optional[dict]:
    file_ids = _policy_ids(acl)
    sh_cs = Web3.to_checksum_address(sh_address)

    def build_job(
        file_id_bytes, file_id_hex, owner, key_epoch,
        refresh_finalized, share_version, old_share_version,
        old_t, old_n, new_t, new_n,
        old_guardians, new_guardians, old_participant_indices,
        finalized_participant_indices, skip_if_local_share_exists: bool,
    ) -> Optional[dict]:
        new_guardians_cs = [Web3.to_checksum_address(g) for g in new_guardians]
        old_guardians_cs = [Web3.to_checksum_address(g) for g in old_guardians]
        participants = [int(x) for x in old_participant_indices]
        finalized_participants = [int(x) for x in finalized_participant_indices]
        new_index = find_address_index(new_guardians_cs, sh_cs)
        old_participant_index = None
        for old_idx in participants:
            if old_idx <= 0 or old_idx > len(old_guardians_cs):
                continue
            if old_guardians_cs[old_idx - 1].lower() == sh_cs.lower():
                old_participant_index = old_idx
                break
        if new_index is None and old_participant_index is None:
            return None
        if skip_if_local_share_exists and new_index is not None:
            out_path = final_share_path_for_version(
                file_id_hex, int(new_n), int(new_t), int(key_epoch), int(share_version), int(new_index),
            )
            if out_path.exists():
                return None
        return {
            "fileIdBytes": file_id_bytes, "fileIdHex": file_id_hex,
            "owner": Web3.to_checksum_address(owner),
            "keyEpoch": int(key_epoch),
            "shareVersion": int(share_version), "oldShareVersion": int(old_share_version),
            "oldT": int(old_t), "oldN": int(old_n), "newT": int(new_t), "newN": int(new_n),
            "oldGuardians": old_guardians_cs, "newGuardians": new_guardians_cs,
            "oldParticipantIndices": participants,
            "finalizedParticipantIndices": finalized_participants,
            "oldParticipantIndex": old_participant_index,
            "newIndex": new_index,
            "refreshFinalized": bool(refresh_finalized),
        }

    for file_id_bytes in file_ids:
        file_id_hex = Web3.to_hex(file_id_bytes)
        try:
            exists, active, owner, policy_t, current_guardians = acl.functions.getFilePolicy(file_id_bytes).call()
        except Exception:
            continue
        if not exists or not active:
            continue
        try:
            key_exists, data_owner, _t, _n, _pkx, _pky, key_epoch = dkg.functions.getKeyForFile(file_id_bytes).call()
        except Exception:
            continue
        if not key_exists or int(key_epoch) <= 0:
            continue

        # Normal pending refresh
        try:
            (refresh_exists, refresh_finalized, share_version, old_share_version,
             old_t, old_n, new_t, new_n, old_guardians, new_guardians, old_participant_indices
             ) = dkg.functions.getPendingRefresh(file_id_bytes, int(key_epoch)).call()
        except Exception:
            refresh_exists = False

        if refresh_exists:
            job = build_job(
                file_id_bytes, file_id_hex, owner, int(key_epoch), bool(refresh_finalized),
                int(share_version), int(old_share_version), int(old_t), int(old_n),
                int(new_t), int(new_n), old_guardians, new_guardians, old_participant_indices, [],
                skip_if_local_share_exists=False,
            )
            if job is not None:
                return job

        # Auto-finalized refresh path
        try:
            active_sv = int(dkg.functions.getActiveShareVersion(file_id_bytes, int(key_epoch)).call())
            if active_sv <= 1:
                continue
            (rr_exists, rr_finalized, rr_old_share_version,
             rr_old_t, rr_old_n, rr_new_t, rr_new_n,
             rr_old_guardians, rr_new_guardians, rr_old_participant_indices,
             ) = dkg.functions.getRefreshRequest(file_id_bytes, int(key_epoch), active_sv).call()
        except Exception:
            continue
        if not rr_exists or not rr_finalized:
            continue
        try:
            rr_finalized_participants = dkg.functions.getRefreshFinalizedParticipants(
                file_id_bytes, int(key_epoch), int(active_sv)
            ).call()
        except Exception:
            rr_finalized_participants = rr_old_participant_indices

        job = build_job(
            file_id_bytes, file_id_hex, owner, int(key_epoch), True,
            int(active_sv), int(rr_old_share_version), int(rr_old_t), int(rr_old_n),
            int(rr_new_t), int(rr_new_n), rr_old_guardians, rr_new_guardians,
            rr_old_participant_indices, rr_finalized_participants,
            skip_if_local_share_exists=True,
        )
        if job is not None:
            return job

    return None


def process_pending_same_pk_refresh(w3: Web3, dkg, acl, guardian_registry, sh_account) -> bool:
    job = discover_pending_same_pk_refresh(dkg, acl, sh_account.address)
    if job is None:
        return False

    file_id_hex = normalize_file_id_hex(job["fileIdHex"])
    key_epoch = int(job["keyEpoch"])
    share_version = int(job["shareVersion"])
    old_share_version = int(job["oldShareVersion"])
    old_index = job["oldParticipantIndex"]
    new_index = job["newIndex"]

    log_state(
        ("refresh-job", file_id_hex, key_epoch, share_version, old_index, new_index),
        (old_share_version, job.get("refreshFinalized", False)),
        f"[refresh] fileId={file_id_hex[:18]}..., keyEpoch={key_epoch}, "
        f"oldShareVersion={old_share_version}, newShareVersion={share_version}, "
        f"oldParticipantIndex={old_index}, newIndex={new_index}",
    )

    if old_index is not None and not job.get("refreshFinalized", False):
        try:
            already_commit = dkg.functions.hasRefreshGuardianCommitments(
                job["fileIdBytes"], key_epoch, share_version, int(old_index)
            ).call()
            all_shares_done = all(
                dkg.functions.hasEncryptedRefreshShare(job["fileIdBytes"], key_epoch, share_version, int(old_index), j).call()
                for j in range(1, int(job["newN"]) + 1)
            )
            if not (already_commit and all_shares_done):
                _share_idx, old_sk = load_final_share_for_version(
                    file_id_hex, int(job["oldN"]), int(job["oldT"]), key_epoch, old_share_version, int(old_index),
                )
                refresh_material_p = refresh_dealer_material_path(
                    file_id_hex, key_epoch, share_version, int(old_index), int(job["newN"]), int(job["newT"]),
                )
                if not refresh_material_p.exists() and any_refresh_material_onchain(
                    dkg, job["fileIdBytes"], key_epoch, share_version, int(old_index), int(job["newN"]),
                ):
                    print(
                        f"[refresh] SAFETY STOP: old participant {old_index} already has partial "
                        f"refresh material on-chain for shareVersion={share_version}, but local saved "
                        f"dealer material is missing. Refusing to regenerate random refresh material."
                    )
                    return True
                commitments_i, shares_row = load_or_create_refresh_dealer_material(
                    file_id_hex, key_epoch, share_version, int(old_index), old_sk,
                    int(job["newT"]), int(job["newN"]),
                )
                print(
                    f"[refresh] old participant {old_index}: ready with {len(commitments_i)} refresh commitment(s) "
                    f"and {len(shares_row)} encrypted refresh share(s) for new Guardians."
                )
                ok_commit = upload_refresh_guardian_commitments(
                    w3, dkg, sh_account, job["fileIdBytes"], key_epoch, share_version, int(old_index), commitments_i,
                )
                if not ok_commit:
                    return True
                ok_shares = upload_encrypted_refresh_shares(
                    w3, dkg, guardian_registry, sh_account, job["fileIdBytes"], key_epoch, share_version,
                    int(old_index), job["newGuardians"], shares_row,
                )
                if not ok_shares:
                    return True
            else:
                log_state(
                    ("refresh-material-published", file_id_hex, key_epoch, share_version, old_index), True,
                    f"[refresh] old participant {old_index}: refresh material already published."
                )
        except Exception as e:
            print(f"[refresh] old participant step failed: {e}")
            return True

    if new_index is not None:
        out_path = final_share_path_for_version(
            file_id_hex, int(job["newN"]), int(job["newT"]), key_epoch, share_version, int(new_index),
        )
        if out_path.exists():
            log_state(
                ("refresh-final-share-exists", file_id_hex, key_epoch, share_version, new_index),
                str(out_path),
                f"[refresh] refreshed final share already exists: {out_path}",
            )
            return True
        if not refresh_material_ready_for_new_guardian(dkg, job):
            log_state(
                ("refresh-wait-material", file_id_hex, key_epoch, share_version, new_index),
                tuple(job.get("finalizedParticipantIndices") or []),
                f"[refresh] new Guardian {new_index}: waiting for all refresh material...",
            )
            return True
        try:
            sk_j, vk_j = compute_refreshed_local_share_from_onchain(dkg, sh_account, job)
            write_final_share_json_for_version(
                file_id_hex, int(job["newN"]), int(job["newT"]), key_epoch, share_version, int(new_index), sk_j, vk_j,
            )
            publish_share_public_key(
                w3, dkg, sh_account, job["fileIdBytes"], job["owner"],
                key_epoch, share_version, new_index, vk_j,
            )
        except Exception as e:
            print(f"[refresh] new Guardian share computation failed: {e}")
            return True

    return True


# ---------------------------------------------------------------------------
# Discovery: same-PK refresh (V2 Baby Jubjub)
# ---------------------------------------------------------------------------

def _v2_refresh_complete_dealers_for_new_guardian(coordinator_v2, job: dict, new_index: int) -> List[int]:
    # The contract fixes one old-threshold set when material is complete.
    # Choosing a local set (or using the new threshold) can produce different
    # polynomials at different receivers and change the reconstructed key.
    selected = [int(i) for i in job.get("finalizedParticipantIndices", [])]
    old_t = int(job["oldT"])
    assigned = {int(i) for i in job["oldParticipantIndices"]}
    if len(selected) != old_t or len(set(selected)) != old_t or not set(selected) <= assigned:
        return []
    file_id_bytes = job["fileIdBytes"]
    key_epoch = int(job["keyEpoch"])
    share_version = int(job["shareVersion"])
    for old_index in selected:
        try:
            has_commitments = coordinator_v2.functions.hasV2DealerCommitments(file_id_bytes, key_epoch, share_version, old_index).call()
            has_share = coordinator_v2.functions.hasV2EncryptedShare(file_id_bytes, key_epoch, share_version, old_index, int(new_index)).call()
        except Exception:
            return []
        if not has_commitments or not has_share:
            return []
    return selected


def compute_v2_refreshed_local_share_from_onchain(coordinator_v2, sh_account, job: dict, selected_old_indices: List[int], w3=None):
    new_index = int(job["newIndex"])
    key_epoch = int(job["keyEpoch"])
    share_version = int(job["shareVersion"])
    file_id_bytes = job["fileIdBytes"]
    sk_j = 0
    selected_old_indices = [int(x) for x in selected_old_indices]
    for old_index in selected_old_indices:
        commitments = _read_v2_dealer_commitments(coordinator_v2, file_id_bytes, key_epoch, old_index, int(job["newT"]), share_version)
        exists, _dealer, recipient, payload = coordinator_v2.functions.getV2EncryptedShare(
            file_id_bytes, key_epoch, share_version, old_index, new_index,
        ).call({"from": sh_account.address})
        if not exists:
            raise ValueError(f"Missing V2 refresh encrypted share from old index {old_index} to new index {new_index}")
        if Web3.to_checksum_address(recipient) != Web3.to_checksum_address(sh_account.address):
            raise ValueError(f"Wrong V2 refresh encrypted share recipient from old index {old_index} to new index {new_index}")
        s_ij = decrypt_dkg_share_payload(payload, my_index=new_index, expected_from_index=old_index) % BABY_L
        if not verify_v2_share_against_commitments(s_ij, new_index, commitments):
            if w3 is not None:
                try:
                    open_zkdkg_invalid_share_dispute(
                        w3, None, sh_account,
                        file_id_bytes, key_epoch, share_version,
                        int(old_index), int(new_index), True,
                    )
                except Exception as _dispute_exc:
                    print(f"[ZKDKG_V2 refresh] failed to open dispute for old index {old_index}: {_dispute_exc}")
            raise ValueError(f"V2 refresh share verification failed for old index {old_index}, new index {new_index}")
        coeff = lagrange_coeff_at_zero(old_index, selected_old_indices, BABY_L)
        sk_j = (sk_j + (int(coeff) * int(s_ij))) % BABY_L
    vk_j = baby_mul(sk_j, BABY_G)
    if vk_j is None or not baby_is_on_curve(vk_j):
        raise ValueError("invalid V2 refreshed final share public key")
    return sk_j, vk_j


def discover_pending_v2_same_pk_refresh(coordinator_v2, acl, sh_address: str) -> Optional[dict]:
    file_ids = _policy_ids(acl)
    sh_cs = Web3.to_checksum_address(sh_address)

    for file_id_bytes in file_ids:
        file_id_hex = Web3.to_hex(file_id_bytes)
        normalized_file_id = normalize_file_id_hex(file_id_hex)
        if _scan_skip_active(("v2-refresh-none", normalized_file_id, sh_cs.lower())):
            continue
        if _scan_skip_active(("v2-refresh-complete", normalized_file_id, sh_cs.lower())):
            continue
        try:
            policy_mode = int(acl.functions.getFilePolicyMode(file_id_bytes).call())
        except Exception:
            policy_mode = 0
        if policy_mode != 1:
            continue
        try:
            exists, active, owner, _policy_t, _policy_guardians = acl.functions.getFilePolicy(file_id_bytes).call()
        except Exception:
            continue
        if not exists or not active:
            continue
        try:
            (key_exists, key_finalized, _data_owner, _active_t, _active_n,
             key_epoch, active_share_version, _pkx, _pky,
             ) = coordinator_v2.functions.getV2Key(file_id_bytes).call()
        except Exception:
            continue
        if not key_exists or not key_finalized or int(key_epoch) <= 0:
            continue
        try:
            (refresh_exists, refresh_finalized, share_version, old_share_version,
             old_t, old_n, new_t, new_n, old_guardians, new_guardians, old_participant_indices,
             ) = coordinator_v2.functions.getPendingV2Refresh(file_id_bytes, int(key_epoch)).call()
        except Exception:
            continue
        if not refresh_exists:
            _remember_scan_skip(
                ("v2-refresh-none", normalized_file_id, sh_cs.lower()),
                _SHORT_SCAN_SKIP_SECONDS,
            )
            continue

        old_index = find_address_index(old_guardians, sh_cs)
        new_index = find_address_index(new_guardians, sh_cs)
        old_participant_set = {int(x) for x in old_participant_indices}
        if old_index is not None and old_index not in old_participant_set:
            old_index = None
        if old_index is None and new_index is None:
            continue
        if new_index is not None:
            out_path = v2_final_share_path(
                file_id_hex, int(key_epoch), int(share_version), int(new_n), int(new_t), int(new_index),
            )
            if bool(refresh_finalized) and out_path.exists():
                _remember_scan_skip(
                    ("v2-refresh-complete", normalized_file_id, sh_cs.lower()),
                    _COMPLETE_SCAN_SKIP_SECONDS,
                )
                continue

        finalized_participants = []
        if refresh_finalized:
            try:
                mask = int(coordinator_v2.functions.v2RefreshContributorMask(
                    file_id_bytes, int(key_epoch), int(share_version),
                ).call())
                finalized_participants = [i for i in range(1, int(old_n) + 1) if mask & (1 << (i - 1))]
            except Exception:
                log_every(("v2-refresh-contributor-set-unavailable", normalized_file_id, int(share_version)),
                          "[ZKDKG_V2 refresh] authoritative contributor set unavailable; refusing to guess shares.", 60)

        return {
            "fileIdBytes": file_id_bytes, "fileIdHex": file_id_hex,
            "owner": Web3.to_checksum_address(owner),
            "keyEpoch": int(key_epoch), "activeShareVersion": int(active_share_version),
            "refreshFinalized": bool(refresh_finalized),
            "shareVersion": int(share_version), "oldShareVersion": int(old_share_version),
            "oldT": int(old_t), "oldN": int(old_n), "newT": int(new_t), "newN": int(new_n),
            "oldGuardians": [Web3.to_checksum_address(g) for g in old_guardians],
            "newGuardians": [Web3.to_checksum_address(g) for g in new_guardians],
            "oldParticipantIndices": [int(x) for x in old_participant_indices],
            "finalizedParticipantIndices": finalized_participants,
            "oldParticipantIndex": old_index,
            "newIndex": new_index,
        }

    return None


def process_pending_v2_same_pk_refresh(w3: Web3, acl, guardian_registry, sh_account) -> bool:
    try:
        coordinator_v2 = load_zkdkg_coordinator_v2(w3)
    except Exception as exc:
        log_every(("v2-refresh-no-coordinator",), f"[ZKDKG_V2 refresh] coordinator not configured: {exc}", 60)
        return False

    job = discover_pending_v2_same_pk_refresh(coordinator_v2, acl, sh_account.address)
    if job is None:
        return False

    file_id_hex = normalize_file_id_hex(job["fileIdHex"])
    key_epoch = int(job["keyEpoch"])
    share_version = int(job["shareVersion"])
    old_share_version = int(job["oldShareVersion"])
    old_index = job["oldParticipantIndex"]
    new_index = job["newIndex"]

    log_state(
        ("v2-refresh-job", file_id_hex, key_epoch, share_version, old_index, new_index),
        (old_share_version, job.get("refreshFinalized", False)),
        f"[ZKDKG_V2 refresh] fileId={file_id_hex[:18]}..., keyEpoch={key_epoch}, "
        f"oldShareVersion={old_share_version}, newShareVersion={share_version}, "
        f"oldParticipantIndex={old_index}, newIndex={new_index}",
    )

    if old_index is not None and not job.get("refreshFinalized", False):
        try:
            already_commit = coordinator_v2.functions.hasV2DealerCommitments(
                job["fileIdBytes"], key_epoch, share_version, int(old_index)
            ).call()
            all_shares_done = all(
                coordinator_v2.functions.hasV2EncryptedShare(job["fileIdBytes"], key_epoch, share_version, int(old_index), j).call()
                for j in range(1, int(job["newN"]) + 1)
            )
            if not (already_commit and all_shares_done):
                _share_idx, old_share = load_v2_final_share_for_version(
                    file_id_hex, key_epoch, old_share_version, int(job["oldN"]), int(job["oldT"]), int(old_index),
                )
                material_path = v2_refresh_material_path(
                    file_id_hex, key_epoch, share_version, int(old_index), int(job["newN"]), int(job["newT"]),
                )
                if not material_path.exists() and any_v2_refresh_material_onchain(
                    coordinator_v2, job["fileIdBytes"], key_epoch, share_version, int(old_index), int(job["newN"]),
                ):
                    print(
                        f"[ZKDKG_V2 refresh] SAFETY STOP: old participant {old_index} already has partial "
                        f"refresh material on-chain for shareVersion={share_version}, but local saved "
                        f"dealer material is missing. Refusing to regenerate random refresh material."
                    )
                    return True
                _coeffs, commitments, shares_row = load_or_create_v2_refresh_material(
                    file_id_hex, key_epoch, share_version, int(old_index), old_share,
                    int(job["newT"]), int(job["newN"]),
                )
                ok_commit = publish_v2_dealer_commitments(
                    w3, coordinator_v2, sh_account, job["fileIdBytes"], key_epoch,
                    int(old_index), commitments, share_version=share_version,
                )
                if not ok_commit:
                    return True
                ok_shares = publish_v2_encrypted_shares_onchain(
                    w3, coordinator_v2, guardian_registry, sh_account, job["fileIdBytes"], key_epoch,
                    int(old_index), job["newGuardians"], shares_row, share_version=share_version,
                )
                if not ok_shares:
                    return True
            else:
                log_state(
                    ("v2-refresh-material-published", file_id_hex, key_epoch, share_version, old_index), True,
                    f"[ZKDKG_V2 refresh] old participant {old_index}: refresh material already published.",
                )
        except Exception as exc:
            print(f"[ZKDKG_V2 refresh] old participant step failed: {exc}")
            return True

    if new_index is not None:
        out_path = v2_final_share_path(
            file_id_hex, key_epoch, share_version, int(job["newN"]), int(job["newT"]), int(new_index),
        )
        if out_path.exists():
            log_state(
                ("v2-refresh-final-share-exists", file_id_hex, key_epoch, share_version, new_index),
                str(out_path),
                f"[ZKDKG_V2 refresh] refreshed final share already exists: {out_path}",
            )
        else:
            selected_old_indices = _v2_refresh_complete_dealers_for_new_guardian(coordinator_v2, job, int(new_index))
            if len(selected_old_indices) != int(job["oldT"]):
                log_state(
                    ("v2-refresh-wait-material", file_id_hex, key_epoch, share_version, new_index),
                    tuple(selected_old_indices),
                    f"[ZKDKG_V2 refresh] new Guardian {new_index}: waiting for enough refresh material "
                    f"{len(selected_old_indices)}/{int(job['newT'])}...",
                )
                return True
            try:
                sk_j, vk_j = compute_v2_refreshed_local_share_from_onchain(coordinator_v2, sh_account, job, selected_old_indices, w3=w3)
                data = {
                    "kind": "zkdkg_v2_refreshed_final_share", "curve": "BabyJubjub",
                    "fileId": normalize_file_id_hex(file_id_hex),
                    "keyEpoch": int(key_epoch), "shareVersion": int(share_version),
                    "index": int(new_index), "n": int(job["newN"]), "t": int(job["newT"]),
                    "share": str(int(sk_j)), "sk": str(int(sk_j)),
                    "vkx": str(int(vk_j[0])), "vky": str(int(vk_j[1])),
                    "computedFromOldIndices": [int(x) for x in selected_old_indices],
                }
                _write_json_atomic(out_path, data)
                print(f"[ZKDKG_V2 refresh] refreshed final Baby Jubjub share written to {out_path}")
            except Exception as exc:
                print(f"[ZKDKG_V2 refresh] new Guardian share computation failed: {exc}")
                return True

        try:
            (key_exists, key_finalized, _data_owner, _stored_t, _stored_n, _key_epoch, active_share_version, _pkx, _pky,
             ) = coordinator_v2.functions.getV2Key(job["fileIdBytes"]).call()
        except Exception:
            key_exists = False
            key_finalized = False
            active_share_version = 0

        if key_exists and key_finalized and int(active_share_version) >= share_version:
            try:
                d = read_secret_json(out_path)
                vk_j = (int(d["vkx"]), int(d["vky"]))
                publish_v2_share_public_key(
                    w3, coordinator_v2, sh_account, job["fileIdBytes"], key_epoch,
                    int(new_index), vk_j, share_version=share_version,
                )
            except Exception as exc:
                print(f"[ZKDKG_V2 refresh] publish refreshed share public key failed: {exc}")
                return True
        else:
            log_state(
                ("v2-refresh-wait-finalized", file_id_hex, key_epoch, share_version), int(active_share_version),
                f"[ZKDKG_V2 refresh] waiting for coordinator to activate shareVersion={share_version} before publishing share public key.",
            )

    return True


# ---------------------------------------------------------------------------
# High-level ZKDKG_V2 policy processing
# ---------------------------------------------------------------------------

def process_zkdkg_v2_policy(
    w3, acl, sh_account, file_id_bytes, file_id_hex, key_epoch, my_index, n, t,
) -> bool:
    dispute_manager = load_zkdkg_dispute_manager(w3)
    coordinator_v2 = load_zkdkg_coordinator_v2(w3)
    guardian_registry = load_guardian_registry(w3)
    try:
        _exists, _active, _owner, _threshold, policy_guardians = acl.functions.getFilePolicy(file_id_bytes).call()
    except Exception as exc:
        print(f"[ZKDKG_V2] could not read policy guardians: {exc}")
        return False

    coeffs, commitments, shares_row = load_or_create_v2_fresh_material(file_id_hex, key_epoch, n, t, my_index)

    ok = publish_v2_dkg_material(
        w3, dispute_manager, coordinator_v2, sh_account,
        file_id_bytes, file_id_hex, key_epoch, my_index, n, t, commitments, shares_row,
    )
    if not ok:
        return False

    ok = publish_v2_dealer_commitments(w3, coordinator_v2, sh_account, file_id_bytes, key_epoch, my_index, commitments)
    if not ok:
        return False

    ok = publish_v2_encrypted_shares_onchain(
        w3, coordinator_v2, guardian_registry, sh_account,
        file_id_bytes, key_epoch, my_index, policy_guardians, shares_row,
    )
    if not ok:
        return False

    _sk, vk = try_compute_and_store_v2_final_share_from_chain(
        coordinator_v2, sh_account, file_id_bytes, file_id_hex, key_epoch, n, t, my_index,
        w3=w3,
    )
    if vk is None:
        print("  -> Waiting for on-chain V2 encrypted incoming shares before writing final share.")
        return True

    if publish_v2_share_public_key(w3, coordinator_v2, sh_account, file_id_bytes, key_epoch, my_index, vk):
        print(f"[ZKDKG_V2] V2 share public key ready on-chain: shareIndex={my_index}")
    else:
        print(f"[ZKDKG_V2] V2 share public key publish pending for shareIndex={my_index}")
    return True


def process_zkdkg_disputes(w3: Web3, sh_account) -> None:
    if not cfg.ENABLE_ZKDKG_MIGRATION:
        return
    global _ZKDKG_DISPUTE_SCANNED_TO
    try:
        dispute_manager = load_zkdkg_dispute_manager(w3)
        head = int(w3.eth.block_number)
        # This runs on a loop. Re-reading the whole chain every time is both
        # refused by chains that cap log ranges and pointless: only blocks we
        # have not seen can hold a new dispute. Catch up once, then stay caught
        # up. Disputes already handled are skipped by the checks further down.
        start = 0 if _ZKDKG_DISPUTE_SCANNED_TO is None else _ZKDKG_DISPUTE_SCANNED_TO + 1
        events = _logs_forward(
            dispute_manager.events.ZkDkgEncryptedShareDisputeOpened(), start, head
        )
        _ZKDKG_DISPUTE_SCANNED_TO = head
    except Exception as e:
        log_every(("zkdkg-dispute-poll-error",), f"  -> zkDKG dispute poll failed: {e}", 60)
        return
    my_addr = Web3.to_checksum_address(sh_account.address)
    try:
        now_ts = int(w3.eth.get_block("latest")["timestamp"])
    except Exception:
        now_ts = 0
    for ev in events:
        args = ev["args"]
        dispute_id = args["disputeId"]
        try:
            d = dispute_manager.functions.getDispute(dispute_id).call()
            if d[1]:
                continue
        except Exception:
            continue
        dealer = Web3.to_checksum_address(args["dealer"])
        deadline = int(d[12])
        if dealer == my_addr:
            try:
                proof_json = build_zkdkg_dispute_justification_proof(w3, dispute_manager, d)
                proof = proof_tuple_from_zokrates_json(proof_json)
                fn = dispute_manager.functions.justifyZkDkgEncryptedShareDispute(dispute_id, proof)
                try:
                    gas_est = fn.estimate_gas({"from": sh_account.address})
                except Exception as exc:
                    print(f"  -> zkDKG dynamic justification gas estimate failed: {exc}")
                    continue
                tx_hash, receipt, _tx = send_contract_transaction(
                    w3, sh_account, fn,
                    gas=gas_est + 120_000,
                    gas_price=cfg.FIXED_GAS_PRICE_WEI,
                )
                print("  -> justifyZkDkgEncryptedShareDispute tx:", tx_hash.hex())
                print("  -> justifyZkDkgEncryptedShareDispute status:", receipt.status)
            except Exception as exc:
                if cfg.ZKDKG_JUSTIFICATION_PROOF_JSON:
                    submit_zkdkg_dispute_justification(
                        w3, dispute_manager, sh_account, dispute_id, cfg.ZKDKG_JUSTIFICATION_PROOF_JSON,
                    )
                else:
                    log_every(
                        ("zkdkg-dynamic-justify-error", str(dispute_id), str(exc)),
                        f"  -> zkDKG dynamic dispute justification unavailable: {exc}",
                        seconds=120,
                    )
            continue
        if deadline > 0 and now_ts > deadline:
            finalize_expired_zkdkg_dispute(w3, dispute_manager, sh_account, dispute_id)


# ---------------------------------------------------------------------------
# PRE-specific chain interactions
# ---------------------------------------------------------------------------

def get_dynamic_guardian_index(acl, file_id_bytes, sh_address: str):
    exists, active, owner, threshold, guardians = acl.functions.getFilePolicy(file_id_bytes).call()
    if not exists or not active:
        raise RuntimeError("PRE: file policy not active")
    sh_cs = Web3.to_checksum_address(sh_address)
    for i, g in enumerate(guardians, start=1):
        if Web3.to_checksum_address(g).lower() == sh_cs.lower():
            return i, int(threshold), len(guardians)
    raise RuntimeError("PRE: this Guardian is not in current file policy")


def get_epoch_guardian_index(job: dict, sh_address: str) -> Optional[int]:
    epoch_guardians = job.get("epochGuardians", [])
    if not epoch_guardians:
        raise RuntimeError("PRE: job has no epochGuardians")
    sh_cs = Web3.to_checksum_address(sh_address)
    for i, g in enumerate(epoch_guardians, start=1):
        if Web3.to_checksum_address(g).lower() == sh_cs.lower():
            return i
    return None


# Moved to g_policy so the rule can be tested without a Guardian identity;
# importing this module requires a real private key.
get_current_policy_info = _get_current_policy_info


def build_allowed_epoch_indices(epoch_guardians, current_guardians):
    current_set = {Web3.to_checksum_address(g).lower() for g in current_guardians}
    allowed_indices, allowed_guardians = [], []
    for i, g in enumerate(epoch_guardians, start=1):
        g_cs = Web3.to_checksum_address(g)
        if g_cs.lower() in current_set:
            allowed_indices.append(i)
            allowed_guardians.append(g_cs)
    return allowed_indices, allowed_guardians


def safe_is_enc_cid_valid(dv, cid_index: int) -> bool:
    try:
        return bool(dv.functions.isEncCidValid(int(cid_index)).call())
    except Exception:
        return True


def safe_get_enc_cid_v2_metadata(dv, cid_index: int) -> dict:
    meta = {"batchId": 0, "pieceIndex": 0, "valid": True, "replacedBy": 0}
    try:
        result = dv.functions.getEncCidV2(int(cid_index)).call()
        if len(result) >= 8:
            meta["batchId"] = int(result[4])
            meta["pieceIndex"] = int(result[5])
            meta["valid"] = bool(result[6])
            meta["replacedBy"] = int(result[7])
    except Exception:
        pass
    return meta


def load_local_share_for_epoch(
    epoch: int, file_id_hex: str, n: int, t: int, epoch_index: int, share_version: int = 1,
) -> Tuple[int, int]:
    base_prefix = f"{make_base_prefix(file_id_hex, n, t)}_k{epoch}"
    if int(share_version) > 1:
        base_prefix = f"{base_prefix}_v{int(share_version)}"
    path = cfg.ROOT / f"{base_prefix}_final_share_{epoch_index}.json"
    if not path.exists():
        raise FileNotFoundError(
            f"Missing DKG share file: {path} "
            f"(epoch_index={epoch_index}, shareVersion={share_version})"
        )
    mtime = path.stat().st_mtime
    cache_key = (normalize_file_id_hex(file_id_hex), int(epoch), int(share_version), int(n), int(t), int(epoch_index))
    if not hasattr(load_local_share_for_epoch, "_cache"):
        load_local_share_for_epoch._cache = {}
    cached = load_local_share_for_epoch._cache.get(cache_key)
    if cached is None or mtime > cached[0]:
        d = read_secret_json(path)
        share_index = int(d["index"])
        sk = int(d["sk"])
        load_local_share_for_epoch._cache[cache_key] = (mtime, share_index, sk)
        print(
            f"[PRE G {cfg.SH_INDEX}] loaded share for fileId={file_id_hex[:18]}..., "
            f"epoch={epoch}, shareVersion={share_version}, epoch_index={epoch_index}, share_index={share_index}"
        )
    else:
        _, share_index, sk = cached
    return share_index, sk


def load_v2_share_for_epoch(
    epoch: int, file_id_hex: str, n: int, t: int, epoch_index: int, share_version: int = 1,
) -> Tuple[int, int]:
    if getattr(cfg,'DKG_ATTEMPT_PROTOCOL',0)==1:
        from .g_dkg_custody import load_active_share
        return load_active_share(cfg,file_id_hex,epoch,share_version,n,t,epoch_index)
    v2_dir = cfg.V2_SHARE_DIR
    short_id = normalize_file_id_hex(file_id_hex)[2:18]
    candidates = [
        v2_dir / f"v2_dkg_file_{short_id}_n{int(n)}_t{int(t)}_k{int(epoch)}_v{int(share_version)}_final_share_{int(epoch_index)}.json",
        v2_dir / f"v2_dkg_file_{short_id}_n{int(n)}_t{int(t)}_k{int(epoch)}_final_share_{int(epoch_index)}.json",
        v2_dir / f"zkdkg_v2_file_{short_id}_n{int(n)}_t{int(t)}_k{int(epoch)}_v{int(share_version)}_final_share_{int(epoch_index)}.json",
        v2_dir / f"zkdkg_v2_file_{short_id}_n{int(n)}_t{int(t)}_k{int(epoch)}_final_share_{int(epoch_index)}.json",
    ]
    for path in candidates:
        if not path.exists():
            continue
        d = read_secret_json(path)
        curve = str(d.get("curve", d.get("dkgMode", ""))).lower()
        if curve and "baby" not in curve and "zkdkg_v2" not in curve:
            continue
        share_index = int(d.get("index", d.get("shareIndex", epoch_index)))
        share = int(d.get("share", d.get("sk")))
        print(
            f"[PRE G {cfg.SH_INDEX}] loaded V2 Baby Jubjub share for fileId={file_id_hex[:18]}..., "
            f"epoch={epoch}, shareVersion={share_version}, share_index={share_index}"
        )
        return share_index, share
    raise FileNotFoundError(
        f"Missing ZKDKG_V2 share file in {v2_dir} for "
        f"fileId={file_id_hex[:18]}..., epoch={epoch}, shareVersion={share_version}, index={epoch_index}"
    )


def count_onchain_pre_partials(telg, request_id: int, guardians: List[str]) -> int:
    seen = set()
    count = 0
    for g in guardians:
        try:
            g_cs = Web3.to_checksum_address(g)
        except Exception:
            continue
        key = g_cs.lower()
        if key in seen:
            continue
        seen.add(key)
        try:
            if telg.functions.hasPrePartial(int(request_id), g_cs).call():
                count += 1
        except Exception:
            pass
    return count


def count_onchain_v2_partials(telg_v2, request_id: int) -> int:
    try:
        return len(telg_v2.functions.getV2PartialGuardians(int(request_id)).call())
    except Exception:
        return 0


def has_v2_partial_for(telg_v2, request_id: int, guardian_address: str) -> bool:
    try:
        result = telg_v2.functions.getV2Partial(int(request_id), Web3.to_checksum_address(guardian_address)).call()
        return bool(result[0])
    except Exception:
        return False


def build_pre_ready_hash(request_id: int, share_version: int, share_index: int, partials: List[dict]):
    cid_indices = [int(x["cidIndex"]) for x in partials]
    dx_values = [int(x["Dx"]) for x in partials]
    dy_values = [int(x["Dy"]) for x in partials]
    return Web3.solidityKeccak(
        ["uint256", "uint32", "uint8", "uint256[]", "uint256[]", "uint256[]"],
        [int(request_id), int(share_version), int(share_index), cid_indices, dx_values, dy_values],
    )


def read_pre_ready_signal(telg, request_id: int, guardian_address: str) -> dict:
    default = {"exists": False, "shareVersion": 0, "shareIndex": 0, "partialsHash": None, "signaledAt": 0, "readyNotUsedCredited": False}
    try:
        result = telg.functions.getPreReadySignal(int(request_id), Web3.to_checksum_address(guardian_address)).call()
        if len(result) != 6:
            return default
        exists, share_version, share_index, partials_hash, signaled_at, ready_not_used_credited = result
        return {
            "exists": bool(exists), "shareVersion": int(share_version), "shareIndex": int(share_index),
            "partialsHash": partials_hash, "signaledAt": int(signaled_at),
            "readyNotUsedCredited": bool(ready_not_used_credited),
        }
    except Exception:
        return default


def submit_partial_onchain(w3, telg, sh_acct, request_id, share_version, share_index, partials) -> bool:
    if not partials:
        return False
    cid_indices = [int(x["cidIndex"]) for x in partials]
    c1x_values = [int(x["C1x"]) for x in partials]
    c1y_values = [int(x["C1y"]) for x in partials]
    dx_values = [int(x["Dx"]) for x in partials]
    dy_values = [int(x["Dy"]) for x in partials]
    a1x_values = [int(x["a1x"]) for x in partials]
    a1y_values = [int(x["a1y"]) for x in partials]
    a2x_values = [int(x["a2x"]) for x in partials]
    a2y_values = [int(x["a2y"]) for x in partials]
    s_values = [int(x["s"]) for x in partials]
    c_values = [int(x["c"]) for x in partials]
    fn = telg.functions.submitPrePartial(
        int(request_id), int(share_version), int(share_index),
        (cid_indices, c1x_values, c1y_values, dx_values, dy_values,
         (a1x_values, a1y_values, a2x_values, a2y_values, s_values, c_values)),
    )
    gas_limit = None
    try:
        gas_est = fn.estimate_gas({"from": sh_acct.address})
        gas_limit = gas_est + 80_000
    except Exception as e:
        msg = str(e)
        if "share index already used" in msg:
            print(f"[PRE G {cfg.SH_INDEX}] skip request {request_id}: share index already submitted")
            return False
        if "PRE threshold already reached" in msg:
            print(f"[PRE G {cfg.SH_INDEX}] full PRE submission skipped for request {request_id}: PRE threshold already reached")
            return False
        if "PRE ready window active" in msg:
            try:
                ready_deadline = int(telg.functions.preReadyWindowDeadline(int(request_id)).call())
                chain_ts = int(w3.eth.get_block("latest")["timestamp"])
            except Exception:
                ready_deadline = 0
                chain_ts = 0
            if ready_deadline > 0 and chain_ts < ready_deadline:
                wait_seconds = int(ready_deadline - chain_ts + 1)
                print(
                    f"[PRE G {cfg.SH_INDEX}] full PRE submission deferred for request "
                    f"{request_id}: blockchain PRE-ready window remains active for "
                    f"approximately {wait_seconds}s"
                )
                return False
            gas_limit = 3_000_000
            print(f"[PRE G {cfg.SH_INDEX}] PRE-ready window passed for request {request_id}; sending full PRE transaction with explicit gas limit")
        else:
            print(f"[PRE G {cfg.SH_INDEX}] submitPrePartial gas estimate failed for request {request_id}: {e}")
            return False
    tx_hash, receipt, _tx = send_contract_transaction(
        w3, sh_acct, fn,
        gas=gas_limit,
        gas_price=cfg.FIXED_GAS_PRICE_WEI,
    )
    print(f"[PRE G {cfg.SH_INDEX}] submitPrePartial request {request_id} tx: {tx_hash.hex()}")
    print(f"[PRE G {cfg.SH_INDEX}] submitPrePartial request {request_id} status: {receipt.status}")
    return receipt.status == 1


def submit_v2_partial_onchain(w3, telg_v2, sh_acct, request_id, share_index, partials) -> bool:
    if not partials:
        return False
    cid_indices = [int(x["cidIndex"]) for x in partials]
    e1x_values = [int(x["E1"][0]) for x in partials]
    e1y_values = [int(x["E1"][1]) for x in partials]
    e2x_values = [int(x["E2"][0]) for x in partials]
    e2y_values = [int(x["E2"][1]) for x in partials]
    proofs = [x["proof"] for x in partials]
    fn = telg_v2.functions.submitV2AccessPartial(
        int(request_id), int(share_index),
        (cid_indices, e1x_values, e1y_values, e2x_values, e2y_values, proofs),
    )
    try:
        gas_est = fn.estimate_gas({"from": sh_acct.address})
        gas_limit = gas_est + 120_000
    except Exception as e:
        print(f"[PRE G {cfg.SH_INDEX}] submitV2AccessPartial gas estimate failed for request {request_id}: {e}")
        return False
    tx_hash, receipt, _tx = send_contract_transaction(
        w3, sh_acct, fn,
        gas=gas_limit,
        gas_price=cfg.FIXED_GAS_PRICE_WEI,
    )
    print(f"[PRE G {cfg.SH_INDEX}] submitV2AccessPartial request {request_id} tx: {tx_hash.hex()}")
    print(f"[PRE G {cfg.SH_INDEX}] submitV2AccessPartial request {request_id} status: {receipt.status}")
    return receipt.status == 1


def submit_v2_batch_partial_onchain(
    w3, telg_v2, sh_acct, request_id, share_index, e1, e2, proof
) -> PreTxOutcome:
    fn = telg_v2.functions.submitV2BatchAccessPartial(
        int(request_id), int(share_index),
        int(e1[0]), int(e1[1]), int(e2[0]), int(e2[1]),
        proof,
    )
    try:
        gas_est = fn.estimate_gas({"from": sh_acct.address})
        gas_limit = gas_est + 120_000
    except Exception as e:
        if is_terminal_v2_pre_error(str(e)):
            print(f"[PRE G {cfg.SH_INDEX}] request {request_id} is terminal: {e}")
            return "complete"
        print(f"[PRE G {cfg.SH_INDEX}] submitV2BatchAccessPartial gas estimate failed for request {request_id}: {e}")
        return "retry"
    try:
        tx_hash, receipt, _tx = send_contract_transaction(
            w3, sh_acct, fn,
            gas=gas_limit,
            gas_price=cfg.FIXED_GAS_PRICE_WEI,
        )
    except Exception as e:
        if is_terminal_v2_pre_error(str(e)):
            print(f"[PRE G {cfg.SH_INDEX}] request {request_id} became terminal: {e}")
            return "complete"
        print(f"[PRE G {cfg.SH_INDEX}] submitV2BatchAccessPartial transaction failed for request {request_id}: {e}")
        return "retry"
    print(f"[PRE G {cfg.SH_INDEX}] submitV2BatchAccessPartial request {request_id} tx: {tx_hash.hex()}")
    print(f"[PRE G {cfg.SH_INDEX}] submitV2BatchAccessPartial request {request_id} status: {receipt.status}")
    return "submitted" if receipt.status == 1 else "retry"


def declare_pre_ready_for_request_onchain(
    w3, telg_v2, sh_acct, request_id
) -> PreTxOutcome:
    fn = telg_v2.functions.declareReadyForRequest(int(request_id))
    try:
        gas_est = fn.estimate_gas({"from": sh_acct.address})
    except Exception as e:
        msg = str(e)
        if "threshold not met" in msg:
            return "retry"
        if is_terminal_v2_pre_error(msg):
            return "complete"
        print(f"[PRE G {cfg.SH_INDEX}] declareReadyForRequest gas estimate failed for request {request_id}: {e}")
        return "retry"
    try:
        tx_hash, receipt, _tx = send_contract_transaction(
            w3, sh_acct, fn,
            gas=gas_est + 60_000,
            gas_price=cfg.FIXED_GAS_PRICE_WEI,
        )
    except Exception as e:
        if is_terminal_v2_pre_error(str(e)):
            return "complete"
        print(f"[PRE G {cfg.SH_INDEX}] declareReadyForRequest transaction failed for request {request_id}: {e}")
        return "retry"
    print(f"[PRE G {cfg.SH_INDEX}] declareReadyForRequest request {request_id} tx: {tx_hash.hex()}")
    print(f"[PRE G {cfg.SH_INDEX}] declareReadyForRequest request {request_id} status: {receipt.status}")
    return "submitted" if receipt.status == 1 else "retry"


def publish_v2_share_public_key_onchain(w3, coordinator_v2, sh_acct, file_id, key_epoch, share_index, share_public_key) -> bool:
    fn = coordinator_v2.functions.publishV2SharePublicKey(
        file_id, int(key_epoch), int(share_index), int(share_public_key[0]), int(share_public_key[1]),
    )
    try:
        gas_est = fn.estimate_gas({"from": sh_acct.address})
        gas_limit = gas_est + 80_000
    except Exception as e:
        msg = str(e)
        if "share key exists" in msg:
            return True
        print(f"[PRE G {cfg.SH_INDEX}] publishV2SharePublicKey gas estimate failed for shareIndex={share_index}: {e}")
        return False
    tx_hash, receipt, _tx = send_contract_transaction(
        w3, sh_acct, fn,
        gas=gas_limit,
        gas_price=cfg.FIXED_GAS_PRICE_WEI,
    )
    print(f"[PRE G {cfg.SH_INDEX}] publishV2SharePublicKey tx: {tx_hash.hex()}")
    print(f"[PRE G {cfg.SH_INDEX}] publishV2SharePublicKey status: {receipt.status}")
    return receipt.status == 1


def signal_pre_ready_onchain(w3, telg, sh_acct, request_id, share_version, share_index, partial_hash) -> bool:
    fn = telg.functions.signalPreReady(int(request_id), int(share_version), int(share_index), partial_hash)
    try:
        gas_est = fn.estimate_gas({"from": sh_acct.address})
    except Exception as e:
        msg = str(e)
        if "PRE threshold already reached" in msg:
            print(f"[PRE G {cfg.SH_INDEX}] ready signal skipped for request {request_id}: PRE threshold already reached")
        elif "ready already signaled" in msg:
            print(f"[PRE G {cfg.SH_INDEX}] ready signal already exists for request {request_id}")
        else:
            print(f"[PRE G {cfg.SH_INDEX}] signalPreReady gas estimate failed for request {request_id}: {e}")
        return False
    tx_hash, receipt, _tx = send_contract_transaction(
        w3, sh_acct, fn,
        gas=gas_est + 80_000,
        gas_price=cfg.FIXED_GAS_PRICE_WEI,
    )
    print(f"[PRE G {cfg.SH_INDEX}] signalPreReady request {request_id} tx: {tx_hash.hex()}")
    print(f"[PRE G {cfg.SH_INDEX}] signalPreReady request {request_id} status: {receipt.status}")
    return receipt.status == 1


def claim_pre_ready_not_used_onchain(w3, telg, sh_acct, request_id) -> bool:
    fn = telg.functions.declareReadyForRequest(int(request_id))
    try:
        gas_est = fn.estimate_gas({"from": sh_acct.address})
    except Exception as e:
        msg = str(e)
        if any(s in msg for s in (
            "ready credit already claimed", "Guardian submitted PRE partial",
            "PRE threshold not reached", "already declared", "already submitted",
            "threshold not met",
        )):
            return False
        print(f"[PRE G {cfg.SH_INDEX}] declareReadyForRequest gas estimate failed for request {request_id}: {e}")
        return False
    tx_hash, receipt, _tx = send_contract_transaction(
        w3, sh_acct, fn,
        gas=gas_est + 80_000,
        gas_price=cfg.FIXED_GAS_PRICE_WEI,
    )
    print(f"[PRE G {cfg.SH_INDEX}] declareReadyForRequest request {request_id} tx: {tx_hash.hex()}")
    print(f"[PRE G {cfg.SH_INDEX}] declareReadyForRequest request {request_id} status: {receipt.status}")
    return receipt.status == 1


def build_job_from_chain(job_id: int, dv, acl, dkg=None, coordinator_v2=None) -> Optional[dict]:
    (exists, file_id, requester, batch_id, data_id, ts, key_epoch,
     pk_req_x, pk_req_y, indices_req,
     ) = dv.functions.getAccessRequest(job_id).call()
    if not exists:
        return None

    (file_id_on, data_owner_on, tag_on, ts_on, n_ida, t_ida, key_epoch_batch, cid_indices,
     ) = dv.functions.getBatch(batch_id).call()

    request_cid_indices = normalize_uint_list(indices_req)
    if not request_cid_indices:
        request_cid_indices = normalize_uint_list(cid_indices)

    file_id_hex = normalize_file_id_hex(file_id_on)
    current_policy = get_current_policy_info(acl, file_id_on)

    try:
        dkg_mode_raw = int(acl.functions.getFilePolicyMode(file_id_on).call())
    except Exception:
        dkg_mode_raw = 0
    dkg_mode = "ZKDKG_V2" if dkg_mode_raw == 1 else "LEGACY"

    try:
        request_share_version = int(dv.functions.getAccessRequestShareVersion(int(job_id)).call())
    except Exception:
        request_share_version = 0
    share_version = request_share_version if request_share_version > 0 else 1

    epoch_guardians = []
    epoch_n = 0
    epoch_t = 0

    try:
        if dkg_mode == "ZKDKG_V2":
            if coordinator_v2 is None:
                raise RuntimeError("ZKDKG_V2 coordinator is not configured")
            (key_exists, finalized, _data_owner, v2_t, v2_n, v2_key_epoch, v2_share_version, _pkx, _pky,
             ) = coordinator_v2.functions.getV2Key(file_id_on).call()
            if not key_exists or not finalized:
                raise RuntimeError("ZKDKG_V2 key is not finalized")
            if int(v2_key_epoch) != int(key_epoch_batch):
                raise RuntimeError("ZKDKG_V2 key epoch mismatch")
            epoch_guardians = list(current_policy["guardians"])
            epoch_n = int(v2_n)
            epoch_t = int(v2_t)
            share_version = request_share_version if request_share_version > 0 else int(v2_share_version)
            raise StopIteration

        if dkg is None:
            raise RuntimeError("DKG contract not configured")

        if request_share_version <= 0:
            share_version = int(dkg.functions.getActiveShareVersion(file_id_on, int(key_epoch_batch)).call())
        if share_version <= 0:
            raise RuntimeError("No request shareVersion")

        (sv_exists, sv_finalized, sv_t, sv_n, previous_sv, sv_guardians, old_participant_indices,
         ) = dkg.functions.getShareVersionInfo(file_id_on, int(key_epoch_batch), int(share_version)).call()
        if not sv_exists or not sv_finalized:
            raise RuntimeError("Request shareVersion is not finalized")
        epoch_guardians = [Web3.to_checksum_address(g) for g in sv_guardians]
        epoch_n = int(sv_n)
        epoch_t = int(sv_t)

    except StopIteration:
        pass
    except Exception:
        epoch_meta = load_epoch_metadata(file_id_hex, int(key_epoch_batch))
        epoch_guardians = [Web3.to_checksum_address(g) for g in epoch_meta["guardians"]]
        epoch_n = int(epoch_meta["dkgN"])
        epoch_t = int(epoch_meta["dkgT"])
        share_version = request_share_version if request_share_version > 0 else 1

    allowed_epoch_indices, allowed_guardians = build_allowed_epoch_indices(epoch_guardians, current_policy["guardians"])
    if len(allowed_epoch_indices) < epoch_t:
        raise RuntimeError(
            f"PRE: not enough active shareVersion Guardians. "
            f"remaining={len(allowed_epoch_indices)}, required={epoch_t}"
        )

    cts = []
    skipped_invalid = []
    for pos, cid_idx in enumerate(request_cid_indices):
        cid_idx = int(cid_idx)
        meta = safe_get_enc_cid_v2_metadata(dv, cid_idx)
        if not meta.get("valid", True) or not safe_is_enc_cid_valid(dv, cid_idx):
            skipped_invalid.append(cid_idx)
            continue
        C1x, C1y, C2, ctSym = dv.functions.getEncCid(cid_idx).call()
        cts.append({
            "cidIndex": cid_idx,
            "C1x": str(int(C1x)), "C1y": str(int(C1y)),
            "C2_hex": C2.hex(),
            "position_in_request": int(pos),
            "pieceIndex": int(meta.get("pieceIndex", 0)),
            "n": int(n_ida), "t": int(t_ida),
            "label": f"cid_{cid_idx}_piece_{int(meta.get('pieceIndex', 0))}",
        })

    if skipped_invalid:
        log_state(
            ("pre-skip-invalid-cids", int(job_id)), tuple(skipped_invalid),
            f"[PRE] request {job_id}: skipped invalid/replaced encCid record(s): {preview_list(skipped_invalid)}",
        )

    return {
        "requestId": int(job_id), "dkgMode": dkg_mode,
        "fileId": file_id_hex, "requester": Web3.to_checksum_address(requester),
        "batchId": int(batch_id), "dataId": data_id, "ts": int(ts),
        "keyEpoch": int(key_epoch_batch), "shareVersion": int(share_version),
        "dkgN": int(epoch_n), "dkgT": int(epoch_t),
        "epochGuardians": epoch_guardians, "currentGuardians": current_policy["guardians"],
        "allowedEpochIndices": allowed_epoch_indices, "allowedGuardians": allowed_guardians,
        "ciphertexts": cts, "requestCidIndices": request_cid_indices,
        "pkReqX": str(int(pk_req_x)), "pkReqY": str(int(pk_req_y)),
    }
