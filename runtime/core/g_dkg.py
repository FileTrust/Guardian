#!/usr/bin/env python3
"""Guardian DKG protocol loop.

Handles:
  - Fresh DKG (secp256k1 and Baby Jubjub ZKDKG_V2)
  - Same-PK share refresh (secp256k1 and ZKDKG_V2)
  - zkDKG dispute detection and justification
  - Service pricing sync on startup

Run from the instance root:
    python core/g_dkg.py
or spawned by start.py as a subprocess.
"""
from __future__ import annotations


import json
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Add instance root to sys.path so `from core.x import ...` resolves.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.g_secret_files import read_secret_json

from web3 import Web3

import core.g_config as cfg
from core.g_policy import policy_parameters_are_safe, select_next_policy
from core.g_chain import (
    any_fresh_dkg_material_onchain,
    claim_guardian_rewards_if_available,
    collect_dkg_event_file_ids,
    compute_local_share_from_onchain,
    discover_file_policy,
    discover_file_policies,
    find_finalized_v2_policy_with_missing_share,
    load_contract,
    load_guardian_registry,
    load_reputation_manager,
    load_zkdkg_coordinator_v2,
    poll_serious_penalties,
    process_pending_same_pk_refresh,
    process_pending_v2_same_pk_refresh,
    process_zkdkg_disputes,
    process_zkdkg_v2_policy,
    publish_share_public_key,
    upload_encrypted_dkg_shares,
    upload_guardian_commitments,
)
from core.g_log import log_every, log_state
from core.g_material import (
    fresh_dkg_material_path,
    load_or_create_fresh_dkg_material,
    make_base_prefix,
    normalize_file_id_hex,
    _write_json_atomic,
    write_epoch_metadata_json,
    write_final_share_json,
    write_local_commitments_file,
    write_outgoing_shares_files,
)
from core.g_pricing import (
    load_guardian_service_prices,
    print_guardian_service_prices,
    sync_guardian_service_pricing,
)

_COMPLETED_DKG_STATE_SECONDS = 1800.0
_DKG_WORKERS = cfg.DKG_WORKERS
_FAST_STARTUP_SECONDS = 120.0
_IDLE_EVENT_CHECK_SECONDS = 30.0


def _completed_dkg_state_path() -> Path:
    return cfg.ROOT / "state" / "completed_dkg.json"


def _load_completed_dkg_skips() -> dict[str, float]:
    path = _completed_dkg_state_path()
    now_wall = time.time()
    now_mono = time.monotonic()
    try:
        raw = read_secret_json(path)
    except Exception:
        return {}
    out: dict[str, float] = {}
    for file_id_hex, seen_at in dict(raw).items():
        try:
            age = now_wall - float(seen_at)
        except Exception:
            continue
        if 0 <= age < _COMPLETED_DKG_STATE_SECONDS:
            out[normalize_file_id_hex(file_id_hex)] = now_mono + (_COMPLETED_DKG_STATE_SECONDS - age)
    return out


def _remember_completed_dkg(file_id_hex: str) -> None:
    path = _completed_dkg_state_path()
    try:
        raw = read_secret_json(path)
    except Exception:
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    now_wall = time.time()
    cutoff = now_wall - _COMPLETED_DKG_STATE_SECONDS
    compact = {
        normalize_file_id_hex(fid): float(ts)
        for fid, ts in raw.items()
        if isinstance(fid, str) and isinstance(ts, (int, float)) and float(ts) >= cutoff
    }
    compact[normalize_file_id_hex(file_id_hex)] = now_wall
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_json_atomic(path, compact)


def _v2_guardian_progress(
    coordinator_v2,
    file_id_bytes: bytes,
    key_epoch: int,
    guardian_index: int,
    guardian_count: int,
) -> tuple:
    """Return the Guardian's authoritative on-chain progress fingerprint."""
    try:
        dealer_ack = bool(
            coordinator_v2.functions.dealerMaterialSubmitted(
                file_id_bytes, int(key_epoch), int(guardian_index)
            ).call()
        )
    except Exception:
        dealer_ack = False
    try:
        commitments = bool(
            coordinator_v2.functions.hasV2DealerCommitments(
                file_id_bytes, int(key_epoch), 1, int(guardian_index)
            ).call()
        )
    except Exception:
        commitments = False
    encrypted_outgoing = 0
    encrypted_incoming = 0
    for receiver_index in range(1, int(guardian_count) + 1):
        try:
            if coordinator_v2.functions.hasV2EncryptedShare(
                file_id_bytes,
                int(key_epoch),
                1,
                int(guardian_index),
                int(receiver_index),
            ).call():
                encrypted_outgoing += 1
        except Exception:
            pass
        try:
            if coordinator_v2.functions.hasV2EncryptedShare(
                file_id_bytes,
                int(key_epoch),
                1,
                int(receiver_index),
                int(guardian_index),
            ).call():
                encrypted_incoming += 1
        except Exception:
            pass
    try:
        share_key = coordinator_v2.functions.getV2SharePublicKey(
            file_id_bytes, int(key_epoch), 1, int(guardian_index)
        ).call()
        share_key_exists = bool(share_key[0])
    except Exception:
        share_key_exists = False
    return (
        dealer_ack,
        commitments,
        encrypted_outgoing,
        encrypted_incoming,
        share_key_exists,
    )


def _process_v2_dkg_policy(
    w3,
    acl,
    guardian_registry,
    sh_account,
    policy,
    completed_v2_policy_skip_until: dict[str, float],
    completed_lock: threading.Lock,
    retry_until: dict[str, float],
    retry_delay: dict[str, float],
    retry_lock: threading.Lock,
) -> bool:
    (
        file_id_bytes, file_id_hex, policy_owner, policy_t,
        policy_n, dynamic_index, policy_guardians,
    ) = policy
    if file_id_bytes is None:
        return False
    normalized_file_id = normalize_file_id_hex(file_id_hex)
    with retry_lock:
        if time.monotonic() < retry_until.get(normalized_file_id, 0.0):
            return False

    policy_owner_checksum = Web3.to_checksum_address(policy_owner)
    is_do = acl.functions.isFileDataOwner(file_id_bytes, policy_owner_checksum).call()
    is_guardian = acl.functions.isGuardianForFile(file_id_bytes, sh_account.address).call()
    has_req = acl.functions.hasRequestedKeyGenForFile(file_id_bytes).call()
    try:
        policy_mode = int(acl.functions.getFilePolicyMode(file_id_bytes).call())
    except Exception:
        policy_mode = 0
    if policy_mode != 1:
        return False

    try:
        coordinator_v2 = load_zkdkg_coordinator_v2(w3)
        key = coordinator_v2.functions.getV2Key(file_id_bytes).call()
        exists = bool(key[0])
        finalized = bool(key[1])
        last_epoch = int(key[5]) if exists else 0
    except Exception:
        exists = False
        finalized = False
        last_epoch = 0

    log_state(
        ("dkg-loop-policy", file_id_hex),
        (policy_owner_checksum, bool(is_do), bool(is_guardian), bool(has_req), bool(exists), bool(finalized), int(last_epoch)),
        f"[loop] fileId={file_id_hex[:18]}..., owner={policy_owner_checksum}, "
        f"isFileDO={is_do}, isGuardian={is_guardian}, "
        f"hasRequestedKeyGen={has_req}, keyExists={exists}, keyFinalized={finalized}, lastEpoch={last_epoch}",
    )

    if exists and finalized and int(last_epoch) > 0 and is_do and is_guardian:
        active_n = int(policy_n)
        active_t = int(policy_t)
        my_dkg_index = int(dynamic_index)
        # The same rule as the path that creates a key. A finalized key is not a
        # reason to skip it: this branch still publishes a share public key and
        # takes part, and doing that for a threshold of one is exactly what the
        # check on the other path exists to refuse.
        safe, unsafe_reason = policy_parameters_are_safe(active_n, active_t)
        if not safe:
            log_state(
                ("dkg-invalid-policy", file_id_hex), (active_n, active_t),
                f"[loop] refusing finalized policy: {unsafe_reason}",
            )
            return False
        try:
            _key_exists, _key_finalized, _data_owner, _stored_t, _stored_n, _key_epoch, active_share_version, _pkx0, _pky0 = coordinator_v2.functions.getV2Key(file_id_bytes).call()
            pk_exists, _pkx, _pky = coordinator_v2.functions.getV2SharePublicKey(
                file_id_bytes, int(last_epoch), int(active_share_version), my_dkg_index,
            ).call()
        except Exception:
            active_share_version = 1
            pk_exists = False

        if not pk_exists:
            log_state(
                ("dkg-v2-post-finalize", file_id_hex, int(last_epoch), int(active_share_version), my_dkg_index), True,
                f"[loop] ZKDKG_V2 key finalized for fileId={file_id_hex[:18]}..., "
                f"activeShareVersion={int(active_share_version)}, "
                f"publishing share public key for shareIndex={my_dkg_index}",
            )
            try:
                if int(active_share_version) > 1:
                    process_pending_v2_same_pk_refresh(w3, acl, guardian_registry, sh_account)
                else:
                    process_zkdkg_v2_policy(
                        w3, acl, sh_account, file_id_bytes, file_id_hex,
                        int(last_epoch), my_dkg_index, active_n, active_t,
                    )
                refreshed = coordinator_v2.functions.getV2SharePublicKey(
                    file_id_bytes,
                    int(last_epoch),
                    int(active_share_version),
                    my_dkg_index,
                ).call()
                if bool(refreshed[0]):
                    claim_guardian_rewards_if_available(
                        w3, sh_account, "claimRewards after V2 share key"
                    )
                    with completed_lock:
                        completed_v2_policy_skip_until[normalized_file_id] = (
                            time.monotonic() + _COMPLETED_DKG_STATE_SECONDS
                        )
                    _remember_completed_dkg(normalized_file_id)
                    with retry_lock:
                        retry_until.pop(normalized_file_id, None)
                        retry_delay.pop(normalized_file_id, None)
                    return True
            except Exception as exc:
                log_state(
                    ("dkg-v2-post-finalize-error", normalized_file_id),
                    str(exc),
                    f"[loop] post-finalization share-key publication failed; "
                    f"will retry with backoff: {exc}",
                )
            with retry_lock:
                previous = retry_delay.get(
                    normalized_file_id, cfg.DKG_RETRY_INITIAL_SECONDS
                )
                delay = min(cfg.DKG_RETRY_MAX_SECONDS, previous * 2)
                retry_delay[normalized_file_id] = delay
                retry_until[normalized_file_id] = (
                    time.monotonic()
                    + delay
                    + random.uniform(0.0, min(2.0, delay / 4))
                )
            return False
        else:
            with completed_lock:
                completed_v2_policy_skip_until[normalized_file_id] = (
                    time.monotonic() + _COMPLETED_DKG_STATE_SECONDS
                )
            _remember_completed_dkg(normalized_file_id)
            with retry_lock:
                retry_until.pop(normalized_file_id, None)
                retry_delay.pop(normalized_file_id, None)
            return False

    if not (is_do and is_guardian and has_req):
        return False

    # The blockchain timestamp is authoritative for this request.  An expired
    # request remains discoverable until the DO (or another caller) settles it,
    # but Guardians must not keep regenerating or submitting material for it.
    try:
        requested_at = int(acl.functions.getKeyGenRequestedAtForFile(file_id_bytes).call())
        dkg_deadline = int(coordinator_v2.functions.dkgKeyGenDeadline().call())
        chain_now = int(w3.eth.get_block("latest")["timestamp"])
    except Exception as exc:
        delay = cfg.DKG_RETRY_INITIAL_SECONDS
        with retry_lock:
            previous = retry_delay.get(normalized_file_id, delay)
            delay = min(cfg.DKG_RETRY_MAX_SECONDS, max(delay, previous * 2))
            retry_delay[normalized_file_id] = delay
            retry_until[normalized_file_id] = time.monotonic() + delay
        log_state(
            ("dkg-chain-state-error", normalized_file_id),
            str(exc),
            f"[loop] could not read authoritative DKG deadline; preserving pending work: {exc}",
        )
        return False
    if requested_at <= 0 or chain_now > requested_at + dkg_deadline:
        with retry_lock:
            retry_delay[normalized_file_id] = cfg.DKG_COMPLETE_RECHECK_SECONDS
            retry_until[normalized_file_id] = (
                time.monotonic() + cfg.DKG_COMPLETE_RECHECK_SECONDS
            )
        log_state(
            ("dkg-expired", normalized_file_id, requested_at),
            (chain_now, dkg_deadline),
            f"[loop] DKG request expired on-chain for fileId={file_id_hex[:18]}...; "
            "Guardian work is paused pending settlement by the DO.",
        )
        return False

    active_n = int(policy_n)
    active_t = int(policy_t)
    my_dkg_index = int(dynamic_index)
    safe, unsafe_reason = policy_parameters_are_safe(active_n, active_t)
    if not safe:
        log_state(
            ("dkg-invalid-policy", file_id_hex), (active_n, active_t),
            f"[loop] refusing policy: {unsafe_reason}",
        )
        return False

    log_state(
        ("dkg-active-params", file_id_hex),
        (active_n, active_t, my_dkg_index),
        f"[loop] active_n={active_n}, active_t={active_t}, my_dkg_index={my_dkg_index}",
    )
    key_epoch = int(last_epoch) + 1 if exists else 1
    log_state(
        ("dkg-v2-active", file_id_hex, key_epoch, my_dkg_index), True,
        f"[loop] ZKDKG_V2 request detected for fileId={file_id_hex[:18]}..., "
        f"epoch={key_epoch}, shareIndex={my_dkg_index}",
    )
    before_progress = _v2_guardian_progress(
        coordinator_v2, file_id_bytes, key_epoch, my_dkg_index, active_n,
    )
    own_material_complete = (
        before_progress[0]
        and before_progress[1]
        and int(before_progress[2]) >= active_n
    )
    incoming_material_complete = int(before_progress[3]) >= active_n
    if bool(before_progress[4]):
        # This Guardian's complete contribution, encrypted shares, and public
        # share key are already on-chain. Only the DO can finalize now.
        with retry_lock:
            retry_delay[normalized_file_id] = cfg.DKG_COMPLETE_RECHECK_SECONDS
            retry_until[normalized_file_id] = (
                time.monotonic()
                + cfg.DKG_COMPLETE_RECHECK_SECONDS
                + random.uniform(0.0, 2.0)
            )
        log_state(
            ("dkg-wait-do-finalize", normalized_file_id, key_epoch, my_dkg_index),
            True,
            f"[loop] Guardian contribution complete for fileId={file_id_hex[:18]}...; "
            "waiting for DO finalization without repeating local work.",
        )
        return False
    if own_material_complete and not incoming_material_complete:
        # Nothing local can advance until other Guardians publish.  In
        # particular, do not recompute/rewrite the same final-share file.
        with retry_lock:
            previous = retry_delay.get(
                normalized_file_id, cfg.DKG_RETRY_INITIAL_SECONDS
            )
            delay = min(cfg.DKG_RETRY_MAX_SECONDS, previous * 2)
            retry_delay[normalized_file_id] = delay
            retry_until[normalized_file_id] = (
                time.monotonic() + delay + random.uniform(0.0, min(2.0, delay / 4))
            )
        log_state(
            ("dkg-wait-incoming", normalized_file_id, key_epoch, my_dkg_index),
            int(before_progress[3]),
            f"[loop] Guardian material complete; waiting for incoming shares "
            f"{int(before_progress[3])}/{active_n} without regenerating local work.",
        )
        return False
    process_zkdkg_v2_policy(
        w3, acl, sh_account, file_id_bytes, file_id_hex,
        key_epoch, my_dkg_index, active_n, active_t,
    )
    after_progress = _v2_guardian_progress(
        coordinator_v2, file_id_bytes, key_epoch, my_dkg_index, active_n,
    )
    made_progress = after_progress != before_progress
    if made_progress:
        claim_guardian_rewards_if_available(w3, sh_account, "claimRewards after V2 DKG work")
    with retry_lock:
        previous = retry_delay.get(
            normalized_file_id, cfg.DKG_RETRY_INITIAL_SECONDS
        )
        delay = (
            cfg.DKG_RETRY_INITIAL_SECONDS
            if made_progress
            else min(cfg.DKG_RETRY_MAX_SECONDS, previous * 2)
        )
        # Small jitter prevents all Guardians from polling the RPC in lockstep.
        retry_delay[normalized_file_id] = delay
        retry_until[normalized_file_id] = (
            time.monotonic() + delay + random.uniform(0.0, min(2.0, delay / 4))
        )
    return made_progress


def main() -> None:
    from core import g_lifecycle
    g_lifecycle.install()
    from core import g_txlog as TX
    TX.install(cfg)

    w3 = Web3(Web3.HTTPProvider(cfg.RPC_URL))
    connection_attempt = 0
    while not w3.is_connected():
        if g_lifecycle.STOP.is_set():
            return
        connection_attempt += 1
        delay = min(30, 2 ** min(connection_attempt, 5))
        log_state(
            ("dkg-rpc-startup-wait",),
            connection_attempt,
            f"[loop] blockchain RPC unavailable at startup; retrying in {delay}s",
        )
        time.sleep(delay)

    sh_account = w3.eth.account.from_key(cfg.SH_PRIVATE_KEY)
    if cfg.DKG_ATTEMPT_PROTOCOL == 1:
        from core.g_dkg_attempt_worker import run
        run(cfg, w3, sh_account)
        return
    print("Using Guardian account:", sh_account.address)
    print(f"GUARDIAN_INDEX={cfg.SH_INDEX}, IS_COORDINATOR={cfg.IS_COORDINATOR}")
    print(f"configured n={cfg.N_SHARES}, t={cfg.T_THRESHOLD}")

    acl = load_contract(w3, cfg.ACL_ADDRESS, str(cfg.resolve_artifact_path(cfg.ACL_JSON)))
    dkg = (
        load_contract(w3, cfg.DKG_ADDRESS, str(cfg.resolve_artifact_path(cfg.DKG_JSON)))
        if cfg.DKG_ADDRESS and cfg.DKG_JSON
        else None
    )
    guardian_registry = load_guardian_registry(w3)
    try:
        coordinator_v2_events = load_zkdkg_coordinator_v2(w3)
    except Exception:
        coordinator_v2_events = None

    service_prices = load_guardian_service_prices(cfg.GUARDIAN_SERVICE_PRICES, cfg.ROOT, cfg.SH_INDEX)
    print_guardian_service_prices(f"G {cfg.SH_INDEX}", service_prices)
    sync_guardian_service_pricing(
        w3=w3,
        guardian_registry=guardian_registry,
        account=sh_account,
        private_key=cfg.SH_PRIVATE_KEY,
        prices=service_prices,
        label=f"G {cfg.SH_INDEX}",
    )

    # Background reputation watcher
    try:
        rep_contract = load_reputation_manager(w3)
        if rep_contract is not None:
            def _rep_watcher():
                last_block = w3.eth.block_number
                while True:
                    try:
                        entries = poll_serious_penalties(rep_contract, from_block=last_block + 1)
                        for e in entries:
                            last_block = max(last_block, e.get("blockNumber", last_block))
                        time.sleep(60)
                    except Exception:
                        time.sleep(60)
            threading.Thread(target=_rep_watcher, daemon=True).start()
            print("ReputationManager watcher started")
    except Exception:
        pass

    print("Starting multi-DO fileId-based DKG watcher loop...")
    completed_v2_policy_skip_until: dict[str, float] = _load_completed_dkg_skips()
    completed_v2_policy_lock = threading.Lock()
    v2_retry_until: dict[str, float] = {}
    v2_retry_delay: dict[str, float] = {}
    v2_retry_lock = threading.Lock()
    idle_dkg_polls = 0
    next_full_dkg_scan_at = 0.0
    full_dkg_scan_seconds = max(60, cfg.POLL_INTERVAL * 12)
    next_dkg_event_check_at = 0.0
    fast_until = time.monotonic() + _FAST_STARTUP_SECONDS
    next_dispute_check_at = 0.0
    dispute_check_seconds = 60.0

    # Which legacy policy to service next. Kept across passes so a policy that
    # always fails cannot hold the same position forever.
    legacy_policy_cursor = 0

    while not g_lifecycle.STOP.is_set():
        try:
            now = time.monotonic()
            for fid, until in list(completed_v2_policy_skip_until.items()):
                if until <= now:
                    completed_v2_policy_skip_until.pop(fid, None)
            completed_v2_policy_skip = set(completed_v2_policy_skip_until)
            event_file_ids: tuple[bytes, ...] = tuple()
            if now >= next_dkg_event_check_at:
                event_file_ids = collect_dkg_event_file_ids(w3, acl, coordinator_v2_events)
                if event_file_ids:
                    fast_until = time.monotonic() + _FAST_STARTUP_SECONDS
                event_check_seconds = max(1, cfg.POLL_INTERVAL) if now < fast_until else max(_IDLE_EVENT_CHECK_SECONDS, cfg.POLL_INTERVAL)
                next_dkg_event_check_at = time.monotonic() + event_check_seconds
            full_dkg_scan_due = now >= next_full_dkg_scan_at

            if now >= next_dispute_check_at:
                process_zkdkg_disputes(w3, sh_account)
                next_dispute_check_at = time.monotonic() + dispute_check_seconds

            # V2 same-PK refresh takes priority — a Guardian can be part of an
            # active finalized policy and still have a pending refresh.
            did_v2_refresh = False
            if event_file_ids or full_dkg_scan_due:
                did_v2_refresh = process_pending_v2_same_pk_refresh(w3, acl, guardian_registry, sh_account)
            if did_v2_refresh:
                idle_dkg_polls = 0
                fast_until = time.monotonic() + _FAST_STARTUP_SECONDS
                claim_guardian_rewards_if_available(w3, sh_account, "claimRewards after V2 refresh")
                time.sleep(cfg.POLL_INTERVAL)
                continue

            candidate_policies = discover_file_policies(
                acl,
                sh_account.address,
                skip_file_ids=completed_v2_policy_skip,
                priority_file_ids=event_file_ids,
                allow_full_scan=full_dkg_scan_due,
                limit=_DKG_WORKERS,
            )
            if candidate_policies:
                v2_candidate_policies = []
                legacy_candidate_policies = []
                for candidate in candidate_policies:
                    try:
                        candidate_mode = int(
                            acl.functions.getFilePolicyMode(candidate[0]).call()
                        )
                    except Exception:
                        candidate_mode = 0
                    if candidate_mode == 1:
                        v2_candidate_policies.append(candidate)
                    else:
                        legacy_candidate_policies.append(candidate)
                worked_count = 0
                if v2_candidate_policies:
                    with ThreadPoolExecutor(
                        max_workers=min(_DKG_WORKERS, len(v2_candidate_policies))
                    ) as executor:
                        futures = [
                            executor.submit(
                                _process_v2_dkg_policy,
                                w3, acl, guardian_registry, sh_account, policy,
                                completed_v2_policy_skip_until, completed_v2_policy_lock,
                                v2_retry_until, v2_retry_delay, v2_retry_lock,
                            )
                            for policy in v2_candidate_policies
                        ]
                        for future in as_completed(futures):
                            try:
                                if future.result():
                                    worked_count += 1
                            except Exception as exc:
                                log_state(("dkg-worker-error",), str(exc), f"[loop] DKG worker error: {exc}")
                if legacy_candidate_policies:
                    # Rotated, not always the first: see select_next_policy.
                    _chosen, legacy_policy_cursor = select_next_policy(
                        legacy_candidate_policies, legacy_policy_cursor
                    )
                    (
                        file_id_bytes, file_id_hex, policy_owner, policy_t,
                        policy_n, dynamic_index, policy_guardians,
                    ) = _chosen
                else:
                    if worked_count > 0:
                        idle_dkg_polls = 0
                        fast_until = time.monotonic() + _FAST_STARTUP_SECONDS
                        next_full_dkg_scan_at = time.monotonic() + cfg.POLL_INTERVAL
                    else:
                        idle_dkg_polls += 1
                    # Every V2 candidate was handled by the V2 worker,
                    # including waiting/expired states. Never process it a
                    # second time in the legacy path.
                    time.sleep(max(1, cfg.POLL_INTERVAL))
                    continue
            else:
                (
                    file_id_bytes, file_id_hex, policy_owner, policy_t,
                    policy_n, dynamic_index, policy_guardians,
                ) = (None, None, None, None, None, None, None)

            if file_id_bytes is None:
                # V2 refresh was already checked at the top of this loop.
                did_refresh = False
                if (event_file_ids or full_dkg_scan_due) and dkg is not None:
                    did_refresh = process_pending_same_pk_refresh(w3, dkg, acl, guardian_registry, sh_account)

                # Catch-up: finalized V2 key where this Guardian's share public key is missing.
                # Happens when DKG finalization raced ahead before this Guardian could read
                # all incoming encrypted shares and publish its share key. The contract
                # allows publishing share keys even after finalization.
                try:
                    catch_up = None
                    if event_file_ids or full_dkg_scan_due:
                        coordinator_v2_cu = coordinator_v2_events or load_zkdkg_coordinator_v2(w3)
                        catch_up = find_finalized_v2_policy_with_missing_share(
                            acl, coordinator_v2_cu, sh_account.address,
                        )
                    if catch_up is not None:
                        cu_fid_bytes, cu_fid_hex, _, cu_t, cu_n, cu_index, _ = catch_up
                        cu_key = coordinator_v2_cu.functions.getV2Key(cu_fid_bytes).call()
                        cu_epoch = int(cu_key[5])
                        log_state(
                            ("dkg-v2-catchup", cu_fid_hex, cu_epoch, cu_index), True,
                            f"[loop] catch-up: V2 key finalized but share public key missing — "
                            f"fileId={cu_fid_hex[:18]}..., epoch={cu_epoch}, shareIndex={cu_index}",
                        )
                        process_zkdkg_v2_policy(
                            w3, acl, sh_account,
                            cu_fid_bytes, cu_fid_hex,
                            cu_epoch, cu_index, cu_n, cu_t,
                        )
                        claim_guardian_rewards_if_available(w3, sh_account, "claimRewards after V2 DKG catch-up")
                        did_refresh = True
                except Exception as cu_err:
                    log_state(
                        ("dkg-v2-catchup-error",), str(cu_err),
                        f"[loop] V2 catch-up error: {cu_err}",
                    )

                if not did_refresh:
                    log_every(
                        ("dkg-idle", cfg.SH_INDEX),
                        "[loop] no active fresh DKG or same-PK refresh found for this Guardian",
                        seconds=300,
                    )
                    idle_dkg_polls += 1
                    if full_dkg_scan_due:
                        next_full_dkg_scan_at = time.monotonic() + full_dkg_scan_seconds
                else:
                    idle_dkg_polls = 0
                    fast_until = time.monotonic() + _FAST_STARTUP_SECONDS
                    next_full_dkg_scan_at = time.monotonic() + cfg.POLL_INTERVAL
                idle_sleep = min(max(cfg.POLL_INTERVAL, 1) * min(max(idle_dkg_polls, 1), 3), 30)
                time.sleep(idle_sleep)
                continue

            idle_dkg_polls = 0
            fast_until = time.monotonic() + _FAST_STARTUP_SECONDS
            next_full_dkg_scan_at = time.monotonic() + cfg.POLL_INTERVAL
            policy_owner_checksum = Web3.to_checksum_address(policy_owner)
            is_do = acl.functions.isFileDataOwner(file_id_bytes, policy_owner_checksum).call()
            is_guardian = acl.functions.isGuardianForFile(file_id_bytes, sh_account.address).call()
            has_req = acl.functions.hasRequestedKeyGenForFile(file_id_bytes).call()
            try:
                policy_mode = int(acl.functions.getFilePolicyMode(file_id_bytes).call())
            except Exception:
                policy_mode = 0

            if policy_mode == 1:
                try:
                    coordinator_v2 = load_zkdkg_coordinator_v2(w3)
                    key = coordinator_v2.functions.getV2Key(file_id_bytes).call()
                    exists = bool(key[0])
                    finalized = bool(key[1])
                    last_epoch = int(key[5]) if exists else 0
                except Exception:
                    exists = False
                    finalized = False
                    last_epoch = 0
            else:
                if dkg is None:
                    log_state(
                        ("dkg-legacy-disabled", file_id_hex), True,
                        "[loop] non-V2 policy ignored because active Guardian runtime is ZKDKG_V2-only",
                    )
                    time.sleep(cfg.POLL_INTERVAL)
                    continue
                finalized = False
                exists, _, _, _, _, _, last_epoch = dkg.functions.getKeyForFile(file_id_bytes).call()

            log_state(
                ("dkg-loop-policy", file_id_hex),
                (policy_owner_checksum, bool(is_do), bool(is_guardian), bool(has_req), bool(exists), bool(finalized), int(last_epoch)),
                f"[loop] fileId={file_id_hex[:18]}..., owner={policy_owner_checksum}, "
                f"isFileDO={is_do}, isGuardian={is_guardian}, "
                f"hasRequestedKeyGen={has_req}, keyExists={exists}, keyFinalized={finalized}, lastEpoch={last_epoch}",
            )

            # V2 post-finalization: publish share public key if missing.
            if policy_mode == 1 and is_do and is_guardian and exists and finalized and int(last_epoch) > 0:
                active_n = int(policy_n)
                active_t = int(policy_t)
                my_dkg_index = int(dynamic_index)
                safe, unsafe_reason = policy_parameters_are_safe(active_n, active_t)
                if not safe:
                    log_state(
                        ("dkg-invalid-policy", file_id_hex), (active_n, active_t),
                        f"[loop] refusing finalized policy: {unsafe_reason}",
                    )
                    time.sleep(cfg.POLL_INTERVAL)
                    continue
                try:
                    _key_exists, _key_finalized, _data_owner, _stored_t, _stored_n, _key_epoch, active_share_version, _pkx0, _pky0 = coordinator_v2.functions.getV2Key(file_id_bytes).call()
                    pk_exists, _pkx, _pky = coordinator_v2.functions.getV2SharePublicKey(
                        file_id_bytes, int(last_epoch), int(active_share_version), my_dkg_index,
                    ).call()
                except Exception:
                    active_share_version = 1
                    pk_exists = False

                if not pk_exists:
                    log_state(
                        ("dkg-v2-post-finalize", file_id_hex, int(last_epoch), int(active_share_version), my_dkg_index), True,
                        f"[loop] ZKDKG_V2 key finalized for fileId={file_id_hex[:18]}..., "
                        f"activeShareVersion={int(active_share_version)}, "
                        f"publishing share public key for shareIndex={my_dkg_index}",
                    )
                    if int(active_share_version) > 1:
                        process_pending_v2_same_pk_refresh(w3, acl, guardian_registry, sh_account)
                    else:
                        process_zkdkg_v2_policy(
                            w3, acl, sh_account, file_id_bytes, file_id_hex,
                            int(last_epoch), my_dkg_index, active_n, active_t,
                        )
                    claim_guardian_rewards_if_available(w3, sh_account, "claimRewards after V2 share key")
                else:
                    normalized_done_file_id = normalize_file_id_hex(file_id_hex)
                    completed_v2_policy_skip_until[normalized_done_file_id] = (
                        time.monotonic() + _COMPLETED_DKG_STATE_SECONDS
                    )
                    _remember_completed_dkg(normalized_done_file_id)
                time.sleep(cfg.POLL_INTERVAL)
                continue

            if not (is_do and is_guardian and has_req):
                time.sleep(cfg.POLL_INTERVAL)
                continue

            active_n = int(policy_n)
            active_t = int(policy_t)
            my_dkg_index = int(dynamic_index)

            safe, unsafe_reason = policy_parameters_are_safe(active_n, active_t)
            if not safe:
                log_state(
                    ("dkg-invalid-policy", file_id_hex), (active_n, active_t),
                    f"[loop] refusing policy: {unsafe_reason}",
                )
                time.sleep(cfg.POLL_INTERVAL)
                continue

            log_state(
                ("dkg-active-params", file_id_hex),
                (active_n, active_t, my_dkg_index),
                f"[loop] active_n={active_n}, active_t={active_t}, my_dkg_index={my_dkg_index}",
            )

            key_epoch = int(last_epoch) + 1 if exists else 1

            # V2 fresh DKG
            if policy_mode == 1:
                log_state(
                    ("dkg-v2-active", file_id_hex, key_epoch, my_dkg_index), True,
                    f"[loop] ZKDKG_V2 request detected for fileId={file_id_hex[:18]}..., "
                    f"epoch={key_epoch}, shareIndex={my_dkg_index}",
                )
                process_zkdkg_v2_policy(
                    w3, acl, sh_account, file_id_bytes, file_id_hex,
                    key_epoch, my_dkg_index, active_n, active_t,
                )
                claim_guardian_rewards_if_available(w3, sh_account, "claimRewards after V2 DKG work")
                time.sleep(cfg.POLL_INTERVAL)
                continue

            # Legacy secp256k1 DKG
            base_prefix_root = make_base_prefix(file_id_hex, active_n, active_t)
            base_prefix = f"{base_prefix_root}_k{key_epoch}"
            final_share = cfg.ROOT / f"{base_prefix}_final_share_{my_dkg_index}.json"

            if not final_share.exists():
                print(
                    f">> DKG request detected for fileId={file_id_hex}. "
                    f"Guardian {sh_account.address} using dynamic DKG index {my_dkg_index}..."
                )
                material_path = fresh_dkg_material_path(file_id_hex, key_epoch, active_n, active_t, my_dkg_index)

                if not material_path.exists() and any_fresh_dkg_material_onchain(
                    dkg, file_id_bytes, key_epoch, my_dkg_index, active_n,
                ):
                    print(
                        f"  -> SAFETY STOP: SH {my_dkg_index} already has partial fresh DKG material "
                        f"on-chain for epoch={key_epoch}, but local saved dealer material is missing. "
                        f"Refusing to regenerate random DKG material."
                    )
                    time.sleep(cfg.POLL_INTERVAL)
                    continue

                commitments_i, shares_row = load_or_create_fresh_dkg_material(
                    file_id_hex, key_epoch, active_n, active_t, my_dkg_index,
                )
                print(
                    f"  -> SH {my_dkg_index}: ready with polynomial degree={active_t - 1}, "
                    f"{len(commitments_i)} commitment(s), and {len(shares_row)} outgoing share(s)."
                )

                write_local_commitments_file(base_prefix, my_dkg_index, active_n, active_t, commitments_i)

                ok_commit = upload_guardian_commitments(
                    w3, dkg, sh_account, file_id_bytes, policy_owner_checksum,
                    key_epoch, my_dkg_index, commitments_i,
                )
                if not ok_commit:
                    print("  -> Failed to publish Guardian commitments on-chain. Retrying later.")
                    time.sleep(cfg.POLL_INTERVAL)
                    continue

                ok_enc_shares = upload_encrypted_dkg_shares(
                    w3, dkg, guardian_registry, sh_account, file_id_bytes,
                    policy_owner_checksum, key_epoch, my_dkg_index, policy_guardians, shares_row,
                )
                if not ok_enc_shares:
                    print("  -> Failed to publish encrypted DKG shares on-chain. Retrying later.")
                    time.sleep(cfg.POLL_INTERVAL)
                    continue

                write_outgoing_shares_files(base_prefix, my_dkg_index, shares_row)

                sk_j, vk_j = compute_local_share_from_onchain(
                    dkg, sh_account, file_id_bytes, key_epoch, my_dkg_index, active_n, active_t,
                )
                write_final_share_json(base_prefix, my_dkg_index, active_n, active_t, sk_j, vk_j)

                if not publish_share_public_key(
                    w3, dkg, sh_account, file_id_bytes, policy_owner_checksum,
                    key_epoch, 1, my_dkg_index, vk_j,
                ):
                    print("  -> Failed to publish verifiable DKG share public key. Retrying later.")
                    continue
                claim_guardian_rewards_if_available(w3, sh_account, "claimRewards after DKG share key")
            else:
                log_state(
                    ("dkg-final-share-exists", file_id_hex, key_epoch, my_dkg_index), str(final_share),
                    f"[loop] final share already exists for epoch={key_epoch}: {final_share}",
                )
                try:
                    existing_share = read_secret_json(final_share)
                    vk_j_existing = (int(existing_share["vkx"]), int(existing_share["vky"]))
                    if not publish_share_public_key(
                        w3, dkg, sh_account, file_id_bytes, policy_owner_checksum,
                        key_epoch, 1, my_dkg_index, vk_j_existing,
                    ):
                        continue
                    claim_guardian_rewards_if_available(w3, sh_account, "claimRewards after existing DKG share key")
                except Exception as e:
                    print(f"  -> Could not publish existing share public key: {e}")
                    continue

            write_epoch_metadata_json(file_id_hex, key_epoch, active_n, active_t, policy_guardians)

            log_state(
                ("dkg-material-ready", file_id_hex, key_epoch, my_dkg_index), True,
                f"[loop] Guardian DKG material ready for fileId={file_id_hex}, "
                f"epoch={key_epoch}. Waiting for DKG.sol auto-finalization.",
            )

            process_pending_same_pk_refresh(w3, dkg, acl, guardian_registry, sh_account)
            process_zkdkg_disputes(w3, sh_account)

        except KeyboardInterrupt:
            print("Interrupted by user. Exiting.")
            break
        except Exception as e:
            log_state(("dkg-loop-error",), str(e), f"Error in loop: {e}")

        time.sleep(cfg.POLL_INTERVAL)


if __name__ == "__main__":
    main()
