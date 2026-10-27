#!/usr/bin/env python3
"""Guardian PRE (Proxy Re-Encryption) protocol loop.

Watches for DataVault access requests and submits PRE partial decryptions.
Supports both the legacy secp256k1 TElG v1 protocol and the ZKDKG_V2 Baby
Jubjub batch-PRE protocol.

Run from the instance root:
    python core/g_pre.py
or spawned by start.py as a subprocess.
"""
from __future__ import annotations


import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.g_secret_files import read_secret_json

from web3 import Web3

import core.g_config as cfg
from core.g_chain import (
    build_job_from_chain,
    claim_guardian_rewards_if_available,
    claim_pre_ready_not_used_onchain,
    collect_pre_event_request_ids,
    declare_pre_ready_for_request_onchain,
    count_onchain_pre_partials,
    count_onchain_v2_partials,
    get_epoch_guardian_index,
    has_v2_partial_for,
    load_contract,
    load_guardian_registry,
    load_reputation_manager,
    build_pre_ready_hash,
    load_local_share_for_epoch,
    load_v2_share_for_epoch,
    poll_serious_penalties,
    publish_v2_share_public_key_onchain,
    read_pre_ready_signal,
    signal_pre_ready_onchain,
    submit_partial_onchain,
    submit_v2_batch_partial_onchain,
)
from core.g_crypto import (
    BABY_G,
    baby_add,
    baby_is_on_curve,
    baby_mul,
    baby_rand_scalar,
    is_on_curve,
    make_pre_dleq_proof,
    v2_batch_context_hash,
)
from core.g_log import log_every, log_state, preview_list
from core.g_material import _write_json_atomic, normalize_file_id_hex
from core.g_pricing import (
    load_guardian_service_prices,
    print_guardian_service_prices,
    sync_guardian_service_pricing,
)
from core.g_zk import (
    generate_v2_pre_proof,
    resolve_zokrates_bin,
    v2_proof_struct,
    zokrates_available,
    zokrates_missing_message,
)


_ZOKRATES_BIN_CFG = cfg.ZOKRATES_BIN
_PRE_JOB_CACHE_SECONDS = 120.0
_PRE_DONE_BACKOFF_SECONDS = 300.0
_PRE_SHORT_BACKOFF_SECONDS = 60.0
_MAX_COMPLETED_PRE_RECORDS = 100_000
_PRE_BUILD_WORKERS = 3
_FAST_STARTUP_SECONDS = 120.0
_IDLE_EVENT_CHECK_SECONDS = 30.0


def _current_zokrates_bin() -> str:
    return resolve_zokrates_bin(_ZOKRATES_BIN_CFG)


def _short_addr(addr: str) -> str:
    addr = str(addr)
    if len(addr) <= 12:
        return addr
    return addr[:6] + "..." + addr[-4:]


def _pre_backoff_seconds(multiplier: int = 12) -> float:
    return max(_PRE_SHORT_BACKOFF_SECONDS, float(cfg.POLL_INTERVAL * multiplier))


def _completed_pre_state_path() -> Path:
    return cfg.ROOT / "state" / "completed_pre.json"


def _load_completed_pre_skips() -> dict[int, float]:
    path = _completed_pre_state_path()
    try:
        raw = read_secret_json(path)
    except Exception:
        return {}
    out: dict[int, float] = {}
    for request_id, seen_at in dict(raw).items():
        try:
            float(seen_at)
            rid = int(request_id)
        except Exception:
            continue
        if rid >= 0:
            out[rid] = float("inf")
    return out


def _remember_completed_pre(request_id: int) -> None:
    path = _completed_pre_state_path()
    try:
        raw = read_secret_json(path)
    except Exception:
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    now_wall = time.time()
    valid = [
        (str(int(rid)), float(ts))
        for rid, ts in raw.items()
        if str(rid).isdigit() and isinstance(ts, (int, float))
    ]
    valid.sort(key=lambda item: item[1], reverse=True)
    compact = dict(valid[:_MAX_COMPLETED_PRE_RECORDS - 1])
    compact[str(int(request_id))] = now_wall
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_json_atomic(path, compact)


def _mark_pre_completed(skip_until: dict[int, float], request_id: int) -> None:
    rid = int(request_id)
    skip_until[rid] = float("inf")
    _remember_completed_pre(rid)


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
            ("pre-rpc-startup-wait",),
            connection_attempt,
            f"[PRE G {cfg.SH_INDEX}] blockchain RPC unavailable at startup; "
            f"retrying in {delay}s",
        )
        time.sleep(delay)

    sh_acct = w3.eth.account.from_key(cfg.SH_PRIVATE_KEY)
    acl = load_contract(w3, cfg.ACL_ADDRESS, str(cfg.resolve_artifact_path(cfg.ACL_JSON)))
    dv = load_contract(w3, cfg.DV_ADDRESS, str(cfg.resolve_artifact_path(cfg.DV_JSON)))
    telg = (
        load_contract(w3, cfg.TELG_ADDRESS, str(cfg.resolve_artifact_path(cfg.TELG_JSON)))
        if cfg.TELG_ADDRESS and cfg.TELG_JSON else None
    )
    dkg = (
        load_contract(w3, cfg.DKG_ADDRESS, str(cfg.resolve_artifact_path(cfg.DKG_JSON)))
        if cfg.DKG_ADDRESS and cfg.DKG_JSON else None
    )
    telg_v2 = (
        load_contract(w3, cfg.TELG_V2_ADDRESS, str(cfg.resolve_artifact_path(cfg.TELG_V2_JSON)))
        if cfg.TELG_V2_ADDRESS and cfg.TELG_V2_JSON else None
    )
    coordinator_v2 = (
        load_contract(w3, cfg.ZKDKG_COORDINATOR_V2_ADDRESS, str(cfg.resolve_artifact_path(cfg.ZKDKG_COORDINATOR_V2_JSON)))
        if cfg.ZKDKG_COORDINATOR_V2_ADDRESS and cfg.ZKDKG_COORDINATOR_V2_JSON else None
    )

    guardian_registry = None
    gr_address = cfg.GUARDIAN_REGISTRY_ADDRESS
    gr_json = cfg.GUARDIAN_REGISTRY_JSON
    if gr_address and gr_json:
        try:
            guardian_registry = load_contract(w3, gr_address, str(cfg.resolve_artifact_path(gr_json)))
        except Exception:
            pass

    service_prices = load_guardian_service_prices(cfg.GUARDIAN_SERVICE_PRICES, cfg.ROOT, cfg.SH_INDEX)
    print_guardian_service_prices(f"G {cfg.SH_INDEX}", service_prices)
    sync_guardian_service_pricing(
        w3=w3, guardian_registry=guardian_registry, account=sh_acct,
        private_key=cfg.SH_PRIVATE_KEY, prices=service_prices, label=f"G {cfg.SH_INDEX}",
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

    print("PRE-G node using account:", _short_addr(sh_acct.address))
    print(f"GUARDIAN_INDEX={cfg.SH_INDEX}")
    pre_job_skip_until: dict[int, float] = _load_completed_pre_skips()
    pre_job_cache: dict[int, tuple[float, dict]] = {}
    next_full_pre_scan_at = 0.0
    full_pre_scan_seconds = max(60, cfg.POLL_INTERVAL * 12)
    next_pre_event_check_at = 0.0
    fast_until = time.monotonic() + _FAST_STARTUP_SECONDS

    while not g_lifecycle.STOP.is_set():
        try:
            now = time.monotonic()
            for cached_job_id, until in list(pre_job_skip_until.items()):
                if until <= now:
                    pre_job_skip_until.pop(cached_job_id, None)
            for cached_job_id, (until, _) in list(pre_job_cache.items()):
                if until <= now:
                    pre_job_cache.pop(cached_job_id, None)

            event_job_ids: tuple[int, ...] = tuple()
            if now >= next_pre_event_check_at:
                event_job_ids = collect_pre_event_request_ids(w3, dv, telg_v2)
                if event_job_ids:
                    fast_until = time.monotonic() + _FAST_STARTUP_SECONDS
                event_check_seconds = max(1, cfg.POLL_INTERVAL) if now < fast_until else max(_IDLE_EVENT_CHECK_SECONDS, cfg.POLL_INTERVAL)
                next_pre_event_check_at = time.monotonic() + event_check_seconds
            full_pre_scan_due = now >= next_full_pre_scan_at
            if full_pre_scan_due:
                next_req_id = int(dv.functions.nextAccessRequestId().call())
                jobs = list(range(next_req_id))
                next_full_pre_scan_at = time.monotonic() + full_pre_scan_seconds
            else:
                jobs = sorted(set(int(job_id) for job_id in event_job_ids))

            if full_pre_scan_due and not jobs:
                log_every(
                    ("pre-idle",),
                    f"[PRE G {cfg.SH_INDEX}] watching DataVault: no access requests yet.",
                    seconds=300,
                )

            build_job_ids = [
                int(job_id) for job_id in jobs
                if pre_job_skip_until.get(int(job_id), 0.0) <= now
                and not (pre_job_cache.get(int(job_id)) is not None and pre_job_cache[int(job_id)][0] > now)
            ]
            if len(build_job_ids) > 1:
                worker_count = min(_PRE_BUILD_WORKERS, len(build_job_ids))
                with ThreadPoolExecutor(max_workers=worker_count) as executor:
                    futures = {
                        executor.submit(build_job_from_chain, job_id, dv, acl, dkg, coordinator_v2): job_id
                        for job_id in build_job_ids
                    }
                    for future in as_completed(futures):
                        job_id = futures[future]
                        try:
                            job = future.result()
                        except Exception as exc:
                            log_state(("pre-build-job-error", job_id), str(exc), f"[PRE G {cfg.SH_INDEX}] PRE job {job_id}: build failed: {exc}")
                            continue
                        if job is not None:
                            pre_job_cache[int(job_id)] = (time.monotonic() + _PRE_JOB_CACHE_SECONDS, job)

            for job_id in jobs:
                if pre_job_skip_until.get(int(job_id), 0.0) > now:
                    continue
                fast_until = time.monotonic() + _FAST_STARTUP_SECONDS
                cached = pre_job_cache.get(int(job_id))
                if cached is not None and cached[0] > now:
                    job = cached[1]
                else:
                    job = build_job_from_chain(job_id, dv, acl, dkg, coordinator_v2)
                    if job is not None:
                        pre_job_cache[int(job_id)] = (time.monotonic() + _PRE_JOB_CACHE_SECONDS, job)
                if job is None:
                    continue

                file_id_hex = normalize_file_id_hex(job.get("fileId", cfg.CONFIG_FILE_ID))
                file_id_bytes = Web3.to_bytes(hexstr=file_id_hex)

                if not acl.functions.isGuardianForFile(file_id_bytes, sh_acct.address).call():
                    log_state(
                        ("pre-skip", job_id, "not-selected"), file_id_hex,
                        f"[PRE G {cfg.SH_INDEX}] skip job {job_id}: not selected Guardian for fileId={file_id_hex}",
                    )
                    continue

                key_epoch = int(job.get("keyEpoch", 1))

                try:
                    (req_exists, req_file_id, requester, batch_id, data_id_req, ts_req,
                     req_key_epoch, pk_req_x, pk_req_y, indices_req,
                     ) = dv.functions.getAccessRequest(job_id).call()
                    if not req_exists:
                        log_state(("pre-skip", job_id, "missing-request"), True, f"[PRE G {cfg.SH_INDEX}] skip job {job_id}: access request does not exist")
                        continue
                    if normalize_file_id_hex(req_file_id) != file_id_hex:
                        log_state(("pre-skip", job_id, "fileid-mismatch"), file_id_hex, f"[PRE G {cfg.SH_INDEX}] skip job {job_id}: fileId mismatch")
                        continue
                    if int(req_key_epoch) != key_epoch:
                        log_state(("pre-skip", job_id, "keyepoch-mismatch"), (int(req_key_epoch), key_epoch), f"[PRE G {cfg.SH_INDEX}] skip job {job_id}: keyEpoch mismatch")
                        continue
                    try:
                        req_share_version = int(dv.functions.getAccessRequestShareVersion(int(job_id)).call())
                        if req_share_version > 0 and req_share_version != int(job.get("shareVersion", 1)):
                            log_state(
                                ("pre-skip", job_id, "shareversion-mismatch"),
                                (req_share_version, int(job.get("shareVersion", 1))),
                                f"[PRE G {cfg.SH_INDEX}] skip job {job_id}: shareVersion mismatch",
                            )
                            continue
                    except Exception:
                        pass
                    if not acl.functions.isRequesterForFile(file_id_bytes, requester).call():
                        log_state(("pre-skip", job_id, "requester-not-allowed"), requester, f"[PRE G {cfg.SH_INDEX}] skip job {job_id}: requester not allowed for file")
                        continue
                    if not acl.functions.hasRequestedReenc(requester).call():
                        log_state(("pre-skip", job_id, "no-reenc-request"), requester, f"[PRE G {cfg.SH_INDEX}] skip job {job_id}: requester has no reenc request")
                        continue
                except Exception as e:
                    log_state(("pre-skip", job_id, "acl-check-failed"), str(e), f"[PRE G {cfg.SH_INDEX}] skip job {job_id}: request ACL check failed: {e}")
                    continue

                share_version = int(job.get("shareVersion", 1))
                epoch_index = get_epoch_guardian_index(job, sh_acct.address)
                if epoch_index is None:
                    log_state(("pre-skip", job_id, "not-in-shareversion"), share_version, f"[PRE G {cfg.SH_INDEX}] skip job {job_id}: not part of active shareVersion")
                    continue

                allowed_indices = set(int(x) for x in job.get("allowedEpochIndices", []))
                if epoch_index not in allowed_indices:
                    log_state(("pre-skip", job_id, "epoch-index-not-allowed"), (epoch_index, tuple(sorted(allowed_indices))), f"[PRE G {cfg.SH_INDEX}] skip job {job_id}: epoch index {epoch_index} not allowed now")
                    continue

                dkg_n = int(job["dkgN"])
                dkg_t = int(job["dkgT"])

                # ---- ZKDKG_V2 Baby Jubjub batch PRE ----
                if job.get("dkgMode") == "ZKDKG_V2":
                    if telg_v2 is None or coordinator_v2 is None:
                        log_state(
                            ("pre-v2-skip", job_id, "missing-contracts"), True,
                            f"[PRE G {cfg.SH_INDEX}] skip V2 job {job_id}: TElGv2 or ZkDkgCoordinatorV2 is not configured",
                        )
                        continue

                    submitted_count = count_onchain_v2_partials(telg_v2, int(job_id))
                    if has_v2_partial_for(telg_v2, int(job_id), sh_acct.address):
                        log_state(("pre-v2-skip", job_id, "already-submitted-self"), sh_acct.address, f"[PRE G {cfg.SH_INDEX}] skip V2 job {job_id}: already submitted by this Guardian")
                        _mark_pre_completed(pre_job_skip_until, int(job_id))
                        continue
                    if submitted_count >= dkg_t:
                        log_state(
                            ("pre-v2-skip", job_id, "enough-partials"), (submitted_count, dkg_t),
                            f"[PRE G {cfg.SH_INDEX}] skip V2 job {job_id}: already enough V2 partials ({submitted_count}/{dkg_t}), declaring readiness",
                        )
                        declare_outcome = declare_pre_ready_for_request_onchain(w3, telg_v2, sh_acct, job_id)
                        if declare_outcome == "submitted":
                            print(f"[PRE G {cfg.SH_INDEX}] V2 job {job_id}: readiness declared on-chain (threshold already met)")
                        if declare_outcome in {"submitted", "complete"}:
                            _mark_pre_completed(pre_job_skip_until, int(job_id))
                        else:
                            pre_job_skip_until[int(job_id)] = time.monotonic() + _pre_backoff_seconds()
                        continue

                    try:
                        share_index, sk = load_v2_share_for_epoch(key_epoch, file_id_hex, dkg_n, dkg_t, epoch_index, share_version)
                    except FileNotFoundError as e:
                        log_state(("pre-v2-skip", job_id, "missing-share-file"), str(e), f"[PRE G {cfg.SH_INDEX}] skip V2 job {job_id}: {e}")
                        continue

                    try:
                        expected_share_public_key = baby_mul(int(sk))
                        pk_exists, share_pk_x, share_pk_y = coordinator_v2.functions.getV2SharePublicKey(
                            Web3.to_bytes(hexstr=normalize_file_id_hex(file_id_hex)),
                            int(key_epoch), int(share_version), int(share_index),
                        ).call()
                        if not pk_exists:
                            print(f"[PRE G {cfg.SH_INDEX}] V2 share public key missing for shareIndex={share_index}; publishing from local finalized share")
                            if not publish_v2_share_public_key_onchain(
                                w3, coordinator_v2, sh_acct,
                                Web3.to_bytes(hexstr=normalize_file_id_hex(file_id_hex)),
                                int(key_epoch), int(share_index), expected_share_public_key,
                            ):
                                raise RuntimeError("V2 share public key not published")
                            pk_exists, share_pk_x, share_pk_y = coordinator_v2.functions.getV2SharePublicKey(
                                Web3.to_bytes(hexstr=normalize_file_id_hex(file_id_hex)),
                                int(key_epoch), int(share_version), int(share_index),
                            ).call()
                            if not pk_exists:
                                raise RuntimeError("V2 share public key still not published after publish tx")
                        share_public_key = (int(share_pk_x), int(share_pk_y))
                        if share_public_key != expected_share_public_key:
                            raise RuntimeError("local V2 share does not match on-chain share public key")
                    except Exception as e:
                        log_state(
                            ("pre-v2-skip", job_id, "missing-share-pk"), str(e),
                            f"[PRE G {cfg.SH_INDEX}] skip V2 job {job_id}: missing verifiable V2 share public key: {e}",
                        )
                        continue

                    batch_id = int(job.get("batchId", 0))
                    try:
                        batch_c1_exists, batch_c1x, batch_c1y = dv.functions.getV2BatchC1(int(batch_id)).call()
                    except Exception as e:
                        log_state(
                            ("pre-v2-batch-c1-error", int(job_id), int(batch_id)), str(e),
                            f"[PRE G {cfg.SH_INDEX}] getV2BatchC1 failed for batchId={batch_id}: {e}",
                        )
                        batch_c1_exists, batch_c1x, batch_c1y = False, 0, 0

                    if not batch_c1_exists:
                        log_state(
                            ("pre-v2-batch-c1-missing", int(job_id), int(batch_id)), False,
                            f"[PRE G {cfg.SH_INDEX}] V2 job {job_id}: batch C1 not found for batchId={batch_id}; waiting for DO setV2BatchC1",
                        )
                        continue

                    batch_c1 = (int(batch_c1x), int(batch_c1y))
                    log_state(
                        ("pre-v2-batch-c1-found", int(job_id), int(batch_id)), batch_c1,
                        f"[PRE G {cfg.SH_INDEX}] V2 job {job_id}: using batchId={batch_id} "
                        f"batch C1=({str(batch_c1[0])[:12]}..., {str(batch_c1[1])[:12]}...)",
                    )
                    if not baby_is_on_curve(batch_c1):
                        print(f"[PRE G {cfg.SH_INDEX}] V2 job {job_id}: batch C1 not on Baby Jubjub")
                        continue

                    # Validate requester's Baby Jubjub public key from access request.
                    pk_req = (int(pk_req_x), int(pk_req_y))
                    if not baby_is_on_curve(pk_req):
                        print(f"[PRE G {cfg.SH_INDEX}] V2 job {job_id}: pkReq is not on Baby Jubjub curve; skipping")
                        continue

                    # D = sk_i * C1  (partial decryption — kept private, never submitted).
                    d_point = baby_mul(int(sk), batch_c1)
                    if d_point is None:
                        print(f"[PRE G {cfg.SH_INDEX}] V2 job {job_id}: batch partial is infinity")
                        continue

                    # El-Gamal encrypt D with requester's public key so only REQ can read it.
                    #   E1 = r * G
                    #   E2 = D + r * pkReq
                    # Anyone on-chain sees (E1, E2) but cannot recover D without sk_req.
                    r_scalar = baby_rand_scalar()
                    E1 = baby_mul(r_scalar, BABY_G)
                    E2 = baby_add(d_point, baby_mul(r_scalar, pk_req))
                    if E1 is None or E2 is None:
                        print(f"[PRE G {cfg.SH_INDEX}] V2 job {job_id}: El-Gamal encryption produced infinity")
                        continue

                    context_hash = v2_batch_context_hash(
                        int(job_id), int(batch_id),
                        Web3.to_bytes(hexstr=normalize_file_id_hex(file_id_hex)),
                        int(key_epoch), int(share_version), int(share_index),
                        batch_c1, share_public_key, E1, E2, pk_req,
                    )
                    zokrates_bin = _current_zokrates_bin()
                    if not zokrates_available(zokrates_bin):
                        log_every(
                            ("pre-v2-zokrates-missing", int(job_id)),
                            f"[PRE G {cfg.SH_INDEX}] V2 job {job_id}: cannot generate batch PRE proof. "
                            f"{zokrates_missing_message(_ZOKRATES_BIN_CFG)}",
                            seconds=60,
                        )
                        continue
                    try:
                        proof_json = generate_v2_pre_proof(
                            cfg.ZK_V2_PRE_BUILD_DIR, int(sk), r_scalar, share_public_key,
                            batch_c1, E1, E2, pk_req, context_hash, zokrates_bin,
                        )
                    except Exception as e:
                        log_every(
                            ("pre-v2-proof-error", int(job_id), str(e)),
                            f"[PRE G {cfg.SH_INDEX}] V2 job {job_id}: batch proof generation failed: {e}",
                            seconds=60,
                        )
                        continue

                    submit_outcome = submit_v2_batch_partial_onchain(
                        w3, telg_v2, sh_acct, job_id, share_index, E1, E2, v2_proof_struct(proof_json),
                    )
                    if submit_outcome == "submitted":
                        print(f"[PRE G {cfg.SH_INDEX}] V2 job {job_id}: proof-backed batch partial stored on-chain")
                        claim_guardian_rewards_if_available(w3, sh_acct, f"claimRewards after V2 PRE job {job_id}")
                        _mark_pre_completed(pre_job_skip_until, int(job_id))
                    elif submit_outcome == "complete":
                        _mark_pre_completed(pre_job_skip_until, int(job_id))
                    else:
                        print(f"[PRE G {cfg.SH_INDEX}] V2 job {job_id}: V2 batch partial not stored in this cycle")
                        pre_job_skip_until[int(job_id)] = time.monotonic() + _pre_backoff_seconds()
                    continue

                # ---- Legacy secp256k1 TElG v1 PRE ----
                if telg is None:
                    log_state(
                        ("pre-legacy-disabled", int(job_id)), True,
                        f"[PRE G {cfg.SH_INDEX}] skip non-V2 job {job_id}: active PRE runtime is TElGv2-only",
                    )
                    continue

                known_guardians = list(job.get("epochGuardians", [])) + list(job.get("currentGuardians", []))
                submitted_count = count_onchain_pre_partials(telg, int(job_id), known_guardians)

                try:
                    if telg.functions.hasPrePartial(int(job_id), sh_acct.address).call():
                        log_state(("pre-skip", job_id, "already-submitted-self"), sh_acct.address, f"[PRE G {cfg.SH_INDEX}] skip job {job_id}: already submitted by this Guardian")
                        _mark_pre_completed(pre_job_skip_until, int(job_id))
                        continue
                except Exception as e:
                    log_state(("pre-error", job_id, "hasPrePartial"), str(e), f"[PRE G {cfg.SH_INDEX}] hasPrePartial check failed for job {job_id}: {e}")
                    continue

                ready_state = read_pre_ready_signal(telg, int(job_id), sh_acct.address)

                if submitted_count >= dkg_t:
                    ok_credit = claim_pre_ready_not_used_onchain(w3, telg, sh_acct, job_id)
                    if ok_credit:
                        print(f"[PRE G {cfg.SH_INDEX}] job {job_id}: ready-but-not-used PRE reputation credit recorded")
                        claim_guardian_rewards_if_available(w3, sh_acct, f"claimRewards after PRE ready credit {job_id}")
                    _mark_pre_completed(pre_job_skip_until, int(job_id))
                    log_state(
                        ("pre-skip", job_id, "enough-partials"), (submitted_count, dkg_t),
                        f"[PRE G {cfg.SH_INDEX}] skip job {job_id}: already enough PRE partials ({submitted_count}/{dkg_t})",
                    )
                    continue

                if dkg_t > len(allowed_indices):
                    log_state(
                        ("pre-skip", job_id, "not-enough-allowed"), (len(allowed_indices), dkg_t),
                        f"[PRE G {cfg.SH_INDEX}] skip job {job_id}: not enough allowed epoch Guardians "
                        f"allowed={len(allowed_indices)}, t={dkg_t}",
                    )
                    continue

                try:
                    share_index, sk = load_local_share_for_epoch(key_epoch, file_id_hex, dkg_n, dkg_t, epoch_index, share_version)
                except FileNotFoundError as e:
                    submitted_count = count_onchain_pre_partials(telg, int(job_id), known_guardians)
                    if submitted_count >= dkg_t:
                        log_state(
                            ("pre-skip", job_id, "enough-partials-after-missing-share"), (submitted_count, dkg_t),
                            f"[PRE G {cfg.SH_INDEX}] skip job {job_id}: already enough PRE partials ({submitted_count}/{dkg_t})",
                        )
                        _mark_pre_completed(pre_job_skip_until, int(job_id))
                    else:
                        log_state(("pre-skip", job_id, "missing-share-file"), str(e), f"[PRE G {cfg.SH_INDEX}] skip job {job_id}: {e}")
                    continue

                if dkg is None:
                    log_state(
                        ("pre-skip", job_id, "missing-dkg"), True,
                        f"[PRE G {cfg.SH_INDEX}] skip job {job_id}: DKG contract is not configured for proof verification",
                    )
                    continue

                try:
                    pk_exists, share_pk_x, share_pk_y = dkg.functions.getSharePublicKey(
                        Web3.to_bytes(hexstr=normalize_file_id_hex(file_id_hex)),
                        int(key_epoch), int(share_version), int(share_index),
                    ).call()
                    if not pk_exists:
                        raise RuntimeError("share public key not published")
                    share_public_key = (int(share_pk_x), int(share_pk_y))
                    if not is_on_curve(share_public_key):
                        raise RuntimeError("share public key is not on curve")
                except Exception as e:
                    log_state(
                        ("pre-skip", job_id, "missing-share-pk"), str(e),
                        f"[PRE G {cfg.SH_INDEX}] skip job {job_id}: missing verifiable DKG share public key: {e}",
                    )
                    continue

                log_state(
                    ("pre-processing", job_id),
                    (file_id_hex, key_epoch, share_version, epoch_index, share_index),
                    f"[PRE G {cfg.SH_INDEX}] processing job {job_id} "
                    f"(fileId={file_id_hex[:18]}..., epoch={key_epoch}, shareVersion={share_version}, "
                    f"epoch_index={epoch_index}, share_index={share_index})...",
                )

                cts = job.get("ciphertexts", [])
                partials: List[dict] = []

                for ct in cts:
                    cid_idx = int(ct["cidIndex"])
                    C1x = int(ct["C1x"])
                    C1y = int(ct["C1y"])
                    C1 = (C1x, C1y)

                    if not is_on_curve(C1):
                        print(f"[PRE G {cfg.SH_INDEX}] job {job_id}: C1 not on curve for cidIdx={cid_idx}")
                        continue

                    try:
                        proof = make_pre_dleq_proof(
                            int(job_id), int(share_version), int(share_index), int(sk), C1, share_public_key,
                        )
                    except Exception as e:
                        print(f"[PRE G {cfg.SH_INDEX}] job {job_id}: DLEQ proof failed for cidIdx={cid_idx}: {e}")
                        continue

                    D = proof["D"]
                    Dx, Dy = D
                    a1x, a1y = proof["a1"]
                    a2x, a2y = proof["a2"]
                    partials.append({
                        "cidIndex": cid_idx,
                        "C1x": str(C1x), "C1y": str(C1y),
                        "Dx": str(Dx), "Dy": str(Dy),
                        "a1x": str(a1x), "a1y": str(a1y),
                        "a2x": str(a2x), "a2y": str(a2y),
                        "s": str(proof["s"]),
                        "c": str(proof["c"]),
                    })

                if partials:
                    partial_cid_indices = [int(x["cidIndex"]) for x in partials]
                    log_state(
                        ("pre-partials-created", job_id, share_version, share_index),
                        tuple(partial_cid_indices),
                        f"[PRE G {cfg.SH_INDEX}] job {job_id}: created {len(partials)} PRE partial(s) "
                        f"for cidIndices={preview_list(partial_cid_indices)} using shareVersion={share_version}, share_index={share_index}",
                    )

                    ready_state = read_pre_ready_signal(telg, int(job_id), sh_acct.address)
                    if not ready_state.get("exists"):
                        partial_hash = build_pre_ready_hash(job_id, share_version, share_index, partials)
                        ok_ready = signal_pre_ready_onchain(w3, telg, sh_acct, job_id, share_version, share_index, partial_hash)
                        if ok_ready:
                            print(f"[PRE G {cfg.SH_INDEX}] job {job_id}: PRE-ready proof stored on-chain")
                            log_state(
                                ("pre-wait-ready-window", job_id, share_version, share_index), True,
                                f"[PRE G {cfg.SH_INDEX}] job {job_id}: waiting for PRE-ready window before full partial submission",
                            )
                            continue
                        ready_state = read_pre_ready_signal(telg, int(job_id), sh_acct.address)

                    submitted_count = count_onchain_pre_partials(telg, int(job_id), known_guardians)
                    if submitted_count >= dkg_t:
                        ok_credit = claim_pre_ready_not_used_onchain(w3, telg, sh_acct, job_id)
                        if ok_credit:
                            print(f"[PRE G {cfg.SH_INDEX}] job {job_id}: ready-but-not-used PRE reputation credit recorded")
                            claim_guardian_rewards_if_available(w3, sh_acct, f"claimRewards after PRE ready credit {job_id}")
                        _mark_pre_completed(pre_job_skip_until, int(job_id))
                        log_state(
                            ("pre-skip", job_id, "enough-partials-after-ready"), (submitted_count, dkg_t),
                            f"[PRE G {cfg.SH_INDEX}] skip job {job_id}: already enough PRE partials ({submitted_count}/{dkg_t})",
                        )
                        continue

                    ok_submit = submit_partial_onchain(w3, telg, sh_acct, job_id, share_version, share_index, partials)

                    if ok_submit:
                        print(f"[PRE G {cfg.SH_INDEX}] job {job_id}: partials stored on-chain")
                        claim_guardian_rewards_if_available(w3, sh_acct, f"claimRewards after PRE job {job_id}")
                        _mark_pre_completed(pre_job_skip_until, int(job_id))
                    else:
                        print(f"[PRE G {cfg.SH_INDEX}] job {job_id}: full PRE partial not stored in this cycle")
                        submitted_count_after_submit = count_onchain_pre_partials(telg, int(job_id), known_guardians)
                        if submitted_count_after_submit >= dkg_t:
                            ok_credit = claim_pre_ready_not_used_onchain(w3, telg, sh_acct, job_id)
                            if ok_credit:
                                print(f"[PRE G {cfg.SH_INDEX}] job {job_id}: ready-but-not-used PRE reputation credit recorded after full PRE submission became unnecessary")
                                claim_guardian_rewards_if_available(w3, sh_acct, f"claimRewards after PRE ready credit {job_id}")
                            _mark_pre_completed(pre_job_skip_until, int(job_id))

            time.sleep(cfg.POLL_INTERVAL)

        except KeyboardInterrupt:
            print("Interrupted. Exiting.")
            break
        except Exception as e:
            log_state(("pre-loop-error",), str(e), f"Error in PRE G loop: {e}")
            time.sleep(cfg.POLL_INTERVAL)


if __name__ == "__main__":
    main()
