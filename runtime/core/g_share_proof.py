#!/usr/bin/env python3
"""Guardian share-possession proof watcher for FileTrust ZKDKG_V2.

Each Guardian proves it still holds its own finalized Baby Jubjub DKG share.
The proof is a Groth16-verified Baby Jubjub DLEQ relation and never exposes
the share:

    publicShare = share * G
    responsePoint = share * challengePoint

Run from the instance root:
    python core/g_share_proof.py
or spawned by start.py as a subprocess.
"""
from __future__ import annotations


import json
import secrets
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.g_secret_files import read_secret_json

from web3 import Web3

import core.g_config as cfg
from core.g_tx import send_contract_transaction
from core.g_chain import load_contract
from core.g_service_renewal import process_pending_renewals
from core.g_crypto import BABY_G, BABY_L, baby_mul
from core.g_material import normalize_file_id_hex
from core.g_zk import (
    generate_share_possession_proof,
    resolve_zokrates_bin,
    v2_proof_struct,
    zokrates_available,
    zokrates_missing_message,
)

_ZOKRATES_BIN_CFG = cfg.ZOKRATES_BIN
_LAST_ZOKRATES_WARNING = 0.0
_SUBMITTED_EPOCH_SKIP_UNTIL = 0.0
_SHARE_PROOF_POLL_INTERVAL = max(1, int(getattr(cfg, "SHARE_PROOF_POLL_INTERVAL", cfg.POLL_INTERVAL)))


def _current_zokrates_bin() -> str:
    return resolve_zokrates_bin(_ZOKRATES_BIN_CFG)


def _warn_zokrates_missing() -> None:
    global _LAST_ZOKRATES_WARNING
    now = time.time()
    if now - _LAST_ZOKRATES_WARNING >= 60:
        print(
            f"[ShareProof G {cfg.SH_INDEX}] waiting for ZoKrates before share-possession proof; "
            f"will retry automatically. {zokrates_missing_message(_ZOKRATES_BIN_CFG)}"
        )
        _LAST_ZOKRATES_WARNING = now


def _normalize_file_id_bytes(value: str) -> bytes:
    h = str(value)
    if h.startswith("0x"):
        h = h[2:]
    data = bytes.fromhex(h)
    if len(data) != 32:
        raise ValueError(f"fileId must be 32 bytes, got {len(data)}")
    return data


def _send_tx(w3: Web3, account, fn, label: str):
    tx_hash, receipt, _tx = send_contract_transaction(
        w3,
        account,
        fn,
        gas=fn.estimate_gas({"from": account.address}) + 80_000,
        gas_price=cfg.FIXED_GAS_PRICE_WEI,
    )
    print(f"[ShareProof G {cfg.SH_INDEX}] {label} tx: {tx_hash.hex()}")
    print(f"[ShareProof G {cfg.SH_INDEX}] {label} status: {receipt.status}")
    return receipt


def _final_share_files() -> list[Path]:
    if getattr(cfg,'DKG_ATTEMPT_PROTOCOL',0)==1:
        from core.g_dkg_custody import active_share_files
        return active_share_files(cfg)
    if not cfg.DKG_LOCAL_DIR.is_dir():
        return []
    return sorted(cfg.DKG_LOCAL_DIR.glob("v2_dkg_file_*_final_share_*.json"))


def _load_local_share(path: Path) -> dict | None:
    try:
        data = read_secret_json(path)
        if getattr(cfg,'DKG_ATTEMPT_PROTOCOL',0)==1:
            from core.g_dkg_custody import active_share_path,load_active_share
            scope=(data['fileId'],data['keyEpoch'],data['shareVersion'],data['n'],data['t'],data['index'])
            if path!=active_share_path(cfg,*scope):
                raise ValueError('Recovery custody file has a different deployment scope')
            load_active_share(cfg,*scope)
        file_id = _normalize_file_id_bytes(data["fileId"])
        key_epoch = int(data["keyEpoch"])
        share_version = int(data.get("shareVersion", 1))
        share_index = int(data.get("index", data.get("shareIndex", 0)))
        if share_index == 0:
            return None
        share = int(data.get("share", data.get("sk"))) % BABY_L
        if share == 0:
            print(f"[ShareProof G {cfg.SH_INDEX}] invalid zero share in {path}")
            return None
        return {
            "path": path, "data": data,
            "file_id": file_id, "key_epoch": key_epoch,
            "share_version": share_version, "share_index": share_index, "share": share,
        }
    except Exception as exc:
        print(f"[ShareProof G {cfg.SH_INDEX}] could not read {path}: {exc}")
        return None


def _load_local_shares() -> dict[tuple, dict]:
    shares: dict[tuple, dict] = {}
    for path in _final_share_files():
        item = _load_local_share(path)
        if item is None:
            continue
        key=(item["file_id"].hex(), int(item["key_epoch"]))
        previous=shares.get(key)
        if previous is None or int(item['share_version'])>int(previous['share_version']):
            shares[key]=item
    return shares


_registered_policy_ids: set[str] = set()

# Policies whose registration is failing, and when to look at them again.
# Without this, one policy that can never register would report the same failure
# on every poll for the life of the process.
_registration_retry_at: dict[str, float] = {}
_registration_backoff: dict[str, float] = {}

_REGISTRATION_RETRY_START = 60.0
_REGISTRATION_RETRY_MAX = 3600.0


def _registration_failed(policy_id_hex: str, message: str) -> None:
    delay = min(
        _REGISTRATION_RETRY_MAX,
        max(_REGISTRATION_RETRY_START, _registration_backoff.get(policy_id_hex, 0.0) * 2),
    )
    _registration_backoff[policy_id_hex] = delay
    _registration_retry_at[policy_id_hex] = time.monotonic() + delay
    print(f"[ShareProof G {cfg.SH_INDEX}] {message}; trying again in {int(delay)}s")


def _ensure_registered_for_policies(w3: Web3, account, share_proof, local_shares: dict[tuple, dict]) -> None:
    """Sign up for every share that is ready, not just the ones before the first that is not.

    Each check below used to `return`. That abandoned every remaining share the
    moment one was already registered, had no service term, or could not be read
    — and it did so again on every poll. A Guardian holding shares for ten
    policies would stop at the first and never sign up for the rest, so the chain
    never asked it to prove them, and nothing said why. Found by killing
    Guardians on a live chain: no Guardian ever registered, because the first
    share in the list belonged to a policy with no term.

    Skipping is the right move rather than a compromise: this runs again on every
    poll, so a share passed over now is looked at again a minute later. Nothing is
    dropped — which is the same rule the rest of FileTrust follows, that a job may
    wait and be retried but must never be lost.
    """
    now = time.monotonic()
    for item in local_shares.values():
        policy_id_hex = item["file_id"].hex()
        if policy_id_hex in _registered_policy_ids:
            continue
        if now < _registration_retry_at.get(policy_id_hex, 0.0):
            continue
        policy_id_bytes = item["file_id"]
        try:
            if share_proof.functions.isRegisteredForPolicy(policy_id_bytes, account.address).call():
                _registered_policy_ids.add(policy_id_hex)
                continue
            if not share_proof.functions.getPolicyServicePeriod(policy_id_bytes).call()[0]:
                # No term on this policy yet. Nothing is wrong and nothing is
                # owed, so this is not a failure and earns no backoff: the owner
                # may start a term at any moment, and the Guardian should notice
                # on the next poll rather than an hour later.
                continue
        except Exception as exc:
            _registration_failed(
                policy_id_hex,
                f"registration check failed for {policy_id_hex[:16]}: {exc}",
            )
            continue
        try:
            _send_tx(
                w3, account,
                share_proof.functions.registerAsGuardianForPolicy(policy_id_bytes),
                f"registerAsGuardianForPolicy policy={policy_id_hex[:16]}",
            )
            _registered_policy_ids.add(policy_id_hex)
            _registration_retry_at.pop(policy_id_hex, None)
            _registration_backoff.pop(policy_id_hex, None)
        except Exception as exc:
            _registration_failed(
                policy_id_hex,
                f"registerAsGuardianForPolicy failed for {policy_id_hex[:16]}: {exc}",
            )


def process_selected_policy(w3: Web3, account, share_proof, local_shares: dict[tuple, dict]) -> None:
    global _SUBMITTED_EPOCH_SKIP_UNTIL
    # ── Step 1: determine if this Guardian is due to submit now ─────────────────
    file_id: bytes | None = None
    key_epoch: int | None = None
    share_index: int | None = None
    challenge_block_number: int | None = None
    proof_epoch: int | None = None

    try:
        if _SUBMITTED_EPOCH_SKIP_UNTIL > time.monotonic():
            return

        try:
            # Rolling random window check. The contract also returns false after
            # this guardian has already submitted for the current epoch, so the
            # idle path stays to a single view call.
            window = share_proof.functions.isProofWindowOpen(account.address).call()
            selected_now, in_fallback, file_id_raw, _key_epoch, _share_index, _window_end, _slot_start = window
            if not selected_now:
                return  # Not selected this slot — check again next poll.
            file_id             = bytes(file_id_raw)
            key_epoch           = int(_key_epoch)
            share_index         = int(_share_index)
            challenge_block_number = int(_slot_start) if int(_slot_start) > 0 else max(0, w3.eth.block_number - 1)
            proof_epoch = int(share_proof.functions.getProofEpoch().call())
            print(f"[ShareProof G {cfg.SH_INDEX}] proof window open"
                  f" (fallback={in_fallback}) epoch={proof_epoch}")
        except Exception:
            # Contract pre-dates isProofWindowOpen — fall back to legacy any-time selection.
            proof_epoch = int(share_proof.functions.getProofEpoch().call())
            if bool(share_proof.functions.hasSubmittedProofForEpoch(account.address, proof_epoch).call()):
                _SUBMITTED_EPOCH_SKIP_UNTIL = time.monotonic() + max(60, _SHARE_PROOF_POLL_INTERVAL * 12)
                return
            latest = w3.eth.get_block("latest")
            challenge_block_number = max(0, int(latest["number"]) - 1)
            selected = share_proof.functions.selectPolicyForGuardian(
                account.address, proof_epoch, challenge_block_number,
            ).call()
            if not bool(selected[0]):
                print(f"[ShareProof G {cfg.SH_INDEX}] no eligible policy for proof epoch {proof_epoch}.")
                return
            file_id     = bytes(selected[1])
            key_epoch   = int(selected[2])
            share_index = int(selected[3])

    except Exception as exc:
        print(f"[ShareProof G {cfg.SH_INDEX}] selected policy lookup failed: {exc}")
        return
    # ────────────────────────────────────────────────────────────────────────────
    item = local_shares.get((file_id.hex(), key_epoch))
    if item is None:
        print(
            f"[ShareProof G {cfg.SH_INDEX}] selected policy {file_id.hex()[:16]} epoch={key_epoch}, "
            "but local final share is not available yet."
        )
        return

    if int(item["share_index"]) != share_index:
        print(
            f"[ShareProof G {cfg.SH_INDEX}] selected policy shareIndex={share_index}, "
            f"local share has index={item['share_index']}; waiting."
        )
        return

    try:
        registered = share_proof.functions.getRegisteredPublicShare(file_id, key_epoch, account.address).call()
        if not bool(registered[0]):
            print(
                f"[ShareProof G {cfg.SH_INDEX}] public share not registered for selected policy; "
                "submitSharePossessionProof will register it in the same transaction."
            )
            share_pub = baby_mul(int(item["share"]), BABY_G)
        elif int(registered[1]) != int(item["share_version"]) or int(registered[2]) != share_index:
            print(f"[ShareProof G {cfg.SH_INDEX}] registered public share metadata differs for selected policy; waiting.")
            return
        else:
            share_pub = (int(registered[3]), int(registered[4]))
        if share_pub is None:
            print(f"[ShareProof G {cfg.SH_INDEX}] could not derive public share for selected policy.")
            return
    except Exception as exc:
        print(f"[ShareProof G {cfg.SH_INDEX}] public share registration check failed: {exc}")
        return

    try:
        nonce = secrets.randbelow(BABY_L - 1) + 1
        challenge_point = baby_mul(nonce, BABY_G)
        if challenge_point is None:
            return
        response_point = baby_mul(int(item["share"]), challenge_point)
        if response_point is None:
            return
        context_hash = int(share_proof.functions.computeSharePossessionContextHash(
            challenge_block_number, file_id, key_epoch, account.address, proof_epoch,
            int(challenge_point[0]), int(challenge_point[1]),
            int(share_pub[0]), int(share_pub[1]),
            int(response_point[0]), int(response_point[1]),
        ).call())
        zokrates_bin = _current_zokrates_bin()
        if not zokrates_available(zokrates_bin):
            _warn_zokrates_missing()
            return
        proof_json = generate_share_possession_proof(
            cfg.ZK_SHARE_POSSESSION_BUILD_DIR, int(item["share"]), share_pub,
            challenge_point, response_point, context_hash, zokrates_bin,
        )
        _send_tx(
            w3, account,
            share_proof.functions.submitSharePossessionProofForBlock(
                file_id, key_epoch, challenge_block_number,
                int(challenge_point[0]), int(challenge_point[1]),
                int(response_point[0]), int(response_point[1]),
                v2_proof_struct(proof_json),
            ),
            f"submitSharePossessionProof epoch={proof_epoch} file={item['data']['fileId'][:18]}",
        )
        _SUBMITTED_EPOCH_SKIP_UNTIL = time.monotonic() + max(60, _SHARE_PROOF_POLL_INTERVAL * 12)
    except Exception as exc:
        print(f"[ShareProof G {cfg.SH_INDEX}] proof submit failed: {exc}")


def main() -> int:
    from core import g_lifecycle
    g_lifecycle.install()
    from core import g_txlog as TX
    TX.install(cfg)

    if not cfg.GUARDIAN_SHARE_PROOF_ADDRESS or not cfg.GUARDIAN_SHARE_PROOF_JSON:
        print(f"[ShareProof G {cfg.SH_INDEX}] GuardianShareProof not configured; watcher disabled.")
        return 0

    from core.g_dkg_rpc import ReadRetryHTTPProvider
    w3 = Web3(ReadRetryHTTPProvider(cfg.RPC_URL, request_kwargs={"timeout": 30}))
    connection_attempt = 0
    while not w3.is_connected():
        if g_lifecycle.STOP.is_set():
            return 0
        connection_attempt += 1
        delay = min(30, 2 ** min(connection_attempt, 5))
        print(
            f"[ShareProof G {cfg.SH_INDEX}] RPC unavailable at startup; "
            f"retrying in {delay}s",
            flush=True,
        )
        time.sleep(delay)

    account = w3.eth.account.from_key(cfg.SH_PRIVATE_KEY)
    artifact_path = cfg.resolve_artifact_path(cfg.GUARDIAN_SHARE_PROOF_JSON)
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    share_proof = w3.eth.contract(
        address=Web3.to_checksum_address(cfg.GUARDIAN_SHARE_PROOF_ADDRESS),
        abi=artifact["abi"],
    )

    print(f"[ShareProof G {cfg.SH_INDEX}] watcher started for {account.address}")
    print(f"[ShareProof G {cfg.SH_INDEX}] local share dir: {cfg.DKG_LOCAL_DIR}")
    if not zokrates_available(_current_zokrates_bin()):
        _warn_zokrates_missing()

    while not g_lifecycle.STOP.is_set():
        try:
            local_shares = _load_local_shares()
            if not local_shares:
                print(f"[ShareProof G {cfg.SH_INDEX}] no local V2 final shares yet.")
            else:
                _ensure_registered_for_policies(w3, account, share_proof, local_shares)
                # Answered before proving: a renewal the Guardian sits on blocks
                # the whole policy, and the answer deadline is short.
                process_pending_renewals(w3, account, share_proof, local_shares, _send_tx)
                process_selected_policy(w3, account, share_proof, local_shares)
        except Exception as exc:
            print(
                f"[ShareProof G {cfg.SH_INDEX}] RPC/proof loop unavailable; "
                f"state preserved and retrying: {exc}",
                flush=True,
            )
        time.sleep(_SHARE_PROOF_POLL_INTERVAL)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
