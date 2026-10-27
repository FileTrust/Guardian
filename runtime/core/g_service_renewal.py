"""Guardian side of service renewal.

Why this exists
---------------
A Data Owner can now ask to keep a policy's Guardians on past the end date they
originally agreed to. The term does not move until every Guardian on the policy
says yes, so a Guardian that never answers quietly blocks the renewal for
everyone. This watcher answers on the Guardian's behalf.

What it checks before saying yes
--------------------------------
Agreeing means taking on more days of holding the share and more days of owing a
daily proof, so the answer is not automatic:

  * the whole span, counted from the term's original start, must still fit
    inside the maximum service length this Guardian published;
  * if this Guardian charges for custody, the money for the extra days must
    already be parked and priced for it. The contract parks the money before
    asking, so "no money parked" means something is wrong and the honest answer
    is to stay silent and let the DO cancel.

A Guardian that charges nothing for custody has nothing to check on the money
side and just answers on the length.
"""
from __future__ import annotations

import json
from pathlib import Path

from web3 import Web3

import core.g_config as cfg

DAY_SECONDS = 86400

# Proposals already answered or refused, so a refusal is logged once rather than
# on every poll. Keyed by (policy id, round) — a fresh proposal is looked at
# again from scratch, which is the point of the round number.
_decided: set[tuple[str, int]] = set()

_reward_manager_contract = None
_reward_manager_loaded = False


def _log(message: str) -> None:
    print(f"[Renewal G {cfg.SH_INDEX}] {message}", flush=True)


def _my_daily_custody_su() -> int:
    prices = getattr(cfg, "GUARDIAN_SERVICE_PRICES", None) or {}
    try:
        return max(0, int(prices.get("daily_share_custody_su", 0) or 0))
    except Exception:
        return 0


def _my_max_service_days() -> int:
    """0 means this Guardian published no limit."""
    prices = getattr(cfg, "GUARDIAN_SERVICE_PRICES", None) or {}
    try:
        return max(0, int(prices.get("max_service_days", 0) or 0))
    except Exception:
        return 0


def _reward_manager(w3: Web3):
    """The reward manager contract, or None when this instance has no address
    configured. Loaded once; a failure is not retried every poll."""
    global _reward_manager_contract, _reward_manager_loaded
    if _reward_manager_loaded:
        return _reward_manager_contract
    _reward_manager_loaded = True

    address = getattr(cfg, "REWARD_MANAGER_ADDRESS", "") or ""
    artifact_name = getattr(cfg, "REWARD_MANAGER_JSON", None)
    if not address or not artifact_name:
        _log("no reward manager configured; custody payment cannot be checked.")
        return None
    try:
        artifact_path = cfg.resolve_artifact_path(artifact_name)
        if artifact_path is None:
            _log(f"reward manager artifact {artifact_name} not found.")
            return None
        artifact = json.loads(Path(artifact_path).read_text(encoding="utf-8"))
        _reward_manager_contract = w3.eth.contract(
            address=Web3.to_checksum_address(address), abi=artifact["abi"]
        )
    except Exception as exc:
        _log(f"could not load the reward manager: {exc}")
        _reward_manager_contract = None
    return _reward_manager_contract


def _custody_parked_for_me(w3: Web3, policy_id: bytes, new_service_end: int, me: str) -> tuple[bool, str]:
    """Is the money for the extra days really parked, and priced for me?

    Returns (ok, reason). A Guardian that charges nothing never gets here.
    """
    reward_manager = _reward_manager(w3)
    if reward_manager is None:
        return False, "no reward manager configured to check the money"
    try:
        _balance, _committed, _free, stretch_count, _claimable = (
            reward_manager.functions.custodyStatus(policy_id, me).call()
        )
        if int(stretch_count) == 0:
            return False, "no custody money is parked for this policy"
        newest = int(stretch_count) - 1
        _start, end_time, reserved_wei, _paid, active, daily_rate_wei = (
            reward_manager.functions.getCustodyStretch(policy_id, newest, me).call()
        )
    except Exception as exc:
        return False, f"could not read the custody stretch: {exc}"

    if bool(active):
        return False, "the newest paid stretch is already running, not a parked renewal"
    if int(end_time) != int(new_service_end):
        return False, (
            f"the parked stretch ends at {int(end_time)}, "
            f"but the renewal asks for {int(new_service_end)}"
        )
    if int(daily_rate_wei) <= 0:
        return False, "the parked stretch pays this Guardian nothing per day"
    if int(reserved_wei) <= 0:
        return False, "the parked stretch holds no money"
    return True, f"{int(daily_rate_wei)} wei/day parked for the extra days"


def _too_long_for_me(service_start: int, new_service_end: int) -> tuple[bool, str]:
    """Would this renewal hold the Guardian past the length it published?"""
    max_days = _my_max_service_days()
    if max_days == 0:
        return False, "no published limit"
    span = max(0, int(new_service_end) - int(service_start))
    # Rounded up, matching the contract, so a part day still counts as a day.
    total_days = (span + DAY_SECONDS - 1) // DAY_SECONDS
    if total_days > max_days:
        return True, f"would run {total_days} day(s), past the {max_days} published"
    return False, f"{total_days} day(s) is within the {max_days} published"


def process_pending_renewals(w3: Web3, account, share_proof, local_shares: dict[tuple, dict],
                             send_tx) -> None:
    """Answer any renewal waiting on a policy this Guardian holds a share for.

    `send_tx(w3, account, fn, label)` sends and waits, matching the watcher's
    own sender so transaction logging and gas settings stay in one place.
    """
    if not local_shares:
        return
    me = account.address

    seen: set[str] = set()
    for item in local_shares.values():
        policy_id = item["file_id"]
        policy_hex = policy_id.hex()
        if policy_hex in seen:
            continue
        seen.add(policy_hex)

        try:
            (pending, round_no, new_service_end, _confirm_by, accepted_count,
             guardian_count, window_open, already_accepted) = (
                share_proof.functions.getServicePeriodExtension(policy_id, me).call()
            )
        except Exception as exc:
            _log(f"could not read the renewal for {policy_hex[:16]}: {exc}")
            continue

        if not bool(pending) or bool(already_accepted):
            continue
        decision_key = (policy_hex, int(round_no))
        if decision_key in _decided:
            continue
        if not bool(window_open):
            _log(f"policy {policy_hex[:16]}: the answer deadline has passed; leaving it to the DO.")
            _decided.add(decision_key)
            continue

        try:
            exists, service_start, _service_end, _duration = (
                share_proof.functions.getPolicyServicePeriod(policy_id).call()
            )
        except Exception as exc:
            _log(f"could not read the term for {policy_hex[:16]}: {exc}")
            continue
        if not bool(exists):
            continue

        too_long, length_reason = _too_long_for_me(int(service_start), int(new_service_end))
        if too_long:
            _log(f"policy {policy_hex[:16]}: refusing renewal — {length_reason}.")
            _decided.add(decision_key)
            continue

        if _my_daily_custody_su() > 0:
            paid, money_reason = _custody_parked_for_me(
                w3, policy_id, int(new_service_end), me
            )
            if not paid:
                _log(f"policy {policy_hex[:16]}: refusing renewal — {money_reason}.")
                _decided.add(decision_key)
                continue
            _log(f"policy {policy_hex[:16]}: renewal is funded — {money_reason}.")

        _log(
            f"policy {policy_hex[:16]}: accepting renewal round {int(round_no)} "
            f"to {int(new_service_end)} ({length_reason}); "
            f"{int(accepted_count)}/{int(guardian_count)} agreed so far."
        )
        try:
            send_tx(
                w3, account,
                share_proof.functions.acceptServicePeriodExtension(policy_id, int(round_no)),
                f"acceptServicePeriodExtension policy={policy_hex[:16]} round={int(round_no)}",
            )
            _decided.add(decision_key)
        except Exception as exc:
            # Left undecided on purpose: a failed send should be retried next
            # poll rather than silently dropping the Guardian's answer.
            _log(f"policy {policy_hex[:16]}: accept failed, will retry: {exc}")
