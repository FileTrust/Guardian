"""Guardian service SU pricing helpers.

Side-effect free until callers ask it to sync local pricing on-chain.
Keeps Guardian-declared service prices in one canonical shape for DKG and
PRE nodes.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import core.g_config as cfg
from core.g_tx import send_contract_transaction


DEFAULT_GUARDIAN_SERVICE_PRICES = {
    "dkg_material_su": 12_000,
    "dkg_share_key_su": 6_325,
    "pre_batch_partial_su": 30_542,
    "daily_share_custody_su": 0,
    "max_service_days": 0,
}


def _as_int(value: Any, fallback: int) -> int:
    try:
        parsed = int(value)
        return parsed if parsed >= 0 else fallback
    except Exception:
        return fallback


def normalize_guardian_service_prices(raw: dict[str, Any] | None) -> dict[str, int]:
    raw = raw or {}
    return {
        "dkg_material_su": _as_int(raw.get("dkg_material_su"), DEFAULT_GUARDIAN_SERVICE_PRICES["dkg_material_su"]),
        "dkg_share_key_su": _as_int(raw.get("dkg_share_key_su"), DEFAULT_GUARDIAN_SERVICE_PRICES["dkg_share_key_su"]),
        "pre_batch_partial_su": _as_int(
            raw.get("pre_batch_partial_su"),
            DEFAULT_GUARDIAN_SERVICE_PRICES["pre_batch_partial_su"],
        ),
        "daily_share_custody_su": _as_int(
            raw.get("daily_share_custody_su"),
            DEFAULT_GUARDIAN_SERVICE_PRICES["daily_share_custody_su"],
        ),
        "max_service_days": _as_int(
            raw.get("max_service_days"),
            DEFAULT_GUARDIAN_SERVICE_PRICES["max_service_days"],
        ),
    }


def load_guardian_service_prices(
    service_prices_cfg: dict | None,
    instance_root: Path,
    guardian_index: int,
) -> dict[str, int]:
    """Resolve service prices from the most specific source available.

    Priority: per-instance config dict → instance config.json →
    defaults.
    """
    if isinstance(service_prices_cfg, dict) and service_prices_cfg:
        return normalize_guardian_service_prices(service_prices_cfg)

    main_config = instance_root / "config.json"
    if main_config.is_file():
        try:
            data = json.loads(main_config.read_text(encoding="utf-8"))
            prices = data.get("service_prices") or data.get("guardian_service_prices")
            if isinstance(prices, dict):
                return normalize_guardian_service_prices(prices)
        except Exception:
            pass

    return dict(DEFAULT_GUARDIAN_SERVICE_PRICES)


def print_guardian_service_prices(label: str, prices: dict[str, int]) -> None:
    print(f"[Pricing] {label} Guardian service prices:")
    print(f"[Pricing] DKG material: {prices['dkg_material_su']} SU")
    print(f"[Pricing] DKG share key: {prices['dkg_share_key_su']} SU")
    print(f"[Pricing] PRE batch partial: {prices['pre_batch_partial_su']} SU")
    print(f"[Pricing] Daily share custody: {prices['daily_share_custody_su']} SU/day")
    max_days = int(prices.get("max_service_days", 0))
    print(f"[Pricing] Max service days: {'unlimited' if max_days == 0 else max_days}")


def sync_guardian_service_pricing(
    *,
    w3,
    guardian_registry,
    account,
    private_key: str,
    prices: dict[str, int],
    label: str,
) -> bool:
    """Set on-chain Guardian pricing if it differs from local config.

    Returns True when a transaction was sent.
    """
    if guardian_registry is None:
        print(f"[Pricing] {label} GuardianRegistry not configured; skipping on-chain pricing sync.")
        return False

    address = account.address if hasattr(account, "address") else str(account)
    target = (
        int(prices["dkg_material_su"]),
        int(prices["dkg_share_key_su"]),
        int(prices["pre_batch_partial_su"]),
        int(prices["daily_share_custody_su"]),
        int(prices.get("max_service_days", 0)),
    )
    setter_name = "setGuardianServicePricingWithAvailability"
    try:
        current = guardian_registry.functions.getGuardianServiceInfo(address).call()
        current_tuple = (int(current[0]), int(current[1]), int(current[2]), int(current[3]), int(current[4]))
        current_exists = bool(current[5])
        if current_exists and current_tuple == target:
            print("[Pricing] On-chain pricing already current.")
            return False
    except Exception as exc:
        try:
            current = guardian_registry.functions.getGuardianServicePricingWithCustody(address).call()
            current_tuple = (int(current[0]), int(current[1]), int(current[2]), int(current[3]))
            current_exists = bool(current[4])
            setter_name = "setGuardianServicePricingWithCustody"
            if current_exists and current_tuple == target[:4] and target[4] == 0:
                print("[Pricing] On-chain pricing already current.")
                return False
        except Exception:
            try:
                legacy_current = guardian_registry.functions.getGuardianServicePricingWithStatus(address).call()
                current_tuple = (int(legacy_current[0]), int(legacy_current[1]), int(legacy_current[2]))
                current_exists = bool(legacy_current[3])
                setter_name = "setGuardianServicePricing"
                if current_exists and current_tuple == target[:3] and target[3] == 0 and target[4] == 0:
                    print("[Pricing] On-chain pricing already current.")
                    return False
            except Exception:
                print(f"[Pricing] Could not read on-chain pricing for {address}: {exc}")

    try:
        if setter_name == "setGuardianServicePricingWithAvailability":
            fn = guardian_registry.functions.setGuardianServicePricingWithAvailability(*target)
        elif setter_name == "setGuardianServicePricingWithCustody":
            fn = guardian_registry.functions.setGuardianServicePricingWithCustody(*target[:4])
        else:
            fn = guardian_registry.functions.setGuardianServicePricing(*target[:3])
        gas_est = fn.estimate_gas({"from": address})

        signer = (
            account if hasattr(account, "sign_transaction")
            else w3.eth.account.from_key(private_key)
        )
        tx_hash, receipt, _tx = send_contract_transaction(
            w3,
            signer,
            fn,
            gas=gas_est + 50_000,
            gas_price=cfg.FIXED_GAS_PRICE_WEI,
        )
        print(f"[Pricing] {setter_name} tx: {tx_hash.hex()}")
        print(f"[Pricing] {setter_name} status: {receipt.status}")
        return bool(receipt.status)
    except Exception as exc:
        print(f"[Pricing] On-chain pricing update failed: {exc}")
        return False
