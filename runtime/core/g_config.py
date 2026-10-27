"""Configuration for a single protected Guardian instance.

The launcher supplies its private state directory. No developer/fleet config
or shared-core path is consulted. Wallet material is loaded only in memory.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

# ---------------------------------------------------------------------------
# The launcher selects the private instance root explicitly.

from .g_secret_files import load_wallet_config

_CORE_DIR = Path(__file__).resolve().parent
_state = os.environ.get("FILETRUST_GUARDIAN_STATE")
if not _state:
    raise RuntimeError("Start this Guardian with guardian.py run")
ROOT = Path(_state).resolve()
_CFG_PATH = ROOT / "config.json"
_cfg = load_wallet_config(_CFG_PATH)

# ---------------------------------------------------------------------------
# Core identity
# ---------------------------------------------------------------------------

RPC_URL: str = _cfg["rpc_url"]

GUARDIAN_INDEX: int = int(_cfg.get("guardian_index", _cfg.get("sh_index", 1)))
SH_INDEX: int = GUARDIAN_INDEX          # backward-compat alias used by log labels

SH_PRIVATE_KEY: str = _cfg["private_key"]

GUARDIAN_ADDRESS: str = _cfg.get("address", "")

N_SHARES: int = int(_cfg.get("n", _cfg.get("dkg_n", 5)))
T_THRESHOLD: int = int(_cfg.get("t", _cfg.get("dkg_t", 3)))

COORDINATOR_INDEX: int = int(_cfg.get("coordinator_index", 1))
IS_COORDINATOR: bool = bool(_cfg.get("is_coordinator", GUARDIAN_INDEX == COORDINATOR_INDEX))

POLL_INTERVAL: int = int(_cfg.get("poll_interval", 10))
SHARE_PROOF_POLL_INTERVAL: int = int(_cfg.get("share_proof_poll_interval", 60))
DKG_WORKERS: int = max(1, int(_cfg.get("dkg_workers", 3)))
DKG_RETRY_INITIAL_SECONDS: float = max(
    1.0, float(_cfg.get("dkg_retry_initial_seconds", 5))
)
DKG_RETRY_MAX_SECONDS: float = max(
    DKG_RETRY_INITIAL_SECONDS,
    float(_cfg.get("dkg_retry_max_seconds", 30)),
)
DKG_COMPLETE_RECHECK_SECONDS: float = max(
    DKG_RETRY_MAX_SECONDS,
    float(_cfg.get("dkg_complete_recheck_seconds", 300)),
)

ENABLE_ZKDKG_MIGRATION: bool = bool(_cfg.get("enable_zkdkg_migration", True))

# Recovery is a versioned deployment; never infer it from an RPC failure.
DKG_ATTEMPT_PROTOCOL = _cfg.get("dkg_attempt_protocol", 0)
if type(DKG_ATTEMPT_PROTOCOL) is not int or DKG_ATTEMPT_PROTOCOL not in (0, 1):
    raise ValueError("Unsupported DKG attempt protocol version")
DKG_RECOVERY = _cfg.get("dkg_recovery", {})


CONFIG_FILE_ID: str | None = _cfg.get("file_id") or None

GUARDIAN_SERVICE_PRICES: dict = _cfg.get("service_prices", {})

_bundled_zokrates = _CORE_DIR / "zk" / "zokrates"
ZOKRATES_BIN: str = str(_cfg.get("zokrates_bin", "") or (
    str(_bundled_zokrates) if _bundled_zokrates.is_file() else "zokrates"
))

DO_ADDRESS: str = _cfg.get("do_address", "")

# ---------------------------------------------------------------------------
# Contract addresses
# ---------------------------------------------------------------------------

ACL_ADDRESS: str = _cfg.get("acl_address", "")
DV_ADDRESS: str = _cfg.get("dv_address", "")
GUARDIAN_REGISTRY_ADDRESS: str = _cfg.get("guardian_registry_address", "")
TELG_V2_ADDRESS: str = _cfg.get("telg_v2_address", "")
ZKDKG_COORDINATOR_V2_ADDRESS: str = _cfg.get("zkdkg_coordinator_v2_address", "")
GUARDIAN_SHARE_PROOF_ADDRESS: str = _cfg.get("guardian_share_proof_address", "")
ZKDKG_DISPUTE_MANAGER_ADDRESS: str = _cfg.get("zkdkg_dispute_manager_address", "")
REPUTATION_MANAGER_ADDRESS: str = _cfg.get("reputation_manager_address", "")
STAKING_MANAGER_ADDRESS: str = _cfg.get("staking_manager_address", "")
REWARD_MANAGER_ADDRESS: str = _cfg.get("reward_manager_address", "")
VAULT_KEEPER_REGISTRY_ADDRESS: str = _cfg.get("vault_keeper_registry_address", "")
ZKDKG_SHARE_VERIFIER_ADDRESS: str = _cfg.get("zkdkg_share_verifier_address", "")
V2_PRE_PARTIAL_VERIFIER_ADDRESS: str = _cfg.get("v2_pre_partial_verifier_address", "")
SHARE_POSSESSION_VERIFIER_ADDRESS: str = _cfg.get("share_possession_verifier_address", "")
FILE_REGISTRATION_ADDRESS: str = _cfg.get("file_registration_address", "")

TRANSACTION_LOG_PATH: str = _cfg.get("transaction_log_path", "")

FIXED_GAS_PRICE_WEI: int = int(_cfg.get("filetrust_fixed_gas_price_wei", 1_000_000))

AUTO_CLAIM_REWARDS: bool = bool(_cfg.get("auto_claim_rewards", True))
MIN_REWARD_CLAIM_WEI: int = int(_cfg.get("min_reward_claim_wei", 0) or 0)
REWARD_CLAIM_COOLDOWN_SECONDS: int = int(_cfg.get("reward_claim_cooldown_seconds", 60) or 0)

# Legacy DKG / TElG v1 (may be absent in new deployments)
DKG_ADDRESS: str | None = _cfg.get("dkg_address") or None
TELG_ADDRESS: str | None = _cfg.get("telg_address") or None

# ---------------------------------------------------------------------------
# Contract ABI paths (relative values like "contracts/Foo.json" → absolute)
# ---------------------------------------------------------------------------

def resolve_artifact_path(path_value: str | None) -> Path | None:
    """Resolve a contract artifact path to an absolute Path.

    *path_value* is typically a relative path stored in config.json such as
    ``"contracts/GuardianRegistry.json"``. Prefer downloaded network ABIs in
    the private instance; fall back to bundled public ABIs. Python code is
    loaded only from the installed application, never the private instance.
    """
    if not path_value:
        return None
    raw = Path(str(path_value)).expanduser()
    if raw.is_absolute():
        return raw
    downloaded = ROOT / "core" / raw
    if downloaded.is_file():
        return downloaded
    return _CORE_DIR / raw


ACL_JSON: str | None = _cfg.get("acl_json")
DV_JSON: str | None = _cfg.get("dv_json")
GUARDIAN_REGISTRY_JSON: str | None = _cfg.get("guardian_registry_json")
TELG_V2_JSON: str | None = _cfg.get("telg_v2_json")
ZKDKG_COORDINATOR_V2_JSON: str | None = _cfg.get("zkdkg_coordinator_v2_json")
GUARDIAN_SHARE_PROOF_JSON: str | None = _cfg.get("guardian_share_proof_json")
ZKDKG_DISPUTE_MANAGER_JSON: str | None = _cfg.get("zkdkg_dispute_manager_json")
REPUTATION_MANAGER_JSON: str | None = _cfg.get("reputation_manager_json")
STAKING_MANAGER_JSON: str | None = _cfg.get("staking_manager_json")
REWARD_MANAGER_JSON: str | None = _cfg.get("reward_manager_json")
VAULT_KEEPER_REGISTRY_JSON: str | None = _cfg.get("vault_keeper_registry_json")
ZKDKG_SHARE_VERIFIER_JSON: str | None = _cfg.get("zkdkg_share_verifier_json")
V2_PRE_PARTIAL_VERIFIER_JSON: str | None = _cfg.get("v2_pre_partial_verifier_json")
SHARE_POSSESSION_VERIFIER_JSON: str | None = _cfg.get("share_possession_verifier_json")
FILE_REGISTRATION_JSON: str | None = _cfg.get("file_registration_json")
ZKDKG_JUSTIFICATION_PROOF_JSON: str | None = _cfg.get("zkdkg_justification_proof_json")

# Legacy (may be absent)
DKG_JSON: str | None = _cfg.get("dkg_json") or None
TELG_JSON: str | None = _cfg.get("telg_json") or None

# ---------------------------------------------------------------------------
# Data directories (created eagerly so protocol scripts can write immediately)
# ---------------------------------------------------------------------------

DKG_LOCAL_DIR: Path = Path(_cfg.get("dkg_local_dir", "") or str(ROOT / "dkg_local"))
PRE_LOCAL_DIR: Path = Path(_cfg.get("pre_local_dir", "") or str(ROOT / "pre_local"))
DEALER_MATERIAL_DIR: Path = Path(_cfg.get("dealer_material_dir", "") or str(ROOT / "dealer_material"))
V2_SHARE_DIR: Path = Path(_cfg.get("v2_share_dir", "") or str(DKG_LOCAL_DIR))

# These hold key shares. Created closed rather than at whatever the umask gives:
# a threshold of the files inside reconstructs the file decryption key, and the
# filenames alone map which Guardian dealt to whom for which file and epoch.
for _d in (DKG_LOCAL_DIR, PRE_LOCAL_DIR, DEALER_MATERIAL_DIR, V2_SHARE_DIR):
    _d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(_d, 0o700)
    except OSError:
        pass  # reported at startup by the material module's read-back check

try:
    from core import g_txlog as _txlog
    _txlog.install(_cfg)
except Exception:
    pass

# ---------------------------------------------------------------------------
# ZoKrates proof build directories.
# Default: core/zk/ inside this instance (fully self-contained).
# Override with 'zk_build_dir' in config.json if needed.
# ---------------------------------------------------------------------------

_zk_build_dir_cfg: str = _cfg.get("zk_build_dir", "")
if _zk_build_dir_cfg:
    _raw = Path(_zk_build_dir_cfg)
    ZK_BUILD_ROOT: Path = _raw if _raw.is_absolute() else ROOT / _raw
else:
    ZK_BUILD_ROOT = _CORE_DIR / "zk"

ZK_V2_PRE_BUILD_DIR: Path = ZK_BUILD_ROOT / "v2_pre_partial"
ZK_SHARE_POSSESSION_BUILD_DIR: Path = ZK_BUILD_ROOT / "share_possession"
