#!/usr/bin/env python3
"""Independent Guardian instance Guardian."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

CODE_ROOT = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("FILETRUST_GUARDIAN_STATE", str(CODE_ROOT)))
CORE = CODE_ROOT / "core"
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))
from core.g_tx import send_contract_transaction
from core import g_lifecycle
from core.g_secret_files import restrict_secret_file, write_json_atomic, read_secret_json, load_wallet_config

LOGS      = ROOT / "logs"
CONTRACTS = ROOT / "core/contracts" if (ROOT / "core/contracts").is_dir() else CORE / "contracts"
LOGS.mkdir(exist_ok=True)

_CFG_PATH = ROOT / "config.json"
_KEY_PATH = ROOT / "guardian_encryption_key.json"

NAME = "Guardian"


def _start_log_archiver() -> None:
    """Zip finished logs in this instance's logs/ and drop old ones, then daily."""
    try:
        from core import log_archive

        with open(_CFG_PATH, encoding="utf-8") as f:
            cfg = json.load(f)
        log_archive.start_daily(
            LOGS,
            keep_days_by_name={"transactions": 90, "calls": 3},
            **log_archive.options_from_config(cfg),
        )
    except Exception:
        pass  # tidying logs must never stop a Guardian starting


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _load_cfg() -> dict:
    return load_wallet_config(_CFG_PATH)


def _say(message: str) -> None:
    """Print, and keep a copy on disk.

    A Guardian that refuses to start says so in a terminal window that a reboot
    may well have closed by the time anyone looks. The copy is the part an
    operator actually reads.
    """
    print(message, flush=True)
    try:
        with open(LOGS / "startup.log", "a", encoding="utf-8") as f:
            f.write(f"{datetime.now(timezone.utc).isoformat(timespec='seconds')} {message}\n")
    except Exception:
        pass


def _wait_for_chain(cfg: dict):
    """Wait for the chain instead of giving up on it.

    The three watchers a Guardian spawns already wait for the RPC with backoff.
    Startup did not: it looked once and exited. That single difference is what
    made a reboot dangerous — bring a machine up before its chain node and the
    Guardian was gone within seconds, quietly, with nothing to restart it.

    Waiting is deliberately open-ended. A deadline here would just recreate the
    same race on a slower boot. The URL is named in every message, so a genuinely
    wrong address is obvious rather than mysterious.
    """
    from web3 import Web3

    registry_address = cfg.get("guardian_registry_address", "")
    from core.g_dkg_rpc import ReadRetryHTTPProvider
    attempt = 0
    while True:
        if g_lifecycle.STOP.is_set():
            raise SystemExit(0)
        attempt += 1
        try:
            w3 = Web3(ReadRetryHTTPProvider(cfg["rpc_url"], request_kwargs={"timeout": 30}))
            if not w3.is_connected():
                reason = "no answer yet"
            else:
                # A node can accept a socket before it can serve a call, and the
                # contracts can still be deploying after that.
                w3.eth.block_number
                if registry_address and not w3.eth.get_code(
                    Web3.to_checksum_address(registry_address)
                ):
                    reason = "chain is up, but the registry is not deployed yet"
                else:
                    if attempt > 1:
                        _say(f"[{NAME}] chain is ready (after {attempt} tries)")
                    return w3
        except Exception as exc:
            reason = str(exc).splitlines()[0][:120]

        delay = min(30, 2 ** min(attempt, 5))
        message = (
            f"[{NAME}] waiting for the chain at {cfg['rpc_url']} — "
            f"{reason}; trying again in {delay}s"
        )
        # Keep a copy now and then, so an all-night wait leaves a trail without
        # filling the log with one line every thirty seconds.
        if attempt == 1 or attempt % 10 == 0:
            _say(message)
        else:
            print(message, flush=True)
        time.sleep(delay)


def _send_tx(w3, account, fn, label: str, value: int = 0) -> None:
    _cfg_gas = _load_cfg()
    gas_price = int(_cfg_gas.get("filetrust_fixed_gas_price_wei", 1_000_000))
    gas = fn.estimate_gas({"from": account.address, "value": value})
    _tx_hash, receipt, _tx = send_contract_transaction(
        w3,
        account,
        fn,
        gas=gas + 50_000,
        gas_price=gas_price,
        value=value,
        lock_root=ROOT,
    )
    if receipt.status != 1:
        raise RuntimeError(f"[{NAME}] {label} tx failed")
    print(f"[{NAME}] {label} OK  tx={receipt.transactionHash.hex()}")


# ---------------------------------------------------------------------------
# step 1 — X25519 keypair
#
# The secret half of this key lives in exactly one place: the file below. The
# chain cannot hand it back and neither can the other Guardians. Everything else
# in this folder can be rebuilt from the chain, so "missing? make a new one" is
# safe for all of it and ruinous here: a replacement key cannot open any share
# ever sent to the old one, and the Guardian goes on looking perfectly healthy
# while helping with nothing.
#
# Generating is right on the very first start and wrong on every start after it.
# The only way to tell those apart is to ask the chain, which holds the public
# half. So that is what happens here, before anything else is done.
# ---------------------------------------------------------------------------

def _public_key_hex(private_key_hex: str) -> str:
    """The public half, rebuilt from the secret half rather than trusted."""
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization

    raw = bytes.fromhex(str(private_key_hex).replace("0x", ""))
    priv = x25519.X25519PrivateKey.from_private_bytes(raw)
    return "0x" + priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    ).hex()


def _chain_enc_key(cfg: dict, w3=None) -> tuple:
    """What key the chain holds for this Guardian.

    Returns (status, public_key_hex, registered_at) where status is:
      "ok"          the chain has a key, and it is returned
      "none"        the chain has never seen this Guardian (or there is no
                    registry configured to ask)
      "unreadable"  the chain could not be asked at all
    Keeping "none" and "unreadable" apart is the whole point: one means a first
    start, the other means we simply do not know yet.
    """
    from web3 import Web3

    registry_address = cfg.get("guardian_registry_address", "")
    artifact = CONTRACTS / "GuardianRegistry.json"
    if not registry_address or not artifact.exists():
        return "none", "", 0

    address = Web3.to_checksum_address(cfg["address"])
    try:
        if w3 is None:
            w3 = Web3(Web3.HTTPProvider(cfg["rpc_url"]))
        abi = json.loads(artifact.read_text(encoding="utf-8"))["abi"]
        gr = w3.eth.contract(
            address=Web3.to_checksum_address(registry_address), abi=abi,
        )
        if not bool(gr.functions.isRegisteredGuardian(address).call()):
            return "none", "", 0
        profile = gr.functions.getGuardian(address).call()
        return "ok", "0x" + bytes(profile[1]).hex(), int(profile[14])
    except Exception:
        return "unreadable", "", 0


def _generate_enc_key(cfg: dict) -> None:
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization
    from web3 import Web3

    priv = x25519.X25519PrivateKey.generate()
    pub  = priv.public_key()
    data = {
        "curve":            "X25519",
        "guardian_address": Web3.to_checksum_address(cfg["address"]),
        "guardian_index":   cfg["guardian_index"],
        "private_key_hex":  "0x" + priv.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()).hex(),
        "public_key_hex":   "0x" + pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
    }
    write_json_atomic(_KEY_PATH, data)
    _say(f"[{NAME}] X25519 key generated -> {_KEY_PATH}")


def _refuse_mismatch(cfg: dict, on_disk: str, on_chain: str, registered_at: int) -> None:
    when = ""
    if registered_at:
        when = "  (registered {})".format(
            datetime.fromtimestamp(int(registered_at), timezone.utc).strftime("%Y-%m-%d")
        )
    _say(
        f"\n[{NAME}] === WILL NOT START ===\n"
        f"\nGuardian {NAME}  ({cfg['address']})\n"
        f"\n  key on the chain : {on_chain}{when}\n"
        f"  key on my disk   : {on_disk or 'MISSING'}\n"
        f"\n  These are not the same. I will not start.\n"
        f"  My old key file is gone or wrong.\n"
        f"  Shares sent to me before today cannot be opened by me.\n"
        f"\n  Put the old key file back:\n"
        f"    {_KEY_PATH}\n"
        f"\n  Or, to make a new key on purpose, start me with --new-key.\n"
        f"  A new key abandons every share already sent to the old one.\n"
    )


def _ensure_enc_key(cfg: dict, allow_new_key: bool = False, w3=None) -> bool:
    """Return True to carry on, False to stop before any work is done."""
    on_disk = ""
    if _KEY_PATH.exists():
        restrict_secret_file(_KEY_PATH)
        try:
            data = read_secret_json(_KEY_PATH)
            on_disk = _public_key_hex(data["private_key_hex"])
        except Exception as exc:
            _say(
                f"\n[{NAME}] === WILL NOT START ===\n"
                f"\n  My key file is there but I cannot read it: {exc}\n"
                f"    {_KEY_PATH}\n"
                f"\n  I will not make a new one on top of it, because that would\n"
                f"  throw away every share already sent to me. Restore the file.\n"
            )
            return False

    status, on_chain, registered_at = _chain_enc_key(cfg, w3)

    if status == "unreadable":
        if on_disk:
            # Startup already waited for the chain, so this means it went away
            # again in the meantime. That must not stop a Guardian that has its key.
            _say(f"[{NAME}] could not reach the chain to check my key — keeping the one I have")
            return True
        _say(
            f"\n[{NAME}] === WILL NOT START ===\n"
            f"\n  I have no key file, and I cannot reach the chain to ask whether\n"
            f"  I already have one: {cfg['rpc_url']}\n"
            f"\n  Making a key now could throw away every share already sent to me,\n"
            f"  so I would rather wait. Start the chain, then start me again.\n"
        )
        return False

    if status == "none":
        if on_disk:
            return True  # not registered yet — registration will publish this key
        _say(f"[{NAME}] first start: no key here, and none on the chain")
        _generate_enc_key(cfg)
        return True

    if on_disk and on_disk.lower() == on_chain.lower():
        print(f"[{NAME}] encryption key matches the chain — reusing")
        return True

    if allow_new_key:
        _say(f"[{NAME}] --new-key given: replacing the key the chain knows, on purpose")
        if not on_disk:
            _generate_enc_key(cfg)
        return True

    _refuse_mismatch(cfg, on_disk, on_chain, registered_at)
    return False


# ---------------------------------------------------------------------------
# step 2 — blockchain registration (idempotent)
# ---------------------------------------------------------------------------

def _register(cfg: dict, w3=None) -> None:
    from web3 import Web3
    from core import g_txlog as TX
    from core.g_tx import read_contract_value
    TX.install(cfg)

    if w3 is None:
        w3 = _wait_for_chain(cfg)

    account = w3.eth.account.from_key(cfg["private_key"])
    address = Web3.to_checksum_address(cfg["address"])
    if account.address.lower() != address.lower():
        raise ValueError(f"[{NAME}] private key does not match address")

    def _contract(addr_key: str, abi_file: str):
        addr = cfg.get(addr_key, "")
        if not addr:
            return None
        p = CONTRACTS / abi_file
        if not p.exists():
            return None
        abi = json.loads(p.read_text(encoding="utf-8")).get("abi")
        return w3.eth.contract(address=Web3.to_checksum_address(addr), abi=abi)

    gr      = _contract("guardian_registry_address", "GuardianRegistry.json")
    staking = _contract("staking_manager_address",   "StakingManager.json")

    if gr is None:
        print(f"[{NAME}] GuardianRegistry not configured — skipping registration")
        return

    min_stake = int(read_contract_value(gr.functions.minStake()))
    if staking:
        min_stake = int(read_contract_value(staking.functions.minStake()))
    if min_stake <= 0:
        try:
            min_stake = int(cfg.get("min_guardian_stake_wei", 0))
        except Exception:
            pass

    # The explicit development profile provisions its approved bond reserve.
    # This is the operator's stake target; protocol minimums stay on chain.
    reserve = cfg.get("dkg_recovery", {}).get("test_stake_reserve_wei", 0)
    if reserve:
        limits = cfg["dkg_recovery"].get("acceptance", {})
        if (type(reserve) is not int or reserve < 0 or
                cfg.get("dkg_attempt_protocol") != 1 or
                int(w3.eth.chain_id) not in (31337, 31338, 31339) or
                limits.get("enabled") is not True or
                reserve != limits.get("max_bond_wei", 0) * limits.get("max_concurrent_attempts", 0)):
            raise ValueError("Invalid explicit development Guardian bond reserve")
    target_stake = min_stake + reserve

    key_data = read_secret_json(_KEY_PATH)
    pubkey   = bytes.fromhex(key_data["public_key_hex"].replace("0x", ""))
    metadata = f"guardian-{cfg['guardian_index']}"

    already = bool(read_contract_value(gr.functions.isRegisteredGuardian(address)))

    try:
        from core.g_pricing import normalize_guardian_service_prices, sync_guardian_service_pricing
        _prices = normalize_guardian_service_prices(cfg.get("service_prices", {}))
    except Exception:
        _prices = {"dkg_material_su": 12000, "dkg_share_key_su": 6325, "pre_batch_partial_su": 30542,
                   "daily_share_custody_su": 0, "max_service_days": 0}

    if already:
        print(f"[{NAME}] already registered — updating")
        _send_tx(w3, account,
                 gr.functions.updateGuardian(pubkey, metadata, 0, 0, 0),
                 "updateGuardian")
        stake_now = int(read_contract_value(staking.functions.stakeOf(address))) if staking \
                    else int(read_contract_value(gr.functions.getGuardian(address))[8])
        if stake_now < target_stake:
            fn = staking.functions.depositStake() if staking else gr.functions.depositStake()
            _send_tx(w3, account, fn, "depositStake (top-up)", value=target_stake - stake_now)
        try:
            sync_guardian_service_pricing(
                w3=w3, guardian_registry=gr, account=account,
                private_key=cfg["private_key"], prices=_prices, label=NAME,
            )
        except Exception as exc:
            print(f"[{NAME}] service pricing sync skipped: {exc}")
    else:
        print(f"[{NAME}] registering  stake={target_stake} wei")
        _send_tx(w3, account,
                 gr.functions.registerGuardian(
                     pubkey, metadata, 0, 0, 0,
                     int(_prices["dkg_material_su"]),
                     int(_prices["dkg_share_key_su"]),
                     int(_prices["pre_batch_partial_su"]),
                     int(_prices["daily_share_custody_su"]),
                     int(_prices.get("max_service_days", 0)),
                 ),
                 "registerGuardian", value=target_stake)


# ---------------------------------------------------------------------------
# step 3 — launch watcher subprocesses
# ---------------------------------------------------------------------------

_PROCS: list = []
_last_line: dict = {}


def _forward(tag: str, stream, log_path: Path) -> None:
    with open(log_path, "a", encoding="utf-8") as lf:
        for line in iter(stream.readline, ""):
            lf.write(f"[{NAME}/{tag}] {line}")
            lf.flush()
            stripped = line.rstrip()
            if stripped and stripped == _last_line.get(tag):
                continue
            _last_line[tag] = stripped
            sys.stdout.write(f"[{NAME}/{tag}] {line}")
            sys.stdout.flush()


def _spawn(tag: str, script: str) -> subprocess.Popen:
    from ft_update_bootstrap import child_lock_options
    p = subprocess.Popen(
        [sys.executable, "-u", str(CORE / script)],
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env={**os.environ, "FILETRUST_GUARDIAN_SUPERVISOR_PID": str(os.getpid())},
        **child_lock_options(),
    )
    _PROCS.append(p)
    threading.Thread(
        target=_forward,
        args=(tag, p.stdout, LOGS / f"{script}.log"),
        daemon=True,
    ).start()
    return p


def _stop_all() -> None:
    (ROOT / ".filetrust-node-health.json").unlink(missing_ok=True)
    for p in _PROCS:
        if p.poll() is None:
            p.terminate()
    for p in _PROCS:
        p.wait()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    g_lifecycle.install()
    allow_new_key = "--new-key" in sys.argv[1:]
    cfg = _load_cfg()
    print(f"[{NAME}] === startup ===")
    _start_log_archiver()
    app_dir = os.environ.get("FILETRUST_GUARDIAN_APP_DIR")
    if app_dir:
        try:
            sys.path.insert(0, app_dir)
            from ft_updates import start_watcher
            start_watcher(app_dir, log=_say, state_dir=ROOT / "updates")
        except Exception:
            _say("Application update checks unavailable; Guardian work continues.")
    # Wait first, so the key check below gets a real answer from the chain
    # rather than an "I could not ask".
    w3 = _wait_for_chain(cfg)
    if g_lifecycle.STOP.is_set():
        return 0
    if not _ensure_enc_key(cfg, allow_new_key, w3):
        return 2
    if g_lifecycle.STOP.is_set():
        return 0
    from core.g_startup_tx import recover_pending_transactions
    if not recover_pending_transactions(w3, cfg, ROOT, g_lifecycle.STOP, _say):
        return 0
    _register(cfg, w3)
    if g_lifecycle.STOP.is_set():
        return 0
    from core.g_heartbeat import start as start_heartbeat
    start_heartbeat(cfg, ROOT, g_lifecycle.STOP, _say)
    print(f"[{NAME}] launching watchers")
    _spawn("DKG",   "g_dkg.py")
    _spawn("PRE",   "g_pre.py")
    _spawn("PROOF", "g_share_proof.py")
    if app_dir:
        from ft_update_bootstrap import ready
        ready(app_dir, ROOT)
    try:
        while not g_lifecycle.STOP.wait(1):
            for p in _PROCS:
                if p.poll() is not None:
                    print(f"[{NAME}] subprocess exited (code={p.returncode}). Stopping.")
                    _stop_all()
                    return p.returncode or 1
        _stop_all()
        return 0
    except KeyboardInterrupt:
        _stop_all()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
