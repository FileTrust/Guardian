#!/usr/bin/env python3
"""One-node public Guardian installer and service entry point."""
from __future__ import annotations

import argparse
import fcntl
import getpass
import json
import os
import platform
import resource
import shutil
import subprocess
import sys
from pathlib import Path

if __name__ == "__main__" and any(command in sys.argv[1:] for command in ('run','claim-dkg')):
    from ft_update_bootstrap import enter
    enter(Path(__file__).resolve().parent)

from eth_account import Account
from web3 import Web3

from artifact_store import GitHubRelease, TAG, destination, extract, installed, verify_manifest
from network import CONFIG_URL, check_network, config_from_payload, fetch_config

HERE = Path(__file__).resolve().parent


def say(message):
    print(message, flush=True)


def private_directory(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError("Guardian state must not be a symbolic link")
    path.chmod(0o700)
    if path.stat().st_mode & 0o077:
        raise PermissionError("State filesystem does not support private permissions")


def atomic_public_json(path, data):
    # Public configuration must remain plain JSON. Do not use the secret writer.
    import tempfile
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".config-")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def activate(state, key_file):
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.environ["FILETRUST_GUARDIAN_STATE"] = str(state)
    if key_file:
        os.environ["FILETRUST_GUARDIAN_KEY_FILE"] = str(key_file)
    sys.path.insert(0, str(HERE / "runtime"))


def setup_wallet(state):
    from core.g_secret_files import write_json_atomic, load_wallet_config
    if (state / "config.json").exists():
        config = load_wallet_config(state / "config.json")
        say(f"Existing wallet retained: {config['address']}")
        return config["address"]
    if (state / "wallet.json").exists():
        from core.g_secret_files import read_secret_json
        return Account.from_key(read_secret_json(state / "wallet.json")["private_key"]).address
    choice = input("Do you have a wallet private key? [y/N]: ").strip().lower()
    if choice not in ("", "n", "no", "y", "yes"):
        raise ValueError("Answer yes or no; no wallet created")
    if choice in ("y", "yes"):
        if not sys.stdin.isatty():
            raise ValueError("Wallet import requires a terminal so the private key stays hidden")
        try:
            account = Account.from_key(getpass.getpass("Wallet private key (hidden): ").strip())
        except Exception:
            raise ValueError("Invalid wallet private key; nothing saved") from None
    else:
        account = Account.create()
    write_json_atomic(state / "wallet.json", {"private_key": account.key.hex(), "address": account.address})
    say(f"Wallet address: {account.address}")
    return account.address


def selected_bundles(manifest, profiles):
    choices = set(profiles or [])
    bundles = [b for b in manifest["bundles"] if not choices or "n" not in b or f"{b['n']}:{b['t']}" in choices]
    found = {f"{b['n']}:{b['t']}" for b in bundles if "n" in b}
    if choices - found:
        raise ValueError("Requested N:t profile is not in the signed release")
    return bundles


def installation_bundles(manifest, profiles, state):
    """Resuming a small installation must not silently select all profiles."""
    paths = [path for path in (state / "config.json", state / "installation-selection.json") if path.exists()]
    if not paths:
        return selected_bundles(manifest, profiles)
    ids = set()
    for path in paths:
        selected = json.loads(path.read_text()).get("artifact_profiles")
        if not isinstance(selected, list) or not selected or any(not isinstance(name, str) for name in selected):
            raise ValueError("Existing profile selection is missing; review it before reinstalling")
        ids.update(selected)
    by_id = {bundle["id"]: bundle for bundle in manifest["bundles"]}
    if any(not isinstance(name, str) or name not in by_id for name in ids):
        raise ValueError("Existing proof profiles differ from this release; explicit migration required")
    old = {f"{by_id[name]['n']}:{by_id[name]['t']}" for name in ids if "n" in by_id[name]}
    if not old and not profiles:
        raise ValueError("Choose at least one N:t profile explicitly")
    return selected_bundles(manifest, sorted(old | set(profiles or [])))


def check_runtime_version(binary):
    """A runtime probe must never leave installation waiting indefinitely."""
    for attempt in range(2):
        say(f"Checking ZoKrates runtime ({attempt + 1}/2)")
        try:
            result = subprocess.run([str(binary), "--version"], stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            if attempt == 0:
                say("Runtime version check timed out; retrying once. Verified downloads are retained.")
                continue
            raise ValueError("ZoKrates version check timed out. Verified downloads are retained; rerun installation to resume.") from None
        if result.returncode != 0 or "0.8.8" not in result.stdout:
            raise ValueError("ZoKrates runtime check failed; expected version 0.8.8")
        return


def install(args):
    state, key_file = args.home.resolve(), args.key_file.resolve()
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        raise ValueError("The packaged ZoKrates runtime requires Linux x86_64; no unsupported binaries will be installed")
    say("[1/7] Checking the installation and private storage")
    private_directory(state)
    running = (state / ".run.lock").open("a")
    try:
        fcntl.flock(running, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise ValueError("Stop this Guardian after its current work before reinstalling") from None
    lock = (state / ".install.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if not (state / "core").exists():
        shutil.copytree(HERE / "runtime" / "core", state / "core")
        shutil.copy2(HERE / "runtime" / "start.py", state / "start.py")
    activate(state, key_file)
    say("[2/7] Reading the signed release and network settings")
    source = json.loads((HERE / "update-source.json").read_text())
    remote = GitHubRelease(repository=source["repository"], tag=args.release)
    manifest, raw, signature = remote.manifest(HERE / "release-key.pub")
    if manifest["version"] != args.release:
        raise ValueError("Release version differs from signed manifest")
    bundles = installation_bundles(manifest, args.profile, state)
    saved_source = json.loads((state / "config.json").read_text()).get("network_config_url") if (state / "config.json").is_file() else None
    args.config_url = args.config_url or saved_source or CONFIG_URL
    payload = fetch_config(args.config_url)
    config = config_from_payload(payload, state / "core" / "contracts", args.rpc_url, write_abis=False)
    config["network_config_url"] = args.config_url
    w3 = Web3(Web3.HTTPProvider(config["rpc_url"], request_kwargs={"timeout": 30}))
    check_network(w3, config, manifest, bundles, say)
    config['chain_id']=w3.eth.chain_id
    if (state / 'config.json').is_file():
        previous=json.loads((state / 'config.json').read_text())
        for key,value in previous.items():
            bound = key.endswith('_address') or key in ('rpc_url','dkg_attempt_protocol','chain_id')
            if bound and config.get(key,0 if key=='dkg_attempt_protocol' else None)!=value:
                raise ValueError('Network changed; use a fresh installation or an explicit migration')
        old_chain=previous.get('dkg_recovery',{}).get('chain_id')
        if old_chain is not None and old_chain!=w3.eth.chain_id:
            raise ValueError('Recovery custody belongs to another chain; explicit migration required')
    # Only write ABIs after the signed binding and existing identity's origin
    # are checked. A refused migration must not rewrite the old node's files.
    config_from_payload(payload, state / 'core' / 'contracts', args.rpc_url)
    atomic_public_json(state / "installation-selection.json", {"artifact_profiles": [bundle["id"] for bundle in bundles]})
    (state / "manifest.json").write_bytes(raw)
    (state / "manifest.sig").write_bytes(signature)
    artifacts = state / "artifacts"
    artifacts.mkdir(exist_ok=True)
    required = sum(sum(f["size"] for f in b["files"].values()) + b["size"] for b in bundles
                   if not installed(destination(artifacts, b), b))
    if shutil.disk_usage(state).free < required + 512 * 1024**2:
        raise ValueError(f"Not enough free space; need about {required / 1024**3:.1f} GiB plus 512 MiB reserve")
    say("[3/7] Downloading and checking public proof artifacts")
    for number, bundle in enumerate(bundles, 1):
        say(f"Artifact {number}/{len(bundles)} — {bundle['id']}")
        target = destination(artifacts, bundle)
        if installed(target, bundle):
            say("Already installed; checksums passed")
            continue
        archive = remote.download(bundle, state / "downloads", say)
        extract(archive, target, bundle)
    binary = artifacts / "runtime-linux-x86_64" / "zokrates"
    check_runtime_version(binary)
    say("[4/7] Importing or creating your protected wallet")
    if not key_file.exists():
        # Never replace the only unlock key for existing encrypted material.
        if (state / "wallet.json").exists():
            raise ValueError("Unlock key missing; restore it from backup")
        private_directory(key_file.parent)
        fd = os.open(key_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(os.urandom(32))
            output.flush()
            os.fsync(output.fileno())
    config["address"] = setup_wallet(state)
    config["zk_build_dir"] = str(artifacts)
    config["zokrates_bin"] = str(binary)
    config["artifact_profiles"] = [b["id"] for b in bundles]
    if (state / "config.json").exists():
        previous = json.loads((state / "config.json").read_text())
        if previous["address"].lower() != config["address"].lower():
            raise ValueError("Existing Guardian identity differs; automatic replacement refused")
        # This is a resume operation, never a silent chain migration or settings reset.
        for key, value in previous.items():
            if key not in ("artifact_profiles", "zk_build_dir", "zokrates_bin"):
                if key.endswith("_address") or key == "rpc_url":
                    if key in config and config[key] != value:
                        raise ValueError("Network changed; use a fresh installation or an explicit migration")
                config[key] = value
    if config.get('dkg_attempt_protocol')==1:
        from recovery_install import operator_limits,profile_document
        from core.g_dkg_recovery_contracts import RecoveryContracts
        RecoveryContracts(w3,config['zkdkg_coordinator_v2_address'],config['acl_address'],
            config['guardian_registry_address'],config['staking_manager_address'])
        say('Accepted duties reserve collateral. Missed accepted work may use that collateral; completed fees are escrow credits.')
        limits=operator_limits(config.get('dkg_recovery'),w3.eth.gas_price)
        raw,digest=profile_document(state,config,manifest,bundles,w3.eth.chain_id)
        atomic_public_json(state/'recovery-profiles.json',json.loads(raw))
        # Pin the bytes actually written by the same atomic JSON encoder.
        import hashlib
        digest=hashlib.sha256((state/'recovery-profiles.json').read_bytes()).hexdigest()
        config['dkg_recovery']={**limits,'chain_id':w3.eth.chain_id,
            'profile_document':'recovery-profiles.json','profile_document_sha256':digest}
    atomic_public_json(state / "config.json", config)
    say("[5/7] Checking backup and recovery requirements")
    say(f"Back up {state} and {key_file} separately. Both are needed to recover shares and wallet.")
    say("The local unlock key enables automatic restart; it does not protect against a full host copy or root compromise.")
    say("[6/7] Preparing automatic service startup")
    if args.service:
        service(state, key_file)
    say("[7/7] Installation checks passed")
    balance = w3.eth.get_balance(config["address"])
    say(f"Wallet: {config['address']} — balance: {balance} wei")
    say("Fund this wallet and review staking/pricing before starting; registration spends network fees and stake.")
    if os.environ.get('FILETRUST_CONTAINER') == '1':
        say("Docker setup complete. Run ./docker.sh start when ready.")
    else:
        say("Service is installed but not started." if args.service else "Run guardian.py run to start when ready.")


def service(state, key_file):
    if os.getuid() != 0 or not Path("/run/systemd/system").is_dir():
        raise ValueError("Automatic system service installation requires root and systemd")
    service_unit(state, key_file)
    import pwd
    try:
        user = pwd.getpwnam("ftguardian")
    except KeyError:
        subprocess.run(["useradd", "--system", "--home-dir", str(state), "--shell", "/usr/sbin/nologin", "ftguardian"], check=True)
        user = pwd.getpwnam("ftguardian")
    for parent, dirs, files in os.walk(state):
        os.chown(parent, user.pw_uid, user.pw_gid)
        for name in files:
            os.chown(Path(parent) / name, user.pw_uid, user.pw_gid, follow_symlinks=False)
    unit = service_unit(state, key_file)
    os.chown(key_file, 0, 0, follow_symlinks=False)
    key_file.chmod(0o600)
    Path("/etc/systemd/system/filetrust-guardian.service").write_text(unit)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "filetrust-guardian.service"], check=True)


def service_unit(state, key_file):
    if any(c in str(state) + str(key_file) + str(HERE) + sys.executable for c in "\n\r\t %\\\""):
        raise ValueError("Service paths must not contain whitespace or systemd expansion characters")
    unit = f"""[Unit]
Description=FileTrust public Guardian
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=ftguardian
Group=ftguardian
WorkingDirectory={state}
LoadCredential=unlock.key:{key_file}
Environment=PYTHONDONTWRITEBYTECODE=1
RuntimeDirectory=filetrust-guardian
RuntimeDirectoryMode=0700
Environment=TMPDIR=/run/filetrust-guardian
ExecStart={sys.executable} {HERE / 'guardian.py'} --home {state} run
Restart=on-failure
RestartSec=15
UMask=0077
LimitCORE=0
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths={state}
RestrictSUIDSGID=yes
CapabilityBoundingSet=
KillMode=mixed
TimeoutStopSec=infinity
SendSIGKILL=no

[Install]
WantedBy=multi-user.target
"""
    return unit


def doctor(args):
    state = args.home.resolve()
    activate(state, args.key_file.resolve())
    from core.g_secret_files import load_wallet_config
    config = load_wallet_config(state / "config.json")
    account = Account.from_key(config["private_key"])
    if account.address.lower() != config["address"].lower():
        raise ValueError("Wallet address mismatch")
    manifest = verify_manifest((state / "manifest.json").read_bytes(), (state / "manifest.sig").read_bytes(), HERE / "release-key.pub")
    bundles = [b for b in manifest["bundles"] if b["id"] in config["artifact_profiles"]]
    if len(bundles) != len(config["artifact_profiles"]):
        raise ValueError("Installed profile list differs from signed release")
    for number, bundle in enumerate(bundles, 1):
        say(f"Checking artifact {number}/{len(bundles)}: {bundle['id']}")
        if not installed(destination(state / "artifacts", bundle), bundle):
            raise ValueError("Missing or changed artifacts; rerun installation")
    binary = state / "artifacts" / "runtime-linux-x86_64" / "zokrates"
    if Path(config["zokrates_bin"]).resolve() != binary.resolve() or Path(config["zk_build_dir"]).resolve() != (state / "artifacts").resolve():
        raise ValueError("Runtime paths differ from verified artifacts")
    check_network(Web3(Web3.HTTPProvider(config["rpc_url"], request_kwargs={"timeout": 30})), config, manifest, bundles, say)
    if config.get('dkg_attempt_protocol')==1:
        from core.g_dkg_recovery_contracts import PinnedProfiles,RecoveryContracts
        w3=Web3(Web3.HTTPProvider(config['rpc_url'],request_kwargs={'timeout':30}))
        RecoveryContracts(w3,config['zkdkg_coordinator_v2_address'],config['acl_address'],
            config['guardian_registry_address'],config['staking_manager_address'])
        settings=config['dkg_recovery']
        if settings['chain_id']!=w3.eth.chain_id:raise ValueError('Recovery custody belongs to another chain')
        pins=PinnedProfiles(state/settings['profile_document'],settings['profile_document_sha256'],w3.eth.chain_id,
            config['zkdkg_coordinator_v2_address'])
        for (n,t),profile in pins.profiles.items():pins.check(w3,n,t,profile['verifier'])
    say(f"Guardian checks passed: {account.address}")


def run(args):
    state = args.home.resolve()
    # Prevent two Guardian supervisors using the same wallet and state folder.
    lock = (state / ".run.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    doctor(args)
    os.environ.pop("GH_TOKEN", None)
    os.environ.pop("GITHUB_TOKEN", None)
    os.environ["FILETRUST_GUARDIAN_APP_DIR"] = str(HERE)
    os.chdir(state)
    os.set_inheritable(lock.fileno(), True)
    os.environ["FILETRUST_GUARDIAN_STATE_LOCK_FD"] = str(lock.fileno())
    os.execv(sys.executable, [sys.executable, "-u", str(HERE / "runtime" / "start.py")])


def claim_dkg(args):
    # Use the node's owner and systemd's private credential channel. Running
    # its outbox as root would replace 0600 files with root-owned state.
    owner=args.home.resolve().stat()
    if os.geteuid()==0 and owner.st_uid!=0:
        command=['systemd-run','--wait','--pipe','--collect',
            '-p',f'User={owner.st_uid}','-p',f'Group={owner.st_gid}',
            '-p',f'LoadCredential=unlock.key:{args.key_file.resolve()}',
            sys.executable,str(HERE/'guardian.py'),'--home',str(args.home.resolve()),
            '--key-file',str(args.key_file.resolve()),'claim-dkg']
        if args.confirm:command.append('--confirm')
        result=subprocess.run(command)
        if result.returncode:raise RuntimeError('Guardian withdrawal did not complete; signed state is retained for retry')
        return
    doctor(args)
    from core import g_config as cfg
    from core.g_dkg_claim import claim
    w3=Web3(Web3.HTTPProvider(cfg.RPC_URL,request_kwargs={'timeout':30}))
    account=w3.eth.account.from_key(cfg.SH_PRIVATE_KEY)
    claim(cfg,w3,account,lambda _:args.confirm or input('Withdraw these credits to your wallet? [y/N]: ').strip().lower() in ('y','yes'))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--home", type=Path, default=Path("/var/lib/filetrust-guardian"))
    p.add_argument("--key-file", type=Path, default=Path("/etc/filetrust-guardian/unlock.key"))
    sub = p.add_subparsers(dest="command", required=True)
    setup = sub.add_parser("install")
    setup.add_argument("--release", default=TAG)
    setup.add_argument("--config-url", default=None)
    setup.add_argument("--rpc-url", default=None, help="Optional HTTPS RPC override; otherwise use the network configuration service")
    setup.add_argument("--profile", action="append", help="Optional N:t subset; default downloads all published profiles")
    setup.add_argument("--service", action="store_true")
    sub.add_parser("doctor")
    sub.add_parser("run")
    claim_parser=sub.add_parser('claim-dkg',help='Withdraw earned fees, refunds and compensation from the recovery escrow')
    claim_parser.add_argument('--confirm',action='store_true',help='Approve within configured transaction fee limits')
    args = p.parse_args()
    try:
        {"install": install, "doctor": doctor, "run": run,'claim-dkg':claim_dkg}[args.command](args)
    except (Exception, KeyboardInterrupt) as exc:
        # Exception details from key import/JSON parsing must never reveal inputs.
        safe = str(exc) if isinstance(exc, (ValueError, RuntimeError, PermissionError)) else type(exc).__name__
        say(f"Guardian stopped: {safe}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
