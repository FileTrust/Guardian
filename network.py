"""Read-only bootstrap and strict verifier compatibility checks."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import requests
from web3 import Web3

CONFIG_URL = "https://config.filetrust.io/v1/network-config"

CONTRACTS = {
    "guardian_registry": "GuardianRegistry", "vault_keeper_registry": "VaultKeeperRegistry",
    "acl": "AccessControlFT", "dv": "DataVault", "telg_v2": "TElGv2",
    "zkdkg_coordinator_v2": "ZkDkgCoordinatorV2", "guardian_share_proof": "GuardianShareProof",
    "zkdkg_dispute_manager": "ZkDkgDisputeManager", "reputation_manager": "ReputationManager",
    "staking_manager": "StakingManager", "reward_manager": "RewardManager",
    "file_registration": "FileRegistrationSC", "zkdkg_share_verifier": "ShareVerifier",
    "v2_pre_partial_verifier": "V2PrePartialVerifier", "share_possession_verifier": "SharePossessionVerifier",
}


def fetch_config(url=CONFIG_URL):
    if not url.startswith("https://"):
        raise ValueError("Network configuration requires HTTPS")
    with requests.get(url, headers={"User-Agent": "FileTrust-Guardian/1"}, stream=True, timeout=(20, 30)) as response:
        response.raise_for_status()
        body = bytearray()
        for chunk in response.iter_content(65536):
            body.extend(chunk)
            if len(body) > 16 * 1024 * 1024:
                raise ValueError("Network configuration exceeds size limit")
        result = json.loads(body)
    if not isinstance(result.get("network"), dict) or not isinstance(result.get("deployed_addresses"), dict):
        raise ValueError("Invalid network configuration")
    return result


def config_from_payload(payload, contracts: Path, rpc_url=None, *, write_abis=True):
    deployed = payload["deployed_addresses"]
    addresses = deployed.get("contracts", {})
    env = deployed.get("env", {})
    config = {"rpc_url": rpc_url or payload["network"].get("rpc_url"), "guardian_index": 1,
              "n": 5, "t": 3, "is_coordinator": False, "poll_interval": 10,
              "dkg_workers": 1, "wallet_file": "wallet.json", "auto_claim_rewards": True}
    protocol=deployed.get('capabilities',{}).get('dkgAttemptProtocol',0)
    if type(protocol) is not int or protocol not in (0,1):raise ValueError('Unsupported DKG deployment version')
    config['dkg_attempt_protocol']=protocol
    if not str(config["rpc_url"]).startswith("https://"):
        raise ValueError("Choose the HTTPS RPC gateway with --rpc-url")
    artifacts = payload.get("artifact_files", {})
    if write_abis:contracts.mkdir(parents=True, exist_ok=True)
    for prefix, name in CONTRACTS.items():
        address = addresses.get(name) or env.get(prefix.upper() + "_ADDRESS")
        artifact = artifacts.get(name + ".json")
        if not Web3.is_address(address or "") or not isinstance(artifact, dict) or not isinstance(artifact.get("abi"), list):
            raise ValueError(f"Missing contract address or ABI: {name}")
        config[prefix + "_address"] = Web3.to_checksum_address(address)
        config[prefix + "_json"] = "contracts/" + name + ".json"
        # Only ABIs are needed, never execute code supplied by the bootstrap API.
        if write_abis:(contracts / (name + ".json")).write_text(json.dumps({"abi": artifact["abi"]}))
    return config


def verifier_address(w3, config, bundle):
    name = bundle["id"]
    if name == "v2_pre_partial":
        return config["v2_pre_partial_verifier_address"]
    if name == "share_possession":
        return config["share_possession_verifier_address"]
    address = config["zkdkg_dispute_manager_address"]
    n, t = int(bundle["n"]), int(bundle["t"])
    for signature, values in (("zkDkgShareVerifierByCommittee(uint8,uint8)", [n, t]),
                              ("zkDkgShareVerifierByParticipantCount(uint8)", [n]),
                              ("zkDkgShareVerifier()", [])):
        data = Web3.keccak(text=signature)[:4] + b"".join(v.to_bytes(32, "big") for v in values)
        raw = bytes(w3.eth.call({"to": address, "data": data}))
        if len(raw) != 32:
            raise ValueError("Invalid verifier registry response")
        if any(raw[-20:]):
            return Web3.to_checksum_address(raw[-20:])
    raise ValueError("No verifier registered for this N/t profile")


def check_network(w3, config, manifest, bundles, progress=print):
    chain = str(w3.eth.chain_id)
    binding = manifest.get("networks", {}).get(chain)
    if not binding:
        raise ValueError("This artifact release is not approved for the selected chain ID")
    if config.get('dkg_attempt_protocol',0)!=binding.get('dkg_attempt_protocol',0):
        raise ValueError('The DKG protocol differs from the signed release; explicit versioned installation required')
    for key, address in binding["contracts"].items():
        if config.get(key, "").lower() != address.lower():
            raise ValueError("Configured contracts differ from the signed release network")
    for bundle in bundles:
        if bundle["id"].startswith("runtime-"):
            continue
        address = verifier_address(w3, config, bundle)
        expected = binding["verifiers"].get(bundle["id"])
        code = bytes(w3.eth.get_code(address))
        if not expected or expected["address"].lower() != address.lower() or not code or hashlib.sha256(code).hexdigest() != expected["code_sha256"]:
            raise ValueError(f"Verifier mismatch: {bundle['id']}; no registration or proof submission permitted")
        progress(f"Verifier checked: {bundle['id']}")


def key_matches_code(key_path, code):
    """Publication sanity check; runtime binds the resulting exact bytecode hash."""
    key = json.loads(Path(key_path).read_text())
    if key.get("scheme") != "g16" or key.get("curve") != "bn128":
        raise ValueError("Unexpected proving system")
    constants = []
    def flatten(value):
        if isinstance(value, list):
            for item in value:
                flatten(item)
        else:
            constants.append(str(value).lower().removeprefix("0x").lstrip("0") or "0")
    for field in ("alpha", "beta", "gamma", "delta", "gamma_abc"):
        flatten(key[field])
    return all(value in code.hex() for value in constants)
