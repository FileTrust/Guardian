"""Explicit versioned deployment and locally approved proof-profile bindings.

No configuration, wallet or network access at import. A missing/changed pin is
an error, never permission to use whatever verifier the RPC currently reports.
The installer/deployment approval supplies the profile document and its digest.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

from web3 import Web3


def record(fn):
    result = fn.call()
    fields = fn.abi['outputs']
    if len(fields) == 1 and fields[0]['type'] == 'tuple':
        fields = fields[0]['components']
    return SimpleNamespace(**{f['name']: value for f, value in zip(fields, result)})


def contract(w3, name, address):
    artifact = json.loads((Path(__file__).parent / 'contracts/recovery-v1' / f'{name}.json').read_text())
    if artifact.get('protocol') != 'filetrust-dkg-recovery-v1':
        raise RuntimeError('Wrong DKG recovery ABI version')
    address = Web3.to_checksum_address(address)
    if not w3.eth.get_code(address):
        raise RuntimeError('DKG recovery contract is not deployed')
    return w3.eth.contract(address=address, abi=artifact['abi'])


class RecoveryContracts:
    def __init__(self, w3, coordinator_address, acl_address, guardian_registry_address, staking_address):
        self.coordinator = contract(w3, 'ZkDkgCoordinatorV2', coordinator_address)
        co = self.coordinator.functions
        self.controller = contract(w3, 'DkgAttemptController', co.attemptController().call())
        ctrl = self.controller.functions
        self.acl = contract(w3, 'AccessControlFT', acl_address)
        self.guardians = contract(w3, 'GuardianRegistry', guardian_registry_address)
        self.staking = contract(w3, 'StakingManager', staking_address)
        self.manager = contract(w3, 'ZkDkgDisputeManager', co.disputeManager().call())
        self.registry = contract(w3, 'DkgAttemptRegistry', ctrl.registry().call())
        self.escrow = contract(w3, 'DkgAttemptEscrow', ctrl.escrow().call())
        self.book = contract(w3, 'DkgCommitmentBook', ctrl.commitments().call())
        checks = [(co.acl().call(), self.acl.address),
                  (ctrl.coordinator().call(), self.coordinator.address),
                  (ctrl.acl().call(), self.acl.address), (ctrl.staking().call(), self.staking.address),
                  (self.acl.functions.guardianRegistry().call(), self.guardians.address),
                  (self.guardians.functions.stakingManager().call(), self.staking.address),
                  (self.manager.functions.zkDkgCoordinatorV2().call(), self.coordinator.address),
                  (self.manager.functions.dkg().call(), self.coordinator.address),
                  (self.manager.functions.acl().call(), self.acl.address),
                  (self.registry.functions.coordinator().call(), self.controller.address),
                  (self.escrow.functions.coordinator().call(), self.controller.address),
                  (self.escrow.functions.staking().call(), self.staking.address),
                  (self.book.functions.controller().call(), self.controller.address)]
        if any(a.lower() != b.lower() for a, b in checks):
            raise RuntimeError('DKG recovery deployment wiring does not match the selected network')


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


class PinnedProfiles:
    """A digest-approved local profile list, scoped to one chain/deployment.

    Contains hashes/paths of already published setup files, never setup secrets.
    Does not download or generate keys/contracts. Code hashes are SHA-256 of
    deployed runtime bytes. Validation is cached only for unchanged local files.
    """
    FILES = ('out', 'abi.json', 'proving.key', 'verification.key')

    def __init__(self, path, digest, chain_id, coordinator_address):
        self.path = Path(path).resolve()
        raw = self.path.read_bytes()
        if len(digest) != 64 or hashlib.sha256(raw).hexdigest() != digest.lower():
            raise RuntimeError('DKG profile document differs from the approved digest')
        document = json.loads(raw)
        if (document.get('format') != 1 or document.get('chain_id') != chain_id or
                document.get('coordinator', '').lower() != coordinator_address.lower()):
            raise RuntimeError('DKG proof profiles belong to another deployment')
        self.profiles = {(int(p['n']), int(p['t'])): p for p in document['profiles']}
        if len(self.profiles) != len(document['profiles']):
            raise ValueError('Duplicate DKG proof profile')
        self.cache = {}
        self.zokrates = document.get('zokrates')

    def check(self, w3, n, t, verifier):
        entry = self.profiles.get((n, t))
        if entry is None or entry['verifier'].lower() != verifier.lower():
            raise RuntimeError('The frozen DKG verifier is not in the approved profile list')
        code = w3.eth.get_code(verifier)
        if not code or hashlib.sha256(code).hexdigest() != entry['code_sha256']:
            raise RuntimeError('Frozen DKG verifier code does not match the approved profile')
        directory = (self.path.parent / entry['directory']).resolve()
        # The digest-approved document chooses the directory; symlink changes
        # and size/mtime/inode changes invalidate the local verification cache.
        paths = [directory / name for name in self.FILES]
        stamps = tuple((p.resolve(), p.stat().st_ino, p.stat().st_size, p.stat().st_mtime_ns) for p in paths)
        if self.cache.get((n, t)) != stamps:
            if any(sha256_file(p) != entry['sha256'][p.name] for p in paths):
                raise RuntimeError('Installed DKG proof files differ from the approved setup')
            self.cache[(n, t)] = stamps
        return directory

    def proof_binary(self):
        if not self.zokrates:
            raise RuntimeError('The approved ZoKrates binary is not configured')
        binary = (self.path.parent / self.zokrates['path']).resolve()
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise RuntimeError('The approved ZoKrates binary is not executable')
        if sha256_file(binary) != self.zokrates['sha256']:
            raise RuntimeError('ZoKrates differs from the approved binary')
        return binary
