"""Accepted-duty DKG worker for the explicitly selected recovery deployment.

All writes carry the exact material ID. Random dealer material and candidate
shares are durable before publication; candidates never become active merely
because their transaction was submitted. Legacy deployments use g_dkg instead.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import random

from requests.exceptions import ConnectionError, HTTPError, Timeout

from web3 import Web3

from .g_crypto import BABY_L, baby_mul, verify_v2_share_against_commitments
from .g_dkg_acceptance import AcceptanceLimits, DutyOffer, acceptance_decision
from .g_dkg_attempt_state import (MaterialContext, activate_share, attempt_directory,
                                  load_dealer_material, stage_share)
from .g_dkg_cipher import (compress_commitment, decrypt_share, encrypt_share,
                           material_id_bytes, read_scalar_payload, receiver_public_key,
                           receiver_secret_key, scalar_payload)
from .g_dkg_identity import ensure_registered_identity, private_lock, read_private_json
from .g_dkg_recovery_contracts import PinnedProfiles, RecoveryContracts, record
from .g_secret_files import write_json_atomic


def hex32(value):
    return '0x' + material_id_bytes(value).hex()


class WorkerStopping(RuntimeError):
    pass


class AttemptWorker:
    """Dependency-injected worker, also exercised against real local contracts.

    submit(fn, unique_action) returns a successful receipt through the durable
    wallet outbox. share_path(file,epoch,version,n,t,index) locates active custody.
    No import-time wallet/config reads and no implied acceptance defaults.
    """
    def __init__(self, w3, address, contracts, root, limits, profiles, submit, share_path, *, stop_requested=lambda: False):
        self.w3, self.address, self.c = w3, Web3.to_checksum_address(address), contracts
        self.root, self.limits, self.profiles = Path(root), limits, profiles
        self.submit, self.share_path = submit, share_path
        self.stop_requested = stop_requested
        self.identity = None

    def start(self):
        self.identity = ensure_registered_identity(self.root, self.address, self.c.guardians,
                                                    self.c.manager, self.submit)

    def _send(self, fn, material, action):
        self._check_stop()
        receipt = self.submit(fn, f'{hex32(material)}:{action}')
        if receipt is None or int(receipt['status']) != 1:
            raise RuntimeError('Accepted DKG work was not confirmed')
        return receipt

    def _check_stop(self):
        if self.stop_requested():
            raise WorkerStopping('DKG worker is stopping; protected state retained')

    def _catalog(self):
        path = self.root / 'catalog/jobs.json'
        return read_private_json(path) if path.exists() or path.is_symlink() else {}

    def _remember(self, mat, j, r):
        with private_lock(self.root / 'catalog'):
            catalog = self._catalog()
            key = hex32(mat)
            item = {'registry_id': hex32(j.registryId), 'context_hash': hex32(j.contextHash),
                    'request': {**vars(r), 'materialId': key, 'fileId': hex32(r.fileId)},
                    'reserved': False, 'done': False}
            if key in catalog:
                old = catalog[key]
                if any(old[name] != item[name] for name in ['registry_id', 'context_hash', 'request']):
                    raise RuntimeError('Saved DKG duty differs from its immutable chain context')
            else:
                catalog[key] = item
                write_json_atomic(self.root / 'catalog/jobs.json', catalog)
            return catalog[key]

    def _old_share(self, r, index):
        path = self.share_path(hex32(r.fileId), r.epoch, r.oldVersion,
                               len(r.oldGuardians), r.oldT, index)
        data = read_private_json(path)
        try:
            share = int(data.get('share', data.get('sk')))
            if (hex32(data['fileId']) != hex32(r.fileId) or int(data['keyEpoch']) != r.epoch or
                    int(data['shareVersion']) != r.oldVersion or int(data['index']) != index or
                    not 0 < share < BABY_L):
                raise ValueError()
        except (KeyError, ValueError, TypeError):
            raise RuntimeError('Previous DKG share does not match the assigned refresh duty') from None
        published = record(self.c.coordinator.functions.getV2SharePublicKeyFull(
            r.fileId, r.epoch, r.oldVersion, index))
        if (not published.exists or published.guardian.lower() != self.address.lower() or
                baby_mul(share) != (published.x, published.y)):
            raise RuntimeError('Previous DKG share differs from its on-chain public share')
        return share

    def _profile(self, mat, j):
        verifier = self.c.manager.functions.getMaterialVerifier(mat).call()
        return self.profiles.check(self.w3, j.receiverCount, j.threshold, verifier)

    def _accept(self, mat, j, r, role, a, duty):
        if not self.limits.enabled:
            return False
        # Serializes local consent across different jobs, not just one mat ID.
        with private_lock(self.root / 'acceptance'):
            a = record(self.c.registry.functions.getAttempt(j.registryId))
            duty = record(self.c.registry.functions.getDuty(j.registryId, self.address))
            if duty.accepted or a.state != 1 or self.w3.eth.get_block('latest')['timestamp'] > a.acceptBy:
                return False
            if not self.c.guardians.functions.isActiveGuardian(self.address).call():
                return False
            original = tuple(self.c.manager.functions.getEncryptionKey(mat, self.address).call())
            derived = tuple(self.c.manager.functions.getReceiverEncryptionKey(mat, self.address).call())
            if original != self.identity.public or (role.receiverIndex and derived != receiver_public_key(original, mat)):
                raise RuntimeError('The attempt encryption snapshot differs from this Guardian identity')
            self._profile(mat, j)
            if role.dealerIndex:
                self.profiles.proof_binary()
            if r.refresh and role.dealerIndex:
                self._old_share(r, role.dealerIndex)
            fees = record(self.c.escrow.functions.getFees(j.registryId, self.address))
            stake = self.c.staking.functions
            available = max(0, stake.stakeOf(self.address).call() - stake.lockedStakeOf(self.address).call()
                            - stake.minimumGuardianStake().call())
            with private_lock(self.root / 'catalog'):
                catalog = self._catalog()
                active = 0
                for key, entry in catalog.items():
                    previous = record(self.c.registry.functions.getAttempt(entry['registry_id']))
                    accepted = record(self.c.registry.functions.getDuty(entry['registry_id'], self.address)).accepted
                    if key != hex32(mat) and previous.state in (1, 2) and (accepted or entry['reserved']):
                        active += 1
                fn = self.c.registry.functions.accept(j.registryId)
                # A plain test sender can supply a quote; production always
                # uses the actual durable sender's bounded simulation/quote.
                gas, price = self.submit.gas_quote(fn)
                offer = DutyOffer(j.receiverCount, j.threshold, bool(role.dealerIndex), bool(role.receiverIndex),
                    duty.bond, fees.acceptance, fees.material, fees.shareKey, j.dealerDuration, j.receiverDuration,j.disputeDuration)
                allowed, reason = acceptance_decision(self.limits, offer,
                    installed_profiles=set(self.profiles.profiles), active_attempts=active,
                    available_stake_wei=available, wallet_fee_balance_wei=self.w3.eth.get_balance(self.address),
                    estimated_acceptance_cost_wei=gas * price, profile_verified=True)
                if not allowed:
                    return False
                catalog[hex32(mat)]['reserved'] = True
                write_json_atomic(self.root / 'catalog/jobs.json', catalog)
            self._send(fn, mat, 'accept')
            return True

    def _material(self, mat, j, r, role, context):
        batch = record(self.c.manager.functions.getMaterialBatch(mat, r.epoch, r.version, r.refresh, role.dealerIndex))
        published = batch.exists or self.c.coordinator.functions.hasV2DealerCommitments(
            r.fileId, r.epoch, r.version, role.dealerIndex).call()
        old = self._old_share(r, role.dealerIndex) if r.refresh else None
        weight = self.c.book.functions.dealerWeight(mat, role.dealerIndex).call() if r.refresh else None
        local = load_dealer_material(self.root, context, published=bool(published), old_share=old, refresh_weight=weight)
        return batch, local

    def _publish(self, mat, j, r, role, context):
        batch, local = self._material(mat, j, r, role, context)
        compressed = [compress_commitment(point) for point in local.commitments]
        ciphers, indices = [], []
        for index, guardian in enumerate(r.receivers, 1):
            self._check_stop()
            if not r.refresh and index == role.dealerIndex:
                continue
            key = tuple(self.c.manager.functions.getReceiverEncryptionKey(mat, guardian).call())
            ciphers.append(encrypt_share(local.shares[index-1], self.identity.secret, key, local.commitments[0]))
            indices.append(index)
        if batch.exists:
            expected_hash = Web3.keccak(b''.join(v.to_bytes(32, 'big') for v in compressed))
            if (batch.dealer.lower() != self.address.lower() or batch.dealerIndex != role.dealerIndex or
                    bytes(batch.commitmentHash) != expected_hash or list(batch.encryptedShares) != ciphers):
                raise RuntimeError('Published DKG batch differs from protected local material')
        else:
            fn = (self.c.manager.functions.publishZkDkgBabyJubjubMaterial if r.refresh else
                  self.c.manager.functions.publishAndAcknowledgeV2Material)
            self._send(fn(mat, r.fileId, r.epoch, r.version, r.refresh, role.dealerIndex,
                          compressed, ciphers, compressed[0]), mat, 'batch')
        existing = self.c.coordinator.functions.getV2DealerCommitments(
            r.fileId, r.epoch, r.version, role.dealerIndex).call()
        xs, ys = [p[0] for p in local.commitments], [p[1] for p in local.commitments]
        if existing[0]:
            if existing[1].lower() != self.address.lower() or list(existing[3]) != xs or list(existing[4]) != ys:
                raise RuntimeError('Published DKG commitments differ from protected material')
        else:
            self._send(self.c.coordinator.functions.publishV2DealerCommitmentsForAttempt(
                mat, r.fileId, r.epoch, r.version, role.dealerIndex, xs, ys), mat, 'commitments')
        for index, ciphertext in zip(indices, ciphers):
            self._check_stop()
            existing = self.c.coordinator.functions.getV2EncryptedShare(
                r.fileId, r.epoch, r.version, role.dealerIndex, index).call()
            if existing[0]:
                if (existing[1].lower() != self.address.lower() or
                        existing[2].lower() != r.receivers[index-1].lower() or
                        bytes(existing[3]) != scalar_payload(ciphertext)):
                    raise RuntimeError('Published DKG ciphertext differs from protected material')
            else:
                self._send(self.c.coordinator.functions.publishV2EncryptedShareForAttempt(
                    mat, r.fileId, r.epoch, r.version, role.dealerIndex, index, scalar_payload(ciphertext)),
                    mat, f'cipher-{index}')

    def _complain(self, mat, r, dealer, receiver):
        functions = self.c.manager.functions
        dispute = functions.disputeIdFor(mat, r.epoch, r.version, r.refresh, dealer, receiver).call()
        if not record(functions.getDispute(dispute)).exists:
            self._send(functions.openZkDkgEncryptedShareDispute(mat, r.fileId, r.epoch, r.version,
                r.refresh, dealer, receiver), mat, f'complaint-{dealer}-{receiver}')

    def _receive(self, mat, j, r, role, context):
        index = role.receiverIndex
        if self.c.manager.functions.pendingReceiverDisputes(mat, self.address).call():
            return
        total = 0
        for dealer_index in r.dealerIndices:
            self._check_stop()
            batch = record(self.c.manager.functions.getMaterialBatch(mat, r.epoch, r.version, r.refresh, dealer_index))
            row = self.c.coordinator.functions.getV2DealerCommitments(r.fileId, r.epoch, r.version, dealer_index).call()
            if not batch.exists or not row[0] or row[1].lower() != r.oldGuardians[dealer_index-1].lower():
                raise RuntimeError('An attempt marked ready has incomplete dealer material')
            commitments = tuple(zip(row[3], row[4]))
            if not r.refresh and dealer_index == index:
                _, local = self._material(mat, j, r, role, context)
                share = local.shares[index-1]
            else:
                payload = self.c.coordinator.functions.getV2EncryptedShare(r.fileId, r.epoch, r.version, dealer_index, index).call()
                if not payload[0] or payload[2].lower() != self.address.lower():
                    raise RuntimeError('The ready attempt is missing this receiver ciphertext')
                ciphertext = read_scalar_payload(payload[3])
                offset = index-1 if r.refresh or index < dealer_index else index-2
                if ciphertext != batch.encryptedShares[offset]:
                    raise RuntimeError('Coordinator and evidence ciphertexts disagree')
                dealer_key = tuple(self.c.manager.functions.getEncryptionKey(mat, row[1]).call())
                try:
                    share = decrypt_share(ciphertext, receiver_secret_key(self.identity.secret, mat), dealer_key, commitments[0])
                except ValueError:
                    self._complain(mat, r, dealer_index, index)
                    return
            if not verify_v2_share_against_commitments(share, index, commitments):
                self._complain(mat, r, dealer_index, index)
                return
            # Refresh dealers already apply their frozen Lagrange weight to
            # their polynomial constant. Receivers MUST NOT weight again.
            total = (total + share) % BABY_L
        expected = tuple(self.c.book.functions.expectedShare(mat, index).call())
        if baby_mul(total) != expected:
            raise RuntimeError('Combined DKG share differs from the frozen commitment book')
        stage_share(self.root, context, index, total, sorted(r.dealerIndices))
        public = self.c.coordinator.functions.getV2SharePublicKey(r.fileId, r.epoch, r.version, index).call()
        if public[0]:
            if tuple(public[1:]) != expected:
                raise RuntimeError('Acknowledged DKG share differs from protected candidate')
        else:
            self._send(self.c.coordinator.functions.publishV2SharePublicKeyForAttempt(
                mat, r.fileId, r.epoch, index, *expected), mat, 'share-key')

    def _disputes(self, mat, j, r, role, context):
        functions = self.c.manager.functions
        # Each pair can open only one complaint. At most 20 public reads for
        # this dealer; no unbounded log-history scan is needed after restart.
        for index in range(1, len(r.receivers)+1):
            self._check_stop()
            if not r.refresh and index == role.dealerIndex:
                continue
            dispute_id = functions.disputeIdFor(mat, r.epoch, r.version, r.refresh, role.dealerIndex, index).call()
            dispute = record(functions.getDispute(dispute_id))
            if not dispute.exists or dispute.resolved:
                continue
            if self.w3.eth.get_block('latest')['timestamp'] > dispute.deadline:
                self._send(functions.finalizeExpiredZkDkgEncryptedShareDispute(dispute_id), mat, f'expire-complaint-{index}')
                continue
            build = self._profile(mat, j)
            _, local = self._material(mat, j, r, role, context)
            from .g_zk import generate_zkdkg_dispute_justification_proof, proof_tuple_from_zokrates_json
            public_hash = functions.justificationPublicInputHash(dispute_id).call()
            receiver_key = tuple(functions.getReceiverEncryptionKey(mat, dispute.receiver).call())
            proof = generate_zkdkg_dispute_justification_proof(build, local.commitments, self.identity.secret,
                self.identity.public, receiver_key, index, dispute.encryptedShare, public_hash,
                str(self.profiles.proof_binary()))
            if int(proof['inputs'][-1], 0) != 1:
                raise RuntimeError('Saved DKG material cannot justify this ciphertext')
            self._send(functions.justifyZkDkgEncryptedShareDispute(dispute_id,
                proof_tuple_from_zokrates_json(proof)), mat, f'justify-{index}')

    def _activate(self, mat, j, r, role, context):
        key = record(self.c.coordinator.functions.getV2Key(r.fileId))
        actual = self.c.coordinator.functions.getMaterialAttemptId(r.fileId, r.epoch, r.version).call()
        if (not key.exists or not key.finalized or key.keyEpoch != r.epoch or key.shareVersion < r.version or
                bytes(actual) != material_id_bytes(mat)):
            raise RuntimeError('Successful DKG attempt is not an activated on-chain share version')
        candidate = read_private_json(attempt_directory(self.root, mat) / f'candidate-{role.receiverIndex}.json')
        public = record(self.c.coordinator.functions.getV2SharePublicKeyFull(r.fileId, r.epoch, r.version, role.receiverIndex))
        if (not public.exists or public.guardian.lower() != self.address.lower() or
                (public.x, public.y) != (int(candidate['vkx']), int(candidate['vky']))):
            raise RuntimeError('Active public DKG share does not match this protected candidate')
        activate_share(self.root, context, role.receiverIndex,
            self.share_path(hex32(r.fileId), r.epoch, r.version, len(r.receivers), r.newT, role.receiverIndex),
            active_material_id=actual)

    def step(self, material_id):
        self._check_stop()
        mat = material_id_bytes(material_id)
        if self.identity is None:
            raise RuntimeError('Start the recovery worker before processing duties')
        with private_lock(self.root / 'workers' / mat.hex()):
            j = record(self.c.controller.functions.getJob(mat))
            if not any(j.registryId):
                return False
            role = record(self.c.controller.functions.getRole(mat, self.address))
            if not (role.dealerIndex or role.receiverIndex):
                return False
            a = record(self.c.registry.functions.getAttempt(j.registryId))
            with private_lock(self.root / 'catalog'):
                saved = self._catalog().get(hex32(mat))
            if saved and saved['done']:
                return False
            if saved:
                r = SimpleNamespace(**saved['request'])
                if saved['context_hash'] != hex32(j.contextHash) or saved['registry_id'] != hex32(j.registryId):
                    raise RuntimeError('DKG duty context changed after acceptance')
            elif a.state in (1, 2):
                r = record(self.c.controller.functions.getAttemptRequest(j.fileId, j.epoch, j.version))
                if bytes(r.materialId) != mat:
                    raise RuntimeError('The requested DKG attempt was superseded')
                self._remember(mat, j, r)
            else:
                return False
            # Canonical bytes remain in all transaction envelopes, including
            # after JSON reload on a worker restart.
            r.materialId, r.fileId = mat, material_id_bytes(r.fileId)
            context = MaterialContext(hex32(mat), hex32(j.contextHash), hex32(j.fileId), j.epoch,
                j.version, role.dealerIndex or 1, j.receiverCount, j.threshold)
            duty = record(self.c.registry.functions.getDuty(j.registryId, self.address))
            if a.state == 1:
                return self._accept(mat, j, r, role, a, duty)
            if a.state >= 3:
                if a.state == 3 and role.receiverIndex and duty.accepted:
                    self._activate(mat, j, r, role, context)
                with private_lock(self.root / 'catalog'):
                    catalog = self._catalog()
                    catalog[hex32(mat)]['done'] = True
                    write_json_atomic(self.root / 'catalog/jobs.json', catalog)
                return True
            if a.state != 2 or not duty.accepted:
                return False
            if role.dealerIndex:
                self._disputes(mat, j, r, role, context)
            timestamp = self.w3.eth.get_block('latest')['timestamp']
            if timestamp > a.workDeadline:
                return False  # Owner/settler closes it; G cannot promote it.
            self._profile(mat, j)
            if role.dealerIndex and timestamp <= a.workDeadline-j.receiverDuration:
                self._publish(mat, j, r, role, context)
            if role.receiverIndex and self.c.controller.functions.materialsReady(mat).call():
                self._receive(mat, j, r, role, context)
            return True

    def scan(self, *, page_size=4):
        """Bounded round-robin discovery plus durable accepted-duty recovery."""
        pending = set()
        with private_lock(self.root / 'catalog'):
            jobs = list(self._catalog().items())
        pending.update(mat for mat, saved in jobs if not saved['done'])
        errors = []
        try:
            count = self.c.acl.functions.getFileCount().call()
            cursor = getattr(self, '_cursor', 0) % max(1, count)
            for offset in range(min(page_size, count)):
                self._check_stop()
                index = (cursor+offset) % count
                file_id = self.c.acl.functions.getFileIdAt(index).call()
                registry_id = self.c.registry.functions.activeAttemptOf(file_id).call()
                if any(registry_id):
                    mat = self.c.controller.functions.materialForRegistryId(registry_id).call()
                    pending.add(hex32(mat))
                # Preserve discovery progress when a later read is throttled.
                self._cursor = (index + 1) % count
        except (ConnectionError, Timeout, HTTPError) as error:
            errors.append(('discovery', type(error).__name__))
            # Discovery trouble must not withhold already accepted duties.
        for mat in sorted(pending):
            self._check_stop()
            try:
                self.step(mat)
            except Exception as error:
                errors.append((mat, type(error).__name__))
        return errors


def _initialize_worker(cfg, w3, account, stop_requested):
    from .g_dkg_attempt_tx import DurableSender
    from .g_material import v2_final_share_path
    c = RecoveryContracts(w3, cfg.ZKDKG_COORDINATOR_V2_ADDRESS, cfg.ACL_ADDRESS,
                          cfg.GUARDIAN_REGISTRY_ADDRESS, cfg.STAKING_MANAGER_ADDRESS)
    settings = cfg.DKG_RECOVERY
    from .g_dkg_custody import deployment_directory
    if settings.get('chain_id')!=w3.eth.chain_id:
        raise RuntimeError('Recovery custody belongs to a different approved chain')
    root = deployment_directory(cfg)
    profiles = PinnedProfiles(cfg.ROOT / settings['profile_document'], settings['profile_document_sha256'],
                              w3.eth.chain_id, c.coordinator.address)
    limits = AcceptanceLimits.from_config(settings.get('acceptance', {}))
    sender = DurableSender(w3, account, nonce_root=cfg.ROOT,
        max_gas=int(settings.get('max_transaction_gas', 10_000_000)),
        max_gas_price_wei=int(settings['max_gas_price_wei']))
    worker = AttemptWorker(w3, account.address, c, root, limits, profiles, sender, v2_final_share_path,
                           stop_requested=stop_requested)
    sender.recover()
    worker.start()
    return worker, sender


def run(cfg, w3, account):
    """Explicit opt-in adapter. No configuration updates or legacy fallback."""
    from . import g_lifecycle
    from .g_dkg_attempt_tx import PendingTransaction
    from .g_log import log_every
    from .g_dkg_rpc import install_read_pacing
    install_read_pacing(w3, getattr(cfg, 'DKG_RECOVERY', {}).get('rpc_read_interval_seconds', 0), g_lifecycle.STOP)
    delay = 2.0
    while not g_lifecycle.STOP.is_set():
        try:
            worker, sender = _initialize_worker(cfg, w3, account, g_lifecycle.STOP.is_set)
            break
        except (ConnectionError, Timeout, HTTPError, PendingTransaction) as error:
            if isinstance(error, HTTPError) and (error.response is None or
                    error.response.status_code != 429 and error.response.status_code < 500):
                raise
            log_every(('dkg-recovery-startup', type(error).__name__),
                f'DKG recovery startup deferred ({type(error).__name__}); protected state retained', seconds=60)
            g_lifecycle.STOP.wait(delay + random.uniform(0, delay / 4))
            delay = min(60.0, delay * 2)
    else:
        return
    print('Guardian DKG recovery worker started; automatic acceptance follows operator limits', flush=True)
    while not g_lifecycle.STOP.is_set():
        try:
            sender.recover()
            for mat, kind in worker.scan():
                log_every(('dkg-recovery-deferred', mat, kind),
                    f'DKG recovery attempt {mat[:12]} deferred ({kind}); protected state retained', seconds=300)
        except Exception as error:
            # RPC exceptions can contain transaction payloads or local paths.
            # Keep operator logs bounded and do not disclose private material.
            log_every(('dkg-recovery-check', type(error).__name__),
                f'DKG recovery check deferred ({type(error).__name__}); protected state retained', seconds=300)
        g_lifecycle.STOP.wait(max(1, cfg.POLL_INTERVAL))
