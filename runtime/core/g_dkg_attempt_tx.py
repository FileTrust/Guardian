"""Restart-safe signed transaction outbox for the recovery worker.

One outstanding envelope is retained before broadcast. A timeout/restart may
resend only those exact bytes; it never silently signs a replacement duty.
The existing account lock also serializes nonces with PRE/share-proof workers.
"""
from web3 import Web3
from web3.exceptions import TransactionNotFound

from .g_dkg_identity import private_lock, read_private_json
from .g_secret_files import write_json_atomic
from .g_tx import (_account_transaction_lock, _raw_transaction,
                  _send_raw_with_ambiguity_recovery, recovery_outbox_root,
                  require_no_pending_heartbeat_transaction)


class PendingTransaction(RuntimeError):
    pass


class DurableSender:
    def __init__(self, w3, account, *, nonce_root, max_gas=10_000_000,
                 max_gas_price_wei, receipt_timeout=30):
        if not 21_000 <= max_gas <= 16_777_216 or max_gas_price_wei <= 0:
            raise ValueError('Set bounded recovery transaction gas and gas-price limits')
        self.w3, self.account = w3, account
        self.root = recovery_outbox_root(nonce_root)
        self.nonce_root, self.max_gas = nonce_root, max_gas
        self.max_gas_price, self.timeout = max_gas_price_wei, receipt_timeout

    def gas_quote(self, fn):
        price = int(self.w3.eth.gas_price)
        if not 0 < price <= self.max_gas_price:
            raise RuntimeError('DKG network gas price exceeds the operator limit')
        # Simulation is mandatory even if the node's gas estimator is overly
        # conservative. The fallback remains below the unchanged block cap.
        fields = {'from': self.account.address, 'gas': self.max_gas}
        fn.call(fields)
        try:
            gas = min(self.max_gas, (int(fn.estimate_gas(fields)) * 6 + 4) // 5)
        except Exception:
            gas = self.max_gas
        return gas, price

    def _finish(self, entry):
        raw = bytes.fromhex(entry['raw'])
        expected = Web3.keccak(raw)
        if (entry['chain_id'] != self.w3.eth.chain_id or
                entry['address'].lower() != self.account.address.lower() or
                expected.hex() != entry['hash']):
            raise RuntimeError('DKG transaction outbox belongs to another wallet/network')
        try:
            receipt = self.w3.eth.get_transaction_receipt(expected)
        except TransactionNotFound:
            try:
                _send_raw_with_ambiguity_recovery(self.w3, raw)
                receipt = self.w3.eth.wait_for_transaction_receipt(expected, timeout=self.timeout)
            except Exception:
                raise PendingTransaction('DKG transaction confirmation is uncertain; retaining the signed envelope') from None
        # Save a completed result before returning to the calling state machine.
        write_json_atomic(self.root / 'outbox.json', {**entry, 'complete': True})
        if int(receipt['status']) != 1:
            raise RuntimeError('DKG transaction reverted; review its on-chain receipt')
        return receipt

    def __call__(self, fn, action):
        with private_lock(self.root):
            path = self.root / 'outbox.json'
            if path.exists() or path.is_symlink():
                entry = read_private_json(path)
                if not entry.get('complete'):
                    receipt = self._finish(entry)
                    if entry['action'] == action:
                        return receipt
            gas, price = self.gas_quote(fn)
            with _account_transaction_lock(self.nonce_root):
                require_no_pending_heartbeat_transaction(self.nonce_root)
                transaction = fn.build_transaction({'from': self.account.address,
                    'chainId': self.w3.eth.chain_id,
                    'nonce': self.w3.eth.get_transaction_count(self.account.address, 'pending'),
                    'gas': gas, 'gasPrice': price})
                raw = _raw_transaction(self.account.sign_transaction(transaction))
                entry = {'chain_id': self.w3.eth.chain_id, 'address': self.account.address,
                         'hash': Web3.keccak(raw).hex(), 'raw': raw.hex(),
                         'action': action, 'complete': False}
                write_json_atomic(path, entry)
                # Keep the account nonce lock until the broadcast is known to
                # have been attempted. Uncertain sends retain this same nonce.
                try:
                    _send_raw_with_ambiguity_recovery(self.w3, raw)
                except Exception:
                    raise PendingTransaction('DKG broadcast is uncertain; retaining the signed envelope') from None
            return self._finish(entry)

    def reconcile_replacement(self, replacement_hash):
        """Explicit operator recovery of a canonically replaced envelope.

        Never broadcasts or signs. A higher nonce alone is insufficient: the
        different confirmed transaction must consume this wallet's exact nonce.
        Keep the original envelope in an immutable audit record before release.
        """
        from eth_account import Account
        from eth_account._utils.legacy_transactions import Transaction
        from hexbytes import HexBytes
        with private_lock(self.root), _account_transaction_lock(self.nonce_root):
            path = self.root / 'outbox.json'
            entry = read_private_json(path)
            if entry.get('complete'):
                return False
            raw = bytes.fromhex(entry['raw'])
            original = Web3.keccak(raw)
            if (entry['chain_id'] != self.w3.eth.chain_id or
                    entry['address'].lower() != self.account.address.lower() or
                    Account.recover_transaction(raw).lower() != self.account.address.lower() or
                    original != HexBytes(entry['hash'])):
                raise RuntimeError('DKG outbox identity or network mismatch')
            try:
                self.w3.eth.get_transaction_receipt(original)
            except TransactionNotFound:
                pass
            else:
                raise RuntimeError('Original transaction already has a receipt; use normal recovery')
            nonce = Transaction.from_bytes(raw).nonce
            tx = self.w3.eth.get_transaction(replacement_hash)
            receipt = self.w3.eth.get_transaction_receipt(replacement_hash)
            if (HexBytes(tx['hash']) != HexBytes(replacement_hash) or HexBytes(tx['hash']) == original or
                    tx['from'].lower() != self.account.address.lower() or tx['nonce'] != nonce or
                    receipt['blockNumber'] is None or not receipt['blockHash'] or
                    HexBytes(tx['blockHash']) != HexBytes(receipt['blockHash']) or
                    HexBytes(receipt['transactionHash']) != HexBytes(tx['hash'])):
                raise RuntimeError('Replacement does not confirm the reserved wallet nonce')
            block = self.w3.eth.get_block(receipt['blockNumber'])
            if (HexBytes(block['hash']) != HexBytes(receipt['blockHash']) or
                    self.w3.eth.get_transaction_count(self.account.address, 'latest') <= nonce):
                raise RuntimeError('Replacement is not confirmed on the current canonical chain')
            archived = {**entry, 'complete': True, 'outcome': 'replaced',
                'replacement_hash': Web3.to_hex(HexBytes(replacement_hash)),
                'replacement_block_hash': Web3.to_hex(HexBytes(block['hash']))}
            archive = self.root / 'replaced' / (original.hex()+'.json')
            if archive.exists() and read_private_json(archive) != archived:
                raise RuntimeError('Existing replacement audit record differs')
            write_json_atomic(archive, archived)
            write_json_atomic(path, archived)
            return True

    def recover(self):
        """Drain an outstanding envelope even if its job closed meanwhile.

        Otherwise a confirmed/expired job needing no more writes could leave
        the shared wallet nonce reserved forever after a process restart.
        """
        with private_lock(self.root):
            path = self.root / 'outbox.json'
            if path.exists() or path.is_symlink():
                entry = read_private_json(path)
                if not entry.get('complete'):
                    return self._finish(entry)
        return None
