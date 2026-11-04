"""Scheduled registry heartbeat with durable, identical-transaction retries."""
import hashlib
import threading
import time
from pathlib import Path

from web3 import Web3
from .g_tx import (_account_transaction_lock, _raw_transaction, _send_raw_with_ambiguity_recovery,
                   require_no_pending_recovery_transaction, recover_regular_transaction,
                   next_guardian_nonce, record_guardian_confirmation, PendingGuardianTransaction)
from .g_secret_files import read_secret_json, write_json_atomic

INTERVAL = 1800


def next_slot(now, chain_id, address, interval=INTERVAL):
    identity = f"filetrust:registry-heartbeat:{chain_id}:{address.lower()}".encode()
    phase = int.from_bytes(hashlib.sha256(identity).digest()[:8], 'big') % interval
    return ((int(now) - phase) // interval + 1) * interval + phase


def initial_due(now, chain_id, address, *, chain_now, last_heartbeat):
    """Resume an overdue registry heartbeat instead of waiting another slot."""
    remaining = max(0, INTERVAL - max(0, int(chain_now) - int(last_heartbeat)))
    return min(next_slot(now, chain_id, address), now + remaining)


def heartbeat_tick(w3, cfg, root, log=lambda message: None):
    account = w3.eth.account.from_key(cfg['private_key'])
    target = Web3.to_checksum_address(cfg['guardian_registry_address'])
    path = Path(root) / 'state' / 'registry-heartbeat.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    # Share the nonce lock used by DKG, PRE and share-proof subprocesses.
    with _account_transaction_lock(root):
        pending = read_secret_json(path) if path.exists() else {}
        chain_id = int(w3.eth.chain_id)
        if pending:
            if pending['chain_id'] != chain_id or pending['address'].lower() != account.address.lower() or pending['target'].lower() != target.lower():
                raise ValueError('Heartbeat identity/network differs from saved transaction')
            try:
                receipt = w3.eth.get_transaction_receipt(pending['hash'])
            except Exception as exc:
                from web3.exceptions import TransactionNotFound
                if not isinstance(exc, TransactionNotFound):
                    raise
                receipt = None
            if receipt is not None:
                if Web3.to_hex(receipt['transactionHash']).lower() != pending['hash'].lower():
                    raise PendingGuardianTransaction('Heartbeat receipt differs from its signed transaction')
                record_guardian_confirmation(w3, account.address, pending['nonce'], receipt, root)
                path.unlink()
                if int(receipt['status']) == 1:
                    log(f"[heartbeat] confirmed tx={pending['hash']}")
                    return 'confirmed'
                return 'reverted'
            if w3.eth.get_transaction_count(account.address, 'latest') > pending['nonce']:
                path.unlink()
                return 'replaced'
        else:
            require_no_pending_recovery_transaction(root)
            recover_regular_transaction(w3, account.address, root)
            nonce = next_guardian_nonce(w3, account.address, root)
            if nonce != int(w3.eth.get_transaction_count(account.address, 'latest')):
                return 'busy'
            data = '0x' + Web3.keccak(text='heartbeat()')[:4].hex().removeprefix('0x')
            tx = {'chainId': chain_id, 'nonce': nonce, 'to': target, 'value': 0,
                  'data': data, 'gasPrice': max(int(cfg.get('filetrust_fixed_gas_price_wei', 1_000_000)), int(w3.eth.gas_price))}
            tx['gas'] = int(w3.eth.estimate_gas({**tx, 'from': account.address}) * 12 // 10)
            raw = _raw_transaction(account.sign_transaction(tx))
            pending = {'chain_id': chain_id, 'address': account.address, 'target': target,
                       'nonce': nonce, 'hash': Web3.to_hex(Web3.keccak(raw)), 'raw': raw.hex()}
            # Persist BEFORE submission: timeouts/restarts resend the same nonce/hash.
            write_json_atomic(path, pending)
        _send_raw_with_ambiguity_recovery(w3, bytes.fromhex(pending['raw']))
        return 'submitted'


def start(cfg, root, stop, log=print):
    def work():
        w3 = Web3(Web3.HTTPProvider(cfg['rpc_url'], request_kwargs={'timeout': 30}))
        due = None
        while not stop.is_set():
            try:
                if due is None:
                    now, chain_id = time.time(), int(w3.eth.chain_id)
                    candidate_due = next_slot(now, chain_id, cfg['address'])
                    if cfg.get('dkg_attempt_protocol') == 1:
                        from .g_dkg_recovery_contracts import contract, record
                        registry = contract(w3, 'GuardianRegistry', cfg['guardian_registry_address'])
                        status = record(registry.functions.getGuardianOperationalStatus(
                            Web3.to_checksum_address(cfg['address'])))
                        if not status.registered:
                            raise ValueError('Heartbeat requires an existing Guardian registration')
                        candidate_due = initial_due(now, chain_id, cfg['address'],
                            chain_now=w3.eth.get_block('latest')['timestamp'], last_heartbeat=status.lastHeartbeat)
                    due = candidate_due
                pending = (Path(root) / 'state' / 'registry-heartbeat.json').exists()
                if pending or time.time() >= due:
                    result = heartbeat_tick(w3, cfg, root, log)
                    if result == 'confirmed':
                        due = next_slot(time.time(), int(w3.eth.chain_id), cfg['address'])
                    elif result in ('reverted', 'replaced'):
                        log('[heartbeat] transaction failed; retry scheduled')
                stop.wait(60 if pending or time.time() >= due else min(60, max(1, due-time.time())))
            except Exception as exc:
                log(f'[heartbeat] check/send unavailable ({type(exc).__name__}); retry in 60s')
                stop.wait(60)
    thread = threading.Thread(target=work, daemon=True, name='registry-heartbeat')
    thread.start()
    return thread
