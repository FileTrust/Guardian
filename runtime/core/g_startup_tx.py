"""Recover already-signed wallet reservations before startup registry writes."""
from pathlib import Path

from requests.exceptions import ConnectionError, HTTPError, Timeout

from .g_dkg_attempt_tx import DurableSender, PendingTransaction
from .g_dkg_identity import read_private_json
from .g_heartbeat import heartbeat_tick
from .g_secret_files import read_secret_json


def recover_pending_transactions(w3, cfg, root, stop, log=lambda _: None):
    root = Path(root)
    heartbeat = root / 'state/registry-heartbeat.json'
    recovery = root / 'state/recovery_transactions/outbox.json'
    sender = None
    delay = 0.5
    reported = None
    while not stop.is_set():
        try:
            if (heartbeat.exists() or heartbeat.is_symlink()) and read_secret_json(heartbeat):
                # A saved envelope is the only reason to tick here. Startup
                # never creates a new heartbeat before registration.
                if heartbeat_tick(w3, cfg, root, log) == 'submitted':
                    raise PendingTransaction('Waiting for saved heartbeat confirmation')
            if (recovery.exists() or recovery.is_symlink()) and not read_private_json(recovery).get('complete'):
                if cfg.get('dkg_attempt_protocol') != 1:
                    raise ValueError('Pending recovery requires its approved deployment configuration')
                if sender is None:
                    settings = cfg['dkg_recovery']
                    account = w3.eth.account.from_key(cfg['private_key'])
                    sender = DurableSender(w3, account, nonce_root=root,
                        max_gas=int(settings.get('max_transaction_gas', 10_000_000)),
                        max_gas_price_wei=int(settings['max_gas_price_wei']))
                sender.recover()
            return True
        except (ConnectionError, HTTPError, Timeout, PendingTransaction) as error:
            if isinstance(error, HTTPError) and (error.response is None or
                    error.response.status_code != 429 and error.response.status_code < 500):
                raise
            kind = type(error).__name__
            if reported != kind:
                log(f'Pending startup transaction retained ({kind}); waiting before registry writes')
                reported = kind
            if stop.wait(delay):
                return False
            delay = min(8, delay * 2)
    return False
