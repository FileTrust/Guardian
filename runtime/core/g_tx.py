"""Guardian transaction submission shared by all Guardian subprocesses.

Each Guardian runs DKG, PRE, and share-proof workers as separate processes, but
all three use the same Ethereum account.  Ethereum nonces are account-wide, so
an in-process ``threading.Lock`` is insufficient.  This module serializes the
nonce allocation and raw transaction submission with an OS file lock shared by
the whole Guardian instance.

An accepted broadcast is not proof that the RPC's pending nonce advanced.
Retain a signed outbox and a confirmation barrier across worker restarts;
never let another worker allocate its nonce while confirmation is uncertain.
"""
from __future__ import annotations

import contextlib
import threading
import time
from pathlib import Path
from typing import Any, Iterator, Literal

import fcntl
from web3 import Web3
from web3.exceptions import TransactionNotFound


class PendingGuardianTransaction(RuntimeError):
    """An existing signed transaction must be reconciled before new signing."""


class GuardianTransactionConflict(PendingGuardianTransaction):
    """The reserved nonce conflicts; retain its envelope for chain review."""


def _state_root(lock_root=None):
    return _lock_path(lock_root).parent


def regular_outbox_root(lock_root=None):
    return _state_root(lock_root) / 'regular_transactions'


def _receipt_field(receipt, name):
    return receipt.get(name) if hasattr(receipt, 'get') else getattr(receipt, name, None)


def record_guardian_confirmation(w3, address, nonce, receipt, lock_root=None):
    """Caller holds the account lock. Persist only confirmed chain evidence."""
    from .g_dkg_identity import read_private_json
    from .g_secret_files import write_json_atomic
    number, block_hash = _receipt_field(receipt, 'blockNumber'), _receipt_field(receipt, 'blockHash')
    if number is None or not block_hash or not _receipt_field(receipt, 'transactionHash'):
        raise PendingGuardianTransaction('Transaction receipt is not confirmed; retaining its nonce')
    path = _state_root(lock_root) / 'guardian_confirmed_nonce.json'
    data = dict(chain_id=int(w3.eth.chain_id), address=address.lower(), nonce=int(nonce),
                hash=Web3.to_hex(_receipt_field(receipt, 'transactionHash')),
                block_number=int(number), block_hash=Web3.to_hex(block_hash))
    if path.exists() or path.is_symlink():
        previous = read_private_json(path)
        if (previous['chain_id'], previous['address']) != (data['chain_id'], data['address']):
            raise RuntimeError('Confirmed nonce evidence belongs to another wallet/network')
        if previous['nonce'] > data['nonce']:
            return
    write_json_atomic(path, data)


def next_guardian_nonce(w3, address, lock_root=None):
    """Bridge pending-state lag using canonical confirmation, never a guess."""
    from .g_dkg_identity import read_private_json
    latest = int(w3.eth.get_transaction_count(address, 'latest'))
    nonce = max(latest, int(w3.eth.get_transaction_count(address, 'pending')))
    path = _state_root(lock_root) / 'guardian_confirmed_nonce.json'
    if path.exists() or path.is_symlink():
        saved = read_private_json(path)
        if (saved['chain_id'], saved['address']) != (int(w3.eth.chain_id), address.lower()):
            raise RuntimeError('Confirmed nonce evidence belongs to another wallet/network')
        if latest <= saved['nonce']:
            try:
                receipt = w3.eth.get_transaction_receipt(saved['hash'])
            except TransactionNotFound:
                raise PendingGuardianTransaction('Confirmed nonce is no longer visible; chain review required') from None
            block = w3.eth.get_block(saved['block_number'])
            if (Web3.to_hex(_receipt_field(receipt, 'transactionHash')) != saved['hash'] or
                    _receipt_field(receipt, 'blockNumber') != saved['block_number'] or
                    Web3.to_hex(_receipt_field(receipt, 'blockHash')) != saved['block_hash'] or
                    Web3.to_hex(block['hash']) != saved['block_hash']):
                raise PendingGuardianTransaction('Confirmed nonce is not on the current canonical chain')
            nonce = max(nonce, saved['nonce'] + 1)
    return nonce


def recover_regular_transaction(w3, address, lock_root=None, receipt_timeout=30):
    """Caller holds the account lock. Reuse only a previously signed envelope."""
    from .g_dkg_identity import read_private_json
    from .g_secret_files import write_json_atomic
    path = regular_outbox_root(lock_root) / 'outbox.json'
    if not (path.exists() or path.is_symlink()):
        return None
    entry = read_private_json(path)
    if entry.get('complete'):
        return None
    raw = bytes.fromhex(entry['raw'])
    expected = Web3.keccak(raw)
    if (entry['chain_id'] != int(w3.eth.chain_id) or entry['address'].lower() != address.lower()
            or Web3.to_hex(expected) != entry['hash']):
        raise RuntimeError('Ordinary transaction outbox belongs to another wallet/network')
    try:
        try:
            receipt = w3.eth.get_transaction_receipt(expected)
        except TransactionNotFound:
            _send_raw_with_ambiguity_recovery(w3, raw)
            if receipt_timeout is None:
                receipt = w3.eth.wait_for_transaction_receipt(expected)
            else:
                receipt = w3.eth.wait_for_transaction_receipt(expected, timeout=receipt_timeout)
        if Web3.to_hex(_receipt_field(receipt, 'transactionHash')) != entry['hash']:
            raise RuntimeError('Receipt differs from the reserved transaction')
        record_guardian_confirmation(w3, address, entry['nonce'], receipt, lock_root)
    except PendingGuardianTransaction:
        raise
    except Exception:
        raise PendingGuardianTransaction('Ordinary transaction confirmation is uncertain; signed envelope retained') from None
    write_json_atomic(path, {**entry, 'complete': True})
    return entry, receipt

_THREAD_LOCK = threading.Lock()
_NONCE_ERROR_MARKERS = (
    "nonce too low",
    "nonce has already been used",
    "invalid transaction nonce",
    "replacement transaction underpriced",
)
_ALREADY_KNOWN_MARKERS = ("already known", "known transaction")
_AMBIGUOUS_SEND_MARKERS = (
    "connection aborted",
    "connection reset",
    "connection refused",
    "remote end closed",
    "read timed out",
    "timed out",
    "eof",
)


def read_contract_value(function, attempts=8):
    """Retry transient read failures; never turn uncertainty into no stake/node."""
    from requests.exceptions import ConnectionError, HTTPError, Timeout
    for attempt in range(attempts):
        try:
            return function.call()
        except (ConnectionError, HTTPError, Timeout) as error:
            if isinstance(error, HTTPError) and (error.response is None or
                    error.response.status_code != 429 and error.response.status_code < 500):
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(min(8, 0.5 * 2**attempt))

PreTxOutcome = Literal["submitted", "complete", "retry"]


def is_terminal_v2_pre_error(message: str) -> bool:
    msg = str(message).lower()
    return any(reason in msg for reason in (
        "threshold reached",
        "request expired",
        "window closed",
        "already declared",
        "already submitted",
        "duplicate guardian",
        "duplicate share index",
        "unknown request",
        "requester not allowed",
        "no request",
    ))


def _lock_path(lock_root: Path | str | None = None) -> Path:
    if lock_root is None:
        # Import lazily: the Guardian Manager selects an instance at runtime
        # and therefore has no process-global g_config.
        import core.g_config as cfg
        lock_root = cfg.ROOT
    path = Path(lock_root) / "state" / "guardian_transaction.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


@contextlib.contextmanager
def _account_transaction_lock(
    lock_root: Path | str | None = None,
) -> Iterator[None]:
    """Hold the per-instance transaction lock across processes and threads."""
    with _THREAD_LOCK:
        with _lock_path(lock_root).open("a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _raw_transaction(signed: Any) -> bytes:
    raw = getattr(signed, "raw_transaction", None)
    if raw is None:
        raw = getattr(signed, "rawTransaction", None)
    if raw is None:
        raise RuntimeError("signed transaction has no raw transaction bytes")
    return bytes(raw)


def _send_raw_with_ambiguity_recovery(w3: Web3, raw: bytes):
    """Send a deterministic raw transaction without creating a second nonce.

    A disconnected HTTP response is ambiguous: the node may already have
    accepted the transaction.  Re-sending the exact same bytes is safe because
    it has the same transaction hash.
    """
    expected_hash = Web3.keccak(raw)
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            return w3.eth.send_raw_transaction(raw)
        except Exception as exc:
            last_error = exc
            message = str(exc).lower()
            if any(marker in message for marker in _ALREADY_KNOWN_MARKERS):
                return expected_hash
            if any(marker in message for marker in _NONCE_ERROR_MARKERS):
                # The transaction may have mined between the receipt lookup
                # and this replay. A higher nonce alone never authorizes a new
                # envelope, nor proves which transaction consumed this nonce.
                try:
                    w3.eth.get_transaction_receipt(expected_hash)
                except TransactionNotFound:
                    raise GuardianTransactionConflict('Reserved nonce conflicts with chain state; original signed envelope retained for review') from None
                return expected_hash
            response = getattr(exc, 'response', None)
            transient_http = response is not None and (response.status_code == 429 or response.status_code >= 500)
            if not transient_http and not any(marker in message for marker in _AMBIGUOUS_SEND_MARKERS):
                raise
            if attempt < 2:
                time.sleep(0.5 * (attempt + 1))
    assert last_error is not None
    raise last_error


def send_contract_transaction(
    w3: Web3,
    account,
    fn,
    *,
    gas: int,
    gas_price: int,
    value: int = 0,
    lock_root: Path | str | None = None,
    receipt_timeout: float | None = None,
):
    """Build, sign, and submit one account transaction safely.

    Returns ``(transaction_hash, receipt, transaction_dict)``. Uncertain sends
    retain their exact signed bytes; a different nonce is never signed as a
    response to ambiguity or an occupied nonce.
    """
    from .g_secret_files import write_json_atomic
    from hexbytes import HexBytes
    with _account_transaction_lock(lock_root):
        # Recovery persists its signed envelope BEFORE broadcast. After a
        # crash, an RPC pending nonce alone may not see that reservation.
        # PRE/share-proof workers must not sign a different transaction at
        # that nonce while recovery confirmation remains uncertain.
        require_no_pending_recovery_transaction(lock_root)
        require_no_pending_heartbeat_transaction(lock_root)
        recovered = recover_regular_transaction(w3, account.address, lock_root, receipt_timeout)
        if recovered is not None:
            previous, receipt = recovered
            proposed = fn.build_transaction({'from': account.address, 'chainId': int(w3.eth.chain_id),
                'nonce': previous['nonce'], 'gas': int(gas), 'gasPrice': int(gas_price), 'value': int(value)})
            def intent(tx):
                return (str(tx.get('to', '')).lower(),
                        str(tx.get('data', tx.get('input', '0x'))).lower(), int(tx.get('value', 0)))
            if intent(proposed) == intent(previous['transaction']):
                return HexBytes(previous['hash']), receipt, previous['transaction']
        nonce = next_guardian_nonce(w3, account.address, lock_root)
        tx_fields = {
            "from": account.address,
            "chainId": int(w3.eth.chain_id),
            "nonce": nonce,
            "gas": int(gas),
            "gasPrice": int(gas_price),
        }
        if int(value):
            tx_fields["value"] = int(value)
        tx = fn.build_transaction(tx_fields)
        signed = account.sign_transaction(tx)
        raw = _raw_transaction(signed)
        entry = dict(chain_id=int(w3.eth.chain_id), address=account.address,
                     nonce=nonce, hash=Web3.to_hex(Web3.keccak(raw)), raw=raw.hex(),
                     transaction=tx, complete=False)
        # Retain before broadcast, including if the process stops before
        # the first HTTP request. This file uses standalone vault protection.
        write_json_atomic(regular_outbox_root(lock_root) / 'outbox.json', entry)
        _, receipt = recover_regular_transaction(w3, account.address, lock_root, receipt_timeout)
        return HexBytes(entry['hash']), receipt, tx


def recovery_outbox_root(lock_root=None):
    if lock_root is None:
        import core.g_config as cfg
        lock_root = cfg.ROOT
    return Path(lock_root) / 'state' / 'recovery_transactions'


def require_no_pending_recovery_transaction(lock_root=None):
    path = recovery_outbox_root(lock_root) / 'outbox.json'
    if path.exists() or path.is_symlink():
        from .g_dkg_identity import read_private_json
        if not read_private_json(path).get('complete'):
            raise RuntimeError('A recovery transaction is awaiting confirmation; retaining its reserved wallet nonce')


def require_no_pending_heartbeat_transaction(lock_root=None):
    if lock_root is None:
        import core.g_config as cfg
        lock_root = cfg.ROOT
    path = Path(lock_root) / 'state' / 'registry-heartbeat.json'
    if path.exists() or path.is_symlink():
        from .g_secret_files import read_secret_json
        if read_secret_json(path):
            raise RuntimeError('A heartbeat transaction is awaiting confirmation; retaining its reserved wallet nonce')
