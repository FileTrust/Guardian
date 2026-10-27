"""Guardian transaction submission shared by all Guardian subprocesses.

Each Guardian runs DKG, PRE, and share-proof workers as separate processes, but
all three use the same Ethereum account.  Ethereum nonces are account-wide, so
an in-process ``threading.Lock`` is insufficient.  This module serializes the
nonce allocation and raw transaction submission with an OS file lock shared by
the whole Guardian instance.

The lock is intentionally released as soon as the node accepts the raw
transaction.  Receipt waiting happens outside the lock, allowing later
transactions to enter the mempool while preserving nonce order.
"""
from __future__ import annotations

import contextlib
import threading
import time
from pathlib import Path
from typing import Any, Iterator, Literal

import fcntl
from web3 import Web3

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
            if not any(marker in message for marker in _AMBIGUOUS_SEND_MARKERS):
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

    Returns ``(transaction_hash, receipt, transaction_dict)``.  A nonce error
    is retried once using the node's authoritative pending nonce.  Other errors
    are propagated so callers retain their existing error semantics.
    """
    nonce_error: Exception | None = None
    for nonce_attempt in range(2):
        with _account_transaction_lock(lock_root):
            # Recovery persists its signed envelope BEFORE broadcast. After a
            # crash, an RPC pending nonce alone may not see that reservation.
            # PRE/share-proof workers must not sign a different transaction at
            # that nonce while recovery confirmation remains uncertain.
            require_no_pending_recovery_transaction(lock_root)
            nonce = int(w3.eth.get_transaction_count(account.address, "pending"))
            tx_fields = {
                "from": account.address,
                "nonce": nonce,
                "gas": int(gas),
                "gasPrice": int(gas_price),
            }
            if int(value):
                tx_fields["value"] = int(value)
            tx = fn.build_transaction(tx_fields)
            signed = account.sign_transaction(tx)
            raw = _raw_transaction(signed)
            try:
                tx_hash = _send_raw_with_ambiguity_recovery(w3, raw)
            except Exception as exc:
                if (
                    nonce_attempt == 0
                    and any(marker in str(exc).lower() for marker in _NONCE_ERROR_MARKERS)
                ):
                    nonce_error = exc
                    continue
                raise
        if receipt_timeout is None:
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        else:
            receipt = w3.eth.wait_for_transaction_receipt(
                tx_hash, timeout=receipt_timeout
            )
        return tx_hash, receipt, tx
    assert nonce_error is not None
    raise nonce_error


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
