"""Lightweight console-log helpers shared by all Guardian protocol loops.

Log suppression keeps repeated watcher-idle noise off the terminal while still
surfacing state transitions and periodic reminders.
"""
from __future__ import annotations

import time
from typing import Any

_LOG_STATE: dict = {}
_LOG_LAST_TIME: dict = {}


def log_state(key: Any, state: Any, message: str) -> None:
    """Print *message* only when *state* for *key* changes."""
    if _LOG_STATE.get(key) != state:
        print(message)
        _LOG_STATE[key] = state


def log_once(key: Any, message: str) -> None:
    log_state(("once", key), True, message)


def log_every(key: Any, message: str, seconds: int = 60) -> None:
    now = time.time()
    last = _LOG_LAST_TIME.get(key, 0.0)
    if now - last >= seconds:
        print(message)
        _LOG_LAST_TIME[key] = now


def preview_list(values, max_items: int = 8) -> str:
    values = list(values)
    if len(values) <= max_items:
        return str(values)
    return str(values[:max_items])[:-1] + f", ... +{len(values) - max_items} more]"
