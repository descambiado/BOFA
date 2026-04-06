"""
Utilities for cooperative cancellation in BOFA scripts and runtime.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional


DEFAULT_CANCEL_CHECK_INTERVAL = float(os.getenv("BOFA_CANCEL_CHECK_INTERVAL", "0.5"))


def get_cancel_file() -> Optional[Path]:
    cancel_file = os.getenv("BOFA_CANCEL_FILE")
    return Path(cancel_file) if cancel_file else None


def check_cancelled(cancel_file: Optional[str] = None) -> bool:
    path = Path(cancel_file) if cancel_file else get_cancel_file()
    return bool(path and path.exists())


def raise_if_cancelled(cancel_file: Optional[str] = None, message: str = "BOFA cancellation requested") -> None:
    if check_cancelled(cancel_file):
        raise KeyboardInterrupt(message)


def cooperative_sleep(seconds: float, interval: Optional[float] = None, cancel_file: Optional[str] = None) -> None:
    remaining = max(0.0, seconds)
    tick = interval or DEFAULT_CANCEL_CHECK_INTERVAL
    while remaining > 0:
        raise_if_cancelled(cancel_file)
        current = min(tick, remaining)
        time.sleep(current)
        remaining -= current
