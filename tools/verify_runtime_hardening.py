#!/usr/bin/env python3
"""
BOFA runtime hardening verification.

Lightweight checks for runtime-control regressions that do not require
external services or a fully provisioned frontend environment.
"""

import asyncio
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from api.execution_queue import ExecutionQueue


async def _check_queue_cancellation_before_process_start():
    queue = ExecutionQueue(max_concurrent=1)
    await queue.add_to_queue("exec-1", "run-1", "step-1", 1, "demo", "script", {})
    item = await queue.get_next()
    cancelled = await queue.cancel("exec-1")
    status = await queue.get_status("exec-1")
    return (
        item is not None
        and cancelled is not None
        and status is not None
        and status.get("status") == "cancelled"
        and len(queue.running) == 0
        and len(queue.completed) == 1
    )


async def _check_queue_cancellation_after_process_start():
    queue = ExecutionQueue(max_concurrent=1)
    await queue.add_to_queue("exec-2", "run-2", "step-2", 1, "demo", "script", {})
    await queue.get_next()
    await queue.mark_process_started("exec-2")
    cancelled = await queue.cancel("exec-2")
    return cancelled is not None and cancelled.get("status") == "running" and len(queue.running) == 1


async def main():
    checks = [
        ("queue cancel before process start frees slot", await _check_queue_cancellation_before_process_start()),
        ("queue cancel after process start keeps live handle", await _check_queue_cancellation_after_process_start()),
    ]

    failed = [name for name, ok in checks if not ok]

    print("BOFA Runtime Hardening Verification")
    print("=" * 40)
    for name, ok in checks:
        print(f"[{'OK' if ok else 'FAIL'}] {name}")

    if failed:
        print()
        print("Failed checks:")
        for name in failed:
            print(f"- {name}")
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
