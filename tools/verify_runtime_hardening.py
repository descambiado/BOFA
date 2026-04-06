#!/usr/bin/env python3
"""
BOFA runtime hardening verification.

Lightweight checks for runtime-control regressions that do not require
external services or a fully provisioned frontend environment.
"""

import asyncio
import ast
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    import yaml  # noqa: F401
except ModuleNotFoundError:
    sys.modules["yaml"] = SimpleNamespace(safe_load=lambda *args, **kwargs: {}, safe_dump=lambda *args, **kwargs: "")

from api.execution_queue import ExecutionQueue
from core.engine.engine import ExecutionError, get_engine


class _FakeTimeoutProcess:
    def __init__(self):
        self.returncode = None

    def communicate(self, timeout=None):
        if self.returncode is not None:
            return ("", "timeout")
        raise subprocess.TimeoutExpired(cmd="fake", timeout=timeout)

    def kill(self):
        self.returncode = -9

    def terminate(self):
        self.returncode = -15


def _load_main_functions(*names):
    source = (_ROOT / "api" / "main.py").read_text(encoding="utf-8")
    tree = ast.parse(source, filename="api/main.py")
    selected = {}
    base_globals = {
        "asyncio": asyncio,
        "Optional": Optional,
        "List": List,
        "Dict": Dict,
        "Any": Any,
    }
    for name in names:
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                module = ast.Module(body=[node], type_ignores=[])
                code = compile(module, filename="api/main.py", mode="exec")
                namespace = dict(base_globals)
                exec(code, namespace)
                selected[name] = namespace[name]
                break
        else:
            raise RuntimeError(f"Function {name} not found in api/main.py")
    return selected


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


async def _check_queue_cancellation_while_launching():
    queue = ExecutionQueue(max_concurrent=1)
    await queue.add_to_queue("exec-2", "run-2", "step-2", 1, "demo", "script", {})
    await queue.get_next()
    await queue.mark_process_launching("exec-2")
    cancelled = await queue.cancel("exec-2")
    status = await queue.get_status("exec-2")
    return (
        cancelled is not None
        and status is not None
        and status.get("status") == "running"
        and status.get("cancel_requested") is True
        and len(queue.running) == 1
    )


async def _check_queue_cancellation_after_process_start():
    queue = ExecutionQueue(max_concurrent=1)
    await queue.add_to_queue("exec-3", "run-3", "step-3", 1, "demo", "script", {})
    await queue.get_next()
    await queue.mark_process_launching("exec-3")
    await queue.mark_process_started("exec-3")
    cancelled = await queue.cancel("exec-3")
    return cancelled is not None and cancelled.get("status") == "running" and len(queue.running) == 1


def _check_timeout_error_metadata():
    engine = get_engine()
    engine.initialize()
    with patch("core.engine.engine.subprocess.Popen", return_value=_FakeTimeoutProcess()):
        try:
            engine.execute_script("examples", "example_info", parameters={}, timeout=0.01)
        except ExecutionError as exc:
            details = getattr(exc, "details", {}) or {}
            return "Timeout ejecutando script" in str(exc) and "error ejecutando script" not in str(exc).lower() and "timeout" in details and "duration" in details
    return False


async def _check_flow_cancel_drain_handles_task_error():
    loaded = _load_main_functions("_wait_for_flow_task_drain")
    emitted = []

    async def _emit_stub(*args, **kwargs):
        emitted.append((args, kwargs))
        return None

    helper = loaded["_wait_for_flow_task_drain"]
    helper.__globals__["CANCEL_GRACE_SECONDS"] = 0.01
    helper.__globals__["_emit_and_persist"] = _emit_stub
    helper.__globals__["db"] = SimpleNamespace(get_run_detail=lambda run_id: {"id": run_id, "status": "failed"})
    helper.__globals__["logger"] = SimpleNamespace(warning=lambda *args, **kwargs: None)

    async def _failing_task():
        raise RuntimeError("boom")

    task = asyncio.create_task(_failing_task())
    result = await helper("run-flow", task)
    return result.get("status") == "failed" and emitted and emitted[0][0][3] == "task_error"


def _check_legacy_execution_status_mapping():
    helper = _load_main_functions("_legacy_execution_status")["_legacy_execution_status"]
    return helper("failed") == "error" and helper("success") == "success"


def _check_history_merge():
    helper = _load_main_functions("_merge_history_items")["_merge_history_items"]
    run_items = [{"id": "run-new", "timestamp": "2026-04-06T12:00:00"}]
    legacy_items = [{"id": "legacy-old", "timestamp": "2026-04-05T12:00:00", "legacy": True}]
    merged = helper(run_items, legacy_items, limit=5)
    return len(merged) == 2 and merged[0]["id"] == "run-new" and merged[1]["id"] == "legacy-old"


async def main():
    checks = [
        ("queue cancel before process start frees slot", await _check_queue_cancellation_before_process_start()),
        ("queue cancel while launching keeps tracked handle", await _check_queue_cancellation_while_launching()),
        ("queue cancel after process start keeps live handle", await _check_queue_cancellation_after_process_start()),
        ("timeout raises preserved ExecutionError metadata", _check_timeout_error_metadata()),
        ("flow cancel drain swallows task exception", await _check_flow_cancel_drain_handles_task_error()),
        ("legacy execution status maps failed to error", _check_legacy_execution_status_mapping()),
        ("history merge preserves runs and legacy rows", _check_history_merge()),
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
