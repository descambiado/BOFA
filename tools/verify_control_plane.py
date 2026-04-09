#!/usr/bin/env python3
"""
BOFA control-plane smoke verification.

Focused checks for the unified run model, retry lineage, timeline persistence
and legacy history compatibility. Designed to run without external services.
"""

import ast
import asyncio
import json
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_VERIFY_ROOT = _ROOT / "data" / ".verify_control_plane"
_VERIFY_ROOT.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("BOFA_DB_PATH", str(_VERIFY_ROOT / "bootstrap.db"))

from api.database import DatabaseManager
from api.run_manager import RunManager


def _load_main_functions(*names):
    source = (_ROOT / "api" / "main.py").read_text(encoding="utf-8")
    tree = ast.parse(source, filename="api/main.py")
    selected = {}
    base_globals = {
        "asyncio": asyncio,
        "json": json,
        "Path": Path,
        "datetime": datetime,
        "timedelta": timedelta,
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


def _make_runtime():
    runtime_id = uuid.uuid4().hex
    temp_dir = _VERIFY_ROOT / f"runtime_{runtime_id}"
    artifact_dir = _VERIFY_ROOT / f"artifacts_{runtime_id}"
    temp_dir.mkdir(parents=True, exist_ok=True)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    db_path = _VERIFY_ROOT / f"runtime_{runtime_id}.db"
    db = DatabaseManager(str(db_path))
    manager = RunManager(db)
    return temp_dir, artifact_dir, db, manager


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _check_run_lifecycle_persistence():
    _, artifact_dir, db, manager = _make_runtime()
    run_id = manager.create_run(
        user_id=1,
        run_type="script",
        source="verify_control_plane",
        requested_action="execute_script",
        target="verify.local",
        metadata={"purpose": "smoke"},
    )
    manager.mark_run_started(run_id, "Smoke run started")
    step_id = manager.create_step(
        run_id=run_id,
        step_type="script",
        step_index=1,
        step_key="step_1",
        module="examples",
        script_name="example_info",
        parameters={"json": True},
    )
    manager.update_step(
        step_id,
        run_id,
        status="success",
        started_at=_utc_now(),
        completed_at=_utc_now(),
        exit_code=0,
        duration=0.25,
        stdout_preview='{"ok": true}',
        message="Script finished cleanly",
    )
    lab_run_id = manager.attach_lab(run_id, "lab-demo", status="running", container_id="container-1", port=31337)
    manager.update_lab(lab_run_id, run_id, "success", stopped_at=_utc_now(), message="Lab lifecycle captured")
    artifact_path = artifact_dir / "artifact.json"
    artifact_path.write_text('{"artifact": true}', encoding="utf-8")
    manager.add_artifact(run_id, "report_json", str(artifact_path), label="Smoke artifact")
    manager.mark_run_finished(run_id, "success", "Smoke run completed", metadata={"verified": True})

    detail = db.get_run_detail(run_id)
    return (
        detail is not None
        and detail.get("status") == "success"
        and len(detail.get("steps", [])) == 1
        and len(detail.get("labs", [])) == 1
        and len(detail.get("artifacts", [])) == 1
        and len(detail.get("events", [])) >= 6
        and any(event.get("event_type") == "artifact_created" for event in detail.get("events", []))
        and detail["steps"][0].get("module") == "examples"
        and detail["labs"][0].get("lab_id") == "lab-demo"
        and detail["artifacts"][0].get("path") == str(artifact_path)
    )


def _check_retry_lineage():
    _, _, db, manager = _make_runtime()
    run_id = manager.create_run(
        user_id=1,
        run_type="flow",
        source="verify_control_plane",
        requested_action="run_flow",
        target="verify.target",
        metadata={"retry_count": 0},
    )
    step_id = manager.create_step(
        run_id=run_id,
        step_type="flow_step",
        step_index=1,
        step_key="step_1",
        module="examples",
        script_name="example_fail",
        parameters={"mode": "error"},
    )
    manager.update_step(
        step_id,
        run_id,
        status="failed",
        completed_at=_utc_now(),
        exit_code=1,
        error_message="Synthetic failure",
        message="Step failed as expected",
    )
    manager.mark_run_finished(run_id, "failed", "Initial run failed", metadata={"retry_count": 0})

    payload = manager.retry_payload(run_id)
    if not payload:
        return False

    retry_run_id = manager.create_run(
        user_id=1,
        run_type=payload["run_type"],
        source=payload["source"],
        requested_action=payload["requested_action"],
        target=payload["target"],
        parent_run_id=run_id,
        metadata={
            "retry_of": payload["retry_of"],
            "retry_count": payload["retry_count"],
            "retry_reason": "smoke",
            "last_non_success_step": payload["last_non_success_step"],
        },
    )
    retry_detail = db.get_run_detail(retry_run_id)
    return (
        payload.get("retry_of") == run_id
        and payload.get("retry_count") == 1
        and payload.get("last_non_success_step", {}).get("script_name") == "example_fail"
        and retry_detail is not None
        and retry_detail.get("parent_run_id") == run_id
        and retry_detail.get("metadata", {}).get("retry_count") == 1
    )


def _check_retry_event_lineage():
    _, _, db, manager = _make_runtime()
    original_run_id = manager.create_run(
        user_id=1,
        run_type="script",
        source="verify_control_plane",
        requested_action="execute_script",
        target="retry.local",
        metadata={
            "module": "examples",
            "script": "example_info",
            "parameters": {"json": True},
            "retry_count": 0,
        },
    )
    original_step_id = manager.create_step(
        run_id=original_run_id,
        step_type="script",
        step_index=1,
        step_key="script_1",
        module="examples",
        script_name="example_info",
        parameters={"json": True},
    )
    manager.update_step(
        original_step_id,
        original_run_id,
        status="failed",
        completed_at=_utc_now(),
        exit_code=1,
        error_message="Synthetic retry failure",
        message="Initial step failed for retry smoke",
    )
    manager.mark_run_finished(original_run_id, "failed", "Retry source failed", metadata={"retry_count": 0})

    payload = manager.retry_payload(original_run_id)
    if not payload:
        return False

    retry_metadata = {
        "retry_of": original_run_id,
        "retry_count": payload.get("retry_count", 1),
        "retry_reason": "failed",
        "last_non_success_step": payload.get("last_non_success_step"),
    }
    manager.add_event(
        original_run_id,
        "run",
        original_run_id,
        "retry_requested",
        "success",
        "Retry requested for run",
        retry_metadata,
    )
    retry_run_id = manager.create_run(
        user_id=1,
        run_type=payload["run_type"],
        source="retry",
        requested_action=payload["requested_action"],
        target=payload["target"],
        parent_run_id=original_run_id,
        metadata={
            "module": "examples",
            "script": "example_info",
            "parameters": {"json": True},
            **retry_metadata,
        },
    )
    manager.add_event(
        retry_run_id,
        "run",
        retry_run_id,
        "retried_from",
        "queued",
        "Run created from retry",
        {"parent_run_id": original_run_id, "retry_count": retry_metadata["retry_count"]},
    )

    original_detail = db.get_run_detail(original_run_id)
    retry_detail = db.get_run_detail(retry_run_id)
    original_events = original_detail.get("events", []) if original_detail else []
    retry_events = retry_detail.get("events", []) if retry_detail else []
    return (
        original_detail is not None
        and retry_detail is not None
        and retry_detail.get("parent_run_id") == original_run_id
        and retry_detail.get("metadata", {}).get("retry_of") == original_run_id
        and any(event.get("event_type") == "retry_requested" for event in original_events)
        and any(event.get("event_type") == "retried_from" for event in retry_events)
        and any(
            event.get("event_type") == "retry_requested"
            and (event.get("payload") or {}).get("last_non_success_step", {}).get("id") == original_step_id
            for event in original_events
        )
        and any(
            event.get("event_type") == "retried_from"
            and (event.get("payload") or {}).get("parent_run_id") == original_run_id
            for event in retry_events
        )
    )


def _check_run_listing_filters():
    _, _, db, manager = _make_runtime()
    run_script = manager.create_run(1, "script", "verify", "execute_script", target="a.local", status="queued")
    run_flow = manager.create_run(1, "flow", "verify", "run_flow", target="b.local", status="queued")
    manager.mark_run_finished(run_script, "success", "Script run succeeded")
    manager.mark_run_finished(run_flow, "failed", "Flow run failed")
    success_runs = db.list_runs(user_id=1, status="success", limit=10)
    flow_runs = db.list_runs(user_id=1, run_type="flow", limit=10)
    return (
        len(success_runs) == 1
        and success_runs[0].get("id") == run_script
        and len(flow_runs) == 1
        and flow_runs[0].get("id") == run_flow
    )


def _check_legacy_history_merge():
    _, _, db, manager = _make_runtime()
    helpers = _load_main_functions("_normalize_history_from_runs", "_normalize_legacy_history", "_merge_history_items")
    helpers["_normalize_history_from_runs"].__globals__["db"] = db
    helpers["_normalize_legacy_history"].__globals__["db"] = db
    run_id = manager.create_run(
        user_id=1,
        run_type="script",
        source="verify_control_plane",
        requested_action="execute_script",
        target="history.local",
    )
    manager.mark_run_finished(run_id, "success", "Modern run completed")

    legacy_id = "legacy_execution_1"
    db.create_execution(
        execution_id=legacy_id,
        user_id=1,
        module="examples",
        script_name="example_info",
        parameters={"legacy": True},
    )
    db.update_execution(
        legacy_id,
        status="error",
        output="legacy stdout",
        error_message="legacy failure",
        execution_time=0.42,
    )

    runs = db.list_runs(user_id=1, limit=10)
    run_items = helpers["_normalize_history_from_runs"](runs)
    normalized = helpers["_normalize_legacy_history"](1, limit=10)
    merged = helpers["_merge_history_items"](run_items, normalized, limit=10)
    legacy_item = next((item for item in merged if item.get("legacy")), None)
    modern_item = next((item for item in merged if item.get("id") == run_id), None)
    return (
        len(merged) == 2
        and modern_item is not None
        and legacy_item is not None
        and legacy_item.get("status") == "error"
        and legacy_item.get("script") == "example_info"
    )


async def _check_runtime_cancellation_updates_run_and_children():
    _, _, db, manager = _make_runtime()
    run_id = manager.create_run(
        user_id=1,
        run_type="script",
        source="verify_control_plane",
        requested_action="execute_script",
        target="cancel.local",
        status="running",
    )
    step_id = manager.create_step(
        run_id=run_id,
        step_type="script",
        step_index=1,
        step_key="step_1",
        module="examples",
        script_name="example_info",
        parameters={"json": True},
        status="running",
    )
    lab_run_id = manager.attach_lab(run_id, "lab-cancel", status="running", container_id="container-cancel", port=4444)

    helpers = _load_main_functions(
        "_cancel_file_path",
        "_get_runtime_control",
        "_write_cancel_marker",
        "_request_runtime_cancellation",
    )

    emitted = []

    async def _emit_stub(*args, **kwargs):
        emitted.append((args, kwargs))
        manager.add_event(args[0], args[1], args[2], args[3], args[4], args[5], args[6])
        return None

    runtime_controls = {}
    cancel_dir = _VERIFY_ROOT / "cancel_markers"
    cancel_dir.mkdir(parents=True, exist_ok=True)

    cancel_file_path = helpers["_cancel_file_path"]
    cancel_file_path.__globals__["CANCEL_DIR"] = cancel_dir
    cancel_file_path.__globals__["Path"] = Path

    get_runtime_control = helpers["_get_runtime_control"]
    get_runtime_control.__globals__["runtime_controls"] = runtime_controls
    get_runtime_control.__globals__["_cancel_file_path"] = cancel_file_path

    write_cancel_marker = helpers["_write_cancel_marker"]
    write_cancel_marker.__globals__["Path"] = Path
    write_cancel_marker.__globals__["json"] = json
    write_cancel_marker.__globals__["datetime"] = datetime

    request_runtime_cancellation = helpers["_request_runtime_cancellation"]
    request_runtime_cancellation.__globals__["_get_runtime_control"] = get_runtime_control
    request_runtime_cancellation.__globals__["_write_cancel_marker"] = write_cancel_marker
    request_runtime_cancellation.__globals__["_emit_and_persist"] = _emit_stub
    request_runtime_cancellation.__globals__["run_manager"] = manager
    request_runtime_cancellation.__globals__["db"] = db
    request_runtime_cancellation.__globals__["runtime_controls"] = runtime_controls
    request_runtime_cancellation.__globals__["RUN_STATUSES_FINAL"] = {"success", "failed", "error", "partial", "cancelled"}
    request_runtime_cancellation.__globals__["CANCEL_GRACE_SECONDS"] = 4
    request_runtime_cancellation.__globals__["datetime"] = datetime

    run_detail = db.get_run_detail(run_id)
    control = await request_runtime_cancellation(run_detail, reason="smoke_cancel")
    updated = db.get_run_detail(run_id)
    marker_path = Path(control["run_cancel_file"])

    return (
        control.get("cancel_requested") is True
        and updated is not None
        and updated.get("status") == "cancelling"
        and updated["steps"][0].get("status") == "cancelling"
        and updated["labs"][0].get("status") == "cancelling"
        and marker_path.exists()
        and any(event.get("event_type") == "cancelling" for event in updated.get("events", []))
        and emitted
        and emitted[0][0][3] == "cancelling"
        and emitted[0][0][4] == "cancelling"
        and emitted[0][0][6].get("cancel_reason") == "smoke_cancel"
        and step_id == updated["steps"][0].get("id")
        and lab_run_id == updated["labs"][0].get("id")
    )


async def _check_runtime_cancellation_is_idempotent():
    _, _, db, manager = _make_runtime()
    run_id = manager.create_run(
        user_id=1,
        run_type="flow",
        source="verify_control_plane",
        requested_action="execute_flow",
        target="idempotent.local",
        status="running",
    )
    manager.create_step(
        run_id=run_id,
        step_type="flow_step",
        step_index=1,
        step_key="step_1",
        module="examples",
        script_name="example_info",
        parameters={},
        status="running",
    )

    helpers = _load_main_functions(
        "_cancel_file_path",
        "_get_runtime_control",
        "_write_cancel_marker",
        "_request_runtime_cancellation",
    )

    emitted = []

    async def _emit_stub(*args, **kwargs):
        emitted.append((args, kwargs))
        manager.add_event(args[0], args[1], args[2], args[3], args[4], args[5], args[6])
        return None

    runtime_controls = {}
    cancel_dir = _VERIFY_ROOT / "cancel_markers"
    cancel_dir.mkdir(parents=True, exist_ok=True)

    cancel_file_path = helpers["_cancel_file_path"]
    cancel_file_path.__globals__["CANCEL_DIR"] = cancel_dir
    cancel_file_path.__globals__["Path"] = Path

    get_runtime_control = helpers["_get_runtime_control"]
    get_runtime_control.__globals__["runtime_controls"] = runtime_controls
    get_runtime_control.__globals__["_cancel_file_path"] = cancel_file_path

    write_cancel_marker = helpers["_write_cancel_marker"]
    write_cancel_marker.__globals__["Path"] = Path
    write_cancel_marker.__globals__["json"] = json
    write_cancel_marker.__globals__["datetime"] = datetime

    request_runtime_cancellation = helpers["_request_runtime_cancellation"]
    request_runtime_cancellation.__globals__["_get_runtime_control"] = get_runtime_control
    request_runtime_cancellation.__globals__["_write_cancel_marker"] = write_cancel_marker
    request_runtime_cancellation.__globals__["_emit_and_persist"] = _emit_stub
    request_runtime_cancellation.__globals__["run_manager"] = manager
    request_runtime_cancellation.__globals__["db"] = db
    request_runtime_cancellation.__globals__["runtime_controls"] = runtime_controls
    request_runtime_cancellation.__globals__["RUN_STATUSES_FINAL"] = {"success", "failed", "error", "partial", "cancelled"}
    request_runtime_cancellation.__globals__["CANCEL_GRACE_SECONDS"] = 4
    request_runtime_cancellation.__globals__["datetime"] = datetime

    run_detail = db.get_run_detail(run_id)
    first = await request_runtime_cancellation(run_detail, reason="first_cancel")
    event_count_after_first = len(db.get_run_events(run_id))
    second = await request_runtime_cancellation(db.get_run_detail(run_id), reason="second_cancel")
    event_count_after_second = len(db.get_run_events(run_id))

    return (
        first.get("cancel_requested") is True
        and second.get("cancel_requested") is True
        and first.get("cancel_requested_at") == second.get("cancel_requested_at")
        and event_count_after_first == event_count_after_second
        and len(emitted) == 1
    )


def main():
    checks = [
        ("run lifecycle persists steps labs events and artifacts", _check_run_lifecycle_persistence()),
        ("retry payload preserves lineage and last failed step", _check_retry_lineage()),
        ("retry events link original and child runs", _check_retry_event_lineage()),
        ("run listing filters by status and type", _check_run_listing_filters()),
        ("legacy history merge keeps modern and legacy rows", _check_legacy_history_merge()),
        ("runtime cancellation updates run steps labs and markers", asyncio.run(_check_runtime_cancellation_updates_run_and_children())),
        ("runtime cancellation is idempotent once requested", asyncio.run(_check_runtime_cancellation_is_idempotent())),
    ]

    failed = [name for name, ok in checks if not ok]

    print("BOFA Control Plane Verification")
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
    main()
