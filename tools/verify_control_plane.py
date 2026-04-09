#!/usr/bin/env python3
"""
BOFA control-plane smoke verification.

Focused checks for the unified run model, retry lineage, timeline persistence
and legacy history compatibility. Designed to run without external services.
"""

import ast
import asyncio
import json
import hashlib
import mimetypes
import os
import re
import sys
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_VERIFY_ROOT = _ROOT / "data" / ".verify_control_plane"
_VERIFY_ROOT.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("BOFA_DB_PATH", str(_VERIFY_ROOT / "bootstrap.db"))

from api.database import DatabaseManager
from api.run_manager import RunManager


def _load_python_functions(source_path: Path, *names):
    source = source_path.read_text(encoding="utf-8")
    filename = str(source_path.relative_to(_ROOT))
    tree = ast.parse(source, filename=filename)
    selected = {}
    base_globals = {
        "asyncio": asyncio,
        "hashlib": hashlib,
        "json": json,
        "mimetypes": mimetypes,
        "Optional": Optional,
        "Path": Path,
        "re": re,
        "datetime": datetime,
        "timedelta": timedelta,
        "List": List,
        "Dict": Dict,
        "Any": Any,
        "zipfile": zipfile,
    }
    for name in names:
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                module = ast.Module(body=[node], type_ignores=[])
                code = compile(module, filename=filename, mode="exec")
                namespace = dict(base_globals)
                exec(code, namespace)
                selected[name] = namespace[name]
                break
        else:
            raise RuntimeError(f"Function {name} not found in {filename}")
    return selected


def _load_main_functions(*names):
    return _load_python_functions(_ROOT / "api" / "main.py", *names)


def _load_flow_functions(*names):
    return _load_python_functions(_ROOT / "flows" / "flow_runner.py", *names)


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


def _check_flow_partial_summary_artifacts():
    _, artifact_dir, db, manager = _make_runtime()
    run_id = manager.create_run(
        user_id=1,
        run_type="flow",
        source="verify_control_plane",
        requested_action="execute_flow",
        target="partial.local",
        status="running",
    )
    loaded = _load_flow_functions(
        "_flow_artifact_content_type",
        "_flow_artifact_metadata",
        "_build_flow_summary",
        "_build_flow_markdown",
        "_finalize_flow_result",
    )
    loaded["_flow_artifact_metadata"].__globals__["Path"] = Path
    loaded["_flow_artifact_metadata"].__globals__["_flow_artifact_content_type"] = loaded["_flow_artifact_content_type"]
    loaded["_flow_artifact_content_type"].__globals__["mimetypes"] = mimetypes
    loaded["_build_flow_summary"].__globals__["datetime"] = datetime
    loaded["_build_flow_markdown"].__globals__["datetime"] = datetime
    finalize = loaded["_finalize_flow_result"]
    finalize.__globals__["datetime"] = datetime
    finalize.__globals__["json"] = json
    finalize.__globals__["Path"] = Path
    finalize.__globals__["_ROOT"] = _ROOT
    finalize.__globals__["_build_flow_summary"] = loaded["_build_flow_summary"]
    finalize.__globals__["_build_flow_markdown"] = loaded["_build_flow_markdown"]
    finalize.__globals__["_flow_artifact_metadata"] = loaded["_flow_artifact_metadata"]

    result = finalize(
        "verify_flow",
        {"name": "verify_flow"},
        "partial.local",
        artifact_dir,
        SimpleNamespace(execute_script=lambda **kwargs: None),
        SimpleNamespace(execution_timeout=60),
        [
            {"index": 1, "module": "examples", "script": "example_info", "status": "success", "exit_code": 0, "duration": 0.1, "stdout_preview": "ok", "stderr_preview": "", "error": None},
            {"index": 2, "module": "examples", "script": "example_fail", "status": "failed", "exit_code": 1, "duration": 0.2, "stdout_preview": "partial", "stderr_preview": "boom", "error": "boom"},
        ],
        "partial",
        run_manager=manager,
        run_id=run_id,
        cause="Synthetic partial flow",
    )

    detail = db.get_run_detail(run_id)
    artifact_types = {artifact.get("artifact_type") for artifact in detail.get("artifacts", [])}
    summary_artifact = next((artifact for artifact in detail.get("artifacts", []) if artifact.get("artifact_type") == "flow_summary_json"), None)
    return (
        result.get("status") == "partial"
        and result.get("artifact_count") == 2
        and Path(result["report_path"]).exists()
        and Path(result["report_json_path"]).exists()
        and {"flow_summary_json", "flow_summary_markdown"}.issubset(artifact_types)
        and summary_artifact is not None
        and (summary_artifact.get("metadata") or {}).get("partial") is True
        and result.get("report_json", {}).get("failed_steps") == 1
        and result.get("report_json", {}).get("cause") == "Synthetic partial flow"
    )


def _check_flow_cancelled_summary_and_post_process_skip():
    _, artifact_dir, db, manager = _make_runtime()
    run_id = manager.create_run(
        user_id=1,
        run_type="flow",
        source="verify_control_plane",
        requested_action="execute_flow",
        target="cancelled.local",
        status="running",
    )
    loaded = _load_flow_functions(
        "_flow_artifact_content_type",
        "_flow_artifact_metadata",
        "_build_flow_summary",
        "_build_flow_markdown",
        "_finalize_flow_result",
    )
    loaded["_flow_artifact_metadata"].__globals__["Path"] = Path
    loaded["_flow_artifact_metadata"].__globals__["_flow_artifact_content_type"] = loaded["_flow_artifact_content_type"]
    loaded["_flow_artifact_content_type"].__globals__["mimetypes"] = mimetypes
    loaded["_build_flow_summary"].__globals__["datetime"] = datetime
    loaded["_build_flow_markdown"].__globals__["datetime"] = datetime
    finalize = loaded["_finalize_flow_result"]
    finalize.__globals__["datetime"] = datetime
    finalize.__globals__["json"] = json
    finalize.__globals__["Path"] = Path
    finalize.__globals__["_ROOT"] = _ROOT
    finalize.__globals__["_build_flow_summary"] = loaded["_build_flow_summary"]
    finalize.__globals__["_build_flow_markdown"] = loaded["_build_flow_markdown"]
    finalize.__globals__["_flow_artifact_metadata"] = loaded["_flow_artifact_metadata"]

    result = finalize(
        "verify_cancelled_flow",
        {"name": "verify_cancelled_flow", "post_process": {"script": "reporting/flow_report_aggregator", "params": {"output": "reports/skip.md"}}},
        "cancelled.local",
        artifact_dir,
        SimpleNamespace(execute_script=lambda **kwargs: None),
        SimpleNamespace(execution_timeout=60),
        [
            {"index": 1, "module": "examples", "script": "example_info", "status": "success", "exit_code": 0, "duration": 0.1, "stdout_preview": "ok", "stderr_preview": "", "error": None},
            {"index": 2, "module": "examples", "script": "example_params", "status": "cancelled", "exit_code": -15, "duration": 0.2, "stdout_preview": "partial", "stderr_preview": "", "error": "cancelled"},
        ],
        "cancelled",
        run_manager=manager,
        run_id=run_id,
        cancelled_at_step=2,
        cause="Synthetic cancellation",
    )

    detail = db.get_run_detail(run_id)
    return (
        result.get("status") == "cancelled"
        and result.get("cancelled_at_step") == 2
        and Path(result["report_path"]).exists()
        and Path(result["report_json_path"]).exists()
        and any(event.get("event_type") == "post_process_skipped" for event in detail.get("events", []))
        and any((artifact.get("metadata") or {}).get("partial") is True for artifact in detail.get("artifacts", []))
    )


def _check_artifact_preview_helpers():
    _, artifact_dir, db, manager = _make_runtime()
    run_id = manager.create_run(
        user_id=1,
        run_type="script",
        source="verify_control_plane",
        requested_action="execute_script",
        target="artifact.local",
        status="cancelled",
    )
    step_id = manager.create_step(
        run_id=run_id,
        step_type="script",
        step_index=1,
        step_key="step_1",
        module="examples",
        script_name="example_info",
        parameters={},
        status="cancelled",
    )
    manager.mark_run_finished(run_id, "cancelled", "Cancelled for artifact smoke", metadata={"reason": "smoke"})

    stdout_path = artifact_dir / "stdout.log"
    stdout_path.write_text("line\n" * 1200, encoding="utf-8")
    manager.add_artifact(run_id, "stdout_log", str(stdout_path), label="stdout smoke", metadata={"step_id": step_id, "execution_id": "exec_smoke"})

    summary_path = artifact_dir / "summary.json"
    summary_path.write_text(json.dumps({"status": "partial", "steps": [1, 2, 3]}, indent=2), encoding="utf-8")
    manager.add_artifact(run_id, "flow_summary_json", str(summary_path), label="summary smoke", metadata={"partial": True})

    binary_path = artifact_dir / "capture.bin"
    binary_path.write_bytes(b"\x00\x01\x02\x03")
    manager.add_artifact(run_id, "binary_capture", str(binary_path), label="binary smoke", metadata={})

    detail = db.get_run_detail(run_id)
    loaded = _load_main_functions(
        "_artifact_role",
        "_artifact_content_type",
        "_is_previewable_content_type",
        "_artifact_preview_mode",
        "_artifact_size_bytes",
        "_serialize_artifact",
        "_build_artifact_preview_payload",
    )
    loaded["_artifact_role"].__globals__["EVIDENCE_EXPORT_ARTIFACT_TYPES"] = {"evidence_bundle_zip", "evidence_manifest_json"}
    loaded["_artifact_content_type"].__globals__["mimetypes"] = mimetypes
    loaded["_artifact_content_type"].__globals__["Path"] = Path
    loaded["_artifact_preview_mode"].__globals__["ARTIFACT_TAIL_PREVIEW_TYPES"] = {"stdout_log", "stderr_log"}
    loaded["_artifact_preview_mode"].__globals__["ARTIFACT_HEAD_PREVIEW_TYPES"] = {"report_json", "report_markdown", "flow_summary_json", "flow_summary_markdown", "post_process_output"}
    loaded["_artifact_preview_mode"].__globals__["_is_previewable_content_type"] = loaded["_is_previewable_content_type"]
    loaded["_artifact_size_bytes"].__globals__["Path"] = Path
    loaded["_serialize_artifact"].__globals__["Path"] = Path
    loaded["_serialize_artifact"].__globals__["_artifact_role"] = loaded["_artifact_role"]
    loaded["_serialize_artifact"].__globals__["_artifact_content_type"] = loaded["_artifact_content_type"]
    loaded["_serialize_artifact"].__globals__["_artifact_preview_mode"] = loaded["_artifact_preview_mode"]
    loaded["_serialize_artifact"].__globals__["_artifact_size_bytes"] = loaded["_artifact_size_bytes"]
    loaded["_build_artifact_preview_payload"].__globals__["Path"] = Path
    loaded["_build_artifact_preview_payload"].__globals__["ARTIFACT_PREVIEW_LIMIT"] = 4000
    loaded["_build_artifact_preview_payload"].__globals__["_serialize_artifact"] = loaded["_serialize_artifact"]

    stdout_artifact = next(artifact for artifact in detail.get("artifacts", []) if artifact.get("artifact_type") == "stdout_log")
    summary_artifact = next(artifact for artifact in detail.get("artifacts", []) if artifact.get("artifact_type") == "flow_summary_json")
    binary_artifact = next(artifact for artifact in detail.get("artifacts", []) if artifact.get("artifact_type") == "binary_capture")

    serialized_stdout = loaded["_serialize_artifact"](stdout_artifact, detail)
    stdout_preview = loaded["_build_artifact_preview_payload"](run_id, stdout_artifact, detail)
    summary_preview = loaded["_build_artifact_preview_payload"](run_id, summary_artifact, detail)
    binary_preview = loaded["_build_artifact_preview_payload"](run_id, binary_artifact, detail)

    return (
        (serialized_stdout.get("metadata") or {}).get("run_status") == "cancelled"
        and (serialized_stdout.get("metadata") or {}).get("step_status") == "cancelled"
        and (serialized_stdout.get("metadata") or {}).get("preview_mode") == "tail"
        and (serialized_stdout.get("metadata") or {}).get("partial") is True
        and stdout_preview.get("previewable") is True
        and stdout_preview.get("preview_mode") == "tail"
        and stdout_preview.get("truncated") is True
        and summary_preview.get("previewable") is True
        and summary_preview.get("preview_mode") == "head"
        and binary_preview.get("previewable") is False
        and binary_preview.get("reason") == "binary_or_unsupported"
    )


def _check_evidence_bundle_export():
    _, artifact_dir, db, manager = _make_runtime()
    run_id = manager.create_run(
        user_id=1,
        run_type="script",
        source="verify_control_plane",
        requested_action="execute_script",
        target="evidence.local",
        status="cancelled",
    )
    step_id = manager.create_step(
        run_id=run_id,
        step_type="script",
        step_index=1,
        step_key="step_1",
        module="examples",
        script_name="example_info",
        parameters={"json": True},
        status="cancelled",
    )
    manager.update_step(
        step_id,
        run_id,
        status="cancelled",
        completed_at=_utc_now(),
        exit_code=-15,
        stdout_preview="partial output",
        error_message="Synthetic cancellation",
        message="Cancelled for export smoke",
    )
    manager.mark_run_finished(run_id, "cancelled", "Evidence export smoke", metadata={"reason": "smoke"})

    included_path = artifact_dir / "stdout.log"
    included_path.write_text("portable evidence\n" * 32, encoding="utf-8")
    manager.add_artifact(run_id, "stdout_log", str(included_path), label="included stdout", metadata={"step_id": step_id})

    missing_path = artifact_dir / "missing.log"
    manager.add_artifact(run_id, "stderr_log", str(missing_path), label="missing stderr", metadata={"step_id": step_id})

    outside_path = Path(_ROOT.anchor) / "outside_bofa_evidence.log"
    manager.add_artifact(run_id, "binary_capture", str(outside_path), label="outside evidence", metadata={})

    loaded = _load_main_functions(
        "_artifact_role",
        "_artifact_content_type",
        "_is_previewable_content_type",
        "_artifact_preview_mode",
        "_artifact_size_bytes",
        "_build_runtime_artifact_metadata",
        "_serialize_artifact",
        "_serialize_artifacts",
        "_serialize_run",
        "_sanitize_export_name",
        "_guess_extension_from_content_type",
        "_is_path_within_root",
        "_sha256_file",
        "_build_evidence_bundle_readme",
        "_find_existing_evidence_export",
        "_create_run_evidence_export",
    )

    evidence_types = {"evidence_bundle_zip", "evidence_manifest_json"}

    loaded["_artifact_role"].__globals__["EVIDENCE_EXPORT_ARTIFACT_TYPES"] = evidence_types
    loaded["_artifact_content_type"].__globals__["mimetypes"] = mimetypes
    loaded["_artifact_content_type"].__globals__["Path"] = Path
    loaded["_artifact_preview_mode"].__globals__["ARTIFACT_TAIL_PREVIEW_TYPES"] = {"stdout_log", "stderr_log"}
    loaded["_artifact_preview_mode"].__globals__["ARTIFACT_HEAD_PREVIEW_TYPES"] = {
        "report_json",
        "report_markdown",
        "flow_summary_json",
        "flow_summary_markdown",
        "post_process_output",
        "evidence_manifest_json",
    }
    loaded["_artifact_preview_mode"].__globals__["_is_previewable_content_type"] = loaded["_is_previewable_content_type"]
    loaded["_artifact_size_bytes"].__globals__["Path"] = Path
    loaded["_build_runtime_artifact_metadata"].__globals__["_artifact_content_type"] = loaded["_artifact_content_type"]
    loaded["_build_runtime_artifact_metadata"].__globals__["_artifact_preview_mode"] = loaded["_artifact_preview_mode"]
    loaded["_build_runtime_artifact_metadata"].__globals__["_artifact_role"] = loaded["_artifact_role"]
    loaded["_build_runtime_artifact_metadata"].__globals__["_artifact_size_bytes"] = loaded["_artifact_size_bytes"]
    loaded["_serialize_artifact"].__globals__["Path"] = Path
    loaded["_serialize_artifact"].__globals__["_artifact_role"] = loaded["_artifact_role"]
    loaded["_serialize_artifact"].__globals__["_artifact_content_type"] = loaded["_artifact_content_type"]
    loaded["_serialize_artifact"].__globals__["_artifact_preview_mode"] = loaded["_artifact_preview_mode"]
    loaded["_serialize_artifact"].__globals__["_artifact_size_bytes"] = loaded["_artifact_size_bytes"]
    loaded["_serialize_artifacts"].__globals__["_serialize_artifact"] = loaded["_serialize_artifact"]
    loaded["_serialize_run"].__globals__["_serialize_artifacts"] = loaded["_serialize_artifacts"]
    loaded["_guess_extension_from_content_type"].__globals__["mimetypes"] = mimetypes
    loaded["_sha256_file"].__globals__["hashlib"] = hashlib
    loaded["_find_existing_evidence_export"].__globals__["Path"] = Path
    loaded["_find_existing_evidence_export"].__globals__["EVIDENCE_EXPORT_ARTIFACT_TYPES"] = evidence_types

    export_root = _VERIFY_ROOT / "evidence_exports"
    export_root.mkdir(parents=True, exist_ok=True)

    create_export = loaded["_create_run_evidence_export"]
    create_export.__globals__["APP_ROOT"] = _ROOT
    create_export.__globals__["RUNTIME_REPORTS_DIR"] = export_root
    create_export.__globals__["EVIDENCE_BUNDLE_VERSION"] = "1.0"
    create_export.__globals__["EVIDENCE_EXPORT_ARTIFACT_TYPES"] = evidence_types
    create_export.__globals__["RUN_STATUSES_FINAL"] = {"success", "failed", "error", "partial", "cancelled"}
    create_export.__globals__["datetime"] = datetime
    create_export.__globals__["json"] = json
    create_export.__globals__["Path"] = Path
    create_export.__globals__["zipfile"] = zipfile
    create_export.__globals__["db"] = db
    create_export.__globals__["run_manager"] = manager
    create_export.__globals__["_serialize_run"] = loaded["_serialize_run"]
    create_export.__globals__["_find_existing_evidence_export"] = loaded["_find_existing_evidence_export"]
    create_export.__globals__["_artifact_content_type"] = loaded["_artifact_content_type"]
    create_export.__globals__["_artifact_size_bytes"] = loaded["_artifact_size_bytes"]
    create_export.__globals__["_build_runtime_artifact_metadata"] = loaded["_build_runtime_artifact_metadata"]
    create_export.__globals__["_sanitize_export_name"] = loaded["_sanitize_export_name"]
    create_export.__globals__["_guess_extension_from_content_type"] = loaded["_guess_extension_from_content_type"]
    create_export.__globals__["_is_path_within_root"] = loaded["_is_path_within_root"]
    create_export.__globals__["_sha256_file"] = loaded["_sha256_file"]
    create_export.__globals__["_build_evidence_bundle_readme"] = loaded["_build_evidence_bundle_readme"]

    export_payload = create_export(run_id)
    second_payload = create_export(run_id)
    bundle_path = Path(export_payload["bundle_path"])
    manifest_path = Path(export_payload["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    detail = db.get_run_detail(run_id)

    included_entry = next((artifact for artifact in manifest.get("artifacts", []) if artifact.get("artifact_type") == "stdout_log"), None)
    missing_entry = next((artifact for artifact in manifest.get("artifacts", []) if artifact.get("artifact_type") == "stderr_log"), None)
    outside_entry = next((artifact for artifact in manifest.get("artifacts", []) if artifact.get("artifact_type") == "binary_capture"), None)
    artifact_types = {artifact.get("artifact_type") for artifact in detail.get("artifacts", [])}

    with zipfile.ZipFile(bundle_path, "r") as archive:
        names = set(archive.namelist())

    return (
        export_payload.get("created") is True
        and second_payload.get("created") is False
        and bundle_path.exists()
        and manifest_path.exists()
        and {"manifest.json", "run.json", "timeline.json", "steps.json", "labs.json", "README.txt"}.issubset(names)
        and any(name.startswith("artifacts/") for name in names)
        and included_entry is not None
        and included_entry.get("included") is True
        and isinstance(included_entry.get("sha256"), str)
        and len(included_entry.get("sha256")) == 64
        and missing_entry is not None
        and missing_entry.get("included") is False
        and missing_entry.get("missing") is True
        and missing_entry.get("reason") == "artifact_not_found"
        and outside_entry is not None
        and outside_entry.get("included") is False
        and outside_entry.get("reason") == "outside_allowed_root"
        and {"evidence_bundle_zip", "evidence_manifest_json"}.issubset(artifact_types)
        and any(event.get("event_type") == "evidence_exported" for event in detail.get("events", []))
        and any(event.get("event_type") == "evidence_export_warning" for event in detail.get("events", []))
    )


def main():
    checks = [
        ("run lifecycle persists steps labs events and artifacts", _check_run_lifecycle_persistence()),
        ("flow partial summaries persist artifacts", _check_flow_partial_summary_artifacts()),
        ("flow cancelled summaries skip post-process cleanly", _check_flow_cancelled_summary_and_post_process_skip()),
        ("artifact helpers enrich and preview runtime evidence", _check_artifact_preview_helpers()),
        ("evidence bundle export packages artifacts and checksums", _check_evidence_bundle_export()),
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
