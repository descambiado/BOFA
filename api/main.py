#!/usr/bin/env python3
"""
BOFA API - operational control plane.
"""

import asyncio
from datetime import datetime
import json
import logging
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Form, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn
import yaml

from auth import AuthManager, Roles, check_permission
from database import db
from execution_queue import execution_queue
from lab_manager import LabManager
from run_manager import RunManager
from script_executor import ScriptExecutor
from websocket_manager import ws_manager
from flows.flow_runner import list_flows, run_flow

APP_ROOT = Path(os.getenv("BOFA_APP_ROOT", Path(__file__).resolve().parents[1]))
SCRIPTS_DIR = Path(os.getenv("BOFA_SCRIPTS_DIR", APP_ROOT / "scripts"))
LOGS_DIR = Path(os.getenv("BOFA_LOGS_DIR", APP_ROOT / "logs"))
DATA_DIR = Path(os.getenv("BOFA_DATA_DIR", APP_ROOT / "data"))
TEMP_DIR = Path(os.getenv("BOFA_TEMP_DIR", APP_ROOT / "temp"))
UPLOADS_DIR = Path(os.getenv("BOFA_UPLOADS_DIR", APP_ROOT / "uploads"))
CANCEL_DIR = TEMP_DIR / "cancellation"
CANCEL_GRACE_SECONDS = float(os.getenv("BOFA_CANCEL_GRACE_SECONDS", "4"))
CANCEL_CHECK_INTERVAL = float(os.getenv("BOFA_CANCEL_CHECK_INTERVAL", "0.5"))
RUNTIME_REPORTS_DIR = APP_ROOT / "reports" / "runs"

for directory in (LOGS_DIR, DATA_DIR, TEMP_DIR, UPLOADS_DIR, CANCEL_DIR, RUNTIME_REPORTS_DIR):
    directory.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOGS_DIR / "api.log"), logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="BOFA Operational Control Plane",
    description="Cybersecurity platform API with unified runs, timeline and operational control.",
    version="2.8.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

auth_manager = AuthManager(db)
script_executor = ScriptExecutor(db, scripts_dir=str(SCRIPTS_DIR))
lab_manager = LabManager(db)
run_manager = RunManager(db)

RUN_STATUSES_FINAL = {"success", "failed", "error", "partial", "cancelled"}
execution_tasks: Dict[str, asyncio.subprocess.Process] = {}
run_lookup_by_execution: Dict[str, str] = {}
runtime_controls: Dict[str, Dict[str, Any]] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "user"


class ExecuteScriptRequest(BaseModel):
    module: str
    script: str
    parameters: Dict[str, Any] = {}


class UpdateProgressRequest(BaseModel):
    progress: float


class RunCreateRequest(BaseModel):
    run_type: str = Field(pattern="^(script|flow|lab_session)$")
    source: str = "api"
    requested_action: str
    target: Optional[str] = None
    metadata: Dict[str, Any] = {}


def load_script_configs() -> Dict[str, list]:
    configs: Dict[str, list] = {}
    if not SCRIPTS_DIR.exists():
        logger.warning(f"Scripts directory not found: {SCRIPTS_DIR}")
        return configs
    for module_dir in SCRIPTS_DIR.iterdir():
        if not module_dir.is_dir():
            continue
        configs[module_dir.name] = []
        for script_file in module_dir.glob("*.yaml"):
            try:
                data = yaml.safe_load(script_file.read_text(encoding="utf-8")) or {}
                data["file_path"] = str(script_file)
                configs[module_dir.name].append(data)
            except Exception as exc:
                logger.error(f"Error loading {script_file}: {exc}")
    return configs


SCRIPT_CONFIGS = load_script_configs()


def _database_health() -> Dict[str, Any]:
    try:
        admin_user = db.get_user_by_username("admin")
        return {
            "service": "database",
            "status": "healthy" if admin_user else "warning",
            "details": "Connected and accessible" if admin_user else "Connected but missing admin user",
        }
    except Exception as exc:
        return {"service": "database", "status": "error", "details": str(exc)}


def _queue_snapshot() -> Dict[str, int]:
    return {
        "queued": len(execution_queue.queue),
        "running": len(execution_queue.running),
        "completed": len(execution_queue.completed),
        "max_concurrent": execution_queue.max_concurrent,
    }


def _scripts_health() -> Dict[str, Any]:
    try:
        stats = script_executor.get_system_stats()
        return {
            "service": "script_executor",
            "status": "healthy" if SCRIPTS_DIR.exists() else "warning",
            "details": f"{sum(len(items) for items in SCRIPT_CONFIGS.values())} scripts discovered",
            "stats": {
                "modules_loaded": len(SCRIPT_CONFIGS),
                "scripts_loaded": sum(len(items) for items in SCRIPT_CONFIGS.values()),
                "active_executions": stats.get("active_executions", 0),
                "cpu_percent": stats.get("cpu_percent", 0),
                "memory_percent": stats.get("memory_percent", 0),
            },
            "queue": _queue_snapshot(),
        }
    except Exception as exc:
        return {"service": "script_executor", "status": "error", "details": str(exc)}


def _labs_health() -> Dict[str, Any]:
    try:
        docker_available = lab_manager.is_docker_available()
        return {
            "service": "lab_manager",
            "status": "healthy" if docker_available else "warning",
            "details": "Docker available" if docker_available else "Docker unavailable in this environment",
            "stats": lab_manager.get_system_resources() if docker_available else {},
        }
    except Exception as exc:
        return {"service": "lab_manager", "status": "error", "details": str(exc)}


def _serialize_run(run: Dict[str, Any]) -> Dict[str, Any]:
    status = run.get("status", "unknown")
    events = run.get("events", [])
    return {
        **run,
        "timeline_count": len(events),
        "step_count": len(run.get("steps", [])),
        "artifact_count": len(run.get("artifacts", [])),
        "lab_count": len(run.get("labs", [])),
        "status": status,
    }


def _build_dashboard_stats(current_user: Dict[str, Any]) -> Dict[str, Any]:
    total_scripts = sum(len(items) for items in SCRIPT_CONFIGS.values())
    scripts_updated_recently = sum(
        1 for items in SCRIPT_CONFIGS.values() for script in items if script.get("last_updated") in {"2025-01-20", "2026-01-20"}
    )
    runs = db.list_runs(None if current_user["role"] == "admin" else current_user["user_id"], limit=200)
    total_runs = len(runs)
    active_runs = len([run for run in runs if run.get("status") in {"queued", "running", "waiting", "cancelling"}])
    failed_runs = len([run for run in runs if run.get("status") in {"failed", "error", "partial"}])
    successful_runs = len([run for run in runs if run.get("status") == "success"])
    success_rate = round((successful_runs / total_runs * 100), 1) if total_runs else 0.0
    docker_stats = lab_manager.get_system_resources()
    system_stats = script_executor.get_system_stats()
    recent_activity = [_serialize_run(db.get_run_detail(run["id"])) for run in runs[:10] if db.get_run_detail(run["id"])]

    return {
        "overview": {
            "total_scripts": total_scripts,
            "modules": len(SCRIPT_CONFIGS),
            "scripts_updated_recently": scripts_updated_recently,
            "system_status": "operational",
            "threat_level": "ELEVATED" if failed_runs else "MEDIUM",
            "last_scan": datetime.utcnow().isoformat(),
        },
        "executions": {
            "total_executions": total_runs,
            "successful": successful_runs,
            "failed": failed_runs,
            "queued": active_runs,
            "running": len([run for run in runs if run.get("status") in {"running", "cancelling"}]),
            "success_rate": success_rate,
        },
        "docker": {
            "active_labs": len([run for run in runs if run.get("run_type") == "lab_session" and run.get("status") == "running"]),
            **docker_stats,
        },
        "system": {
            "cpu_percent": system_stats.get("cpu_percent", 0),
            "memory_percent": system_stats.get("memory_percent", 0),
            "active_executions": system_stats.get("active_executions", 0),
            "disk_free_gb": system_stats.get("disk_free_gb", 0),
        },
        "queue": _queue_snapshot(),
        "recent_activity": recent_activity,
        "user": {
            "role": current_user["role"],
            "permissions": Roles.get_permissions(current_user["role"]),
            "user_executions": len([run for run in runs if run.get("user_id") == current_user["user_id"]]),
        },
        "total_scripts": total_scripts,
        "total_executions": total_runs,
        "active_labs": len([run for run in runs if run.get("run_type") == "lab_session" and run.get("status") == "running"]),
        "completion_rate": success_rate,
        "threat_level": "ELEVATED" if failed_runs else "MEDIUM",
        "last_scan": datetime.utcnow().isoformat(),
        "modules": len(SCRIPT_CONFIGS),
        "system_status": "operational",
    }


def _resolve_run_identifier(identifier: str) -> Optional[str]:
    if db.get_run(identifier):
        return identifier
    for item in db.get_execution_history(limit=1000):
        if item["id"] == identifier and item.get("run_id"):
            return item["run_id"]
    return run_lookup_by_execution.get(identifier)


def _cancel_file_path(run_id: str, step_id: Optional[str] = None) -> Path:
    suffix = step_id or "run"
    return CANCEL_DIR / f"{run_id}_{suffix}.cancel"


def _get_runtime_control(run_id: str, run_type: Optional[str] = None) -> Dict[str, Any]:
    control = runtime_controls.setdefault(
        run_id,
        {
            "run_id": run_id,
            "run_type": run_type,
            "cancel_requested": False,
            "cancel_requested_at": None,
            "force_kill_deadline": None,
            "run_cancel_file": str(_cancel_file_path(run_id)),
            "step_cancel_file": None,
            "step_id": None,
            "execution_id": None,
            "process": None,
            "task": None,
        },
    )
    if run_type and not control.get("run_type"):
        control["run_type"] = run_type
    return control


def _write_cancel_marker(path_str: Optional[str], payload: Optional[Dict[str, Any]] = None):
    if not path_str:
        return
    path = Path(path_str)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload or {"cancelled_at": datetime.utcnow().isoformat()}), encoding="utf-8")


def _clear_cancel_marker(path_str: Optional[str]):
    if not path_str:
        return
    path = Path(path_str)
    if path.exists():
        path.unlink()


def _is_run_cancelling(run_id: str) -> bool:
    control = runtime_controls.get(run_id) or {}
    if control.get("cancel_requested"):
        return True
    run = db.get_run(run_id)
    if not run:
        return False
    return run.get("status") == "cancelling" or Path(_cancel_file_path(run_id)).exists()


async def _emit_and_persist(
    run_id: str,
    scope_type: str,
    scope_id: str,
    event_type: str,
    status: Optional[str] = None,
    message: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
):
    run_manager.add_event(run_id, scope_type, scope_id, event_type, status, message, payload or {})
    await ws_manager.emit(run_id, scope_type, scope_id, event_type, status, message, payload or {})


async def _request_runtime_cancellation(run: Dict[str, Any], reason: str = "user_requested") -> Dict[str, Any]:
    run_id = run["id"]
    control = _get_runtime_control(run_id, run.get("run_type"))
    if control.get("cancel_requested"):
        return control

    control["cancel_requested"] = True
    control["cancel_requested_at"] = datetime.utcnow().isoformat()
    control["force_kill_deadline"] = (datetime.utcnow().timestamp() + CANCEL_GRACE_SECONDS)

    run_manager.mark_run_cancelling(
        run_id,
        message="Run cancellation requested",
        payload={"cancel_reason": reason, "grace_timeout": CANCEL_GRACE_SECONDS},
    )

    _write_cancel_marker(control.get("run_cancel_file"), {"run_id": run_id, "reason": reason})
    _write_cancel_marker(control.get("step_cancel_file"), {"run_id": run_id, "step_id": control.get("step_id"), "reason": reason})

    for step in run.get("steps", []):
        if step.get("status") not in RUN_STATUSES_FINAL:
            run_manager.update_step(
                step["id"],
                run_id,
                status="cancelling",
                message="Cancellation requested for step",
                metadata={"cancel_reason": reason, "grace_timeout": CANCEL_GRACE_SECONDS},
            )
    for lab in run.get("labs", []):
        if lab.get("status") not in RUN_STATUSES_FINAL:
            run_manager.update_lab(
                lab["id"],
                run_id,
                status="cancelling",
                message="Cancellation requested for lab operation",
                metadata={"cancel_reason": reason, "grace_timeout": CANCEL_GRACE_SECONDS},
            )

    await _emit_and_persist(
        run_id,
        "run",
        run_id,
        "cancelling",
        "cancelling",
        "Run cancellation requested",
        {"cancel_reason": reason, "grace_timeout": CANCEL_GRACE_SECONDS},
    )
    return control


async def _force_stop_process(run_id: str, execution_id: str, process: asyncio.subprocess.Process):
    await _emit_and_persist(
        run_id,
        "run",
        run_id,
        "force_kill",
        "cancelling",
        "Grace period expired, forcing process termination",
        {"forced": True, "signal_sent": "terminate"},
    )
    process.terminate()
    try:
        await asyncio.wait_for(process.wait(), timeout=1.0)
    except asyncio.TimeoutError:
        process.kill()
        await _emit_and_persist(
            run_id,
            "run",
            run_id,
            "force_kill",
            "cancelling",
            "Process still alive after terminate; kill issued",
            {"forced": True, "signal_sent": "kill"},
        )
        await process.wait()
    execution_tasks.pop(execution_id, None)


def _write_runtime_artifact(run_id: str, step_id: str, kind: str, content: str) -> Optional[str]:
    if not content:
        return None
    artifact_dir = RUNTIME_REPORTS_DIR / run_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"{step_id}_{kind}.log"
    artifact_path.write_text(content, encoding="utf-8", errors="replace")
    return str(artifact_path)


async def _execute_script_step(item: Dict[str, Any]):
    run_id = item["run_id"]
    step_id = item["step_id"]
    execution_id = item["execution_id"]
    module = item["module"]
    script = item["script"]
    parameters = item["parameters"]
    script_file = SCRIPTS_DIR / module / f"{script}.py"
    control = _get_runtime_control(run_id, "script")
    control["execution_id"] = execution_id
    control["step_id"] = step_id
    control["run_cancel_file"] = str(_cancel_file_path(run_id))
    control["step_cancel_file"] = str(_cancel_file_path(run_id, step_id))
    _clear_cancel_marker(control["run_cancel_file"])
    _clear_cancel_marker(control["step_cancel_file"])

    if _is_run_cancelling(run_id):
        await execution_queue.cancel(execution_id)
        db.create_execution(execution_id, item["user_id"], module, script, parameters, run_id=run_id, step_id=step_id)
        db.update_execution(execution_id, "cancelled", error_message="Execution cancelled before start")
        run_manager.update_step(step_id, run_id, status="cancelled", completed_at=datetime.utcnow().isoformat(), error_message="Execution cancelled before start")
        run_manager.mark_run_finished(run_id, "cancelled", "Run cancelled before script start")
        await _emit_and_persist(run_id, "step", step_id, "cancelled", "cancelled", f"{module}/{script} cancelled before start")
        return

    run_manager.mark_run_started(run_id, f"Running script {module}/{script}")
    run_manager.update_step(step_id, run_id, status="running", started_at=datetime.utcnow().isoformat(), message=f"Script step started: {module}/{script}")
    await _emit_and_persist(run_id, "step", step_id, "status_changed", "running", f"Running {module}/{script}", {"module": module, "script": script})

    if not script_file.exists():
        error_message = f"Script not found: {script_file}"
        await execution_queue.mark_failed(execution_id, error_message)
        run_manager.update_step(step_id, run_id, status="failed", completed_at=datetime.utcnow().isoformat(), error_message=error_message)
        run_manager.mark_run_finished(run_id, "failed", error_message)
        await _emit_and_persist(run_id, "step", step_id, "status_changed", "failed", error_message)
        return

    command = [sys.executable, str(script_file)]
    for key, value in parameters.items():
        if isinstance(value, bool):
            if value:
                command.append(f"--{key}")
        else:
            command.extend([f"--{key}", str(value)])

    db.create_execution(execution_id, item["user_id"], module, script, parameters, run_id=run_id, step_id=step_id)
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(APP_ROOT),
        env={
            **os.environ,
            "BOFA_RUN_ID": run_id,
            "BOFA_STEP_ID": step_id,
            "BOFA_CANCEL_FILE": control["step_cancel_file"],
            "BOFA_CANCEL_CHECK_INTERVAL": str(CANCEL_CHECK_INTERVAL),
        },
    )
    execution_tasks[execution_id] = process
    run_lookup_by_execution[execution_id] = run_id
    control["process"] = process
    await execution_queue.mark_process_started(execution_id)

    stdout_chunks: List[str] = []
    stderr_chunks: List[str] = []
    started = datetime.utcnow()

    async def _stream(stream, stream_name: str, collector: List[str]):
        while True:
            line = await stream.readline()
            if not line:
                break
            text = line.decode(errors="replace").rstrip()
            if text:
                collector.append(text)
                await _emit_and_persist(run_id, "step", step_id, stream_name, "running", text, {"stream": stream_name})

    await asyncio.gather(_stream(process.stdout, "stdout", stdout_chunks), _stream(process.stderr, "stderr", stderr_chunks))
    await process.wait()
    execution_tasks.pop(execution_id, None)

    duration = (datetime.utcnow() - started).total_seconds()
    stdout_preview = "\n".join(stdout_chunks)[-2000:]
    stderr_preview = "\n".join(stderr_chunks)[-1000:]
    output = "\n".join(stdout_chunks)
    error_output = "\n".join(stderr_chunks) or output
    stdout_artifact = _write_runtime_artifact(run_id, step_id, "stdout", output)
    stderr_artifact = _write_runtime_artifact(run_id, step_id, "stderr", "\n".join(stderr_chunks))
    if stdout_artifact:
        run_manager.add_artifact(run_id, "stdout_log", stdout_artifact, label=f"stdout {module}/{script}", metadata={"step_id": step_id, "execution_id": execution_id})
    if stderr_artifact:
        run_manager.add_artifact(run_id, "stderr_log", stderr_artifact, label=f"stderr {module}/{script}", metadata={"step_id": step_id, "execution_id": execution_id})

    cancelled = (control.get("cancel_requested") and process.returncode != 0) or process.returncode in {-15, -9, 130}

    if cancelled:
        result_status = "cancelled"
        await execution_queue.mark_completed(execution_id, {"status": result_status, "run_id": run_id, "step_id": step_id})
        db.update_execution(execution_id, "cancelled", error_message="Execution cancelled", execution_time=duration)
        run_manager.update_step(
            step_id,
            run_id,
            status=result_status,
            completed_at=datetime.utcnow().isoformat(),
            exit_code=process.returncode,
            duration=duration,
            stdout_preview=stdout_preview,
            stderr_preview=stderr_preview,
            error_message="Execution cancelled",
            message=f"Script step cancelled: {module}/{script}",
        )
        run_manager.mark_run_finished(run_id, result_status, f"Script {module}/{script} cancelled", metadata={"execution_id": execution_id})
        await _emit_and_persist(run_id, "step", step_id, "cancelled", result_status, f"{module}/{script} cancelled", {"exit_code": process.returncode, "duration": duration})
    elif process.returncode == 0:
        result_status = "success"
        await execution_queue.mark_completed(execution_id, {"status": result_status, "exit_code": process.returncode, "run_id": run_id, "step_id": step_id})
        db.update_execution(execution_id, result_status, output=output, execution_time=duration)
        run_manager.update_step(
            step_id,
            run_id,
            status=result_status,
            completed_at=datetime.utcnow().isoformat(),
            exit_code=process.returncode,
            duration=duration,
            stdout_preview=stdout_preview,
            stderr_preview=stderr_preview,
            message=f"Script step finished: {module}/{script}",
        )
        run_manager.mark_run_finished(run_id, result_status, f"Script {module}/{script} completed", metadata={"execution_id": execution_id})
        if control.get("cancel_requested"):
            await _emit_and_persist(run_id, "run", run_id, "cancel_requested", "success", "Cancel requested after process completed", {"forced": False})
        await _emit_and_persist(run_id, "step", step_id, "completed", result_status, f"{module}/{script} completed", {"exit_code": process.returncode, "duration": duration})
    else:
        result_status = "failed"
        await execution_queue.mark_failed(execution_id, error_output)
        db.update_execution(execution_id, "error", error_message=error_output, execution_time=duration)
        run_manager.update_step(
            step_id,
            run_id,
            status=result_status,
            completed_at=datetime.utcnow().isoformat(),
            exit_code=process.returncode,
            duration=duration,
            stdout_preview=stdout_preview,
            stderr_preview=stderr_preview,
            error_message=error_output,
            message=f"Script step failed: {module}/{script}",
        )
        run_manager.mark_run_finished(run_id, result_status, f"Script {module}/{script} failed", metadata={"execution_id": execution_id, "exit_code": process.returncode})
        await _emit_and_persist(run_id, "step", step_id, "completed", result_status, error_output, {"exit_code": process.returncode, "duration": duration})

    _clear_cancel_marker(control.get("step_cancel_file"))
    if result_status in RUN_STATUSES_FINAL:
        _clear_cancel_marker(control.get("run_cancel_file"))
    control["process"] = None


async def process_execution_queue():
    while True:
        item = await execution_queue.get_next()
        if not item:
            break
        try:
            await _execute_script_step(item)
        except Exception as exc:
            await execution_queue.mark_failed(item["execution_id"], str(exc))
            run_manager.update_step(item["step_id"], item["run_id"], status="failed", completed_at=datetime.utcnow().isoformat(), error_message=str(exc))
            run_manager.mark_run_finished(item["run_id"], "failed", f"Execution error: {exc}")
            await _emit_and_persist(item["run_id"], "step", item["step_id"], "completed", "failed", str(exc))


async def _start_script_run(
    current_user: Dict[str, Any],
    module: str,
    script: str,
    parameters: Dict[str, Any],
    source: str = "api",
    parent_run_id: Optional[str] = None,
    metadata_extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    metadata = {"module": module, "script": script, "parameters": parameters}
    if metadata_extra:
        metadata.update(metadata_extra)
    run_id = run_manager.create_run(
        user_id=current_user["user_id"],
        run_type="script",
        source=source,
        requested_action="execute_script",
        target=parameters.get("target") or parameters.get("url"),
        parent_run_id=parent_run_id,
        metadata=metadata,
        status="queued",
    )
    step_id = run_manager.create_step(run_id, "script", 1, "script_1", module, script, parameters, {"source": source})
    execution_id = f"exec_{step_id}"
    await execution_queue.add_to_queue(execution_id, run_id, step_id, current_user["user_id"], module, script, parameters)
    asyncio.create_task(process_execution_queue())
    return {"run_id": run_id, "step_id": step_id, "execution_id": execution_id, "status": "queued", "message": f"Script {script} queued"}


async def _start_flow_run(
    current_user: Dict[str, Any],
    flow_id: str,
    target: str,
    source: str = "api",
    parent_run_id: Optional[str] = None,
    metadata_extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    metadata = {"flow_id": flow_id}
    if metadata_extra:
        metadata.update(metadata_extra)
    run_id = run_manager.create_run(
        user_id=current_user["user_id"],
        run_type="flow",
        source=source,
        requested_action="execute_flow",
        target=target,
        parent_run_id=parent_run_id,
        metadata=metadata,
        status="queued",
    )
    control = _get_runtime_control(run_id, "flow")
    control["run_cancel_file"] = str(_cancel_file_path(run_id))
    _clear_cancel_marker(control["run_cancel_file"])
    run_manager.mark_run_started(run_id, f"Flow {flow_id} started")
    await _emit_and_persist(run_id, "run", run_id, "status_changed", "running", f"Flow {flow_id} started", {"flow_id": flow_id, "target": target})

    async def _runner():
        try:
            result = await asyncio.to_thread(
                run_flow,
                flow_id,
                target,
                None,
                None,
                run_manager,
                run_id,
                control["run_cancel_file"],
                CANCEL_CHECK_INTERVAL,
                {
                    "should_cancel": lambda: _is_run_cancelling(run_id),
                    "set_active_step": lambda step_id, step_cancel_file, metadata=None: control.update(
                        {"step_id": step_id, "step_cancel_file": step_cancel_file, "active_step": metadata or {}}
                    ),
                    "clear_active_step": lambda step_id=None: control.update({"active_step": None, "step_cancel_file": None}),
                },
            )
            final_status = result.get("status", "failed")
            run_manager.mark_run_finished(run_id, final_status, f"Flow {flow_id} completed", metadata={"flow_id": flow_id})
            await _emit_and_persist(run_id, "run", run_id, "cancelled" if final_status == "cancelled" else "completed", final_status, f"Flow {flow_id} completed", {"flow_id": flow_id})
        except Exception as exc:
            run_manager.mark_run_finished(run_id, "failed", f"Flow {flow_id} failed", metadata={"error": str(exc)})
            await _emit_and_persist(run_id, "run", run_id, "completed", "failed", str(exc), {"flow_id": flow_id})
        finally:
            _clear_cancel_marker(control.get("run_cancel_file"))
            _clear_cancel_marker(control.get("step_cancel_file"))
            control["task"] = None

    task = asyncio.create_task(_runner())
    control["task"] = task
    return {"run_id": run_id, "status": "running", "message": f"Flow {flow_id} started"}


async def _start_lab_run(
    current_user: Dict[str, Any],
    lab_id: str,
    action: str,
    source: str = "api",
    parent_run_id: Optional[str] = None,
    metadata_extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if action not in {"start_lab", "stop_lab"}:
        raise HTTPException(status_code=400, detail="Unsupported lab action")
    metadata = {"lab_id": lab_id, "action": action}
    if metadata_extra:
        metadata.update(metadata_extra)
    run_id = run_manager.create_run(
        user_id=current_user["user_id"],
        run_type="lab_session",
        source=source,
        requested_action=action,
        target=lab_id,
        parent_run_id=parent_run_id,
        metadata=metadata,
        status="running",
    )
    lab_run_id = run_manager.attach_lab(run_id, lab_id, status="running" if action == "start_lab" else "waiting")
    run_manager.mark_run_started(run_id, f"Lab action {action} started")
    result = lab_manager.start_lab(lab_id, current_user["user_id"]) if action == "start_lab" else lab_manager.stop_lab(lab_id, current_user["user_id"])
    status = "success" if result.get("status") == "success" else "failed"
    lab_status = "running" if action == "start_lab" and status == "success" else "stopped" if action == "stop_lab" and status == "success" else "failed"
    run_manager.update_lab(
        lab_run_id,
        run_id,
        status=lab_status,
        container_id=result.get("container_id"),
        port=result.get("port"),
        started_at=datetime.utcnow().isoformat() if lab_status == "running" else None,
        stopped_at=datetime.utcnow().isoformat() if lab_status == "stopped" else None,
        message=result.get("message"),
    )
    run_manager.mark_run_finished(run_id, status, result.get("message"), metadata=result)
    await _emit_and_persist(run_id, "lab", lab_run_id, "completed", status, result.get("message"), result)
    return {"run_id": run_id, "lab_run_id": lab_run_id, **result}


def _normalize_history_from_runs(runs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    items = []
    for run in runs:
        detail = db.get_run_detail(run["id"])
        if not detail:
            continue
        first_step = detail["steps"][0] if detail.get("steps") else {}
        items.append(
            {
                "id": run["id"],
                "run_id": run["id"],
                "script": first_step.get("script_name") or detail.get("requested_action"),
                "module": first_step.get("module") or detail.get("run_type"),
                "parameters": first_step.get("parameters") or detail.get("metadata", {}),
                "timestamp": detail.get("created_at"),
                "status": detail.get("status"),
                "execution_time": first_step.get("duration"),
                "output": first_step.get("stdout_preview"),
                "error": first_step.get("error_message"),
            }
        )
    return items


def _normalize_legacy_history(user_id: Optional[int], limit: int = 50) -> List[Dict[str, Any]]:
    items = []
    for item in db.get_execution_history(user_id, limit=limit * 4):
        if item.get("run_id"):
            continue
        items.append(
            {
                "id": item["id"],
                "run_id": None,
                "script": item.get("script_name"),
                "module": item.get("module"),
                "parameters": item.get("parameters") or {},
                "timestamp": item.get("timestamp"),
                "status": item.get("status"),
                "execution_time": item.get("execution_time"),
                "output": item.get("output"),
                "error": item.get("error"),
                "legacy": True,
            }
        )
        if len(items) >= limit:
            break
    return items


def _merge_history_items(run_items: List[Dict[str, Any]], legacy_items: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
    merged = run_items + legacy_items
    merged.sort(key=lambda item: item.get("timestamp") or "", reverse=True)
    return merged[:limit]


@app.on_event("startup")
async def startup_event():
    logger.info("BOFA Operational Control Plane starting")


@app.post("/auth/login")
async def login(request: LoginRequest):
    user = auth_manager.authenticate_user(request.username, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = auth_manager.create_access_token(user)
    return {"access_token": token, "token_type": "bearer", "user": user, "expires_in": 86400}


@app.post("/auth/register")
async def register(request: RegisterRequest):
    user_id = auth_manager.register_user(request.username, request.email, request.password, request.role)
    if not user_id:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    return {"message": "User registered successfully", "user_id": user_id}


@app.get("/auth/me")
async def get_current_user_info(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    return {"user": current_user, "permissions": Roles.get_permissions(current_user["role"])}


@app.get("/")
async def root():
    return {
        "name": "BOFA Operational Control Plane",
        "version": "2.8.0",
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "capabilities": {"runs": True, "script_execution": True, "lab_management": True, "flow_execution": True, "timeline": True},
    }


@app.get("/health")
async def health_check():
    database = _database_health()
    scripts = _scripts_health()
    labs = _labs_health()
    system_stats = script_executor.get_system_stats()
    overall = "healthy"
    if any(item["status"] == "error" for item in (database, scripts, labs)):
        overall = "degraded"
    elif any(item["status"] == "warning" for item in (database, scripts, labs)):
        overall = "warning"
    return {
        "status": overall,
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "database": database["status"],
            "script_executor": scripts["status"],
            "docker": labs["status"],
            "queue": "healthy",
            "runs": "healthy",
        },
        "system": {
            "cpu_usage": system_stats.get("cpu_percent", 0),
            "memory_usage": system_stats.get("memory_percent", 0),
            "active_executions": system_stats.get("active_executions", 0),
            "disk_free_gb": system_stats.get("disk_free_gb", 0),
        },
        "queue": _queue_snapshot(),
        "checks": {"database": database, "scripts": scripts, "labs": labs},
    }


@app.get("/health/database")
async def health_database():
    return {**_database_health(), "timestamp": datetime.utcnow().isoformat()}


@app.get("/health/scripts")
async def health_scripts():
    return {**_scripts_health(), "timestamp": datetime.utcnow().isoformat()}


@app.get("/health/labs")
async def health_labs():
    return {**_labs_health(), "timestamp": datetime.utcnow().isoformat()}


@app.get("/health/queue")
async def health_queue():
    return {"service": "execution_queue", "status": "healthy", "stats": _queue_snapshot(), "timestamp": datetime.utcnow().isoformat()}


@app.get("/modules")
async def get_modules():
    modules = []
    for module_id, scripts in SCRIPT_CONFIGS.items():
        modules.append({"id": module_id, "name": module_id.title(), "description": f"Herramientas de {module_id}", "icon": "terminal", "script_count": len(scripts)})
    return modules


@app.get("/modules/{module_id}/scripts")
async def get_scripts_by_module(module_id: str):
    if module_id not in SCRIPT_CONFIGS:
        raise HTTPException(status_code=404, detail=f"Module {module_id} not found")
    return SCRIPT_CONFIGS[module_id]


@app.get("/scripts/catalog")
async def get_scripts_catalog():
    catalog = []
    for module_id, scripts in SCRIPT_CONFIGS.items():
        for script_config in scripts:
            yaml_path = Path(script_config.get("file_path", ""))
            slug = yaml_path.stem
            py_path = yaml_path.with_suffix(".py")
            if not py_path.exists():
                for alt in yaml_path.parent.glob("*.py"):
                    if slug.lower() in alt.stem.lower():
                        py_path = alt
                        break
            catalog.append(
                {
                    "id": slug,
                    "name": script_config.get("display_name") or script_config.get("name") or slug,
                    "description": script_config.get("description", ""),
                    "category": module_id,
                    "author": script_config.get("author", "unknown"),
                    "version": script_config.get("version", "1.0"),
                    "last_updated": script_config.get("last_updated"),
                    "usage": script_config.get("usage") or (script_config.get("usage_examples", [])[:1] or [None])[0],
                    "file_path_yaml": str(yaml_path),
                    "file_path_py": str(py_path) if py_path.exists() else None,
                    "has_code": py_path.exists(),
                }
            )
    return sorted(catalog, key=lambda item: (item["category"], item["name"]))


@app.get("/scripts/{module_id}/{script_name}/code")
async def get_script_code(module_id: str, script_name: str):
    module_dir = SCRIPTS_DIR / module_id
    if not module_dir.exists():
        raise HTTPException(status_code=404, detail=f"Module {module_id} not found")
    py_file = module_dir / f"{script_name}.py"
    if not py_file.exists():
        matches = [path for path in module_dir.glob("*.py") if script_name.lower() in path.stem.lower()]
        if matches:
            py_file = matches[0]
    if not py_file.exists():
        raise HTTPException(status_code=404, detail=f"Script code not found for {script_name}")
    content = py_file.read_text(encoding="utf-8")
    return {"filename": py_file.name, "language": "python", "size": py_file.stat().st_size, "lines": len(content.splitlines()), "content": content}


@app.get("/flows")
async def get_flows(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    if not check_permission(current_user, "execute_scripts"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return list_flows()


@app.websocket("/ws/runs/{run_id}")
async def websocket_run(websocket: WebSocket, run_id: str):
    await ws_manager.connect(websocket, run_id)
    try:
        while True:
            await websocket.receive_text()
            await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket, run_id)
    except Exception:
        await ws_manager.disconnect(websocket, run_id)


@app.websocket("/ws/execute/{identifier}")
async def websocket_execution_alias(websocket: WebSocket, identifier: str):
    run_id = _resolve_run_identifier(identifier) or identifier
    await websocket_run(websocket, run_id)


@app.post("/runs")
async def create_run(request: RunCreateRequest, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    if request.run_type == "script":
        if not check_permission(current_user, "execute_scripts"):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        module = request.metadata.get("module")
        script = request.metadata.get("script")
        parameters = request.metadata.get("parameters", {})
        if not module or not script:
            raise HTTPException(status_code=400, detail="Script runs require metadata.module and metadata.script")
        return await _start_script_run(current_user, module, script, parameters, source=request.source)
    if request.run_type == "flow":
        if not check_permission(current_user, "execute_scripts"):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        flow_id = request.metadata.get("flow_id")
        target = request.target or request.metadata.get("target")
        if not flow_id or not target:
            raise HTTPException(status_code=400, detail="Flow runs require metadata.flow_id and target")
        return await _start_flow_run(current_user, flow_id, target, source=request.source)
    if request.run_type == "lab_session":
        if not check_permission(current_user, "manage_labs"):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        lab_id = request.metadata.get("lab_id")
        action = request.requested_action or request.metadata.get("action") or "start_lab"
        if not lab_id:
            raise HTTPException(status_code=400, detail="Lab runs require metadata.lab_id")
        return await _start_lab_run(current_user, lab_id, action, source=request.source)
    raise HTTPException(status_code=400, detail="Unsupported run_type")


@app.get("/runs")
async def list_runs_endpoint(
    run_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    current_user: Dict[str, Any] = Depends(auth_manager.get_current_user),
):
    user_id = None if current_user["role"] == "admin" else current_user["user_id"]
    runs = db.list_runs(user_id=user_id, run_type=run_type, status=status, limit=limit)
    return [_serialize_run(run) for run in runs]


@app.get("/runs/{run_id}")
async def get_run(run_id: str, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    run = db.get_run_detail(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if current_user["role"] != "admin" and run.get("user_id") != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    return _serialize_run(run)


@app.get("/runs/{run_id}/timeline")
async def get_run_timeline(run_id: str, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    run = db.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if current_user["role"] != "admin" and run.get("user_id") != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    return {"run_id": run_id, "events": db.get_run_events(run_id), "artifacts": db.get_run_artifacts(run_id)}


@app.post("/runs/{run_id}/cancel")
async def cancel_run(run_id: str, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    run = db.get_run_detail(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if current_user["role"] != "admin" and run.get("user_id") != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    if run.get("status") in RUN_STATUSES_FINAL:
        return {
            "run_id": run_id,
            "status": run.get("status"),
            "message": "Run already finished",
            "cancel_mode": "noop",
            "grace_period_seconds": CANCEL_GRACE_SECONDS,
        }

    control = await _request_runtime_cancellation(run, reason="user_requested")

    if run.get("status") == "queued":
        for step in run.get("steps", []):
            execution_id = f"exec_{step['id']}"
            await execution_queue.cancel(execution_id)
            db.create_execution(execution_id, current_user["user_id"], step.get("module") or "unknown", step.get("script_name") or step.get("step_key") or step["id"], step.get("parameters") or {}, run_id=run_id, step_id=step["id"])
            db.update_execution(execution_id, "cancelled", error_message="Execution cancelled before start")
            run_manager.update_step(step["id"], run_id, status="cancelled", completed_at=datetime.utcnow().isoformat(), error_message="Execution cancelled before start")
        run_manager.mark_run_finished(run_id, "cancelled", "Run cancelled before execution")
        await _emit_and_persist(run_id, "run", run_id, "cancelled", "cancelled", "Run cancelled before execution")
        _clear_cancel_marker(control.get("run_cancel_file"))
        return {
            "run_id": run_id,
            "status": "cancelled",
            "message": "Run cancelled before execution",
            "cancel_mode": "graceful_then_kill",
            "grace_period_seconds": CANCEL_GRACE_SECONDS,
        }

    process = control.get("process")
    execution_id = control.get("execution_id")
    if run.get("run_type") == "script" and process and execution_id and process.returncode is None:
        try:
            await asyncio.wait_for(process.wait(), timeout=CANCEL_GRACE_SECONDS)
        except asyncio.TimeoutError:
            await _force_stop_process(run_id, execution_id, process)

        updated = db.get_run_detail(run_id) or {}
        return {
            "run_id": run_id,
            "status": updated.get("status", "cancelling"),
            "message": "Run cancellation requested",
            "cancel_mode": "graceful_then_kill",
            "grace_period_seconds": CANCEL_GRACE_SECONDS,
        }

    if run.get("run_type") == "flow":
        task = control.get("task")
        if task:
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=CANCEL_GRACE_SECONDS)
            except asyncio.TimeoutError:
                await _emit_and_persist(
                    run_id,
                    "run",
                    run_id,
                    "force_kill",
                    "cancelling",
                    "Flow cancellation still draining after grace period",
                    {"forced": False, "signal_sent": "cancel_marker"},
                )
            except asyncio.CancelledError:
                pass
        updated = db.get_run_detail(run_id) or {}
        return {
            "run_id": run_id,
            "status": updated.get("status", "cancelling"),
            "message": "Flow cancellation requested",
            "cancel_mode": "graceful_then_kill",
            "grace_period_seconds": CANCEL_GRACE_SECONDS,
        }

    if run.get("run_type") == "lab_session":
        run_manager.mark_run_finished(run_id, "cancelled", "Lab cancellation requested", metadata={"cancelled": True})
        await _emit_and_persist(run_id, "run", run_id, "cancelled", "cancelled", "Lab cancellation requested")
        _clear_cancel_marker(control.get("run_cancel_file"))
        return {
            "run_id": run_id,
            "status": "cancelled",
            "message": "Lab run cancelled",
            "cancel_mode": "graceful_then_kill",
            "grace_period_seconds": CANCEL_GRACE_SECONDS,
        }

    return {
        "run_id": run_id,
        "status": "cancelling",
        "message": "Run cancellation requested",
        "cancel_mode": "graceful_then_kill",
        "grace_period_seconds": CANCEL_GRACE_SECONDS,
    }


@app.post("/runs/{run_id}/retry")
async def retry_run(run_id: str, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    run = db.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if current_user["role"] != "admin" and run.get("user_id") != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    if run.get("status") not in {"failed", "error", "partial", "cancelled"}:
        raise HTTPException(status_code=400, detail="Retry only supported for failed, partial or cancelled runs")
    payload = run_manager.retry_payload(run_id)
    if not payload:
        raise HTTPException(status_code=400, detail="Retry payload unavailable")
    metadata = payload.get("metadata") or {}
    retry_metadata = {
        "retry_of": run_id,
        "retry_count": payload.get("retry_count", 1),
        "retry_reason": run.get("status"),
        "last_non_success_step": payload.get("last_non_success_step"),
    }
    run_manager.add_event(
        run_id,
        "run",
        run_id,
        "retry_requested",
        "success",
        "Retry requested for run",
        retry_metadata,
    )
    if payload["run_type"] == "script":
        result = await _start_script_run(
            current_user,
            metadata.get("module"),
            metadata.get("script"),
            metadata.get("parameters", {}),
            source="retry",
            parent_run_id=run_id,
            metadata_extra=retry_metadata,
        )
    elif payload["run_type"] == "flow":
        result = await _start_flow_run(
            current_user,
            metadata.get("flow_id"),
            payload.get("target"),
            source="retry",
            parent_run_id=run_id,
            metadata_extra=retry_metadata,
        )
    elif payload["run_type"] == "lab_session":
        result = await _start_lab_run(
            current_user,
            metadata.get("lab_id"),
            payload.get("requested_action") or metadata.get("action") or "start_lab",
            source="retry",
            parent_run_id=run_id,
            metadata_extra=retry_metadata,
        )
    else:
        raise HTTPException(status_code=400, detail="Retry not supported for this run")

    run_manager.add_event(
        result["run_id"],
        "run",
        result["run_id"],
        "retried_from",
        "queued" if result.get("status") == "queued" else result.get("status", "running"),
        "Run created from retry",
        {"parent_run_id": run_id, "retry_count": retry_metadata["retry_count"]},
    )
    return {
        **result,
        "parent_run_id": run_id,
        "retry_count": retry_metadata["retry_count"],
        "retry_reason": run.get("status"),
    }


@app.post("/execute")
async def execute_script(request: ExecuteScriptRequest, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    result = await _start_script_run(current_user, request.module, request.script, request.parameters, source="legacy_execute")
    return {
        "execution_id": result["execution_id"],
        "run_id": result["run_id"],
        "status": result["status"],
        "message": result["message"],
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/execute/{execution_id}")
async def get_execution_status(execution_id: str, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    status = await execution_queue.get_status(execution_id)
    if status:
        run = db.get_run_detail(status["run_id"])
        if current_user["role"] != "admin" and run and run.get("user_id") != current_user["user_id"]:
            raise HTTPException(status_code=403, detail="Access denied")
        step = next((item for item in (run or {}).get("steps", []) if item["id"] == status["step_id"]), None)
        legacy_status = step.get("status") if step else status.get("status")
        if legacy_status == "failed":
            legacy_status = "error"
        return {
            "id": execution_id,
            "run_id": status["run_id"],
            "step_id": status["step_id"],
            "status": legacy_status,
            "run_status": step.get("status") if step else status.get("status"),
            "output": step.get("stdout_preview") if step else None,
            "error": step.get("error_message") if step else status.get("error"),
            "execution_time": step.get("duration") if step else None,
        }
    for item in db.get_execution_history(None if current_user["role"] == "admin" else current_user["user_id"], limit=1000):
        if item["id"] == execution_id:
            return item
    raise HTTPException(status_code=404, detail="Execution not found")


@app.post("/execute/{execution_id}/stop")
async def stop_execution(execution_id: str, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    run_id = _resolve_run_identifier(execution_id)
    if not run_id:
        raise HTTPException(status_code=404, detail="Execution not found")
    return await cancel_run(run_id, current_user)


@app.get("/queue/info")
async def get_queue_info(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    if not check_permission(current_user, "execute_scripts"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return await execution_queue.get_queue_info()


@app.get("/history")
async def get_execution_history(limit: int = 50, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    user_id = None if current_user["role"] == "admin" else current_user["user_id"]
    runs = db.list_runs(user_id=user_id, limit=limit)
    run_items = _normalize_history_from_runs(runs)
    legacy_items = _normalize_legacy_history(user_id, limit)
    return _merge_history_items(run_items, legacy_items, limit)


@app.get("/labs")
async def get_labs(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    if not check_permission(current_user, "manage_labs"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    labs = lab_manager.get_available_labs()
    for lab in labs:
        try:
            lab.update(lab_manager.get_lab_status(lab["id"], current_user["user_id"]))
        except Exception as exc:
            lab["status"] = "error"
            lab["message"] = str(exc)
    return labs


@app.post("/labs/{lab_id}/start")
async def start_lab(lab_id: str, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    if not check_permission(current_user, "manage_labs"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return await _start_lab_run(current_user, lab_id, "start_lab", source="legacy_lab")


@app.post("/labs/{lab_id}/stop")
async def stop_lab(lab_id: str, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    if not check_permission(current_user, "manage_labs"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return await _start_lab_run(current_user, lab_id, "stop_lab", source="legacy_lab")


@app.get("/study/lessons")
async def get_study_lessons(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    lessons = [
        {"id": "web_application_security", "title": "Seguridad en Aplicaciones Web", "description": "OWASP Top 10", "category": "web_security", "difficulty": "intermediate", "duration": 180, "completed": False, "progress": 0},
        {"id": "cloud_native_security", "title": "Cloud Native Security", "description": "Kubernetes y contenedores", "category": "cloud_security", "difficulty": "expert", "duration": 420, "completed": False, "progress": 0},
        {"id": "ai_threat_hunting", "title": "AI-Powered Threat Hunting", "description": "Detección avanzada", "category": "ai_security", "difficulty": "expert", "duration": 360, "completed": False, "progress": 0},
    ]
    try:
        progress = {item["lesson_id"]: item for item in db.get_learning_progress(current_user["user_id"])}
        for lesson in lessons:
            if lesson["id"] in progress:
                lesson["progress"] = progress[lesson["id"]]["progress"]
                lesson["completed"] = progress[lesson["id"]]["completed"]
    except Exception:
        pass
    return lessons


@app.put("/study/lessons/{lesson_id}/progress")
async def update_lesson_progress(lesson_id: str, request: UpdateProgressRequest, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    db.update_lesson_progress(current_user["user_id"], lesson_id, request.progress)
    return {"message": "Progress updated", "lesson_id": lesson_id, "progress": request.progress}


@app.post("/api-keys/{service_name}")
async def store_api_key(service_name: str, api_key: str = Form(...), current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    if not check_permission(current_user, "manage_api_keys"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    db.store_api_key(current_user["user_id"], service_name, api_key)
    return {"message": f"API key for {service_name} stored successfully"}


@app.get("/api-keys")
async def get_user_api_keys(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    if not check_permission(current_user, "manage_api_keys"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    services = ["shodan_key", "virustotal_key", "hibp_key", "github_token"]
    payload = {}
    for service in services:
        key = db.get_api_key(current_user["user_id"], service)
        payload[service] = {"configured": bool(key), "masked_key": f"****{key[-4:]}" if key else None}
    return payload


@app.get("/dashboard/stats")
async def get_dashboard_stats(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    return _build_dashboard_stats(current_user)


@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(status_code=404, content={"error": "Not Found", "message": "The requested resource was not found", "timestamp": datetime.utcnow().isoformat()})


@app.exception_handler(500)
async def server_error_handler(request, exc):
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(status_code=500, content={"error": "Internal Server Error", "message": "An internal error occurred", "timestamp": datetime.utcnow().isoformat()})


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, log_level="info")
