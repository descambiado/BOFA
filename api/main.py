#!/usr/bin/env python3
"""
BOFA Extended Systems v2.5.1 - Main API
FastAPI backend for the cybersecurity platform with real functionality.
"""

from datetime import datetime
import asyncio
import json
import logging
import os
from pathlib import Path
import sys
from typing import Any, Dict

from fastapi import Depends, FastAPI, Form, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn
import yaml

from auth import AuthManager, Roles, check_permission
from database import db
from execution_queue import execution_queue
from lab_manager import LabManager
from script_executor import ScriptExecutor
from websocket_manager import ws_manager

APP_ROOT = Path(os.getenv("BOFA_APP_ROOT", Path(__file__).resolve().parents[1]))
SCRIPTS_DIR = Path(os.getenv("BOFA_SCRIPTS_DIR", APP_ROOT / "scripts"))
LOGS_DIR = Path(os.getenv("BOFA_LOGS_DIR", APP_ROOT / "logs"))
DATA_DIR = Path(os.getenv("BOFA_DATA_DIR", APP_ROOT / "data"))
TEMP_DIR = Path(os.getenv("BOFA_TEMP_DIR", APP_ROOT / "temp"))
UPLOADS_DIR = Path(os.getenv("BOFA_UPLOADS_DIR", APP_ROOT / "uploads"))

for directory in (LOGS_DIR, DATA_DIR, TEMP_DIR, UPLOADS_DIR):
    directory.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOGS_DIR / "api.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="BOFA Extended Systems API",
    description="Cybersecurity Platform API v2.5.1 - Neural Security Edge with Real Functionality",
    version="2.5.1",
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


def load_script_configs() -> Dict[str, list]:
    """Load script configurations from YAML files."""
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
                with open(script_file, "r", encoding="utf-8") as handle:
                    script_config = yaml.safe_load(handle) or {}
                script_config["file_path"] = str(script_file)
                configs[module_dir.name].append(script_config)
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
            "details": "Conectada y accesible" if admin_user else "Conectada pero sin usuario admin",
        }
    except Exception as exc:
        logger.error(f"Database health check failed: {exc}")
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
        scripts_loaded = sum(len(items) for items in SCRIPT_CONFIGS.values())
        status = "healthy" if SCRIPTS_DIR.exists() else "warning"
        details = "Catálogo de scripts cargado" if SCRIPTS_DIR.exists() else f"No existe {SCRIPTS_DIR}"
        return {
            "service": "script_executor",
            "status": status,
            "details": details,
            "stats": {
                "modules_loaded": len(SCRIPT_CONFIGS),
                "scripts_loaded": scripts_loaded,
                "active_executions": stats.get("active_executions", 0),
                "cpu_percent": stats.get("cpu_percent", 0),
                "memory_percent": stats.get("memory_percent", 0),
            },
            "queue": _queue_snapshot(),
        }
    except Exception as exc:
        logger.error(f"Script executor health check failed: {exc}")
        return {"service": "script_executor", "status": "error", "details": str(exc)}


def _labs_health() -> Dict[str, Any]:
    try:
        docker_available = lab_manager.is_docker_available()
        resources = lab_manager.get_system_resources() if docker_available else {}
        return {
            "service": "lab_manager",
            "status": "healthy" if docker_available else "warning",
            "details": "Docker disponible" if docker_available else "Docker no disponible en este entorno",
            "stats": resources,
        }
    except Exception as exc:
        logger.error(f"Lab manager health check failed: {exc}")
        return {"service": "lab_manager", "status": "error", "details": str(exc)}


def _build_dashboard_stats(current_user: Dict[str, Any]) -> Dict[str, Any]:
    total_scripts = sum(len(scripts) for scripts in SCRIPT_CONFIGS.values())
    scripts_updated_recently = 0
    for scripts in SCRIPT_CONFIGS.values():
        for script in scripts:
            if script.get("last_updated") in {"2025-01-20", "2026-01-20"}:
                scripts_updated_recently += 1

    if current_user["role"] == "admin":
        executions = db.get_execution_history(limit=1000)
    else:
        executions = db.get_execution_history(user_id=current_user["user_id"], limit=200)

    total_executions = len(executions)
    successful = len([item for item in executions if item.get("status") == "success"])
    failed = len([item for item in executions if item.get("status") in {"error", "failed"}])
    queue_stats = _queue_snapshot()
    success_rate = round((successful / total_executions * 100), 1) if total_executions else 0.0

    system_stats = script_executor.get_system_stats()
    docker_stats = lab_manager.get_system_resources()

    recent_activity = []
    for execution in executions[:10]:
        recent_activity.append(
            {
                "id": execution.get("id"),
                "module": execution.get("module"),
                "script": execution.get("script_name") or execution.get("script"),
                "status": execution.get("status", "unknown"),
                "timestamp": execution.get("started_at") or execution.get("created_at") or execution.get("timestamp"),
                "output": execution.get("output"),
            }
        )

    threat_level = "MEDIUM" if failed == 0 else "ELEVATED"
    last_scan = datetime.now().isoformat()

    return {
        "total_scripts": total_scripts,
        "new_scripts_2025": scripts_updated_recently,
        "total_executions": total_executions,
        "successful_executions": successful,
        "active_labs": docker_stats.get("containers_running", 0),
        "completion_rate": success_rate,
        "threat_level": threat_level,
        "last_scan": last_scan,
        "modules": len(SCRIPT_CONFIGS),
        "system_status": "operational",
        "overview": {
            "total_scripts": total_scripts,
            "modules": len(SCRIPT_CONFIGS),
            "scripts_updated_recently": scripts_updated_recently,
            "system_status": "operational",
            "threat_level": threat_level,
            "last_scan": last_scan,
        },
        "executions": {
            "total_executions": total_executions,
            "successful": successful,
            "failed": failed,
            "queued": queue_stats["queued"],
            "running": queue_stats["running"],
            "success_rate": success_rate,
        },
        "docker": {
            "active_labs": docker_stats.get("containers_running", 0),
            **docker_stats,
        },
        "system": {
            "cpu_percent": system_stats.get("cpu_percent", 0),
            "memory_percent": system_stats.get("memory_percent", 0),
            "active_executions": system_stats.get("active_executions", 0),
            "disk_free_gb": system_stats.get("disk_free_gb", 0),
        },
        "queue": queue_stats,
        "recent_activity": recent_activity,
        "user": {
            "role": current_user["role"],
            "permissions": Roles.get_permissions(current_user["role"]),
            "user_executions": len([item for item in executions if item.get("user_id") == current_user["user_id"]]),
        },
    }


@app.on_event("startup")
async def startup_event():
    """Initialize application on startup."""
    logger.info("BOFA Extended Systems v2.5.1 - Neural Security Edge API Starting")
    logger.info(f"Scripts loaded from {len(SCRIPT_CONFIGS)} modules")
    logger.info(f"Using scripts directory: {SCRIPTS_DIR}")
    logger.info("Database initialized")
    logger.info("Authentication system ready")
    logger.info("Script executor ready")
    logger.info("Lab manager initialized")
    logger.info("BOFA API v2.5.1 Ready")


@app.post("/auth/login")
async def login(request: LoginRequest):
    user = auth_manager.authenticate_user(request.username, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = auth_manager.create_access_token(user)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user,
        "expires_in": 86400,
    }


@app.post("/auth/register")
async def register(request: RegisterRequest):
    user_id = auth_manager.register_user(
        request.username,
        request.email,
        request.password,
        request.role,
    )
    if not user_id:
        raise HTTPException(status_code=400, detail="Username or email already exists")

    return {"message": "User registered successfully", "user_id": user_id}


@app.get("/auth/me")
async def get_current_user_info(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    permissions = Roles.get_permissions(current_user["role"])
    return {"user": current_user, "permissions": permissions}


@app.get("/")
async def root():
    return {
        "name": "BOFA Extended Systems API",
        "version": "2.5.1",
        "edition": "Neural Security Edge",
        "status": "operational",
        "timestamp": datetime.now().isoformat(),
        "features": [
            "Real Script Execution",
            "JWT Authentication",
            "Docker Lab Management",
            "SQLite Database",
            "AI/ML Integration",
            "Post-Quantum Ready",
            "Supply Chain Security",
            "Zero Trust Validation",
            "Cloud Native Attacks",
            "Deepfake Detection",
            "IoT Security Mapping",
        ],
        "capabilities": {
            "authentication": True,
            "script_execution": True,
            "lab_management": True,
            "user_management": True,
            "real_time_monitoring": True,
        },
    }


@app.get("/health")
async def health_check():
    try:
        database = _database_health()
        scripts = _scripts_health()
        labs = _labs_health()
        system_stats = script_executor.get_system_stats()

        overall_status = "healthy"
        if any(service["status"] == "error" for service in (database, scripts, labs)):
            overall_status = "degraded"
        elif any(service["status"] == "warning" for service in (database, scripts, labs)):
            overall_status = "warning"

        return {
            "status": overall_status,
            "timestamp": datetime.now().isoformat(),
            "version": "2.5.1",
            "edition": "Neural Security Edge",
            "services": {
                "database": database["status"],
                "docker": labs["status"],
                "authentication": "healthy",
                "script_executor": scripts["status"],
                "queue": "healthy",
            },
            "system": {
                "cpu_usage": system_stats.get("cpu_percent", 0),
                "memory_usage": system_stats.get("memory_percent", 0),
                "active_executions": system_stats.get("active_executions", 0),
                "disk_free_gb": system_stats.get("disk_free_gb", 0),
            },
            "queue": _queue_snapshot(),
            "checks": {
                "database": database,
                "scripts": scripts,
                "labs": labs,
            },
            "uptime": "operational",
        }
    except Exception as exc:
        logger.error(f"Health check error: {exc}")
        return {
            "status": "degraded",
            "timestamp": datetime.now().isoformat(),
            "error": str(exc),
        }


@app.get("/health/database")
async def health_database():
    return {**_database_health(), "timestamp": datetime.now().isoformat()}


@app.get("/health/scripts")
async def health_scripts():
    return {**_scripts_health(), "timestamp": datetime.now().isoformat()}


@app.get("/health/labs")
async def health_labs():
    return {**_labs_health(), "timestamp": datetime.now().isoformat()}


@app.get("/health/queue")
async def health_queue():
    return {
        "service": "execution_queue",
        "status": "healthy",
        "details": "Cola operativa",
        "stats": _queue_snapshot(),
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/modules")
async def get_modules():
    modules = []
    module_descriptions = {
        "red": {"name": "Red Team", "description": "Arsenal ofensivo avanzado + Supply Chain + Cloud Native", "icon": "terminal"},
        "blue": {"name": "Blue Team", "description": "Defensiva + AI Threat Hunting + Zero Trust", "icon": "shield"},
        "purple": {"name": "Purple Team", "description": "Coordinado + Quantum-Safe + Behavioral", "icon": "users"},
        "osint": {"name": "OSINT", "description": "Intelligence + IoT Mapping + Threat Intel", "icon": "search"},
        "malware": {"name": "Malware Analysis", "description": "Análisis estático + IOC extraction + Forensics", "icon": "bug"},
        "social": {"name": "Social Engineering", "description": "Concienciación + Phishing + Training", "icon": "users"},
        "study": {"name": "Study & Training", "description": "CTF + Educational + Skill Assessment", "icon": "book-open"},
    }

    for module_id, scripts in SCRIPT_CONFIGS.items():
        module_info = module_descriptions.get(
            module_id,
            {"name": module_id.title(), "description": f"Herramientas de {module_id}", "icon": "terminal"},
        )
        modules.append(
            {
                "id": module_id,
                "name": module_info["name"],
                "description": module_info["description"],
                "icon": module_info["icon"],
                "script_count": len(scripts),
            }
        )

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
            try:
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
                        "dependencies": script_config.get("dependencies") or script_config.get("requirements"),
                        "file_path_yaml": str(yaml_path),
                        "file_path_py": str(py_path) if py_path.exists() else None,
                        "has_code": py_path.exists(),
                    }
                )
            except Exception as exc:
                logger.warning(f"Catalog build error for {script_config}: {exc}")
    catalog.sort(key=lambda item: (item["category"], item["name"]))
    return catalog


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

    try:
        content = py_file.read_text(encoding="utf-8")
        return {
            "filename": py_file.name,
            "language": "python",
            "size": py_file.stat().st_size,
            "lines": len(content.splitlines()),
            "content": content,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error reading code: {exc}") from exc


@app.websocket("/ws/execute/{execution_id}")
async def websocket_execution(websocket: WebSocket, execution_id: str):
    await ws_manager.connect(websocket, execution_id)
    try:
        while True:
            await websocket.receive_text()
            await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket, execution_id)
    except Exception as exc:
        logger.error(f"WebSocket error: {exc}")
        await ws_manager.disconnect(websocket, execution_id)


@app.post("/execute")
async def execute_script(request: ExecuteScriptRequest, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    if not check_permission(current_user, "execute_scripts"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    if not request.module or not request.script:
        raise HTTPException(status_code=400, detail="Module and script are required")

    import uuid

    execution_id = str(uuid.uuid4())
    queue_item = await execution_queue.add_to_queue(
        execution_id,
        current_user["user_id"],
        request.module,
        request.script,
        request.parameters,
    )
    asyncio.create_task(process_execution_queue())

    logger.info(f"Queued execution {execution_id}: {request.module}/{request.script} by {current_user['username']}")
    return {
        "execution_id": execution_id,
        "status": "queued",
        "position": queue_item["position"],
        "message": f"Script {request.script} added to queue",
        "timestamp": datetime.now().isoformat(),
    }


async def process_execution_queue():
    while True:
        item = await execution_queue.get_next()
        if not item:
            break

        execution_id = item["execution_id"]
        try:
            await ws_manager.send_status(execution_id, "running", {"message": "Execution started"})
            logger.info(f"Starting execution: {execution_id}")
            await execute_script_with_streaming(
                execution_id,
                item["user_id"],
                item["module"],
                item["script"],
                item["parameters"],
            )
        except Exception as exc:
            logger.error(f"Execution error: {exc}")
            await execution_queue.mark_failed(execution_id, str(exc))
            await ws_manager.send_status(execution_id, "error", {"error": str(exc)})


async def execute_script_with_streaming(execution_id: str, user_id: int, module: str, script: str, parameters: Dict[str, Any]):
    script_file = SCRIPTS_DIR / module / f"{script}.py"
    if not script_file.exists():
        raise FileNotFoundError(f"Script not found: {script_file}")

    command = [sys.executable, str(script_file)]
    for key, value in parameters.items():
        command.extend([f"--{key}", str(value)])

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(APP_ROOT),
    )

    async def stream_output(stream, output_type):
        while True:
            line = await stream.readline()
            if not line:
                break
            text = line.decode(errors="replace").strip()
            if text:
                await ws_manager.send_output(execution_id, output_type, text)

    await asyncio.gather(
        stream_output(process.stdout, "stdout"),
        stream_output(process.stderr, "stderr"),
    )
    await process.wait()

    result = {
        "exit_code": process.returncode,
        "status": "success" if process.returncode == 0 else "error",
        "user_id": user_id,
    }
    await execution_queue.mark_completed(execution_id, result)
    await ws_manager.send_completed(execution_id, result)


@app.get("/execute/{execution_id}")
async def get_execution_status(execution_id: str, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    status = await execution_queue.get_status(execution_id)
    if not status:
        execution = script_executor.get_execution_status(execution_id)
        if not execution:
            raise HTTPException(status_code=404, detail="Execution not found")
        return execution

    if status["user_id"] != current_user["user_id"] and current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    return status


@app.get("/queue/info")
async def get_queue_info(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    return await execution_queue.get_queue_info()


@app.post("/execute/{execution_id}/stop")
async def stop_execution(execution_id: str, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    success = script_executor.stop_execution(execution_id, current_user["user_id"])
    if not success:
        raise HTTPException(status_code=404, detail="Execution not found or already stopped")
    return {"message": "Execution stopped", "execution_id": execution_id}


@app.get("/history")
async def get_execution_history(limit: int = 50, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    if current_user["role"] == "admin":
        history = db.get_execution_history(limit=limit)
    else:
        history = db.get_execution_history(user_id=current_user["user_id"], limit=limit)

    for item in history:
        if "parameters" in item and isinstance(item["parameters"], str):
            try:
                item["parameters"] = json.loads(item["parameters"])
            except Exception:
                pass
        if item.get("output") and len(item["output"]) > 200:
            item["output"] = item["output"][:200] + "..."
    return history


@app.get("/labs")
async def get_labs(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    if not check_permission(current_user, "manage_labs"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    labs = lab_manager.get_available_labs()
    for lab in labs:
        try:
            status_info = lab_manager.get_lab_status(lab["id"], current_user["user_id"])
            lab.update(status_info)
        except Exception as exc:
            logger.warning(f"Error getting status for lab {lab['id']}: {exc}")
            lab["status"] = "unknown"
    return labs


@app.post("/labs/{lab_id}/start")
async def start_lab(lab_id: str, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    if not check_permission(current_user, "manage_labs"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    result = lab_manager.start_lab(lab_id, current_user["user_id"])
    if result["status"] != "success":
        raise HTTPException(status_code=400, detail=result["message"])
    return result


@app.post("/labs/{lab_id}/stop")
async def stop_lab(lab_id: str, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    if not check_permission(current_user, "manage_labs"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    result = lab_manager.stop_lab(lab_id, current_user["user_id"])
    if result["status"] != "success":
        raise HTTPException(status_code=400, detail=result["message"])
    return result


@app.get("/study/lessons")
async def get_study_lessons(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    default_lessons = [
        {
            "id": "web_application_security",
            "title": "Seguridad en Aplicaciones Web",
            "description": "Curso completo sobre vulnerabilidades web y OWASP Top 10",
            "category": "web_security",
            "difficulty": "intermediate",
            "duration": 180,
            "completed": False,
            "progress": 0,
        },
        {
            "id": "cloud_native_security",
            "title": "Cloud Native Security",
            "description": "Seguridad en contenedores, Kubernetes y arquitecturas serverless",
            "category": "cloud_security",
            "difficulty": "expert",
            "duration": 420,
            "completed": False,
            "progress": 0,
        },
        {
            "id": "ai_threat_hunting",
            "title": "AI-Powered Threat Hunting",
            "description": "Uso de inteligencia artificial para detección avanzada de amenazas",
            "category": "ai_security",
            "difficulty": "expert",
            "duration": 360,
            "completed": False,
            "progress": 0,
        },
        {
            "id": "malware_analysis_fundamentals",
            "title": "Fundamentos de Análisis de Malware",
            "description": "Técnicas básicas y avanzadas para análisis de malware",
            "category": "malware_analysis",
            "difficulty": "advanced",
            "duration": 300,
            "completed": False,
            "progress": 0,
        },
        {
            "id": "quantum_cryptography",
            "title": "Post-Quantum Cryptography",
            "description": "Criptografía resistente a computación cuántica",
            "category": "quantum_security",
            "difficulty": "expert",
            "duration": 480,
            "completed": False,
            "progress": 0,
        },
    ]

    try:
        user_progress = db.get_learning_progress(current_user["user_id"])
        progress_dict = {entry["lesson_id"]: entry for entry in user_progress}
        for lesson in default_lessons:
            if lesson["id"] in progress_dict:
                progress = progress_dict[lesson["id"]]
                lesson["progress"] = progress["progress"]
                lesson["completed"] = progress["completed"]
    except Exception as exc:
        logger.warning(f"Error loading user progress: {exc}")

    return default_lessons


@app.put("/study/lessons/{lesson_id}/progress")
async def update_lesson_progress(lesson_id: str, request: UpdateProgressRequest, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    try:
        db.update_lesson_progress(current_user["user_id"], lesson_id, request.progress)
        return {"message": "Progress updated", "lesson_id": lesson_id, "progress": request.progress}
    except Exception as exc:
        logger.error(f"Error updating progress: {exc}")
        raise HTTPException(status_code=500, detail="Error updating progress") from exc


@app.post("/api-keys/{service_name}")
async def store_api_key(
    service_name: str,
    api_key: str = Form(...),
    current_user: Dict[str, Any] = Depends(auth_manager.get_current_user),
):
    if not check_permission(current_user, "manage_api_keys"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    allowed_services = ["shodan_key", "virustotal_key", "hibp_key", "github_token"]
    if service_name not in allowed_services:
        raise HTTPException(status_code=400, detail=f"Service must be one of: {allowed_services}")

    try:
        db.store_api_key(current_user["user_id"], service_name, api_key)
        return {"message": f"API key for {service_name} stored successfully"}
    except Exception as exc:
        logger.error(f"Error storing API key: {exc}")
        raise HTTPException(status_code=500, detail="Error storing API key") from exc


@app.get("/api-keys")
async def get_user_api_keys(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    if not check_permission(current_user, "manage_api_keys"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    services = ["shodan_key", "virustotal_key", "hibp_key", "github_token"]
    keys_status = {}
    for service in services:
        api_key = db.get_api_key(current_user["user_id"], service)
        keys_status[service] = {
            "configured": bool(api_key),
            "masked_key": f"****{api_key[-4:]}" if api_key else None,
        }
    return keys_status


@app.get("/dashboard/stats")
async def get_dashboard_stats(current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    try:
        return _build_dashboard_stats(current_user)
    except Exception as exc:
        logger.error(f"Error getting dashboard stats: {exc}")
        queue_stats = _queue_snapshot()
        return {
            "total_scripts": sum(len(scripts) for scripts in SCRIPT_CONFIGS.values()),
            "total_executions": 0,
            "active_labs": 0,
            "completion_rate": 0,
            "threat_level": "UNKNOWN",
            "system_status": "degraded",
            "overview": {
                "total_scripts": sum(len(scripts) for scripts in SCRIPT_CONFIGS.values()),
                "modules": len(SCRIPT_CONFIGS),
                "scripts_updated_recently": 0,
                "system_status": "degraded",
                "threat_level": "UNKNOWN",
                "last_scan": datetime.now().isoformat(),
            },
            "executions": {
                "total_executions": 0,
                "successful": 0,
                "failed": 0,
                "queued": queue_stats["queued"],
                "running": queue_stats["running"],
                "success_rate": 0,
            },
            "docker": {"active_labs": 0},
            "system": {
                "cpu_percent": 0,
                "memory_percent": 0,
                "active_executions": 0,
                "disk_free_gb": 0,
            },
            "queue": queue_stats,
            "recent_activity": [],
            "error": str(exc),
        }


@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={
            "error": "Not Found",
            "message": "The requested resource was not found",
            "timestamp": datetime.now().isoformat(),
        },
    )


@app.exception_handler(500)
async def server_error_handler(request, exc):
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An internal error occurred",
            "timestamp": datetime.now().isoformat(),
        },
    )


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
