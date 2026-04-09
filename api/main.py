#!/usr/bin/env python3
"""
BOFA API - operational control plane.
"""

import asyncio
import base64
from datetime import datetime
import hashlib
import json
import logging
import mimetypes
import os
from pathlib import Path
import re
import sys
import zipfile
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from fastapi import Depends, FastAPI, Form, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
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
EVIDENCE_KEYS_DIR = DATA_DIR / "evidence_keys"
EVIDENCE_PRIVATE_KEY_PATH = EVIDENCE_KEYS_DIR / "evidence_ed25519_private.pem"
EVIDENCE_PUBLIC_KEY_PATH = EVIDENCE_KEYS_DIR / "evidence_ed25519_public.pem"

for directory in (LOGS_DIR, DATA_DIR, TEMP_DIR, UPLOADS_DIR, CANCEL_DIR, RUNTIME_REPORTS_DIR, EVIDENCE_KEYS_DIR):
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
    version="2.8.2",
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
ARTIFACT_PREVIEW_LIMIT = 4000
ARTIFACT_TAIL_PREVIEW_TYPES = {"stdout_log", "stderr_log"}
ARTIFACT_HEAD_PREVIEW_TYPES = {
    "report_json",
    "report_markdown",
    "flow_summary_json",
    "flow_summary_markdown",
    "post_process_output",
    "evidence_manifest_json",
    "evidence_signature",
    "evidence_public_key_pem",
}
EVIDENCE_EXPORT_ARTIFACT_TYPES = {
    "evidence_bundle_zip",
    "evidence_manifest_json",
    "evidence_signature",
    "evidence_public_key_pem",
}
EVIDENCE_BUNDLE_VERSION = "1.0"
EVIDENCE_SIGNING_ALGORITHM = "Ed25519"
EVIDENCE_SIGNATURE_SCOPE = "canonical_manifest_without_manifest_sha256_and_self_referential_files"
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
    artifacts = _serialize_artifacts(run.get("artifacts", []), run)
    return {
        **run,
        "artifacts": artifacts,
        "timeline_count": len(events),
        "step_count": len(run.get("steps", [])),
        "artifact_count": len(artifacts),
        "lab_count": len(run.get("labs", [])),
        "status": status,
    }


def _artifact_role(artifact_type: Optional[str]) -> str:
    if artifact_type in {"stdout_log", "stderr_log"}:
        return "execution_log"
    if artifact_type in {"report_json", "report_markdown", "flow_summary_json", "flow_summary_markdown"}:
        return "summary"
    if artifact_type in EVIDENCE_EXPORT_ARTIFACT_TYPES:
        return "export"
    if artifact_type == "post_process_output":
        return "post_process"
    return "evidence"


def _artifact_content_type(path_str: Optional[str], artifact_type: Optional[str]) -> str:
    if artifact_type in {"stdout_log", "stderr_log"}:
        return "text/plain"
    if artifact_type == "evidence_bundle_zip":
        return "application/zip"
    if artifact_type == "evidence_manifest_json":
        return "application/json"
    if artifact_type in {"evidence_signature", "evidence_public_key_pem"}:
        return "text/plain"
    if artifact_type in {"report_json", "flow_summary_json"}:
        return "application/json"
    if artifact_type in {"report_markdown", "flow_summary_markdown"}:
        return "text/markdown"
    if path_str:
        guessed, _ = mimetypes.guess_type(path_str)
        if guessed:
            return guessed
        suffix = Path(path_str).suffix.lower()
        if suffix in {".log", ".txt"}:
            return "text/plain"
        if suffix == ".md":
            return "text/markdown"
        if suffix == ".json":
            return "application/json"
        if suffix in {".yaml", ".yml"}:
            return "application/x-yaml"
    return "application/octet-stream"


def _is_previewable_content_type(content_type: Optional[str]) -> bool:
    if not content_type:
        return False
    return content_type.startswith("text/") or content_type in {"application/json", "application/x-yaml", "application/xml"}


def _artifact_preview_mode(artifact_type: Optional[str], content_type: Optional[str]) -> Optional[str]:
    if not _is_previewable_content_type(content_type):
        return None
    if artifact_type in ARTIFACT_TAIL_PREVIEW_TYPES:
        return "tail"
    if artifact_type in ARTIFACT_HEAD_PREVIEW_TYPES:
        return "head"
    return "head"


def _artifact_size_bytes(path_str: Optional[str]) -> Optional[int]:
    if not path_str:
        return None
    path = Path(path_str)
    if not path.exists() or not path.is_file():
        return None
    try:
        return path.stat().st_size
    except OSError:
        return None


def _artifact_download_state(path_str: Optional[str]) -> Dict[str, Any]:
    if not path_str:
        return {"downloadable": False, "download_reason": "artifact_path_missing"}
    path = Path(path_str)
    if not _is_path_within_root(path, APP_ROOT):
        return {"downloadable": False, "download_reason": "outside_allowed_root"}
    if not path.exists() or not path.is_file():
        return {"downloadable": False, "download_reason": "artifact_not_found"}
    return {"downloadable": True, "download_reason": None}


def _build_runtime_artifact_metadata(
    path_str: str,
    artifact_type: str,
    run_status: str,
    step_status: Optional[str] = None,
    step_id: Optional[str] = None,
    execution_id: Optional[str] = None,
    partial: Optional[bool] = None,
) -> Dict[str, Any]:
    content_type = _artifact_content_type(path_str, artifact_type)
    preview_mode = _artifact_preview_mode(artifact_type, content_type)
    download_state = _artifact_download_state(path_str)
    return {
        "step_id": step_id,
        "execution_id": execution_id,
        "run_status": run_status,
        "step_status": step_status or run_status,
        "artifact_role": _artifact_role(artifact_type),
        "previewable": preview_mode is not None,
        "preview_mode": preview_mode,
        "content_type": content_type,
        "size_bytes": _artifact_size_bytes(path_str),
        "partial": (run_status in {"partial", "cancelled", "failed", "error"}) if partial is None else partial,
        "downloadable": download_state["downloadable"],
        "download_reason": download_state["download_reason"],
    }


def _serialize_artifact(artifact: Dict[str, Any], run: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    serialized = dict(artifact)
    metadata = dict(serialized.get("metadata") or {})
    step_lookup = {step["id"]: step for step in (run.get("steps", []) if run else [])}
    step = step_lookup.get(metadata.get("step_id")) if metadata.get("step_id") else None
    run_status = metadata.get("run_status") or (run.get("status") if run else None)
    step_status = metadata.get("step_status") or (step.get("status") if step else None)
    content_type = metadata.get("content_type") or _artifact_content_type(serialized.get("path"), serialized.get("artifact_type"))
    preview_mode = metadata.get("preview_mode") or _artifact_preview_mode(serialized.get("artifact_type"), content_type)
    size_bytes = metadata.get("size_bytes")
    if size_bytes is None:
        size_bytes = _artifact_size_bytes(serialized.get("path"))
    download_state = _artifact_download_state(serialized.get("path"))
    partial = metadata.get("partial")
    if partial is None:
        partial = (run_status in {"partial", "cancelled"}) or (step_status in {"failed", "cancelled"})
    serialized["metadata"] = {
        **metadata,
        "step_id": metadata.get("step_id"),
        "execution_id": metadata.get("execution_id"),
        "run_status": run_status,
        "step_status": step_status,
        "artifact_role": metadata.get("artifact_role") or _artifact_role(serialized.get("artifact_type")),
        "previewable": metadata.get("previewable") if "previewable" in metadata else preview_mode is not None,
        "preview_mode": preview_mode,
        "content_type": content_type,
        "size_bytes": size_bytes,
        "partial": bool(partial),
        "downloadable": metadata.get("downloadable") if "downloadable" in metadata else download_state["downloadable"],
        "download_reason": metadata.get("download_reason") if "download_reason" in metadata else download_state["download_reason"],
    }
    return serialized


def _serialize_artifacts(artifacts: List[Dict[str, Any]], run: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    return [_serialize_artifact(artifact, run) for artifact in artifacts]


def _build_artifact_preview_payload(run_id: str, artifact: Dict[str, Any], run: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    serialized = _serialize_artifact(artifact, run)
    metadata = dict(serialized.get("metadata") or {})
    preview_mode = metadata.get("preview_mode")
    base_payload = {
        "run_id": run_id,
        "artifact": serialized,
        "previewable": bool(metadata.get("previewable")),
        "preview": None,
        "truncated": False,
        "preview_mode": preview_mode,
        "content_type": metadata.get("content_type"),
        "size_bytes": metadata.get("size_bytes"),
        "reason": None,
    }

    if not base_payload["previewable"]:
        return {**base_payload, "reason": "binary_or_unsupported"}

    path = Path(serialized.get("path") or "")
    if not path.exists() or not path.is_file():
        return {**base_payload, "previewable": False, "reason": "artifact_not_found"}

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {**base_payload, "previewable": False, "reason": "artifact_unreadable"}

    limit = ARTIFACT_PREVIEW_LIMIT
    if preview_mode == "tail":
        preview = content[-limit:]
    else:
        preview = content[:limit]
        preview_mode = preview_mode or "head"

    return {
        **base_payload,
        "previewable": True,
        "preview": preview,
        "truncated": len(content) > limit,
        "preview_mode": preview_mode,
    }


def _sanitize_export_name(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "").strip("._")
    return safe or "artifact"


def _guess_extension_from_content_type(content_type: Optional[str]) -> str:
    if not content_type:
        return ""
    extension = mimetypes.guess_extension(content_type, strict=False)
    if extension == ".ksh":
        return ".txt"
    return extension or ""


def _is_path_within_root(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _canonical_file_entry(content: bytes, content_type: str) -> Dict[str, Any]:
    return {
        "sha256": _sha256_bytes(content),
        "size_bytes": len(content),
        "content_type": content_type,
    }


def _manifest_signature_payload(manifest: Dict[str, Any]) -> Dict[str, Any]:
    payload = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    canonical_files = payload.get("canonical_files")
    if canonical_files:
        payload["canonical_files"] = {
            name: value for name, value in canonical_files.items() if name not in {"manifest.json", "manifest.sig"}
        }
    return payload


def _load_or_create_evidence_signing_keypair(create_if_missing: bool = True) -> Optional[Dict[str, Any]]:
    private_exists = EVIDENCE_PRIVATE_KEY_PATH.exists()
    if not private_exists and not create_if_missing:
        return None

    generated = False
    if private_exists:
        private_key = load_pem_private_key(EVIDENCE_PRIVATE_KEY_PATH.read_bytes(), password=None)
    else:
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        EVIDENCE_PRIVATE_KEY_PATH.write_bytes(private_bytes)
        generated = True

    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if not EVIDENCE_PUBLIC_KEY_PATH.exists() or EVIDENCE_PUBLIC_KEY_PATH.read_bytes() != public_key_pem:
        EVIDENCE_PUBLIC_KEY_PATH.write_bytes(public_key_pem)

    return {
        "private_key": private_key,
        "public_key": public_key,
        "public_key_pem": public_key_pem,
        "private_key_path": str(EVIDENCE_PRIVATE_KEY_PATH),
        "public_key_path": str(EVIDENCE_PUBLIC_KEY_PATH),
        "public_key_fingerprint": _sha256_bytes(public_key_pem),
        "generated": generated,
    }


def _get_evidence_public_key_info(create_if_missing: bool = True) -> Optional[Dict[str, Any]]:
    keypair = _load_or_create_evidence_signing_keypair(create_if_missing=create_if_missing)
    if not keypair:
        return None
    return {
        "signing_algorithm": EVIDENCE_SIGNING_ALGORITHM,
        "public_key_fingerprint": keypair["public_key_fingerprint"],
        "public_key_pem": keypair["public_key_pem"].decode("utf-8"),
        "path": keypair["public_key_path"],
        "trust_anchor": f"sha256:{keypair['public_key_fingerprint']}",
    }


def _build_evidence_bundle_readme(run: Dict[str, Any], manifest: Dict[str, Any]) -> str:
    return "\n".join(
        [
            "BOFA Evidence Bundle",
            "====================",
            "",
            f"Run ID: {run.get('id')}",
            f"Run type: {run.get('run_type')}",
            f"Requested action: {run.get('requested_action')}",
            f"Target: {run.get('target') or 'n/a'}",
            f"Run status: {run.get('status')}",
            f"Exported at: {manifest.get('exported_at')}",
            f"Bundle version: {manifest.get('bundle_version')}",
            f"Signing algorithm: {manifest.get('signing_algorithm')}",
            f"Public key fingerprint: {manifest.get('public_key_fingerprint')}",
            "",
            "Bundle contents:",
            "- manifest.json: canonical export manifest with checksums and inclusion status",
            "- manifest.sig: detached Ed25519 signature for the canonical manifest payload",
            "- public_key.pem: embedded public key for portable verification",
            "- run.json: serialized run snapshot",
            "- timeline.json: persisted run events",
            "- steps.json: persisted run steps",
            "- labs.json: persisted run labs",
            "- artifacts/: evidence files included in this export",
            "",
            "Integrity guidance:",
            "- Verify manifest.sig against the canonical manifest payload before trusting the bundle",
            "- Use manifest.json as the source of truth for included artifacts and canonical file hashes",
            "- Validate sha256 values before reusing or sharing evidence",
            "- Missing or omitted artifacts are explicitly documented in manifest.json",
        ]
    )


def _find_existing_evidence_export(run: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    export_groups: Dict[str, Dict[str, Dict[str, Any]]] = {}
    artifacts = sorted(run.get("artifacts", []), key=lambda item: item.get("created_at") or "")
    for artifact in artifacts:
        if artifact.get("artifact_type") not in EVIDENCE_EXPORT_ARTIFACT_TYPES:
            continue
        metadata = artifact.get("metadata") or {}
        export_timestamp = metadata.get("export_timestamp")
        if not export_timestamp:
            continue
        export_groups.setdefault(export_timestamp, {})[artifact["artifact_type"]] = artifact

    for export_timestamp in sorted(export_groups.keys(), reverse=True):
        group = export_groups[export_timestamp]
        bundle_artifact = group.get("evidence_bundle_zip")
        manifest_artifact = group.get("evidence_manifest_json")
        signature_artifact = group.get("evidence_signature")
        public_key_artifact = group.get("evidence_public_key_pem")
        if not bundle_artifact or not manifest_artifact or not signature_artifact or not public_key_artifact:
            continue
        bundle_path = Path(bundle_artifact.get("path") or "")
        manifest_path = Path(manifest_artifact.get("path") or "")
        signature_path = Path(signature_artifact.get("path") or "")
        public_key_path = Path(public_key_artifact.get("path") or "")
        if bundle_path.exists() and manifest_path.exists() and signature_path.exists() and public_key_path.exists():
            return {
                "bundle_artifact": bundle_artifact,
                "manifest_artifact": manifest_artifact,
                "signature_artifact": signature_artifact,
                "public_key_artifact": public_key_artifact,
                "bundle_path": str(bundle_path),
                "manifest_path": str(manifest_path),
                "signature_path": str(signature_path),
                "public_key_path": str(public_key_path),
                "export_timestamp": export_timestamp,
                "created": False,
            }
    return None


def _create_run_evidence_export(run_id: str) -> Dict[str, Any]:
    run_snapshot = db.get_run_detail(run_id)
    if not run_snapshot:
        raise HTTPException(status_code=404, detail="Run not found")

    serialized_run = _serialize_run(run_snapshot)
    existing_export = _find_existing_evidence_export(serialized_run)
    if existing_export:
        return existing_export

    export_timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    export_dir = RUNTIME_REPORTS_DIR / run_id / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = export_dir / f"manifest_{run_id}_{export_timestamp}.json"
    signature_path = export_dir / f"manifest_{run_id}_{export_timestamp}.sig"
    public_key_export_path = export_dir / f"public_key_{run_id}_{export_timestamp}.pem"
    bundle_path = export_dir / f"bofa_evidence_{run_id}_{export_timestamp}.zip"

    run_manager.add_event(
        run_id,
        "run",
        run_id,
        "evidence_export_started",
        "running",
        "Evidence bundle export started",
        {"bundle_version": EVIDENCE_BUNDLE_VERSION, "export_timestamp": export_timestamp},
    )

    signing_keypair = _load_or_create_evidence_signing_keypair(create_if_missing=True)
    if not signing_keypair:
        raise HTTPException(status_code=500, detail="Evidence signing key is unavailable")
    if signing_keypair["generated"]:
        run_manager.add_event(
            run_id,
            "run",
            run_id,
            "evidence_key_generated",
            "success",
            "Evidence signing key generated",
            {
                "signing_algorithm": EVIDENCE_SIGNING_ALGORITHM,
                "public_key_fingerprint": signing_keypair["public_key_fingerprint"],
                "public_key_path": signing_keypair["public_key_path"],
            },
        )

    run_snapshot = db.get_run_detail(run_id) or run_snapshot
    serialized_run = _serialize_run(run_snapshot)
    steps = run_snapshot.get("steps", [])
    labs = run_snapshot.get("labs", [])
    events = run_snapshot.get("events", [])
    source_artifacts = [artifact for artifact in serialized_run.get("artifacts", []) if artifact.get("artifact_type") not in EVIDENCE_EXPORT_ARTIFACT_TYPES]

    included_artifacts: List[Dict[str, Any]] = []
    manifest_artifacts: List[Dict[str, Any]] = []
    warning_count = 0

    for artifact in source_artifacts:
        metadata = artifact.get("metadata") or {}
        original_path = Path(artifact.get("path") or "")
        content_type = metadata.get("content_type") or _artifact_content_type(str(original_path), artifact.get("artifact_type"))
        relative_path = None
        sha256 = None
        included = False
        missing = False
        reason = None

        if not _is_path_within_root(original_path, APP_ROOT):
            reason = "outside_allowed_root"
        elif not original_path.exists() or not original_path.is_file():
            reason = "artifact_not_found"
            missing = True
        else:
            try:
                sha256 = _sha256_file(original_path)
                extension = original_path.suffix or _guess_extension_from_content_type(content_type)
                relative_path = f"artifacts/{_sanitize_export_name(artifact['id'])}_{_sanitize_export_name(artifact['artifact_type'])}{extension}"
                included = True
                included_artifacts.append({"source_path": original_path, "relative_path": relative_path})
            except OSError:
                reason = "artifact_unreadable"

        if reason:
            warning_count += 1
            run_manager.add_event(
                run_id,
                "artifact",
                artifact.get("id"),
                "evidence_export_warning",
                "warning",
                f"Artifact omitted from evidence bundle: {artifact.get('artifact_type')}",
                {"artifact_id": artifact.get("id"), "reason": reason, "path": artifact.get("path")},
            )

        manifest_artifacts.append(
            {
                "artifact_id": artifact.get("id"),
                "artifact_type": artifact.get("artifact_type"),
                "label": artifact.get("label"),
                "original_path": artifact.get("path"),
                "relative_path": relative_path,
                "content_type": content_type,
                "size_bytes": metadata.get("size_bytes") or _artifact_size_bytes(artifact.get("path")),
                "sha256": sha256,
                "included": included,
                "missing": missing,
                "reason": reason,
            }
        )

    final_events = [
        event
        for event in events
        if event.get("status") in RUN_STATUSES_FINAL or event.get("event_type") in {"cancelled", "completed", "status_changed"}
    ]
    run_json_bytes = json.dumps(serialized_run, indent=2, ensure_ascii=False).encode("utf-8")
    timeline_json_bytes = json.dumps(events, indent=2, ensure_ascii=False).encode("utf-8")
    steps_json_bytes = json.dumps(steps, indent=2, ensure_ascii=False).encode("utf-8")
    labs_json_bytes = json.dumps(labs, indent=2, ensure_ascii=False).encode("utf-8")
    public_key_bytes = signing_keypair["public_key_pem"]
    public_key_export_path.write_bytes(public_key_bytes)

    manifest = {
        "bundle_version": EVIDENCE_BUNDLE_VERSION,
        "exported_at": datetime.utcnow().isoformat(),
        "signing_algorithm": EVIDENCE_SIGNING_ALGORITHM,
        "signature_scope": EVIDENCE_SIGNATURE_SCOPE,
        "public_key_fingerprint": signing_keypair["public_key_fingerprint"],
        "trust_anchor": f"sha256:{signing_keypair['public_key_fingerprint']}",
        "run": {
            "id": serialized_run.get("id"),
            "run_type": serialized_run.get("run_type"),
            "source": serialized_run.get("source"),
            "requested_action": serialized_run.get("requested_action"),
            "target": serialized_run.get("target"),
            "status": serialized_run.get("status"),
            "created_at": serialized_run.get("created_at"),
            "started_at": serialized_run.get("started_at"),
            "completed_at": serialized_run.get("completed_at"),
            "parent_run_id": serialized_run.get("parent_run_id"),
        },
        "steps": [
            {
                "id": step.get("id"),
                "step_index": step.get("step_index"),
                "step_type": step.get("step_type"),
                "step_key": step.get("step_key"),
                "module": step.get("module"),
                "script_name": step.get("script_name"),
                "status": step.get("status"),
                "exit_code": step.get("exit_code"),
                "duration": step.get("duration"),
            }
            for step in steps
        ],
        "labs": [
            {
                "id": lab.get("id"),
                "lab_id": lab.get("lab_id"),
                "status": lab.get("status"),
                "container_id": lab.get("container_id"),
                "port": lab.get("port"),
            }
            for lab in labs
        ],
        "canonical_files": {
            "run.json": _canonical_file_entry(run_json_bytes, "application/json"),
            "timeline.json": _canonical_file_entry(timeline_json_bytes, "application/json"),
            "steps.json": _canonical_file_entry(steps_json_bytes, "application/json"),
            "labs.json": _canonical_file_entry(labs_json_bytes, "application/json"),
            "public_key.pem": _canonical_file_entry(public_key_bytes, "text/plain"),
        },
        "events": {
            "event_count": len(events),
            "final_event_count": len(final_events),
            "final_events": final_events,
        },
        "artifacts": manifest_artifacts,
        "artifact_count": len(source_artifacts),
        "included_count": len([artifact for artifact in manifest_artifacts if artifact["included"]]),
        "missing_count": len([artifact for artifact in manifest_artifacts if artifact["missing"]]),
        "warning_count": warning_count,
    }
    readme_bytes = _build_evidence_bundle_readme(serialized_run, manifest).encode("utf-8")
    manifest["canonical_files"]["README.txt"] = _canonical_file_entry(readme_bytes, "text/plain")
    manifest_payload = _canonical_json_bytes(_manifest_signature_payload(manifest))
    manifest_sha256 = _sha256_bytes(manifest_payload)
    signature_bytes = signing_keypair["private_key"].sign(manifest_payload)
    signature_text = base64.b64encode(signature_bytes).decode("ascii") + "\n"
    signature_file_bytes = signature_text.encode("utf-8")
    signature_path.write_text(signature_text, encoding="utf-8")
    manifest["manifest_sha256"] = manifest_sha256
    manifest["canonical_files"]["manifest.json"] = {
        "sha256": manifest_sha256,
        "size_bytes": len(manifest_payload),
        "content_type": "application/json",
        "scope": EVIDENCE_SIGNATURE_SCOPE,
    }
    manifest["canonical_files"]["manifest.sig"] = _canonical_file_entry(signature_file_bytes, "text/plain")

    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))
        archive.writestr("manifest.sig", signature_text)
        archive.writestr("public_key.pem", public_key_bytes)
        archive.writestr("run.json", run_json_bytes)
        archive.writestr("timeline.json", timeline_json_bytes)
        archive.writestr("steps.json", steps_json_bytes)
        archive.writestr("labs.json", labs_json_bytes)
        archive.writestr("README.txt", readme_bytes)
        for item in included_artifacts:
            archive.write(item["source_path"], item["relative_path"])

    manifest_metadata = _build_runtime_artifact_metadata(
        str(manifest_path),
        "evidence_manifest_json",
        serialized_run.get("status", "unknown"),
        partial=serialized_run.get("status") in {"partial", "cancelled", "failed", "error"},
    )
    manifest_metadata.update(
        {
            "artifact_role": "export",
            "export_timestamp": export_timestamp,
            "bundle_version": EVIDENCE_BUNDLE_VERSION,
            "signing_algorithm": EVIDENCE_SIGNING_ALGORITHM,
            "public_key_fingerprint": signing_keypair["public_key_fingerprint"],
            "manifest_sha256": manifest_sha256,
            "included_count": manifest["included_count"],
            "missing_count": manifest["missing_count"],
        }
    )
    signature_metadata = _build_runtime_artifact_metadata(
        str(signature_path),
        "evidence_signature",
        serialized_run.get("status", "unknown"),
        partial=serialized_run.get("status") in {"partial", "cancelled", "failed", "error"},
    )
    signature_metadata.update(
        {
            "artifact_role": "export",
            "export_timestamp": export_timestamp,
            "bundle_version": EVIDENCE_BUNDLE_VERSION,
            "signing_algorithm": EVIDENCE_SIGNING_ALGORITHM,
            "public_key_fingerprint": signing_keypair["public_key_fingerprint"],
            "manifest_sha256": manifest_sha256,
        }
    )
    public_key_metadata = _build_runtime_artifact_metadata(
        str(public_key_export_path),
        "evidence_public_key_pem",
        serialized_run.get("status", "unknown"),
        partial=serialized_run.get("status") in {"partial", "cancelled", "failed", "error"},
    )
    public_key_metadata.update(
        {
            "artifact_role": "export",
            "export_timestamp": export_timestamp,
            "bundle_version": EVIDENCE_BUNDLE_VERSION,
            "signing_algorithm": EVIDENCE_SIGNING_ALGORITHM,
            "public_key_fingerprint": signing_keypair["public_key_fingerprint"],
        }
    )
    bundle_metadata = _build_runtime_artifact_metadata(
        str(bundle_path),
        "evidence_bundle_zip",
        serialized_run.get("status", "unknown"),
        partial=serialized_run.get("status") in {"partial", "cancelled", "failed", "error"},
    )
    bundle_metadata.update(
        {
            "artifact_role": "export",
            "previewable": False,
            "preview_mode": None,
            "content_type": "application/zip",
            "export_timestamp": export_timestamp,
            "bundle_version": EVIDENCE_BUNDLE_VERSION,
            "signing_algorithm": EVIDENCE_SIGNING_ALGORITHM,
            "public_key_fingerprint": signing_keypair["public_key_fingerprint"],
            "manifest_sha256": manifest_sha256,
            "included_count": manifest["included_count"],
            "missing_count": manifest["missing_count"],
        }
    )

    manifest_artifact_id = run_manager.add_artifact(
        run_id,
        "evidence_manifest_json",
        str(manifest_path),
        label="Evidence manifest",
        metadata=manifest_metadata,
    )
    signature_artifact_id = run_manager.add_artifact(
        run_id,
        "evidence_signature",
        str(signature_path),
        label="Evidence signature",
        metadata=signature_metadata,
    )
    public_key_artifact_id = run_manager.add_artifact(
        run_id,
        "evidence_public_key_pem",
        str(public_key_export_path),
        label="Evidence public key",
        metadata=public_key_metadata,
    )
    bundle_artifact_id = run_manager.add_artifact(
        run_id,
        "evidence_bundle_zip",
        str(bundle_path),
        label="Evidence bundle",
        metadata=bundle_metadata,
    )
    run_manager.add_event(
        run_id,
        "run",
        run_id,
        "evidence_signed",
        "success",
        "Evidence bundle signed",
        {
            "bundle_version": EVIDENCE_BUNDLE_VERSION,
            "export_timestamp": export_timestamp,
            "signing_algorithm": EVIDENCE_SIGNING_ALGORITHM,
            "public_key_fingerprint": signing_keypair["public_key_fingerprint"],
            "signature_artifact_id": signature_artifact_id,
            "public_key_artifact_id": public_key_artifact_id,
            "manifest_sha256": manifest_sha256,
        },
    )
    run_manager.add_event(
        run_id,
        "run",
        run_id,
        "evidence_exported",
        "success",
        "Evidence bundle exported",
        {
            "bundle_version": EVIDENCE_BUNDLE_VERSION,
            "export_timestamp": export_timestamp,
            "signing_algorithm": EVIDENCE_SIGNING_ALGORITHM,
            "public_key_fingerprint": signing_keypair["public_key_fingerprint"],
            "bundle_path": str(bundle_path),
            "manifest_path": str(manifest_path),
            "signature_path": str(signature_path),
            "public_key_path": str(public_key_export_path),
            "artifact_count": manifest["artifact_count"],
            "included_count": manifest["included_count"],
            "missing_count": manifest["missing_count"],
            "bundle_artifact_id": bundle_artifact_id,
            "manifest_artifact_id": manifest_artifact_id,
            "signature_artifact_id": signature_artifact_id,
            "public_key_artifact_id": public_key_artifact_id,
        },
    )
    return {
        "bundle_path": str(bundle_path),
        "manifest_path": str(manifest_path),
        "signature_path": str(signature_path),
        "public_key_path": str(public_key_export_path),
        "bundle_artifact_id": bundle_artifact_id,
        "manifest_artifact_id": manifest_artifact_id,
        "signature_artifact_id": signature_artifact_id,
        "public_key_artifact_id": public_key_artifact_id,
        "export_timestamp": export_timestamp,
        "public_key_fingerprint": signing_keypair["public_key_fingerprint"],
        "created": True,
    }


def _find_run_artifact(run: Dict[str, Any], artifact_id: str) -> Optional[Dict[str, Any]]:
    for artifact in run.get("artifacts", []):
        if artifact.get("id") == artifact_id:
            return artifact
    return None


def _resolve_downloadable_artifact_path(artifact: Dict[str, Any]) -> Path:
    path = Path(artifact.get("path") or "")
    if not _is_path_within_root(path, APP_ROOT):
        raise HTTPException(status_code=403, detail="Artifact path is outside the allowed workspace root")
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="Artifact file not found")
    return path


def _verify_run_evidence_export(run_id: str) -> Dict[str, Any]:
    run_snapshot = db.get_run_detail(run_id)
    if not run_snapshot:
        raise HTTPException(status_code=404, detail="Run not found")

    serialized_run = _serialize_run(run_snapshot)
    latest_export = _find_existing_evidence_export(serialized_run)
    if not latest_export:
        raise HTTPException(status_code=404, detail="Evidence bundle not found for this run")

    bundle_artifact = _serialize_artifact(latest_export["bundle_artifact"], run_snapshot)
    manifest_artifact = _serialize_artifact(latest_export["manifest_artifact"], run_snapshot)
    signature_artifact = _serialize_artifact(latest_export["signature_artifact"], run_snapshot)
    public_key_artifact = _serialize_artifact(latest_export["public_key_artifact"], run_snapshot)
    bundle_path = _resolve_downloadable_artifact_path(bundle_artifact)
    manifest_path = _resolve_downloadable_artifact_path(manifest_artifact)
    signature_path = _resolve_downloadable_artifact_path(signature_artifact)
    public_key_path = _resolve_downloadable_artifact_path(public_key_artifact)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    required_files = {"manifest.json", "manifest.sig", "public_key.pem", "run.json", "timeline.json", "steps.json", "labs.json", "README.txt"}
    canonical_definition = manifest.get("canonical_files") or {}
    manifest_payload = _canonical_json_bytes(_manifest_signature_payload(manifest))
    expected_manifest_sha256 = manifest.get("manifest_sha256")
    calculated_manifest_sha256 = _sha256_bytes(manifest_payload)
    manifest_sha_valid = bool(expected_manifest_sha256) and expected_manifest_sha256 == calculated_manifest_sha256
    signature_valid = False
    signature_error = None

    with zipfile.ZipFile(bundle_path, "r") as archive:
        names = set(archive.namelist())
        missing_canonical = sorted(required_files - names)
        canonical_file_checks = []
        artifact_checks = []
        verified_artifacts = 0
        bundle_manifest = json.loads(archive.read("manifest.json").decode("utf-8")) if "manifest.json" in names else None
        public_key_bytes = archive.read("public_key.pem") if "public_key.pem" in names else public_key_path.read_bytes()
        signature_text = archive.read("manifest.sig").decode("utf-8") if "manifest.sig" in names else signature_path.read_text(encoding="utf-8")

        try:
            signature_bytes = base64.b64decode(signature_text.strip())
            public_key = load_pem_public_key(public_key_bytes)
            public_key.verify(signature_bytes, manifest_payload)
            signature_valid = True
        except (InvalidSignature, ValueError, TypeError) as exc:
            signature_error = str(exc) or "invalid_signature"

        for canonical_name in sorted(required_files):
            expected = canonical_definition.get(canonical_name) or {}
            if canonical_name not in names:
                canonical_file_checks.append(
                    {
                        "name": canonical_name,
                        "verified": False,
                        "reason": "missing_from_bundle",
                        "expected_sha256": expected.get("sha256"),
                        "expected_size_bytes": expected.get("size_bytes"),
                        "actual_sha256": None,
                        "actual_size_bytes": None,
                    }
                )
                continue

            entry_bytes = archive.read(canonical_name)
            if canonical_name == "manifest.json":
                actual_sha256 = calculated_manifest_sha256
                actual_size_bytes = len(manifest_payload)
            else:
                actual_sha256 = _sha256_bytes(entry_bytes)
                actual_size_bytes = len(entry_bytes)

            expected_sha256 = expected.get("sha256")
            expected_size_bytes = expected.get("size_bytes")
            verified = bool(expected_sha256) and expected_sha256 == actual_sha256 and (
                expected_size_bytes is None or expected_size_bytes == actual_size_bytes
            )
            canonical_file_checks.append(
                {
                    "name": canonical_name,
                    "verified": verified,
                    "reason": None if verified else "canonical_mismatch",
                    "expected_sha256": expected_sha256,
                    "expected_size_bytes": expected_size_bytes,
                    "actual_sha256": actual_sha256,
                    "actual_size_bytes": actual_size_bytes,
                }
            )

        for artifact in manifest.get("artifacts", []):
            if not artifact.get("included"):
                artifact_checks.append(
                    {
                        "artifact_id": artifact.get("artifact_id"),
                        "artifact_type": artifact.get("artifact_type"),
                        "included": False,
                        "verified": True,
                        "reason": artifact.get("reason"),
                    }
                )
                continue

            relative_path = artifact.get("relative_path")
            if not relative_path or relative_path not in names:
                artifact_checks.append(
                    {
                        "artifact_id": artifact.get("artifact_id"),
                        "artifact_type": artifact.get("artifact_type"),
                        "included": True,
                        "verified": False,
                        "reason": "missing_from_bundle",
                    }
                )
                continue

            bundle_entry_sha256 = hashlib.sha256(archive.read(relative_path)).hexdigest()
            manifest_sha256 = artifact.get("sha256")
            bundle_match = bool(manifest_sha256) and bundle_entry_sha256 == manifest_sha256
            source_match = None
            source_reason = None
            original_path = artifact.get("original_path")

            if original_path:
                original_file = Path(original_path)
                if not _is_path_within_root(original_file, APP_ROOT):
                    source_reason = "outside_allowed_root"
                elif not original_file.exists() or not original_file.is_file():
                    source_reason = "artifact_not_found"
                else:
                    source_match = _sha256_file(original_file) == manifest_sha256

            verified = bundle_match and (source_match is None or source_match is True)
            if verified:
                verified_artifacts += 1

            artifact_checks.append(
                {
                    "artifact_id": artifact.get("artifact_id"),
                    "artifact_type": artifact.get("artifact_type"),
                    "included": True,
                    "verified": verified,
                    "relative_path": relative_path,
                    "manifest_sha256": manifest_sha256,
                    "bundle_entry_sha256": bundle_entry_sha256,
                    "bundle_match": bundle_match,
                    "source_match": source_match,
                    "source_reason": source_reason,
                    }
                )

    server_key_info = _get_evidence_public_key_info(create_if_missing=False)
    public_key_matches_server = None
    trust_mode = "bundle_embedded_public_key"
    if server_key_info:
        public_key_matches_server = server_key_info.get("public_key_fingerprint") == manifest.get("public_key_fingerprint")
        if public_key_matches_server:
            trust_mode = "server_managed_key"

    manifest_artifact_match = bundle_manifest == manifest
    signature_artifact_match = signature_path.read_text(encoding="utf-8") == signature_text
    public_key_artifact_match = public_key_path.read_text(encoding="utf-8") == public_key_bytes.decode("utf-8")
    integrity_valid = (
        manifest_sha_valid
        and len(missing_canonical) == 0
        and all(item.get("verified") for item in canonical_file_checks)
        and all(item.get("verified") for item in artifact_checks)
        and manifest_artifact_match
        and signature_artifact_match
        and public_key_artifact_match
    )
    verification_payload = {
        "run_id": run_id,
        "verified": signature_valid and integrity_valid,
        "export_timestamp": latest_export["export_timestamp"],
        "bundle_artifact": bundle_artifact,
        "manifest_artifact": manifest_artifact,
        "signature_artifact": signature_artifact,
        "public_key_artifact": public_key_artifact,
        "bundle_sha256": _sha256_file(bundle_path),
        "manifest_sha256": manifest.get("manifest_sha256"),
        "manifest_file_sha256": _sha256_file(manifest_path),
        "canonical_files": sorted(required_files),
        "missing_canonical_files": missing_canonical,
        "canonical_file_checks": canonical_file_checks,
        "artifact_checks": artifact_checks,
        "artifact_count": len(manifest.get("artifacts", [])),
        "included_count": len([artifact for artifact in manifest.get("artifacts", []) if artifact.get("included")]),
        "verified_artifact_count": verified_artifacts,
        "missing_count": manifest.get("missing_count", 0),
        "warning_count": manifest.get("warning_count", 0),
        "bundle_version": manifest.get("bundle_version"),
        "signature_valid": signature_valid,
        "integrity_valid": integrity_valid,
        "signing_algorithm": manifest.get("signing_algorithm"),
        "public_key_fingerprint": manifest.get("public_key_fingerprint"),
        "public_key_matches_server": public_key_matches_server,
        "trust_mode": trust_mode,
        "signature_error": signature_error,
        "manifest_sha_valid": manifest_sha_valid,
        "manifest_artifact_match": manifest_artifact_match,
        "signature_artifact_match": signature_artifact_match,
        "public_key_artifact_match": public_key_artifact_match,
    }
    run_manager.add_event(
        run_id,
        "run",
        run_id,
        "evidence_verified",
        "success" if verification_payload["verified"] else "warning",
        "Evidence bundle integrity verified" if verification_payload["verified"] else "Evidence bundle verification found issues",
        {
            "export_timestamp": latest_export["export_timestamp"],
            "verified": verification_payload["verified"],
            "signature_valid": signature_valid,
            "integrity_valid": integrity_valid,
            "trust_mode": trust_mode,
            "public_key_fingerprint": manifest.get("public_key_fingerprint"),
            "missing_canonical_files": missing_canonical,
            "verified_artifact_count": verified_artifacts,
            "included_count": verification_payload["included_count"],
        },
    )
    return verification_payload


def _build_run_completion_payload(run_id: str, status: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    detail = db.get_run_detail(run_id) or {}
    steps = detail.get("steps", [])
    payload = {
        "run_status": status,
        "step_count": len(steps),
        "completed_steps": len([step for step in steps if step.get("status") == "success"]),
        "failed_steps": len([step for step in steps if step.get("status") in {"failed", "error"}]),
        "cancelled_steps": len([step for step in steps if step.get("status") == "cancelled"]),
        "artifact_count": len(detail.get("artifacts", [])),
        "lab_count": len(detail.get("labs", [])),
    }
    if extra:
        payload.update({key: value for key, value in extra.items() if value is not None})
    return payload


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
        await execution_queue.mark_cancelled(execution_id, {"status": "cancelled", "run_id": run_id, "step_id": step_id})
        db.create_execution(execution_id, item["user_id"], module, script, parameters, run_id=run_id, step_id=step_id)
        db.update_execution(execution_id, "cancelled", error_message="Execution cancelled before start")
        run_manager.update_step(step_id, run_id, status="cancelled", completed_at=datetime.utcnow().isoformat(), error_message="Execution cancelled before start")
        completion_payload = _build_run_completion_payload(
            run_id,
            "cancelled",
            {"execution_id": execution_id, "step_id": step_id, "module": module, "script": script, "reason": "cancelled_before_start"},
        )
        run_manager.mark_run_finished(run_id, "cancelled", "Run cancelled before script start", metadata=completion_payload)
        await _emit_and_persist(run_id, "run", run_id, "cancelled", "cancelled", f"{module}/{script} cancelled before start", completion_payload)
        await _emit_and_persist(run_id, "step", step_id, "cancelled", "cancelled", f"{module}/{script} cancelled before start")
        return

    run_manager.mark_run_started(run_id, f"Running script {module}/{script}")
    run_manager.update_step(step_id, run_id, status="running", started_at=datetime.utcnow().isoformat(), message=f"Script step started: {module}/{script}")
    await _emit_and_persist(run_id, "step", step_id, "status_changed", "running", f"Running {module}/{script}", {"module": module, "script": script})

    if not script_file.exists():
        error_message = f"Script not found: {script_file}"
        await execution_queue.mark_failed(execution_id, error_message)
        run_manager.update_step(step_id, run_id, status="failed", completed_at=datetime.utcnow().isoformat(), error_message=error_message)
        completion_payload = _build_run_completion_payload(
            run_id,
            "failed",
            {"execution_id": execution_id, "step_id": step_id, "module": module, "script": script, "reason": error_message},
        )
        run_manager.mark_run_finished(run_id, "failed", error_message, metadata=completion_payload)
        await _emit_and_persist(run_id, "run", run_id, "completed", "failed", error_message, completion_payload)
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
    await execution_queue.mark_process_launching(execution_id)
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

    if _is_run_cancelling(run_id):
        try:
            process.terminate()
        except ProcessLookupError:
            pass

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
    cancelled = (control.get("cancel_requested") and process.returncode != 0) or process.returncode in {-15, -9, 130}
    result_status = "cancelled" if cancelled else "success" if process.returncode == 0 else "failed"

    stdout_artifact = _write_runtime_artifact(run_id, step_id, "stdout", output)
    stderr_artifact = _write_runtime_artifact(run_id, step_id, "stderr", "\n".join(stderr_chunks))
    if stdout_artifact:
        run_manager.add_artifact(
            run_id,
            "stdout_log",
            stdout_artifact,
            label=f"stdout {module}/{script}",
            metadata=_build_runtime_artifact_metadata(
                stdout_artifact,
                "stdout_log",
                result_status,
                step_status=result_status,
                step_id=step_id,
                execution_id=execution_id,
            ),
        )
    if stderr_artifact:
        run_manager.add_artifact(
            run_id,
            "stderr_log",
            stderr_artifact,
            label=f"stderr {module}/{script}",
            metadata=_build_runtime_artifact_metadata(
                stderr_artifact,
                "stderr_log",
                result_status,
                step_status=result_status,
                step_id=step_id,
                execution_id=execution_id,
            ),
        )

    if cancelled:
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
        completion_payload = _build_run_completion_payload(
            run_id,
            result_status,
            {
                "execution_id": execution_id,
                "step_id": step_id,
                "module": module,
                "script": script,
                "exit_code": process.returncode,
                "duration": duration,
                "reason": "Execution cancelled",
            },
        )
        run_manager.mark_run_finished(run_id, result_status, f"Script {module}/{script} cancelled", metadata=completion_payload)
        await _emit_and_persist(
            run_id,
            "run",
            run_id,
            "cancelled",
            result_status,
            f"Script {module}/{script} cancelled",
            completion_payload,
        )
        await _emit_and_persist(run_id, "step", step_id, "cancelled", result_status, f"{module}/{script} cancelled", {"exit_code": process.returncode, "duration": duration})
    elif process.returncode == 0:
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
        completion_payload = _build_run_completion_payload(
            run_id,
            result_status,
            {
                "execution_id": execution_id,
                "step_id": step_id,
                "module": module,
                "script": script,
                "exit_code": process.returncode,
                "duration": duration,
            },
        )
        run_manager.mark_run_finished(run_id, result_status, f"Script {module}/{script} completed", metadata=completion_payload)
        if control.get("cancel_requested"):
            await _emit_and_persist(run_id, "run", run_id, "cancel_requested", "success", "Cancel requested after process completed", {"forced": False})
        await _emit_and_persist(
            run_id,
            "run",
            run_id,
            "completed",
            result_status,
            f"Script {module}/{script} completed",
            completion_payload,
        )
        await _emit_and_persist(run_id, "step", step_id, "completed", result_status, f"{module}/{script} completed", {"exit_code": process.returncode, "duration": duration})
    else:
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
        completion_payload = _build_run_completion_payload(
            run_id,
            result_status,
            {
                "execution_id": execution_id,
                "step_id": step_id,
                "module": module,
                "script": script,
                "exit_code": process.returncode,
                "duration": duration,
                "reason": error_output,
            },
        )
        run_manager.mark_run_finished(run_id, result_status, f"Script {module}/{script} failed", metadata=completion_payload)
        await _emit_and_persist(
            run_id,
            "run",
            run_id,
            "completed",
            result_status,
            f"Script {module}/{script} failed",
            completion_payload,
        )
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
            completion_payload = _build_run_completion_payload(
                item["run_id"],
                "failed",
                {
                    "execution_id": item["execution_id"],
                    "step_id": item["step_id"],
                    "module": item["module"],
                    "script": item["script"],
                    "reason": str(exc),
                },
            )
            run_manager.mark_run_finished(item["run_id"], "failed", f"Execution error: {exc}", metadata=completion_payload)
            await _emit_and_persist(item["run_id"], "run", item["run_id"], "completed", "failed", str(exc), completion_payload)
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
            completion_payload = _build_run_completion_payload(
                run_id,
                final_status,
                {"flow_id": flow_id, "cancelled_at_step": result.get("cancelled_at_step"), "cause": result.get("cause")},
            )
            run_manager.mark_run_finished(run_id, final_status, f"Flow {flow_id} completed", metadata=completion_payload)
            await _emit_and_persist(
                run_id,
                "run",
                run_id,
                "cancelled" if final_status == "cancelled" else "completed",
                final_status,
                f"Flow {flow_id} completed",
                completion_payload,
            )
        except Exception as exc:
            completion_payload = _build_run_completion_payload(run_id, "failed", {"flow_id": flow_id, "cause": str(exc)})
            run_manager.mark_run_finished(run_id, "failed", f"Flow {flow_id} failed", metadata=completion_payload)
            await _emit_and_persist(run_id, "run", run_id, "completed", "failed", str(exc), completion_payload)
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


def _legacy_execution_status(status: Optional[str]) -> Optional[str]:
    return "error" if status == "failed" else status


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


async def _wait_for_flow_task_drain(run_id: str, task: Optional[asyncio.Task]) -> Dict[str, Any]:
    if not task:
        return db.get_run_detail(run_id) or {}

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
    except Exception as exc:
        logger.warning("Flow task raised while draining during cancellation", extra={"run_id": run_id, "error": str(exc)})
        await _emit_and_persist(
            run_id,
            "run",
            run_id,
            "task_error",
            "failed",
            "Flow task raised while cancellation was in progress",
            {"error": str(exc)},
        )

    return db.get_run_detail(run_id) or {}


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
        "version": "2.8.2",
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


@app.get("/evidence/public-key")
async def get_evidence_public_key(
    download: bool = False,
    current_user: Dict[str, Any] = Depends(auth_manager.get_current_user),
):
    key_info = _get_evidence_public_key_info(create_if_missing=True)
    if not key_info:
        raise HTTPException(status_code=500, detail="Evidence public key is unavailable")
    if download:
        return FileResponse(
            path=key_info["path"],
            media_type="text/plain",
            filename=Path(key_info["path"]).name,
        )
    return key_info


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
    run = db.get_run_detail(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if current_user["role"] != "admin" and run.get("user_id") != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    return {"run_id": run_id, "events": db.get_run_events(run_id), "artifacts": _serialize_artifacts(run.get("artifacts", []), run)}


@app.get("/runs/{run_id}/artifacts/{artifact_id}/preview")
async def get_run_artifact_preview(run_id: str, artifact_id: str, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    run = db.get_run_detail(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if current_user["role"] != "admin" and run.get("user_id") != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    artifact = next((item for item in run.get("artifacts", []) if item.get("id") == artifact_id), None)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return _build_artifact_preview_payload(run_id, artifact, run)


@app.get("/runs/{run_id}/artifacts/{artifact_id}/download")
async def download_run_artifact(run_id: str, artifact_id: str, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    run = db.get_run_detail(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if current_user["role"] != "admin" and run.get("user_id") != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    artifact = _find_run_artifact(run, artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    safe_path = _resolve_downloadable_artifact_path(artifact)
    serialized = _serialize_artifact(artifact, run)
    return FileResponse(
        path=safe_path,
        media_type=(serialized.get("metadata") or {}).get("content_type") or "application/octet-stream",
        filename=safe_path.name,
    )


@app.get("/runs/{run_id}/export")
async def export_run_evidence(run_id: str, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    run = db.get_run_detail(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if current_user["role"] != "admin" and run.get("user_id") != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Access denied")

    export_payload = _create_run_evidence_export(run_id)
    bundle_path = Path(export_payload["bundle_path"])
    if not bundle_path.exists():
        raise HTTPException(status_code=500, detail="Evidence bundle was not created")

    return FileResponse(
        path=bundle_path,
        media_type="application/zip",
        filename=bundle_path.name,
    )


@app.get("/runs/{run_id}/export/verify")
async def verify_run_evidence_export(run_id: str, current_user: Dict[str, Any] = Depends(auth_manager.get_current_user)):
    run = db.get_run_detail(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if current_user["role"] != "admin" and run.get("user_id") != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    return _verify_run_evidence_export(run_id)


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
        completion_payload = _build_run_completion_payload(run_id, "cancelled", {"reason": "cancelled_before_execution"})
        run_manager.mark_run_finished(run_id, "cancelled", "Run cancelled before execution", metadata=completion_payload)
        await _emit_and_persist(run_id, "run", run_id, "cancelled", "cancelled", "Run cancelled before execution", completion_payload)
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
        updated = await _wait_for_flow_task_drain(run_id, control.get("task"))
        return {
            "run_id": run_id,
            "status": updated.get("status", "cancelling"),
            "message": "Flow cancellation requested",
            "cancel_mode": "graceful_then_kill",
            "grace_period_seconds": CANCEL_GRACE_SECONDS,
        }

    if run.get("run_type") == "lab_session":
        completion_payload = _build_run_completion_payload(run_id, "cancelled", {"cancelled": True, "reason": "lab_cancellation_requested"})
        run_manager.mark_run_finished(run_id, "cancelled", "Lab cancellation requested", metadata=completion_payload)
        await _emit_and_persist(run_id, "run", run_id, "cancelled", "cancelled", "Lab cancellation requested", completion_payload)
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
        legacy_status = _legacy_execution_status(step.get("status") if step else status.get("status"))
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
