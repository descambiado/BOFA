"""Offline BOFA worker that verifies signed jobs before tool execution."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import threading
from typing import Any, Callable, Dict, Iterable, Mapping, Optional

from core.execution import ExecutionBackend, ExecutionCapability, ExecutionProfile, ExecutionRequest
from core.execution.signing import verify_envelope


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _target_binding_matches(request: ExecutionRequest) -> bool:
    if ExecutionCapability.NETWORK_PASSIVE not in request.required_capabilities and (
        ExecutionCapability.NETWORK_ACTIVE not in request.required_capabilities
    ):
        return True
    metadata = dict(request.metadata)
    if metadata.get("run_type") != "script":
        return bool(request.target)
    parameters = dict(metadata.get("parameters") or {})
    values = [
        str(parameters[key]).strip()
        for key in ("url", "target", "host", "domain", "ip")
        if parameters.get(key) is not None and not isinstance(parameters.get(key), (dict, list))
    ]
    return bool(request.target and values and all(value == request.target for value in values))


def _safe_identifier(value: Any) -> bool:
    return bool(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value))


def _valid_image_digest(value: Any) -> bool:
    return bool(isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value))


def _adapter_contract_matches(request: ExecutionRequest) -> bool:
    metadata = dict(request.metadata)
    run_type = metadata.get("run_type")
    if run_type == "script":
        return (
            _safe_identifier(metadata.get("module"))
            and _safe_identifier(metadata.get("script"))
            and request.requested_steps in {None, 1}
        )
    if run_type == "flow":
        return (
            _safe_identifier(metadata.get("flow_id"))
            and bool(request.target)
            and request.requested_steps is not None
        )
    return False


class WorkerRuntime:
    def __init__(
        self,
        worker_id: str,
        trusted_public_key_pem: bytes,
        capabilities: Iterable[str | ExecutionCapability],
        image_reference: str,
        image_digest: str,
        runtime_network_mode: str,
        allowed_scripts: Iterable[str],
        allowed_flows: Iterable[str],
        script_executor: Optional[Callable[..., Any]] = None,
        flow_executor: Optional[Callable[..., Any]] = None,
        replay_store_path: Optional[str | Path] = None,
    ):
        self.worker_id = worker_id
        self.trusted_public_key_pem = trusted_public_key_pem
        self.capabilities = {ExecutionCapability(value) for value in capabilities}
        self.image_reference = str(image_reference).strip()
        self.image_digest = str(image_digest).strip()
        self.runtime_network_mode = str(runtime_network_mode).strip().lower()
        self.allowed_scripts = {str(value).strip() for value in allowed_scripts}
        self.allowed_flows = {str(value).strip() for value in allowed_flows}
        self.script_executor = script_executor
        self.flow_executor = flow_executor
        self.replay_store_path = Path(replay_store_path) if replay_store_path else None
        self._claimed_jobs: set[str] = set()
        self._claim_lock = threading.Lock()

    def _adapter_allowed(self, request: ExecutionRequest) -> bool:
        metadata = dict(request.metadata)
        if metadata.get("run_type") == "script":
            return f"{metadata.get('module')}/{metadata.get('script')}" in self.allowed_scripts
        if metadata.get("run_type") == "flow":
            return metadata.get("flow_id") in self.allowed_flows
        return False

    def _identity_fields(self) -> Dict[str, str]:
        return {
            "worker_image": self.image_reference,
            "worker_image_digest": self.image_digest,
            "runtime_network_mode": self.runtime_network_mode,
        }

    def _claim_job(self, manifest_sha256: str) -> bool:
        if len(manifest_sha256) != 64 or any(char not in "0123456789abcdef" for char in manifest_sha256):
            return False
        with self._claim_lock:
            if manifest_sha256 in self._claimed_jobs:
                return False
            if self.replay_store_path:
                self.replay_store_path.mkdir(parents=True, exist_ok=True)
                marker = self.replay_store_path / f"{manifest_sha256}.claimed"
                try:
                    descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                except FileExistsError:
                    return False
                else:
                    os.close(descriptor)
            self._claimed_jobs.add(manifest_sha256)
            return True

    def inspect(self, envelope: Mapping[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
        verified, verification_code = verify_envelope(envelope, self.trusted_public_key_pem)
        checks = {"signature": verified}
        reasons = [] if verified else [verification_code]
        manifest = envelope.get("manifest") if isinstance(envelope.get("manifest"), Mapping) else {}
        if not verified:
            return {"accepted": False, "checks": checks, "reasons": reasons}

        try:
            request = ExecutionRequest.from_dict(manifest["request"])
            profile = ExecutionProfile.from_dict(manifest["profile"])
            expires_at = datetime.fromisoformat(str(manifest["expires_at"]).replace("Z", "+00:00"))
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
        except (KeyError, TypeError, ValueError) as exc:
            return {
                "accepted": False,
                "checks": {**checks, "contract": False},
                "reasons": [f"contract_invalid:{exc}"],
            }

        current = now or datetime.now(timezone.utc)
        requested_capabilities = set(request.required_capabilities)
        checks.update(
            {
                "contract": True,
                "not_expired": current < expires_at,
                "remote_backend": profile.backend in {ExecutionBackend.OCI, ExecutionBackend.REMOTE},
                "ephemeral": profile.ephemeral,
                "image_digest": _valid_image_digest(profile.image_digest),
                "image_identity": bool(
                    self.image_reference
                    and _valid_image_digest(self.image_digest)
                    and profile.image == self.image_reference
                    and profile.image_digest == self.image_digest
                ),
                "network_mode": profile.network_mode in {"none", "restricted"},
                "runtime_network_mode": profile.network_mode == self.runtime_network_mode,
                "worker_capabilities": requested_capabilities.issubset(self.capabilities),
                "target_binding": _target_binding_matches(request),
                "adapter_contract": _adapter_contract_matches(request),
                "adapter_allowed": self._adapter_allowed(request),
                "blocked_capabilities": not bool(
                    requested_capabilities
                    & {ExecutionCapability.PRIVILEGED, ExecutionCapability.CLOUD_MUTATION}
                ),
            }
        )
        for key, passed in checks.items():
            if not passed and key != "signature":
                reasons.append(key)
        return {
            "accepted": not reasons,
            "checks": checks,
            "reasons": reasons,
            "request": request.to_dict(),
            "profile": profile.to_dict(),
            "manifest_sha256": manifest.get("sha256"),
        }

    def execute(self, envelope: Mapping[str, Any]) -> Dict[str, Any]:
        inspection = self.inspect(envelope)
        if not inspection["accepted"]:
            return {
                "worker_id": self.worker_id,
                "status": "denied",
                "executed": False,
                "inspection": inspection,
                "completed_at": _utc_timestamp(),
                **self._identity_fields(),
            }
        manifest_sha256 = str(inspection["manifest_sha256"])
        if not self._claim_job(manifest_sha256):
            return {
                "worker_id": self.worker_id,
                "job_id": envelope["manifest"].get("id"),
                "manifest_sha256": manifest_sha256,
                "status": "denied",
                "executed": False,
                "reason": "replay_detected",
                "completed_at": _utc_timestamp(),
                **self._identity_fields(),
            }

        request = inspection["request"]
        metadata = dict(request.get("metadata") or {})
        run_type = metadata.get("run_type")
        expires_at = datetime.fromisoformat(str(envelope["manifest"]["expires_at"]).replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        timeout_seconds = (expires_at - datetime.now(timezone.utc)).total_seconds()
        if timeout_seconds <= 0:
            return {
                "worker_id": self.worker_id,
                "job_id": envelope["manifest"].get("id"),
                "manifest_sha256": inspection["manifest_sha256"],
                "status": "denied",
                "executed": False,
                "reason": "expired_before_execution",
                "completed_at": _utc_timestamp(),
                **self._identity_fields(),
            }
        effective_limits = dict(envelope["manifest"].get("effective_limits") or {})
        max_output_bytes = max(1, int(effective_limits.get("max_output_bytes") or 10 * 1024 * 1024))
        started_at = _utc_timestamp()
        try:
            if run_type == "script":
                result = self._execute_script(metadata, timeout_seconds, max_output_bytes)
            elif run_type == "flow":
                result = self._execute_flow(
                    metadata,
                    request.get("target"),
                    request.get("requested_steps"),
                    timeout_seconds,
                )
            else:
                raise ValueError("Workers currently support script and flow jobs only")
        except Exception as exc:
            return {
                "worker_id": self.worker_id,
                "job_id": envelope["manifest"].get("id"),
                "manifest_sha256": inspection["manifest_sha256"],
                "status": "failed",
                "executed": True,
                "started_at": started_at,
                "completed_at": _utc_timestamp(),
                "error": str(exc),
                **self._identity_fields(),
            }

        stdout = str(result.get("stdout", ""))
        stderr = str(result.get("stderr", ""))
        output_size = len(stdout.encode("utf-8", errors="replace")) + len(
            stderr.encode("utf-8", errors="replace")
        )
        output_limit_exceeded = output_size > max_output_bytes
        return {
            "worker_id": self.worker_id,
            "job_id": envelope["manifest"].get("id"),
            "manifest_sha256": inspection["manifest_sha256"],
            "status": "failed" if output_limit_exceeded else result.get("status", "unknown"),
            "executed": True,
            "started_at": started_at,
            "completed_at": _utc_timestamp(),
            "exit_code": result.get("exit_code"),
            "stdout_sha256": _sha256_text(stdout),
            "stderr_sha256": _sha256_text(stderr),
            "stdout_preview": stdout[:2000],
            "stderr_preview": stderr[:1000],
            "output_bytes": output_size,
            "output_limit_bytes": max_output_bytes,
            "error": "output_limit_exceeded" if output_limit_exceeded else result.get("error"),
            "artifacts": result.get("artifacts", []),
            **self._identity_fields(),
        }

    def _execute_script(
        self,
        metadata: Dict[str, Any],
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> Dict[str, Any]:
        module = metadata.get("module")
        script = metadata.get("script")
        parameters = dict(metadata.get("parameters") or {})
        if not module or not script:
            raise ValueError("Script job requires module and script")
        if self.script_executor:
            return dict(
                self.script_executor(
                    module,
                    script,
                    parameters,
                    timeout_seconds,
                    max_output_bytes,
                )
            )

        from core.engine import get_engine

        result = get_engine().execute_script(
            module_name=module,
            script_name=script,
            parameters=parameters,
            timeout=timeout_seconds,
        )
        return {
            "status": result.status,
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    def _execute_flow(
        self,
        metadata: Dict[str, Any],
        target: Optional[str],
        requested_steps: Optional[int],
        timeout_seconds: float,
    ) -> Dict[str, Any]:
        flow_id = metadata.get("flow_id")
        if not flow_id or not target:
            raise ValueError("Flow job requires flow_id and target")
        if self.flow_executor:
            return dict(self.flow_executor(flow_id, target))

        from flows.flow_runner import load_flow, run_flow

        actual_steps = len(load_flow(flow_id).get("steps", []))
        if not actual_steps or requested_steps != actual_steps:
            raise ValueError(f"Flow step contract mismatch: expected {requested_steps}, catalog has {actual_steps}")
        result = run_flow(flow_id, target, total_timeout_seconds=timeout_seconds)
        return {
            "status": result.get("status"),
            "exit_code": 0 if result.get("status") == "success" else 1,
            "stdout": json.dumps(result.get("report_json") or {}, ensure_ascii=False),
            "stderr": result.get("cause") or "",
            "artifacts": [
                path
                for path in (result.get("report_path"), result.get("report_json_path"))
                if path
            ],
        }
