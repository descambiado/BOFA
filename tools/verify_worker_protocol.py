#!/usr/bin/env python3
"""Smoke verification for signed BOFA worker jobs."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import uuid

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.execution import (
    AuthorizationGrant,
    ExecutionBackend,
    ExecutionCapability,
    ExecutionLimits,
    ExecutionManifest,
    ExecutionPolicyEngine,
    ExecutionProfile,
    ExecutionRequest,
)
from core.execution.signing import (
    load_or_create_signing_key,
    public_key_pem,
    sign_manifest,
    verify_envelope,
)
from worker import WorkerRuntime


NOW = datetime.now(timezone.utc)
VERIFY_ROOT = _ROOT / "data" / ".verify_worker_protocol" / uuid.uuid4().hex


def _grant():
    return AuthorizationGrant.from_dict(
        {
            "id": "grant_worker_test",
            "subject_id": "42",
            "project_id": "project_worker_test",
            "environment_id": "env_worker_test",
            "issued_at": (NOW - timedelta(minutes=1)).isoformat(),
            "expires_at": (NOW + timedelta(hours=1)).isoformat(),
            "scopes": [{"kind": "host", "value": "authorized.example"}],
            "capabilities": ["network_active", "container"],
            "limits": {
                "max_duration_seconds": 300,
                "max_output_bytes": 1_000_000,
                "max_steps": 5,
                "cpu_cores": 1,
                "memory_mb": 512,
            },
            "approval_id": "approval_worker_test",
            "approved_by": "human_reviewer",
        }
    )


def _profile():
    return ExecutionProfile(
        id="remote-test",
        backend=ExecutionBackend.REMOTE,
        capabilities=(ExecutionCapability.NETWORK_ACTIVE, ExecutionCapability.CONTAINER),
        limits=ExecutionLimits(
            max_duration_seconds=300,
            max_output_bytes=1_000_000,
            max_steps=5,
            cpu_cores=1,
            memory_mb=512,
        ),
        network_mode="restricted",
        image="ghcr.io/descambiado/bofa-worker",
        image_digest=f"sha256:{'a' * 64}",
        ephemeral=True,
        enabled=True,
    )


def _request(parameter_target: str = "https://authorized.example"):
    return ExecutionRequest.from_dict(
        {
            "subject_id": "42",
            "action": "run_script:web/param_finder",
            "profile_id": "remote-test",
            "required_capabilities": ["network_active"],
            "project_id": "project_worker_test",
            "environment_id": "env_worker_test",
            "target": "https://authorized.example",
            "approval_id": "approval_worker_test",
            "requested_duration_seconds": 60,
            "requested_steps": 1,
            "metadata": {
                "run_type": "script",
                "module": "web",
                "script": "param_finder",
                "parameters": {"url": parameter_target, "json": True},
            },
        }
    )


def _signed_envelope(request=None):
    request = request or _request()
    grant = _grant()
    profile = _profile()
    decision = ExecutionPolicyEngine().evaluate(request, grant, profile, now=NOW)
    assert decision.allowed, decision.reasons
    manifest = ExecutionManifest.build(request, grant, profile, decision.policy_version, now=NOW)
    private_key = load_or_create_signing_key(
        VERIFY_ROOT / "private.pem",
        VERIFY_ROOT / "public.pem",
    )
    return sign_manifest(manifest.to_dict(), private_key), public_key_pem(private_key)


def _runtime(public_key, executor=None):
    return WorkerRuntime(
        worker_id="worker_test",
        trusted_public_key_pem=public_key,
        capabilities=["network_active", "container"],
        script_executor=executor,
    )


def _check_signed_job_is_accepted() -> None:
    envelope, public_key = _signed_envelope()
    inspection = _runtime(public_key).inspect(envelope, now=NOW)
    assert inspection["accepted"], inspection
    assert all(inspection["checks"].values())


def _check_tampering_and_wrong_keys_fail() -> None:
    envelope, public_key = _signed_envelope()
    envelope["manifest"]["request"]["target"] = "https://outside.example"
    verified, code = verify_envelope(envelope, public_key)
    assert not verified and code == "manifest_digest_invalid"

    clean_envelope, _ = _signed_envelope()
    wrong_key = load_or_create_signing_key(
        VERIFY_ROOT / "wrong-private.pem",
        VERIFY_ROOT / "wrong-public.pem",
    )
    verified, code = verify_envelope(clean_envelope, public_key_pem(wrong_key))
    assert not verified and code == "key_id_mismatch"


def _check_worker_revalidates_target_binding() -> None:
    envelope, public_key = _signed_envelope(_request(parameter_target="https://outside.example"))
    inspection = _runtime(public_key).inspect(envelope, now=NOW)
    assert not inspection["accepted"]
    assert not inspection["checks"]["target_binding"]


def _check_worker_rejects_unsafe_adapter_identifiers() -> None:
    request = _request()
    unsafe_request = ExecutionRequest.from_dict(
        {
            **request.to_dict(),
            "metadata": {
                **request.to_dict()["metadata"],
                "module": "../web",
            },
        }
    )
    envelope, public_key = _signed_envelope(unsafe_request)
    inspection = _runtime(public_key).inspect(envelope, now=NOW)
    assert not inspection["accepted"]
    assert not inspection["checks"]["adapter_contract"]


def _check_expired_jobs_fail() -> None:
    envelope, public_key = _signed_envelope()
    inspection = _runtime(public_key).inspect(envelope, now=NOW + timedelta(minutes=2))
    assert not inspection["accepted"]
    assert not inspection["checks"]["not_expired"]


def _check_execution_receipt_hashes_output() -> None:
    envelope, public_key = _signed_envelope()

    def fake_executor(module, script, parameters):
        assert (module, script) == ("web", "param_finder")
        assert parameters["url"] == "https://authorized.example"
        return {"status": "success", "exit_code": 0, "stdout": "evidence", "stderr": ""}

    runtime = _runtime(public_key, executor=fake_executor)
    receipt = runtime.execute(envelope)
    assert receipt["status"] == "success"
    assert receipt["executed"] is True
    assert len(receipt["stdout_sha256"]) == 64
    assert receipt["manifest_sha256"] == envelope["manifest"]["sha256"]
    replay = runtime.execute(envelope)
    assert replay["status"] == "denied"
    assert replay["reason"] == "replay_detected"


def _check_output_quota_is_enforced() -> None:
    envelope, public_key = _signed_envelope()

    def oversized_executor(module, script, parameters):
        return {
            "status": "success",
            "exit_code": 0,
            "stdout": "x" * 1_000_001,
            "stderr": "",
        }

    receipt = _runtime(public_key, executor=oversized_executor).execute(envelope)
    assert receipt["status"] == "failed"
    assert receipt["error"] == "output_limit_exceeded"
    assert receipt["output_limit_bytes"] == 1_000_000


def main() -> int:
    checks = [
        ("signed remote jobs are accepted by a pinned worker", _check_signed_job_is_accepted),
        ("manifest tampering and untrusted keys fail closed", _check_tampering_and_wrong_keys_fail),
        ("workers revalidate script target binding", _check_worker_revalidates_target_binding),
        ("workers reject unsafe adapter identifiers", _check_worker_rejects_unsafe_adapter_identifiers),
        ("expired jobs cannot execute", _check_expired_jobs_fail),
        ("worker receipts hash output and reject replay", _check_execution_receipt_hashes_output),
        ("worker receipts enforce the effective output quota", _check_output_quota_is_enforced),
    ]
    print("BOFA Worker Protocol Verification")
    print("=" * 40)
    for label, check in checks:
        check()
        print(f"[OK] {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
