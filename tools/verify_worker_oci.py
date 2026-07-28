#!/usr/bin/env python3
"""Verify the OCI worker image contract and an optional container receipt."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
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
from core.execution.signing import load_or_create_signing_key, public_key_pem, sign_manifest
from worker import WorkerRuntime
from worker.adapter_executor import OCIAdapterExecutor
from worker.catalog import CATALOG_SCHEMA, load_worker_catalog
from worker.entrypoint import RECEIPT_SCHEMA, _write_receipt


IMAGE_REFERENCE = "ghcr.io/descambiado/bofa-worker"
IMAGE_DIGEST = f"sha256:{'a' * 64}"
EXPECTED_HASH = hashlib.sha256(b"BOFA OCI worker proof").hexdigest()
VERIFY_ROOT = _ROOT / "data" / ".verify_worker_oci"


def _fixture_directory() -> Path:
    path = VERIFY_ROOT / uuid.uuid4().hex
    path.mkdir(parents=True, exist_ok=False)
    return path


def _signed_fixture(root: Path):
    now = datetime.now(timezone.utc)
    limits = ExecutionLimits(
        max_duration_seconds=60,
        max_output_bytes=64 * 1024,
        max_steps=1,
        cpu_cores=1,
        memory_mb=256,
    )
    grant = AuthorizationGrant.from_dict(
        {
            "id": "grant_oci_verify",
            "subject_id": "verify-user",
            "project_id": "verify-project",
            "environment_id": "verify-environment",
            "issued_at": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
            "scopes": [],
            "capabilities": ["evidence_read"],
            "limits": limits.to_dict(),
            "approval_id": "approval_oci_verify",
            "approved_by": "verify-human",
        }
    )
    profile = ExecutionProfile(
        id="oci-verify",
        backend=ExecutionBackend.OCI,
        capabilities=(ExecutionCapability.EVIDENCE_READ,),
        limits=limits,
        network_mode="none",
        image=IMAGE_REFERENCE,
        image_digest=IMAGE_DIGEST,
        ephemeral=True,
        enabled=True,
    )
    request = ExecutionRequest.from_dict(
        {
            "subject_id": grant.subject_id,
            "action": "run_script:forensics/hash_calculator",
            "profile_id": profile.id,
            "required_capabilities": ["evidence_read"],
            "project_id": grant.project_id,
            "environment_id": grant.environment_id,
            "approval_id": grant.approval_id,
            "requested_duration_seconds": 30,
            "requested_steps": 1,
            "metadata": {
                "run_type": "script",
                "module": "forensics",
                "script": "hash_calculator",
                "parameters": {"input": "BOFA OCI worker proof", "algorithm": "sha256"},
            },
        }
    )
    decision = ExecutionPolicyEngine().evaluate(request, grant, profile, now=now)
    assert decision.allowed, decision.reasons
    manifest = ExecutionManifest.build(request, grant, profile, decision.policy_version, now=now)
    private_key = load_or_create_signing_key(root / "private.pem", root / "public.pem")
    return sign_manifest(manifest.to_dict(), private_key), public_key_pem(private_key)


def _verify_runtime_identity_and_catalog() -> None:
    catalog = load_worker_catalog(_ROOT / "worker" / "catalog.json")
    assert CATALOG_SCHEMA == "bofa.worker-catalog/v1"
    assert [item.value for item in catalog.capabilities] == ["evidence_read"]
    assert catalog.network_modes == ("none",)
    assert catalog.scripts == ("forensics/hash_calculator",)
    assert not catalog.flows

    directory = _fixture_directory()
    envelope, public_key = _signed_fixture(directory)

    def executor(module, script, parameters, timeout_seconds, max_output_bytes):
        assert f"{module}/{script}" == "forensics/hash_calculator"
        assert parameters["input"] == "BOFA OCI worker proof"
        assert timeout_seconds > 0
        assert max_output_bytes == 64 * 1024
        return {
            "status": "success",
            "exit_code": 0,
            "stdout": f"{EXPECTED_HASH}\n",
            "stderr": "",
        }

    runtime = WorkerRuntime(
        worker_id="oci-verify",
        trusted_public_key_pem=public_key,
        capabilities=catalog.capabilities,
        image_reference=IMAGE_REFERENCE,
        image_digest=IMAGE_DIGEST,
        runtime_network_mode="none",
        allowed_scripts=catalog.scripts,
        allowed_flows=catalog.flows,
        script_executor=executor,
    )
    receipt = runtime.execute(envelope)
    assert receipt["status"] == "success"
    assert receipt["worker_image_digest"] == IMAGE_DIGEST

    wrong_image = WorkerRuntime(
        worker_id="oci-verify",
        trusted_public_key_pem=public_key,
        capabilities=catalog.capabilities,
        image_reference=IMAGE_REFERENCE,
        image_digest=f"sha256:{'b' * 64}",
        runtime_network_mode="none",
        allowed_scripts=catalog.scripts,
        allowed_flows=catalog.flows,
    )
    inspection = wrong_image.inspect(envelope, now=datetime.now(timezone.utc))
    assert not inspection["accepted"]
    assert not inspection["checks"]["image_identity"]


def _verify_container_definition() -> None:
    dockerfile = (_ROOT / "worker" / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^# syntax=docker/dockerfile:1\.7@sha256:[0-9a-f]{64}$", dockerfile, re.MULTILINE)
    assert re.search(r"^FROM python:3\.11-slim-trixie@sha256:[0-9a-f]{64}$", dockerfile, re.MULTILINE)
    assert "USER 65532:65532" in dockerfile
    assert 'ENTRYPOINT ["python", "-m", "worker.entrypoint"]' in dockerfile
    assert "--require-hashes" in dockerfile
    assert "pip uninstall --yes setuptools wheel packaging" in dockerfile
    assert "pip uninstall --yes pip" in dockerfile
    assert "apt-get" not in dockerfile
    assert "curl " not in dockerfile
    assert "scripts/red" not in dockerfile
    assert "COPY --chown=65532:65532 core ./core" not in dockerfile
    assert "COPY --chown=65532:65532 worker ./worker" not in dockerfile
    assert "core/execution ./core/execution" in dockerfile
    assert "COPY --chown=65532:65532 scripts/forensics/hash_calculator.py" in dockerfile

    dockerignore = (_ROOT / "worker" / "Dockerfile.dockerignore").read_text(encoding="utf-8")
    assert dockerignore.splitlines()[0] == "**"
    assert "!core/**" not in dockerignore
    assert "!worker/**" not in dockerignore
    assert "!scripts/**" not in dockerignore
    assert "!scripts/forensics/hash_calculator.py" in dockerignore
    requirements = (_ROOT / "worker" / "requirements.txt").read_text(encoding="utf-8")
    assert requirements.count("--hash=sha256:") == 5
    assert "cffi==2.1.0" in requirements
    assert "pycparser==3.0" in requirements


def _verify_bounded_adapter_executor() -> None:
    root = _fixture_directory()
    script_dir = root / "scripts" / "proof"
    script_dir.mkdir(parents=True)
    (script_dir / "emit.py").write_text(
        "\n".join(
            (
                "import argparse",
                "parser = argparse.ArgumentParser()",
                "parser.add_argument('--bytes', type=int, required=True)",
                "args = parser.parse_args()",
                "print('x' * args.bytes)",
            )
        ),
        encoding="utf-8",
    )
    (script_dir / "sleep.py").write_text(
        "\n".join(
            (
                "import argparse",
                "import time",
                "parser = argparse.ArgumentParser()",
                "parser.add_argument('--seconds', type=int, required=True)",
                "args = parser.parse_args()",
                "time.sleep(args.seconds)",
            )
        ),
        encoding="utf-8",
    )
    executor = OCIAdapterExecutor(root)
    oversized = executor("proof", "emit", {"bytes": 4096}, 5, 1024)
    assert oversized["status"] == "failed"
    assert oversized["error"] == "output_limit_exceeded"
    assert len(oversized["stdout"].encode("utf-8")) <= 1024

    timed_out = executor("proof", "sleep", {"seconds": 5}, 1, 1024)
    assert timed_out["status"] == "failed"
    assert timed_out["error"] == "execution_timeout_exceeded"


def _verify_supply_chain_workflow() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "worker-image.yml").read_text(encoding="utf-8")
    required_fragments = (
        "provenance: mode=max",
        "sbom: true",
        "cosign sign --yes",
        "cosign verify",
        "severity: CRITICAL,HIGH",
        "exit-code: 1",
    )
    assert all(fragment in workflow for fragment in required_fragments)
    assert workflow.count("ignore-unfixed: true") == 2
    uses_lines = [
        line.strip()
        for line in workflow.splitlines()
        if line.strip().startswith("uses:")
    ]
    assert uses_lines
    assert all(re.search(r"@[0-9a-f]{40}(?:\s+#.*)?$", line) for line in uses_lines)


def _verify_receipt_creation_is_exclusive() -> None:
    receipt_path = _fixture_directory() / "receipt.json"
    _write_receipt(receipt_path, {"receipt_schema": RECEIPT_SCHEMA, "status": "success"})
    original = receipt_path.read_bytes()
    try:
        _write_receipt(receipt_path, {"status": "overwritten"})
    except FileExistsError:
        pass
    else:
        raise AssertionError("Worker receipts must not be overwritten")
    assert receipt_path.read_bytes() == original


def _verify_container_receipt(
    receipt_path: Path,
    job_path: Path,
    expected_image_reference: str,
    expected_image_digest: str,
) -> None:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    job = json.loads(job_path.read_text(encoding="utf-8"))
    assert receipt["receipt_schema"] == RECEIPT_SCHEMA
    assert receipt["status"] == "success"
    assert receipt["executed"] is True
    assert receipt["manifest_sha256"] == job["manifest"]["sha256"]
    assert receipt["worker_image"] == expected_image_reference
    assert receipt["worker_image_digest"] == expected_image_digest
    assert receipt["runtime_network_mode"] == "none"
    assert EXPECTED_HASH in receipt["stdout_preview"]
    assert re.fullmatch(r"[0-9a-f]{64}", receipt["stdout_sha256"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the BOFA OCI worker contract")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--job", type=Path)
    parser.add_argument("--expected-image-reference", default=IMAGE_REFERENCE)
    parser.add_argument("--expected-image-digest", default=IMAGE_DIGEST)
    args = parser.parse_args()
    if bool(args.receipt) != bool(args.job):
        parser.error("--receipt and --job must be supplied together")

    checks = [
        ("runtime binds the signed job to image identity and catalog", _verify_runtime_identity_and_catalog),
        ("container definition is minimal and non-root", _verify_container_definition),
        ("OCI adapter kills excessive output and expired execution", _verify_bounded_adapter_executor),
        ("supply-chain workflow scans, attests and signs", _verify_supply_chain_workflow),
        ("receipt creation is one-use and non-overwriting", _verify_receipt_creation_is_exclusive),
    ]
    if args.receipt and args.job:
        checks.append(
            (
                "container receipt proves the expected offline execution",
                lambda: _verify_container_receipt(
                    args.receipt,
                    args.job,
                    args.expected_image_reference,
                    args.expected_image_digest,
                ),
            )
        )

    print("BOFA OCI Worker Verification")
    print("=" * 40)
    for label, check in checks:
        check()
        print(f"[OK] {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
