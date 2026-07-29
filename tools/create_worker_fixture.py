#!/usr/bin/env python3
"""Create a signed, offline JobSpec fixture for the BOFA OCI worker."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sys

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
from core.execution.signing import load_or_create_signing_key, sign_manifest


_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a signed BOFA worker fixture")
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--image-reference", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    if not args.image_reference.strip() or "@" in args.image_reference:
        parser.error("--image-reference must be a repository or tag without a digest")
    if not _DIGEST_PATTERN.fullmatch(args.image_digest):
        parser.error("--image-digest must be an exact lowercase sha256 digest")

    output_dir = args.output_dir.resolve()
    job_path = output_dir / "job.json"
    control_private_path = output_dir / "control-plane-private.pem"
    control_public_path = output_dir / "control-plane-public.pem"
    receipt_private_path = output_dir / "worker-receipt-private.pem"
    receipt_public_path = output_dir / "worker-receipt-public.pem"
    generated_paths = (
        job_path,
        control_private_path,
        control_public_path,
        receipt_private_path,
        receipt_public_path,
    )
    if not args.force and any(path.exists() for path in generated_paths):
        parser.error("output files already exist; choose a fresh directory or pass --force")
    output_dir.mkdir(parents=True, exist_ok=True)

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
            "id": "grant_oci_worker_fixture",
            "subject_id": "fixture-user",
            "project_id": "fixture-project",
            "environment_id": "fixture-environment",
            "issued_at": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(minutes=10)).isoformat(),
            "scopes": [],
            "capabilities": [ExecutionCapability.EVIDENCE_READ.value],
            "limits": limits.to_dict(),
            "approval_id": "approval_oci_worker_fixture",
            "approved_by": "fixture-human-reviewer",
        }
    )
    profile = ExecutionProfile(
        id="oci-worker-fixture",
        backend=ExecutionBackend.OCI,
        capabilities=(ExecutionCapability.EVIDENCE_READ,),
        limits=limits,
        network_mode="none",
        image=args.image_reference,
        image_digest=args.image_digest,
        ephemeral=True,
        enabled=True,
    )
    request = ExecutionRequest.from_dict(
        {
            "subject_id": grant.subject_id,
            "action": "run_script:forensics/hash_calculator",
            "profile_id": profile.id,
            "required_capabilities": [ExecutionCapability.EVIDENCE_READ.value],
            "project_id": grant.project_id,
            "environment_id": grant.environment_id,
            "approval_id": grant.approval_id,
            "requested_duration_seconds": 30,
            "requested_steps": 1,
            "metadata": {
                "run_type": "script",
                "module": "forensics",
                "script": "hash_calculator",
                "parameters": {
                    "input": "BOFA OCI worker proof",
                    "algorithm": "sha256",
                },
            },
        }
    )
    decision = ExecutionPolicyEngine().evaluate(request, grant, profile, now=now)
    if not decision.allowed:
        raise RuntimeError(f"Fixture was denied by policy: {decision.reasons}")

    manifest = ExecutionManifest.build(
        request,
        grant,
        profile,
        decision.policy_version,
        now=now,
    )
    private_key = load_or_create_signing_key(
        control_private_path,
        control_public_path,
    )
    load_or_create_signing_key(receipt_private_path, receipt_public_path)
    envelope = sign_manifest(manifest.to_dict(), private_key)
    job_path.write_text(
        json.dumps(envelope, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "job": str(job_path),
                "trusted_public_key": str(control_public_path),
                "manifest_sha256": envelope["manifest"]["sha256"],
                "private_key_for_fixture_only": str(control_private_path),
                "receipt_verification_key": str(receipt_public_path),
                "receipt_private_key_for_fixture_only": str(receipt_private_path),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
