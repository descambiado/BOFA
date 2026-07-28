#!/usr/bin/env python3
"""Smoke verification for BOFA execution fabric contracts and policy."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.execution import (
    AuthorizationGrant,
    ExecutionBackend,
    ExecutionCapability,
    ExecutionFabric,
    ExecutionLimits,
    ExecutionPolicyEngine,
    ExecutionProfile,
    ExecutionRequest,
)


NOW = datetime(2026, 7, 28, 10, 0, tzinfo=timezone.utc)


def _grant(**overrides):
    payload = {
        "id": "grant_demo",
        "subject_id": "user_demo",
        "project_id": "project_demo",
        "environment_id": "env_demo",
        "issued_at": (NOW - timedelta(minutes=5)).isoformat(),
        "expires_at": (NOW + timedelta(hours=1)).isoformat(),
        "scopes": [{"kind": "host", "value": "example.com", "include_subdomains": True}],
        "capabilities": ["network_passive", "network_active", "evidence_read"],
        "limits": {
            "max_duration_seconds": 600,
            "max_output_bytes": 5_000_000,
            "max_steps": 10,
            "cpu_cores": 1,
            "memory_mb": 512,
        },
        "require_human_approval": True,
        "approval_id": "approval_demo",
        "approved_by": "reviewer_demo",
    }
    payload.update(overrides)
    return AuthorizationGrant.from_dict(payload)


def _request(**overrides):
    payload = {
        "subject_id": "user_demo",
        "action": "run_flow:web_security_review",
        "profile_id": "local-controlled",
        "required_capabilities": ["network_passive"],
        "project_id": "project_demo",
        "environment_id": "env_demo",
        "target": "https://api.example.com/v1/health",
        "approval_id": "approval_demo",
        "requested_duration_seconds": 120,
        "requested_steps": 5,
    }
    payload.update(overrides)
    return ExecutionRequest.from_dict(payload)


def _local_profile():
    return ExecutionFabric().profiles["local-controlled"]


def _check_allowed_manifest() -> None:
    fabric = ExecutionFabric()
    decision = fabric.policy.evaluate(_request(), _grant(), _local_profile(), now=NOW)
    assert decision.allowed, decision.reasons
    result = fabric.preflight(_request().to_dict(), _grant().to_dict(), now=NOW)
    assert result["decision"]["allowed"]
    manifest = result["manifest"]
    assert manifest and len(manifest["sha256"]) == 64
    canonical = {key: value for key, value in manifest.items() if key != "sha256"}
    expected = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    assert manifest["sha256"] == expected


def _check_scope_and_approval_denials() -> None:
    policy = ExecutionPolicyEngine()
    profile = _local_profile()
    outside = policy.evaluate(_request(target="https://example.net"), _grant(), profile, now=NOW)
    assert not outside.allowed and not outside.checks["scope"]
    missing_approval = policy.evaluate(_request(approval_id=None), _grant(), profile, now=NOW)
    assert not missing_approval.allowed and not missing_approval.checks["approval"]
    wildcard = policy.evaluate(
        _request(target="https://anything.invalid"),
        _grant(scopes=[{"kind": "host", "value": "*"}]),
        profile,
        now=NOW,
    )
    assert not wildcard.allowed and not wildcard.checks["scope"]


def _check_identity_time_and_limits() -> None:
    policy = ExecutionPolicyEngine()
    profile = _local_profile()
    wrong_subject = policy.evaluate(_request(subject_id="other"), _grant(), profile, now=NOW)
    assert not wrong_subject.allowed and not wrong_subject.checks["identity"]
    expired = policy.evaluate(
        _request(),
        _grant(expires_at=(NOW - timedelta(seconds=1)).isoformat()),
        profile,
        now=NOW,
    )
    assert not expired.allowed and not expired.checks["grant_time"]
    too_long = policy.evaluate(_request(requested_duration_seconds=601), _grant(), profile, now=NOW)
    assert not too_long.allowed and not too_long.checks["duration"]


def _check_blocked_capabilities() -> None:
    privileged_profile = ExecutionProfile(
        id="dangerous",
        backend=ExecutionBackend.LOCAL,
        capabilities=(ExecutionCapability.PRIVILEGED,),
        limits=ExecutionLimits(),
    )
    decision = ExecutionPolicyEngine().evaluate(
        _request(profile_id="dangerous", required_capabilities=["privileged"]),
        _grant(capabilities=["privileged"]),
        privileged_profile,
        now=NOW,
    )
    assert not decision.allowed and not decision.checks["blocked_capability"]


def _check_remote_image_and_ephemeral_invariants() -> None:
    grant = _grant(capabilities=["network_passive", "container"])
    request = _request(
        profile_id="remote-test",
        required_capabilities=["network_passive", "container"],
    )
    unsafe_profile = ExecutionProfile(
        id="remote-test",
        backend=ExecutionBackend.REMOTE,
        capabilities=(ExecutionCapability.NETWORK_PASSIVE, ExecutionCapability.CONTAINER),
        image="ghcr.io/example/bofa-worker",
        image_digest=None,
        ephemeral=False,
        network_mode="egress",
    )
    decision = ExecutionPolicyEngine().evaluate(request, grant, unsafe_profile, now=NOW)
    assert not decision.allowed
    assert not decision.checks["image_digest"]
    assert not decision.checks["ephemeral"]
    assert not decision.checks["network_mode"]


def _check_evidence_only_and_unknown_profile() -> None:
    fabric = ExecutionFabric()
    grant = _grant(
        scopes=[],
        capabilities=["evidence_read"],
        require_human_approval=False,
        approval_id=None,
        approved_by=None,
    )
    request = _request(
        action="summarize_evidence",
        target=None,
        required_capabilities=["evidence_read"],
        approval_id=None,
    )
    assert fabric.policy.evaluate(request, grant, _local_profile(), now=NOW).allowed
    unknown = fabric.preflight(
        {**request.to_dict(), "profile_id": "missing"},
        grant.to_dict(),
    )
    assert not unknown["decision"]["allowed"] and unknown["manifest"] is None


def main() -> int:
    checks = [
        ("authorized jobs produce a canonical manifest", _check_allowed_manifest),
        ("scope wildcard and missing approvals fail closed", _check_scope_and_approval_denials),
        ("identity grant time and quotas are enforced", _check_identity_time_and_limits),
        ("privileged and cloud mutation capabilities remain blocked", _check_blocked_capabilities),
        ("remote jobs require isolation and pinned images", _check_remote_image_and_ephemeral_invariants),
        ("evidence-only work stays local and unknown profiles fail", _check_evidence_only_and_unknown_profile),
    ]
    print("BOFA Execution Fabric Verification")
    print("=" * 40)
    for label, check in checks:
        check()
        print(f"[OK] {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
