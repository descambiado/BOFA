#!/usr/bin/env python3
"""Verify the persisted execution grant and signed preflight API contract."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import secrets
import sys
import textwrap
import uuid

_ROOT = Path(__file__).resolve().parent.parent
_VERIFY_ROOT = _ROOT / "data" / ".verify_execution_api" / uuid.uuid4().hex
_VERIFY_ROOT.mkdir(parents=True, exist_ok=True)

os.environ["BOFA_APP_ROOT"] = str(_VERIFY_ROOT)
os.environ["BOFA_DB_PATH"] = str(_VERIFY_ROOT / "bofa.db")
os.environ["BOFA_SCRIPTS_DIR"] = str(_ROOT / "scripts")
os.environ["BOFA_DATA_DIR"] = str(_VERIFY_ROOT / "data")
os.environ["BOFA_LOGS_DIR"] = str(_VERIFY_ROOT / "logs")
os.environ["BOFA_TEMP_DIR"] = str(_VERIFY_ROOT / "temp")
os.environ["BOFA_UPLOADS_DIR"] = str(_VERIFY_ROOT / "uploads")
os.environ["JWT_SECRET"] = secrets.token_urlsafe(48)
os.environ["DOCKER_HOST"] = "tcp://127.0.0.1:9"
os.environ["NO_PROXY"] = "127.0.0.1,localhost"
os.environ.pop("HTTP_PROXY", None)
os.environ.pop("HTTPS_PROXY", None)

for path in (_ROOT, _ROOT / "api"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import main as api_main
from core.execution.signing import verify_envelope


def _admin_user():
    password = f"verify-{uuid.uuid4().hex}"
    user_id = api_main.auth_manager.bootstrap_admin(
        f"owner_{uuid.uuid4().hex[:8]}",
        f"{uuid.uuid4().hex}@example.test",
        password,
    )
    assert user_id
    user = api_main.db.get_user_by_id(user_id)
    assert user
    return {
        "user_id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
    }


async def _check_local_execution_limits(current_user):
    scripts_root = _VERIFY_ROOT / "limit_scripts"
    module_root = scripts_root / "verify"
    module_root.mkdir(parents=True, exist_ok=True)
    (module_root / "oversized.py").write_text(
        textwrap.dedent(
            """
            import time

            for _ in range(20):
                print("x" * 256, flush=True)
                time.sleep(0.01)
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    (module_root / "slow.py").write_text(
        "import time\ntime.sleep(3)\nprint('late')\n",
        encoding="utf-8",
    )
    original_scripts_dir = api_main.SCRIPTS_DIR
    api_main.SCRIPTS_DIR = scripts_root
    try:
        cases = (
            ("oversized", 10, 1024, "exceeded 1024 bytes"),
            ("slow", 1, 4096, "timed out after 1 seconds"),
        )
        for script, timeout_seconds, max_output_bytes, expected_reason in cases:
            run_id = api_main.run_manager.create_run(
                user_id=current_user["user_id"],
                run_type="script",
                source="execution_fabric_verifier",
                requested_action=f"verify_{script}",
                status="queued",
            )
            step_id = api_main.run_manager.create_step(
                run_id,
                "script",
                1,
                "script_1",
                "verify",
                script,
                {},
                {"source": "execution_fabric_verifier"},
            )
            await api_main._execute_script_step(
                {
                    "execution_id": f"exec_{step_id}",
                    "run_id": run_id,
                    "step_id": step_id,
                    "user_id": current_user["user_id"],
                    "module": "verify",
                    "script": script,
                    "parameters": {},
                    "timeout_seconds": timeout_seconds,
                    "max_output_bytes": max_output_bytes,
                }
            )
            detail = api_main.run_manager.get_run(run_id)
            assert detail and detail["status"] == "failed"
            limit_events = [
                event
                for event in detail.get("events", [])
                if event.get("event_type") == "execution_limit_exceeded"
            ]
            assert limit_events
            assert expected_reason in str(limit_events[-1].get("message"))
    finally:
        api_main.SCRIPTS_DIR = original_scripts_dir


async def _exercise_api():
    current_user = _admin_user()
    await _check_local_execution_limits(current_user)
    grant_request = api_main.ExecutionGrantCreateRequest(
        subject_user_id=current_user["user_id"],
        project_id="project_api_test",
        environment_id="env_api_test",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        scopes=[api_main.ScopeRuleRequest(kind="host", value="authorized.example")],
        capabilities=["network_active"],
        limits=api_main.ExecutionLimitsRequest(
            max_duration_seconds=300,
            max_output_bytes=1_000_000,
            max_steps=5,
            cpu_cores=1,
            memory_mb=512,
        ),
    )
    issued = await api_main.create_execution_grant(grant_request, current_user)
    grant = issued["grant"]
    assert issued["status"] == "active"
    assert grant["approved_by"] == current_user["username"]

    job_request = api_main.ExecutionJobCreateRequest(
        grant_id=grant["id"],
        approval_id=grant["approval_id"],
        profile_id="local-controlled",
        run_type="flow",
        requested_action="web security review",
        target="https://authorized.example",
        required_capabilities=["network_active"],
        requested_duration_seconds=120,
        requested_steps=3,
        metadata={"flow_id": "web_security_review"},
    )
    preflight = await api_main.preflight_execution_job(job_request, current_user)
    assert preflight["decision"]["allowed"]
    assert preflight["manifest"]
    assert preflight["manifest"]["effective_limits"]["max_output_bytes"] == 1_000_000
    assert preflight["envelope"]
    verified, code = verify_envelope(preflight["envelope"], api_main.execution_public_key_pem)
    assert verified, code

    passive_request = job_request.model_copy(update={"required_capabilities": ["network_passive"]})
    try:
        await api_main.preflight_execution_job(passive_request, current_user)
    except api_main.HTTPException as exc:
        assert exc.status_code == 400
        assert "network_active" in str(exc.detail)
    else:
        raise AssertionError("Preflight signed a target flow with an undeclared active network capability")

    outside_request = job_request.model_copy(update={"target": "https://outside.example"})
    outside = await api_main.preflight_execution_job(outside_request, current_user)
    assert not outside["decision"]["allowed"]
    assert outside["envelope"] is None

    listed = await api_main.list_execution_grants(current_user)
    assert len(listed) == 1 and listed[0]["id"] == grant["id"]
    revoked = await api_main.revoke_execution_grant(grant["id"], current_user)
    assert revoked["status"] == "revoked"
    inactive = await api_main.preflight_execution_job(job_request, current_user)
    assert inactive["decision"]["code"] == "grant_inactive"
    return grant["id"]


def _check_routes() -> None:
    paths = {route.path for route in api_main.app.routes}
    expected = {
        "/execution/capabilities",
        "/execution/trust",
        "/execution/grants",
        "/execution/preflight",
        "/execution/jobs",
        "/ai/providers",
        "/ai/plan",
    }
    assert expected.issubset(paths), expected - paths


def main() -> int:
    print("BOFA Execution API Verification")
    print("=" * 40)
    grant_id = asyncio.run(_exercise_api())
    print("[OK] local script adapter enforces output quota and total timeout")
    print(f"[OK] persisted grant {grant_id} signs and gates preflight")
    _check_routes()
    print("[OK] execution and plan-first AI routes are registered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
