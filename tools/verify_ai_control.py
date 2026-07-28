#!/usr/bin/env python3
"""Verify that BOFA LLM copilots cannot bypass execution policy."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from agents import security_agent
from agents.llm_providers import (
    OllamaProvider,
    OpenAICompatibleProvider,
    get_provider,
    list_provider_descriptors,
)


class FakeProvider:
    provider_id = "fake-local"
    locality = "local"

    def complete(self, prompt: str, system=None, max_tokens: int = 2048) -> str:
        return (
            '{"action":"execute_script","module":"web","script":"param_finder",'
            '"parameters":{"url":"https://authorized.example","json":true}}'
        )


def _grant(scope: str = "authorized.example"):
    now = datetime.now(timezone.utc)
    return {
        "id": "grant_ai_test",
        "subject_id": "42",
        "project_id": "project_ai_test",
        "environment_id": "env_ai_test",
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=30)).isoformat(),
        "scopes": [{"kind": "host", "value": scope}],
        "capabilities": ["network_active"],
        "limits": {
            "max_duration_seconds": 300,
            "max_output_bytes": 1_000_000,
            "max_steps": 5,
            "cpu_cores": 1,
            "memory_mb": 512,
        },
        "require_human_approval": True,
        "approval_id": "approval_ai_test",
        "approved_by": "human_reviewer",
    }


def _profile():
    return {
        "id": "local-controlled",
        "backend": "local",
        "capabilities": ["network_active"],
        "limits": {
            "max_duration_seconds": 300,
            "max_output_bytes": 1_000_000,
            "max_steps": 5,
            "cpu_cores": 1,
            "memory_mb": 512,
        },
        "network_mode": "restricted",
        "ephemeral": True,
        "enabled": True,
    }


def _check_plan_mode_never_executes() -> None:
    original = security_agent._execute_action

    def forbidden(*args, **kwargs):
        raise AssertionError("Plan mode reached the executor")

    security_agent._execute_action = forbidden
    try:
        result = security_agent.run_security_agent(
            "https://authorized.example",
            llm_provider=FakeProvider(),
            verbose=False,
        )
    finally:
        security_agent._execute_action = original
    assert result["status"] == "plan_ready"
    assert result["executed"] is False
    assert result["proposed_action"]["action"] == "execute_script"


def _check_execute_requires_policy_contract() -> None:
    result = security_agent.run_security_agent(
        "https://authorized.example",
        execute=True,
        llm_provider=FakeProvider(),
        verbose=False,
    )
    assert result["status"] == "policy_required"
    assert result["executed"] is False


def _check_out_of_scope_stops_before_executor() -> None:
    original = security_agent._execute_action

    def forbidden(*args, **kwargs):
        raise AssertionError("Denied action reached the executor")

    security_agent._execute_action = forbidden
    try:
        result = security_agent.run_security_agent(
            "https://outside.example",
            execute=True,
            grant_payload=_grant(),
            profile_payload=_profile(),
            subject_id="42",
            llm_provider=FakeProvider(),
            verbose=False,
        )
    finally:
        security_agent._execute_action = original
    assert result["status"] == "policy_denied"
    assert result["executed"] is False
    assert not result["preflight"]["decision"]["checks"]["scope"]


def _check_auto_is_local_first() -> None:
    with patch.dict(os.environ, {"BOFA_LLM_PROVIDER": "ollama"}, clear=False):
        assert isinstance(get_provider("auto"), OllamaProvider)
    assert isinstance(get_provider("openai_compatible"), OpenAICompatibleProvider)
    descriptors = {item["id"]: item for item in list_provider_descriptors()}
    assert descriptors["ollama"]["transmits_workspace_data"] is False
    assert descriptors["openai_compatible"]["transmits_workspace_data"] is False
    assert descriptors["openai"]["transmits_workspace_data"] is True
    assert descriptors["anthropic"]["transmits_workspace_data"] is True


def main() -> int:
    checks = [
        ("plan mode never reaches an executor", _check_plan_mode_never_executes),
        ("execute mode requires a policy contract", _check_execute_requires_policy_contract),
        ("out-of-scope LLM actions stop before execution", _check_out_of_scope_stops_before_executor),
        ("auto provider selection remains local-first", _check_auto_is_local_first),
    ]
    print("BOFA AI Control Verification")
    print("=" * 40)
    for label, check in checks:
        check()
        print(f"[OK] {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
