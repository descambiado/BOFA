"""Deterministic runner for the BOFA OAuth triage demo."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, Mapping

from bofa.agent.evidence import EvidenceRecorder, read_evidence
from bofa.agent.report import build_report, write_report_json, write_report_markdown
from bofa.agent.scope import AgentScope, load_scope

ToolFn = Callable[[Mapping[str, Any]], Dict[str, Any]]


def inspect_oauth_metadata(input_data: Mapping[str, Any]) -> Dict[str, Any]:
    app = input_data["application"]
    findings = []
    risk_delta = 0
    if not app.get("publisher_verified", False):
        risk_delta += 25
        findings.append(
            {
                "title": "Publisher is not verified",
                "summary": "The synthetic OAuth application is marked as unverified, so user consent should be reviewed before trust is granted.",
            }
        )
    if any(uri.startswith("http://") for uri in app.get("redirect_uris", [])):
        risk_delta += 20
        findings.append(
            {
                "title": "Insecure redirect URI present",
                "summary": "At least one synthetic redirect URI uses plain HTTP, which is inappropriate for OAuth callback handling.",
            }
        )
    return {"tool": "inspect_oauth_metadata", "risk_delta": risk_delta, "findings": findings}


def evaluate_permissions(input_data: Mapping[str, Any]) -> Dict[str, Any]:
    permissions = input_data["application"].get("permissions", [])
    risky = sorted(
        permission
        for permission in permissions
        if permission in {"Mail.Read", "offline_access", "User.ReadWrite.All"}
    )
    findings = []
    risk_delta = 10 * len(risky)
    if risky:
        findings.append(
            {
                "title": "Broad or persistent permissions requested",
                "summary": "The synthetic OAuth application requests permissions that can expand exposure if consent is granted.",
            }
        )
    return {
        "tool": "evaluate_permissions",
        "risk_delta": risk_delta,
        "risky_permissions": risky,
        "findings": findings,
    }


def score_risk(input_data: Mapping[str, Any]) -> Dict[str, Any]:
    consent_count = len(input_data["application"].get("sample_consents", []))
    risk_delta = 15 if consent_count else 0
    findings = []
    if consent_count:
        findings.append(
            {
                "title": "Existing sample consents observed",
                "summary": "The synthetic data includes existing sample consents, so revocation and owner validation should be considered.",
            }
        )
    return {
        "tool": "score_risk",
        "risk_delta": risk_delta,
        "sample_consent_count": consent_count,
        "findings": findings,
    }


DEMO_TOOLS: Dict[str, ToolFn] = {
    "inspect_oauth_metadata": inspect_oauth_metadata,
    "evaluate_permissions": evaluate_permissions,
    "score_risk": score_risk,
}


def run_agent_demo(scope_path: Path, input_path: Path, output_dir: Path) -> Dict[str, Path]:
    scope = load_scope(scope_path)
    with input_path.open("r", encoding="utf-8") as handle:
        input_data = json.load(handle)

    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = output_dir / "evidence.jsonl"
    report_json_path = output_dir / "report.json"
    report_md_path = output_dir / "report.md"

    recorder = EvidenceRecorder(evidence_path, timestamp=str(input_data["observed_at"]))
    recorder.append("run.start", {"mission_id": scope.mission_id, "run_id": input_data["run_id"]})

    planned_tools = list(input_data["planned_tool_calls"])
    for tool in planned_tools:
        decision = scope.decide_tool(tool)
        if not decision.allowed:
            recorder.append(
                "tool.blocked",
                {"tool": decision.tool, "reason": decision.reason},
            )
            continue

        recorder.append("tool.allowed", {"tool": decision.tool, "reason": decision.reason})
        result = DEMO_TOOLS[tool](input_data)
        recorder.append("tool.result", result)

    recorder.append("run.complete", {"status": "completed"})
    events = read_evidence(evidence_path)
    report = build_report(scope, input_data, events)
    write_report_json(report, report_json_path)
    write_report_markdown(report, report_md_path)

    return {
        "evidence": evidence_path,
        "report_json": report_json_path,
        "report_markdown": report_md_path,
    }

