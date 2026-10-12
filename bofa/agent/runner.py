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


def run_agent_demo(
    scope_path: Path,
    input_path: Path,
    output_dir: Path,
    overwrite: bool = False,
) -> Dict[str, Path]:
    scope = load_scope(scope_path)
    with input_path.open("r", encoding="utf-8") as handle:
        input_data = json.load(handle)

    _validate_demo_input(input_data)
    planned_tools = input_data["planned_tool_calls"]

    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = output_dir / "evidence.jsonl"
    report_json_path = output_dir / "report.json"
    report_md_path = output_dir / "report.md"

    existing_outputs = [
        path.name for path in (evidence_path, report_json_path, report_md_path) if path.exists()
    ]
    if existing_outputs and not overwrite:
        raise FileExistsError(
            "Refusing to overwrite existing run artifacts: "
            + ", ".join(existing_outputs)
            + ". Choose a new output directory or pass overwrite=True."
        )

    recorder = EvidenceRecorder(
        evidence_path, timestamp=str(input_data["observed_at"]), overwrite=overwrite
    )
    recorder.append("run.start", {"mission_id": scope.mission_id, "run_id": input_data["run_id"]})

    failed_tools = []
    for tool in planned_tools:
        decision = scope.decide_tool(tool)
        if not decision.allowed or tool not in DEMO_TOOLS:
            reason = decision.reason if not decision.allowed else "tool has no reviewed implementation"
            recorder.append(
                "tool.blocked",
                {"tool": decision.tool, "reason": reason},
            )
            continue

        recorder.append("tool.allowed", {"tool": decision.tool, "reason": decision.reason})
        try:
            result = _validate_tool_result(tool, DEMO_TOOLS[tool](input_data))
        except Exception as error:
            failed_tools.append(tool)
            recorder.append(
                "tool.failed",
                {"tool": tool, "error_type": type(error).__name__},
            )
            continue
        recorder.append("tool.result", result)

    run_status = "partial_failed" if failed_tools else "completed"
    recorder.append("run.complete", {"status": run_status})
    events = read_evidence(evidence_path)
    report = build_report(
        scope,
        input_data,
        events,
        run_status=run_status,
        evidence_verified=True,
    )
    write_report_json(report, report_json_path)
    write_report_markdown(report, report_md_path)

    return {
        "evidence": evidence_path,
        "report_json": report_json_path,
        "report_markdown": report_md_path,
    }


def _validate_demo_input(input_data: Any) -> None:
    if not isinstance(input_data, dict):
        raise ValueError("demo input must be a JSON object")

    planned_tools = input_data.get("planned_tool_calls")
    if not isinstance(planned_tools, list) or any(
        not isinstance(tool, str) or not tool.strip() for tool in planned_tools
    ):
        raise ValueError("planned_tool_calls must be a list of non-empty tool names")
    if len(planned_tools) > 32:
        raise ValueError("planned_tool_calls must not exceed 32 entries")
    if len(planned_tools) != len(set(planned_tools)):
        raise ValueError("planned_tool_calls must not contain duplicates")

    application = input_data.get("application")
    if not isinstance(application, dict):
        raise ValueError("demo input must include an application object")
    for field in ("application_id", "display_name", "publisher"):
        value = application.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"application.{field} must be a non-empty string")

    if "publisher_verified" in application and not isinstance(
        application["publisher_verified"], bool
    ):
        raise ValueError("application.publisher_verified must be a boolean")
    for field in ("redirect_uris", "permissions"):
        values = application.get(field, [])
        if not isinstance(values, list) or any(
            not isinstance(value, str) or not value.strip() for value in values
        ):
            raise ValueError(f"application.{field} must be a list of non-empty strings")
    consents = application.get("sample_consents", [])
    if not isinstance(consents, list) or any(not isinstance(item, dict) for item in consents):
        raise ValueError("application.sample_consents must be a list of objects")

    if not isinstance(input_data.get("run_id"), str) or not input_data["run_id"].strip():
        raise ValueError("demo input must include a non-empty run_id")
    if not isinstance(input_data.get("observed_at"), str) or not input_data["observed_at"].strip():
        raise ValueError("demo input must include a non-empty observed_at timestamp")


def _validate_tool_result(tool: str, result: Any) -> Dict[str, Any]:
    if not isinstance(result, dict):
        raise TypeError("tool result must be an object")
    if result.get("tool") != tool:
        raise ValueError("tool result name does not match the requested tool")

    risk_delta = result.get("risk_delta")
    if isinstance(risk_delta, bool) or not isinstance(risk_delta, int) or not 0 <= risk_delta <= 100:
        raise ValueError("tool result risk_delta must be an integer from 0 to 100")

    findings = result.get("findings", [])
    if not isinstance(findings, list) or any(
        not isinstance(finding, dict)
        or any(
            not isinstance(finding.get(field), str) or not finding[field].strip()
            for field in ("title", "summary")
        )
        for finding in findings
    ):
        raise ValueError("tool result findings must contain non-empty titles and summaries")

    json.dumps(result, ensure_ascii=False, allow_nan=False)
    return result
