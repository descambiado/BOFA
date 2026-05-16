"""Report generation for the passive OAuth triage demo."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping

from bofa.agent.evidence import EvidenceEvent, summarize_evidence
from bofa.agent.scope import AgentScope


def build_report(
    scope: AgentScope,
    input_data: Mapping[str, Any],
    events: Iterable[EvidenceEvent],
) -> Dict[str, Any]:
    event_list = list(events)
    tool_results = [
        event.data for event in event_list if event.event_type == "tool.result"
    ]
    blocked_tools = [
        event.data for event in event_list if event.event_type == "tool.blocked"
    ]

    risk_score = _risk_score(tool_results)
    severity = _severity_from_score(risk_score)
    app = dict(input_data["application"])
    actions = _actions(event_list)

    return {
        "schema_version": "1.0",
        "mission_id": scope.mission_id,
        "title": scope.title,
        "run_id": str(input_data["run_id"]),
        "generated_at": str(input_data["observed_at"]),
        "subject": {
            "application_id": app["application_id"],
            "display_name": app["display_name"],
            "publisher": app["publisher"],
        },
        "demo_notice": "Synthetic demo input only; no real tenant, target, credential, or external API was used.",
        "scope": {
            "profile": scope.report_profile,
            "constraints": scope.constraints,
            "allowed_tools": scope.allowed_tools,
        },
        "actions_executed": actions,
        "classification": {
            "severity": severity,
            "risk_score": risk_score,
            "status": "review_required" if risk_score >= 50 else "monitor",
        },
        "findings": _findings(tool_results),
        "blocked_tools": blocked_tools,
        "evidence_summary": summarize_evidence(event_list),
        "limitations": [
            "The application record is synthetic and intentionally small.",
            "No live OAuth tenant, Graph API, identity provider, or user directory was queried.",
            "Findings demonstrate passive triage flow, not production assurance.",
        ],
        "next_steps": [
            "Review publisher ownership before granting consent.",
            "Remove insecure redirect URIs before any real deployment.",
            "Validate requested permissions with an application owner.",
            "Re-run against approved internal evidence only if this pattern is adopted beyond the demo.",
        ],
        "sotyhub": {
            "adapter_version": "example-v1",
            "ingestion_type": "passive_oauth_triage_report",
            "dedupe_key": f"{scope.mission_id}:{app['application_id']}",
        },
    }


def write_report_json(report: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_report_markdown(report: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(report), encoding="utf-8")


def render_markdown(report: Mapping[str, Any]) -> str:
    subject = report["subject"]
    classification = report["classification"]
    lines = [
        f"# {report['title']}",
        "",
        "## Executive Summary",
        "",
        "This local demo triaged a synthetic suspicious OAuth application using only scoped, deterministic checks. "
        f"The result is `{classification['severity']}` risk with score `{classification['risk_score']}` and status `{classification['status']}`.",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Application: `{subject['display_name']}`",
        f"- Publisher: `{subject['publisher']}`",
        "",
        "## Scope",
        "",
        report["demo_notice"],
        "",
        "Allowed tools:",
    ]

    for tool in report["scope"]["allowed_tools"]:
        lines.append(f"- `{tool}`")

    lines.extend(["", "Constraints:"])
    for constraint in report["scope"]["constraints"]:
        lines.append(f"- `{constraint}`")

    lines.extend(["", "## Actions Executed", ""])
    for action in report["actions_executed"]:
        lines.append(f"- `{action['tool']}`: {action['status']}")

    lines.extend(["", "## Evidence", ""])
    for event_type, count in sorted(report["evidence_summary"].items()):
        lines.append(f"- `{event_type}`: {count}")

    lines.extend(
        [
            "",
            "## Risk Decision",
            "",
        ]
    )
    lines.extend(
        [
            f"- Severity: `{classification['severity']}`",
            f"- Risk score: `{classification['risk_score']}`",
            f"- Status: `{classification['status']}`",
            "",
            "## Findings",
            "",
        ]
    )

    for finding in report["findings"]:
        lines.extend(
            [
                f"### {finding['title']}",
                "",
                finding["summary"],
                "",
            ]
        )

    lines.extend(["## Blocked Tool Calls", ""])
    for blocked in report["blocked_tools"]:
        lines.append(f"- `{blocked['tool']}`: {blocked['reason']}")

    lines.extend(["", "## Limitations", ""])
    for limitation in report["limitations"]:
        lines.append(f"- {limitation}")

    lines.extend(["", "## Next Steps", ""])
    for step in report["next_steps"]:
        lines.append(f"- {step}")

    return "\n".join(lines).rstrip() + "\n"


def _risk_score(tool_results: Iterable[Mapping[str, Any]]) -> int:
    score = 0
    for result in tool_results:
        score += int(result.get("risk_delta", 0))
    return min(score, 100)


def _severity_from_score(score: int) -> str:
    if score >= 75:
        return "high"
    if score >= 50:
        return "medium"
    if score >= 25:
        return "low"
    return "informational"


def _findings(tool_results: Iterable[Mapping[str, Any]]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    for result in tool_results:
        for finding in result.get("findings", []):
            findings.append(
                {
                    "title": str(finding["title"]),
                    "summary": str(finding["summary"]),
                }
            )
    return findings


def _actions(events: Iterable[EvidenceEvent]) -> List[Dict[str, str]]:
    actions: List[Dict[str, str]] = []
    for event in events:
        if event.event_type == "tool.allowed":
            actions.append({"tool": str(event.data["tool"]), "status": "executed"})
        if event.event_type == "tool.blocked":
            actions.append({"tool": str(event.data["tool"]), "status": "blocked"})
    return actions
