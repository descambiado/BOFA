#!/usr/bin/env python3
"""
Create a real BOFA bounty workspace offline using bundled sample inputs.

This is meant to be the fastest way to feel what BOFA does without setting up
external targets or third-party services.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import sys
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api.database import DatabaseManager
from api.run_manager import RunManager
from core.bounty_service import BountyWorkspaceService

SAMPLE_ROOT = ROOT / "docs" / "examples" / "bounty_demo_workspace"
DEFAULT_OUTPUT_ROOT = ROOT / "data" / "demo_bounty_workspace"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a BOFA duplicate-aware bounty demo workspace.")
    parser.add_argument(
        "--output-root",
        default=str(DEFAULT_OUTPUT_ROOT),
        help="Directory where the demo database, runtime and generated reports will be stored.",
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="Delete the previous demo output root before creating a new demo workspace.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the final summary as JSON in addition to the human-readable output.",
    )
    return parser.parse_args()


def _load_demo_inputs() -> List[Tuple[str, str, str, Path]]:
    return [
        ("scope", "Demo scope", "txt", SAMPLE_ROOT / "scope.txt"),
        ("url_list", "Observed surface", "txt", SAMPLE_ROOT / "url_list.txt"),
        ("disclosed_reports", "Public disclosures", "json", SAMPLE_ROOT / "disclosed_reports.json"),
        ("notes", "Analyst notes", "md", SAMPLE_ROOT / "notes.md"),
    ]


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _select_showcase_queue(queue: List[Dict[str, Any]], limit: int = 5) -> List[Dict[str, Any]]:
    interesting_terms = ("auth", "admin", "graphql", "debug", "preview", "tenant", "workspace", "callback", "return")

    def rank(item: Dict[str, Any]) -> Tuple[int, float, float]:
        text = f"{item.get('hypothesis', '')} {item.get('why_now', '')}".lower()
        score = 0
        if item.get("report_candidate"):
            score += 50
        if item.get("root_cause"):
            score += 20
        if any(term in text for term in interesting_terms):
            score += 10
        if text.endswith(": /") or text.endswith(" /"):
            score -= 10
        return (score, float(item.get("novelty_score") or 0), -float(item.get("duplicate_risk_score") or 0))

    ranked = sorted(queue, key=rank, reverse=True)
    selected: List[Dict[str, Any]] = []
    seen = set()
    for item in ranked:
        key = re.sub(r"https?://[^/\s]+", "", str(item.get("hypothesis") or "").strip().lower())
        if not key or key in seen:
            continue
        selected.append(item)
        seen.add(key)
        if len(selected) >= limit:
            break
    return selected


def _build_summary_markdown(summary: Dict[str, Any]) -> str:
    lines = [
        "# BOFA Demo Workspace",
        "",
        f"- Workspace: `{summary['workspace']['name']}`",
        f"- Workspace ID: `{summary['workspace']['id']}`",
        f"- Program: `{summary['workspace']['program_handle']}`",
        f"- Imports: `{summary['metrics']['imports']}`",
        f"- Snapshots: `{summary['metrics']['snapshots']}`",
        f"- Graph nodes: `{summary['metrics']['nodes']}`",
        f"- Graph edges: `{summary['metrics']['edges']}`",
        f"- Findings: `{summary['metrics']['findings']}`",
        f"- Review queue items: `{summary['metrics']['review_queue']}`",
        "",
        "## Top Review Queue",
        "",
    ]
    queue = summary.get("top_review_queue") or []
    if not queue:
        lines.append("No review queue items were produced.")
    else:
        for index, item in enumerate(queue, start=1):
            lines.extend(
                [
                    f"{index}. {item['hypothesis']}",
                    f"   - why_now: {item['why_now']}",
                    f"   - next_manual_step: {item['next_manual_step']}",
                    f"   - novelty: {item['novelty_score']}",
                    f"   - duplicate_risk: {item['duplicate_risk_score']}",
                    f"   - root_cause: {item['root_cause'] or 'n/a'}",
                    f"   - report_candidate: {bool(item['report_candidate'])}",
                ]
            )
    lines.extend(
        [
            "",
            "## Artifacts",
            "",
            f"- Analysis JSON: `{summary['artifacts']['analysis_json']}`",
            f"- Analysis Markdown: `{summary['artifacts']['analysis_markdown']}`",
            f"- Review queue JSON: `{summary['artifacts']['review_queue_json']}`",
            f"- Review queue Markdown: `{summary['artifacts']['review_queue_markdown']}`",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    args = _parse_args()
    output_root = Path(args.output_root).resolve()
    if args.fresh and output_root.exists():
        shutil.rmtree(output_root)

    db_path = output_root / "bofa_demo.db"
    runtime_root = output_root / "runtime"
    summary_dir = output_root / "summary"

    db = DatabaseManager(str(db_path))
    run_manager = RunManager(db)
    service = BountyWorkspaceService(db, run_manager, runtime_root, skills_dir=ROOT / "skills" / "bounty")

    workspace = service.create_workspace(
        user_id=1,
        name="Acme Demo Workspace",
        platform="hackerone",
        program_handle="acme-demo",
        notes="Offline BOFA demo workspace",
        metadata={"source": "demo_bounty_workspace", "sample_root": str(SAMPLE_ROOT)},
    )
    workspace_id = workspace["id"]

    import_results: List[Dict[str, Any]] = []
    for import_type, source_label, content_format, path in _load_demo_inputs():
        content = path.read_text(encoding="utf-8")
        import_results.append(
            service.import_content(
                workspace_id=workspace_id,
                user_id=1,
                import_type=import_type,
                source_label=source_label,
                content=content,
                content_format=content_format,
                source_path=str(path),
                source="demo_tool",
            )
        )

    analysis = service.analyze_workspace(workspace_id, user_id=1, source="demo_tool")
    latest_snapshot = service.get_latest_surface_snapshot(workspace_id)
    if latest_snapshot is None:
        raise SystemExit("Demo workspace did not produce a surface snapshot.")
    review_export = service.export_review_queue(
        workspace_id=workspace_id,
        user_id=1,
        snapshot_id=latest_snapshot["id"],
        source="demo_tool",
    )

    manual_handoff = None
    if any(skill.get("skill_key") == "manual_handoff" for skill in service.list_skills()):
        manual_handoff = service.run_skill(workspace_id, "manual_handoff", user_id=1, source="demo_tool")

    detail = service.get_workspace_detail(workspace_id) or {}
    graph = detail.get("graph") or {}
    queue = detail.get("review_queue") or []
    showcase_queue = _select_showcase_queue(queue)
    summary_payload = {
        "workspace": {
            "id": detail.get("id"),
            "name": detail.get("name"),
            "platform": detail.get("platform"),
            "program_handle": detail.get("program_handle"),
        },
        "metrics": {
            "imports": len(detail.get("imports") or []),
            "snapshots": len(detail.get("snapshots") or []),
            "nodes": len(graph.get("nodes") or []),
            "edges": len(graph.get("edges") or []),
            "findings": len(detail.get("findings") or []),
            "review_queue": len(queue),
        },
        "runs": {
            "analysis_run_id": analysis.get("run_id"),
            "review_queue_export_run_id": review_export.get("run_id"),
            "manual_handoff_run_id": None if manual_handoff is None else manual_handoff.get("run_id"),
        },
        "artifacts": {
            "analysis_json": str(runtime_root / "reports" / "workspaces" / workspace_id / "analysis" / f"{analysis['run_id']}_findings.json"),
            "analysis_markdown": str(runtime_root / "reports" / "workspaces" / workspace_id / "analysis" / f"{analysis['run_id']}_findings.md"),
            "review_queue_json": review_export["artifacts"][0],
            "review_queue_markdown": review_export["artifacts"][1],
        },
        "top_review_queue": [
            {
                "hypothesis": item.get("hypothesis"),
                "why_now": item.get("why_now"),
                "next_manual_step": item.get("next_manual_step"),
                "novelty_score": item.get("novelty_score"),
                "duplicate_risk_score": item.get("duplicate_risk_score"),
                "report_candidate": item.get("report_candidate"),
                "root_cause": item.get("root_cause"),
            }
            for item in showcase_queue
        ],
        "imports": [
            {
                "import_type": item.get("summary", {}).get("import_type"),
                "snapshot_id": item.get("snapshot_id"),
                "source_label": item.get("summary", {}).get("source_label"),
            }
            for item in import_results
        ],
    }

    summary_json = summary_dir / "demo_summary.json"
    summary_markdown = summary_dir / "demo_summary.md"
    _write_json(summary_json, summary_payload)
    _write_text(summary_markdown, _build_summary_markdown(summary_payload))

    print("BOFA demo workspace ready")
    print(f"Output root: {output_root}")
    print(f"Workspace: {summary_payload['workspace']['name']} ({summary_payload['workspace']['id']})")
    print(
        "Counts: "
        f"{summary_payload['metrics']['imports']} imports, "
        f"{summary_payload['metrics']['snapshots']} snapshots, "
        f"{summary_payload['metrics']['findings']} findings, "
        f"{summary_payload['metrics']['review_queue']} review queue items"
    )
    print(f"Summary markdown: {summary_markdown}")
    print(f"Analysis markdown: {summary_payload['artifacts']['analysis_markdown']}")
    print(f"Review queue markdown: {summary_payload['artifacts']['review_queue_markdown']}")
    if summary_payload["top_review_queue"]:
        print("Top hypotheses:")
        for item in summary_payload["top_review_queue"][:3]:
            print(f"- {item['hypothesis']} | next: {item['next_manual_step']}")

    if args.json:
        print(json.dumps(summary_payload, indent=2, ensure_ascii=False))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
