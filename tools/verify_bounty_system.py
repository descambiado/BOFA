#!/usr/bin/env python3
"""
BOFA duplicate-aware bounty verification.

Focused smoke checks for workspaces, imports, target graph, novelty findings
and skill execution without requiring external services.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_VERIFY_ROOT = _ROOT / "data" / ".verify_bounty_system"
_VERIFY_ROOT.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("BOFA_DB_PATH", str(_VERIFY_ROOT / "bootstrap.db"))

from api.database import DatabaseManager
from api.run_manager import RunManager
from core.bounty_service import BountyWorkspaceService


def _make_runtime():
    runtime_id = uuid.uuid4().hex
    app_root = _VERIFY_ROOT / f"runtime_{runtime_id}"
    app_root.mkdir(parents=True, exist_ok=True)
    db_path = _VERIFY_ROOT / f"runtime_{runtime_id}.db"
    db = DatabaseManager(str(db_path))
    manager = RunManager(db)
    service = BountyWorkspaceService(db, manager, app_root, skills_dir=_ROOT / "skills" / "bounty")
    return app_root, db, manager, service


def _check_workspace_lifecycle():
    _, _, _, service = _make_runtime()
    workspace = service.create_workspace(
        user_id=1,
        name="Acme H1",
        platform="hackerone",
        program_handle="acme",
        notes="smoke",
        metadata={"purpose": "verify"},
    )
    listed = service.list_workspaces(user_id=1)
    detail = service.get_workspace_detail(workspace["id"])
    return (
        workspace.get("name") == "Acme H1"
        and any(item["id"] == workspace["id"] for item in listed)
        and detail is not None
        and detail.get("program_handle") == "acme"
    )


def _check_imports_graph_analysis_and_skills():
    app_root, db, _, service = _make_runtime()
    workspace = service.create_workspace(
        user_id=1,
        name="Delta Target",
        platform="hackerone",
        program_handle="delta-target",
        notes="Focus on web/API deltas",
    )
    workspace_id = workspace["id"]

    scope_result = service.import_content(
        workspace_id=workspace_id,
        user_id=1,
        import_type="scope",
        source_label="scope batch",
        content="https://app.delta.test\napi.delta.test\nbeta.delta.test\n",
        content_format="txt",
        metadata={"batch": 1},
    )
    disclosed_result = service.import_content(
        workspace_id=workspace_id,
        user_id=1,
        import_type="disclosed_reports",
        source_label="public disclosures",
        content=json.dumps(
            [
                {
                    "title": "Broken access control on admin API",
                    "summary": "Missing authorization on /api/admin/export.",
                    "severity": "high",
                    "asset_hint": "https://app.delta.test/api/admin/export",
                },
                {
                    "title": "Stored XSS on search parameter",
                    "summary": "Search field reflected payload in dashboard.",
                    "severity": "medium",
                },
            ]
        ),
        content_format="json",
    )
    urls_result = service.import_content(
        workspace_id=workspace_id,
        user_id=1,
        import_type="url_list",
        source_label="url diff",
        content="\n".join(
            [
                "https://app.delta.test/api/v2/internal/users?tenant_id=123&debug=true",
                "https://app.delta.test/static/app.bundle.js",
                "https://beta.delta.test/preview/export?workspace=acme",
                "https://app.delta.test/login?redirect=%2Fadmin&q=test",
            ]
        ),
        content_format="txt",
    )

    graph = service.get_workspace_graph(workspace_id)
    analysis = service.analyze_workspace(workspace_id, user_id=1)
    skill_result = service.run_skill(workspace_id, "delta_recon", user_id=1)

    detail = service.get_workspace_detail(workspace_id)
    findings = detail.get("findings", []) if detail else []
    run_ids = [scope_result["run_id"], disclosed_result["run_id"], urls_result["run_id"], analysis["run_id"], skill_result["run_id"]]
    runs = [db.get_run_detail(run_id) for run_id in run_ids]
    run_types = {run.get("run_type") for run in runs if run}

    return (
        graph["nodes"]
        and graph["edges"]
        and any(node.get("node_type") == "api_endpoint" for node in graph["nodes"])
        and any(node.get("node_type") == "js_file" for node in graph["nodes"])
        and any(node.get("node_type") == "param" for node in graph["nodes"])
        and any(finding.get("category") == "what_changed" for finding in findings)
        and any(finding.get("category") == "likely_duplicate" for finding in findings)
        and skill_result.get("skill_key") == "delta_recon"
        and "intel_import" in run_types
        and "workspace_analysis" in run_types
        and "skill_run" in run_types
        and (app_root / "reports" / "workspaces" / workspace_id).exists()
        and any(artifact.get("artifact_type") == "workspace_analysis_result" for artifact in (runs[3] or {}).get("artifacts", []))
        and any(artifact.get("artifact_type") == "bounty_skill_result" for artifact in (runs[4] or {}).get("artifacts", []))
    )


def main():
    checks = [
        ("workspace lifecycle persists correctly", _check_workspace_lifecycle()),
        ("imports, graph, analysis and skill runs work together", _check_imports_graph_analysis_and_skills()),
    ]
    failed = [name for name, ok in checks if not ok]

    print("BOFA Duplicate-Aware Bounty Verification")
    print("=" * 44)
    for name, ok in checks:
        print(f"[{'OK' if ok else 'FAIL'}] {name}")

    if failed:
        print()
        print("Failed checks:")
        for name in failed:
            print(f"- {name}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
