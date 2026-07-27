#!/usr/bin/env python3
"""
BOFA duplicate-aware bounty verification.

Smoke checks for workspaces, snapshots, deltas, clusters, review queue
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
    detail = service.get_workspace_detail(workspace["id"])
    return bool(detail and detail.get("name") == "Acme H1" and isinstance(detail.get("snapshots"), list))


def _check_snapshots_deltas_clusters_and_queue():
    app_root, db, _, service = _make_runtime()
    workspace = service.create_workspace(
        user_id=1,
        name="Delta Target",
        platform="hackerone",
        program_handle="delta-target",
        notes="Focus on web/API deltas",
    )
    workspace_id = workspace["id"]

    first_import = service.import_content(
        workspace_id=workspace_id,
        user_id=1,
        import_type="scope",
        source_label="scope batch 1",
        content="https://app.delta.test\napi.delta.test\n",
        content_format="txt",
    )
    second_import = service.import_content(
        workspace_id=workspace_id,
        user_id=1,
        import_type="url_list",
        source_label="url diff batch 2",
        content="\n".join(
            [
                "https://app.delta.test/api/v2/internal/users?tenant_id=123&debug=true",
                "https://beta.delta.test/preview/export?workspace=acme",
                "https://app.delta.test/static/app.bundle.js",
            ]
        ),
        content_format="txt",
    )
    service.import_content(
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

    analysis = service.analyze_workspace(workspace_id, user_id=1)
    review_export = service.export_review_queue(workspace_id, user_id=1, snapshot_id=second_import["snapshot_id"])
    manual_handoff = service.run_skill(workspace_id, "manual_handoff", user_id=1)

    detail = service.get_workspace_detail(workspace_id)
    snapshots = service.list_snapshots(workspace_id)
    first_snapshot = service.get_snapshot(workspace_id, first_import["snapshot_id"])
    second_snapshot = service.get_snapshot(workspace_id, second_import["snapshot_id"])
    first_deltas = service.get_snapshot_deltas(workspace_id, first_import["snapshot_id"])
    second_deltas = service.get_snapshot_deltas(workspace_id, second_import["snapshot_id"])
    latest_deltas = service.get_latest_deltas(workspace_id)
    clusters = service.list_finding_clusters(workspace_id, snapshot_id=second_import["snapshot_id"])
    queue = service.get_review_queue(workspace_id, snapshot_id=second_import["snapshot_id"])
    summary = service.summarize_workspaces(user_id=1)
    export_run = db.get_run_detail(review_export["run_id"])
    analysis_run = db.get_run_detail(analysis["run_id"])

    return all(
        [
            len(snapshots) >= 2,
            any(snapshot.get("id") == first_import["snapshot_id"] for snapshot in snapshots),
            any(snapshot.get("id") == second_import["snapshot_id"] for snapshot in snapshots),
            first_snapshot is not None,
            second_snapshot is not None,
            len(first_deltas) > 0,
            len(second_deltas) > len(first_deltas),
            len(latest_deltas) > 0,
            latest_deltas == second_deltas,
            all(delta.get("snapshot_id") == first_import["snapshot_id"] for delta in first_deltas),
            all(delta.get("snapshot_id") == second_import["snapshot_id"] for delta in second_deltas),
            any(delta.get("entity_type") == "api_endpoint" for delta in latest_deltas),
            len(clusters) > 0,
            len(queue) > 0,
            all(item.get("evidence") and item.get("next_manual_step") for item in queue),
            any(item.get("report_candidate") for item in queue),
            manual_handoff.get("skill_key") == "manual_handoff",
            bool(manual_handoff.get("manual_queue")),
            summary.get("workspaces") == 1,
            summary.get("active_workspaces") == 1,
            summary.get("snapshots", 0) >= 2,
            summary.get("findings", 0) >= len(detail.get("findings", [])),
            summary.get("review_queue_items", 0) >= len(queue),
            summary.get("report_candidates", 0) >= 1,
            summary.get("latest_workspace_id") == workspace_id,
            summary.get("latest_workspace_name") == workspace.get("name"),
            any(artifact.get("artifact_type") == "review_queue_json" for artifact in (export_run or {}).get("artifacts", [])),
            any(artifact.get("artifact_type") == "workspace_analysis_result" for artifact in (analysis_run or {}).get("artifacts", [])),
            isinstance(detail.get("clusters"), list),
            isinstance(detail.get("review_queue"), list),
        ]
    )


def main():
    checks = [
        ("workspace lifecycle persists correctly", _check_workspace_lifecycle()),
        ("snapshots, deltas, clusters and review queue work together", _check_snapshots_deltas_clusters_and_queue()),
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
