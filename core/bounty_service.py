#!/usr/bin/env python3
"""
BOFA bounty workspace service.

Local-first intelligence layer focused on duplicate-aware bug bounty work.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import json
import re
from pathlib import Path
import uuid
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlparse

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - lightweight fallback for smoke environments
    yaml = None


NODE_TYPES = {
    "host",
    "subdomain",
    "url",
    "route",
    "param",
    "js_file",
    "api_endpoint",
    "role",
    "finding_hint",
}

EDGE_TYPES = {
    "contains",
    "links_to",
    "emits",
    "accepts_param",
    "uses_role",
    "calls_api",
    "derived_from",
}

SUPPORTED_IMPORT_TYPES = {
    "scope",
    "disclosed_reports",
    "burp_sitemap",
    "url_list",
    "js_endpoints",
    "notes",
}

DEFAULT_SKILL_ORDER = [
    "program_intel",
    "disclosed_report_graph",
    "delta_recon",
    "js_api_diff",
    "authz_matrix",
    "duplicate_risk",
    "report_novelty_gate",
]

INTERESTING_ROUTE_HINTS = (
    "api",
    "graphql",
    "internal",
    "preview",
    "beta",
    "admin",
    "callback",
    "oauth",
    "token",
    "debug",
    "export",
)
COMMON_PARAM_HINTS = {"id", "page", "q", "query", "search", "lang", "redirect", "next", "return"}
AUTH_HINTS = ("role", "admin", "auth", "permission", "token", "session", "impersonate")
WEIRD_PARAM_HINTS = ("tenant", "workspace", "account", "role", "permission", "debug", "preview", "callback", "return")


def _utc_now() -> str:
    return datetime.utcnow().isoformat()


def _safe_slug(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9._-]+", "_", value.strip())
    return normalized.strip("_") or "item"


class BountyWorkspaceService:
    def __init__(self, database_manager, run_manager, app_root: Path, skills_dir: Optional[Path] = None):
        self.db = database_manager
        self.run_manager = run_manager
        self.app_root = Path(app_root)
        self.reports_dir = self.app_root / "reports" / "workspaces"
        self.skills_dir = Path(skills_dir or self.app_root / "skills" / "bounty")
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.skills_dir.mkdir(parents=True, exist_ok=True)

    def create_workspace(
        self,
        user_id: int,
        name: str,
        platform: str,
        program_handle: str,
        notes: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        workspace_id = self._id("workspace")
        now = _utc_now()
        payload = metadata or {}
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO bounty_workspaces
            (id, user_id, name, platform, program_handle, notes, metadata, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (workspace_id, user_id, name, platform, program_handle, notes, json.dumps(payload), now, now),
        )
        conn.commit()
        conn.close()
        return self.get_workspace_detail(workspace_id) or {}

    def list_workspaces(self, user_id: Optional[int] = None) -> List[Dict[str, Any]]:
        conn = self.db.get_connection()
        cursor = conn.cursor()
        if user_id is None:
            cursor.execute("SELECT * FROM bounty_workspaces ORDER BY updated_at DESC, created_at DESC")
        else:
            cursor.execute(
                "SELECT * FROM bounty_workspaces WHERE user_id = ? ORDER BY updated_at DESC, created_at DESC",
                (user_id,),
            )
        rows = self.db._rows_to_dicts(cursor.fetchall())
        conn.close()
        return [self._serialize_workspace(row, include_children=False) for row in rows]

    def get_workspace(self, workspace_id: str) -> Optional[Dict[str, Any]]:
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM bounty_workspaces WHERE id = ?", (workspace_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return self.db._rows_to_dicts([row])[0]

    def get_workspace_detail(self, workspace_id: str) -> Optional[Dict[str, Any]]:
        workspace = self.get_workspace(workspace_id)
        if not workspace:
            return None
        workspace["assets"] = self._get_workspace_assets(workspace_id)
        workspace["imports"] = self._get_workspace_imports(workspace_id)
        workspace["graph"] = self.get_workspace_graph(workspace_id)
        workspace["findings"] = self.list_findings(workspace_id, include_archived=False)
        workspace["skills"] = self.list_skills()
        return self._serialize_workspace(workspace, include_children=True)

    def list_skills(self) -> List[Dict[str, Any]]:
        skills: List[Dict[str, Any]] = []
        for skill_key in DEFAULT_SKILL_ORDER:
            path = self.skills_dir / f"{skill_key}.yaml"
            if not path.exists():
                continue
            data = self._load_skill_yaml(path)
            data["path"] = str(path)
            skills.append(data)
        for extra_path in sorted(self.skills_dir.glob("*.yaml")):
            if extra_path.stem in DEFAULT_SKILL_ORDER:
                continue
            data = self._load_skill_yaml(extra_path)
            data["path"] = str(extra_path)
            skills.append(data)
        return skills

    def get_workspace_graph(self, workspace_id: str) -> Dict[str, Any]:
        return {
            "nodes": self._get_graph_nodes(workspace_id),
            "edges": self._get_graph_edges(workspace_id),
            "assets": self._get_workspace_assets(workspace_id),
            "imports": self._get_workspace_imports(workspace_id),
        }

    def list_findings(self, workspace_id: str, include_archived: bool = True) -> List[Dict[str, Any]]:
        conn = self.db.get_connection()
        cursor = conn.cursor()
        if include_archived:
            cursor.execute(
                "SELECT * FROM novelty_findings WHERE workspace_id = ? ORDER BY created_at DESC, novelty_score DESC",
                (workspace_id,),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM novelty_findings
                WHERE workspace_id = ? AND status != 'archived'
                ORDER BY created_at DESC, novelty_score DESC
                """,
                (workspace_id,),
            )
        findings = self.db._rows_to_dicts(cursor.fetchall())
        conn.close()
        return findings

    def get_finding(self, workspace_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM novelty_findings WHERE workspace_id = ? AND id = ?",
            (workspace_id, finding_id),
        )
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return self.db._rows_to_dicts([row])[0]

    def import_content(
        self,
        workspace_id: str,
        user_id: int,
        import_type: str,
        source_label: str,
        content: str,
        content_format: str = "txt",
        source_url: Optional[str] = None,
        source_path: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        source: str = "api",
    ) -> Dict[str, Any]:
        if import_type not in SUPPORTED_IMPORT_TYPES:
            raise ValueError(f"Unsupported import_type: {import_type}")

        workspace = self.get_workspace(workspace_id)
        if not workspace:
            raise ValueError("Workspace not found")

        snapshot_id = self._id("snapshot")
        run_metadata = {
            "workspace_id": workspace_id,
            "import_type": import_type,
            "source_label": source_label,
            "source_url": source_url,
            "source_path": source_path,
            "content_format": content_format,
            "snapshot_id": snapshot_id,
            **(metadata or {}),
        }
        run_id = self.run_manager.create_run(
            user_id=user_id,
            run_type="intel_import",
            source=source,
            requested_action=f"import_{import_type}",
            target=workspace.get("program_handle"),
            metadata=run_metadata,
        )
        self.run_manager.mark_run_started(run_id, f"Importing {import_type} into workspace {workspace_id}")

        workspace_dir = self._workspace_dir(workspace_id)
        raw_name = f"{snapshot_id}_{_safe_slug(import_type)}.{content_format or 'txt'}"
        raw_path = workspace_dir / "imports" / raw_name
        self._write_text_artifact(raw_path, content)
        self._touch_workspace(workspace_id, {"last_import_type": import_type, "last_snapshot_id": snapshot_id})

        import_id = self._id("import")
        parsed = self._parse_import_content(import_type, content, content_format)
        summary = self._build_import_summary(import_type, parsed, source_label, snapshot_id)
        self._insert_workspace_import(
            import_id=import_id,
            workspace_id=workspace_id,
            run_id=run_id,
            import_type=import_type,
            source_label=source_label,
            source_path=source_path,
            source_url=source_url,
            content_format=content_format,
            snapshot_id=snapshot_id,
            status="success",
            summary=json.dumps(summary, ensure_ascii=False),
            metadata={"snapshot_id": snapshot_id, "summary": summary, **(metadata or {})},
        )

        ingest_result = self._ingest_import_payload(
            workspace_id=workspace_id,
            import_type=import_type,
            snapshot_id=snapshot_id,
            parsed=parsed,
            source_label=source_label,
            source_url=source_url,
        )

        summary_path = workspace_dir / "imports" / f"{snapshot_id}_{_safe_slug(import_type)}_summary.json"
        self._write_json_artifact(
            summary_path,
            {
                "workspace_id": workspace_id,
                "snapshot_id": snapshot_id,
                "import_type": import_type,
                "source_label": source_label,
                "content_format": content_format,
                "summary": summary,
                "ingest_result": ingest_result,
            },
        )

        self.run_manager.add_artifact(
            run_id,
            "workspace_import_raw",
            str(raw_path),
            label=f"Raw import: {source_label}",
            metadata={
                "workspace_id": workspace_id,
                "snapshot_id": snapshot_id,
                "import_type": import_type,
                "previewable": True,
                "content_type": "text/plain",
                "artifact_role": "workspace_import",
            },
        )
        self.run_manager.add_artifact(
            run_id,
            "workspace_import_summary",
            str(summary_path),
            label=f"Import summary: {source_label}",
            metadata={
                "workspace_id": workspace_id,
                "snapshot_id": snapshot_id,
                "import_type": import_type,
                "previewable": True,
                "content_type": "application/json",
                "artifact_role": "workspace_summary",
            },
        )
        self.run_manager.add_event(
            run_id,
            "workspace",
            workspace_id,
            "intel_import_completed",
            status="success",
            message=f"Imported {import_type} for workspace {workspace.get('name')}",
            payload={
                "workspace_id": workspace_id,
                "snapshot_id": snapshot_id,
                "summary": summary,
                "ingest_result": ingest_result,
            },
        )
        self.run_manager.mark_run_finished(
            run_id,
            status="success",
            message=f"Import completed for {import_type}",
            metadata=run_metadata,
        )

        return {
            "workspace_id": workspace_id,
            "run_id": run_id,
            "import_id": import_id,
            "snapshot_id": snapshot_id,
            "summary": summary,
            "ingest_result": ingest_result,
        }

    def analyze_workspace(self, workspace_id: str, user_id: int, source: str = "api") -> Dict[str, Any]:
        workspace = self.get_workspace(workspace_id)
        if not workspace:
            raise ValueError("Workspace not found")

        graph = self.get_workspace_graph(workspace_id)
        self._ingest_recon_run_artifacts(workspace_id)
        graph = self.get_workspace_graph(workspace_id)
        reports = self._get_disclosed_reports(workspace_id)
        latest_snapshot_id = self._latest_snapshot_id(workspace_id)
        run_metadata = {"workspace_id": workspace_id, "snapshot_id": latest_snapshot_id}
        run_id = self.run_manager.create_run(
            user_id=user_id,
            run_type="workspace_analysis",
            source=source,
            requested_action="analyze_workspace",
            target=workspace.get("program_handle"),
            metadata=run_metadata,
        )
        self.run_manager.mark_run_started(run_id, f"Analyzing workspace {workspace.get('name')}")

        self._archive_findings(workspace_id)
        findings, summary = self._build_findings(workspace_id, graph, reports, latest_snapshot_id, run_id)

        for finding in findings:
            self._insert_finding(workspace_id, run_id, finding)

        workspace_dir = self._workspace_dir(workspace_id)
        results_path = workspace_dir / "analysis" / f"{run_id}_findings.json"
        markdown_path = workspace_dir / "analysis" / f"{run_id}_findings.md"
        self._write_json_artifact(results_path, {"workspace_id": workspace_id, "run_id": run_id, "summary": summary, "findings": findings})
        self._write_text_artifact(markdown_path, self._render_findings_markdown(workspace, summary, findings))

        self.run_manager.add_artifact(
            run_id,
            "workspace_analysis_result",
            str(results_path),
            label=f"Workspace analysis {workspace.get('name')}",
            metadata={
                "workspace_id": workspace_id,
                "snapshot_id": latest_snapshot_id,
                "previewable": True,
                "content_type": "application/json",
                "artifact_role": "analysis_result",
            },
        )
        self.run_manager.add_artifact(
            run_id,
            "workspace_analysis_markdown",
            str(markdown_path),
            label=f"Workspace analysis markdown {workspace.get('name')}",
            metadata={
                "workspace_id": workspace_id,
                "snapshot_id": latest_snapshot_id,
                "previewable": True,
                "content_type": "text/markdown",
                "artifact_role": "analysis_summary",
            },
        )
        self.run_manager.mark_run_finished(
            run_id,
            status="success",
            message=f"Workspace analysis completed for {workspace.get('name')}",
            metadata={**run_metadata, "finding_count": len(findings), "summary": summary},
        )
        return {"workspace_id": workspace_id, "run_id": run_id, "summary": summary, "findings": findings}

    def run_skill(self, workspace_id: str, skill_key: str, user_id: int, source: str = "api") -> Dict[str, Any]:
        workspace = self.get_workspace(workspace_id)
        if not workspace:
            raise ValueError("Workspace not found")
        skill = next((item for item in self.list_skills() if item.get("skill_key") == skill_key), None)
        if not skill:
            raise ValueError("Skill not found")

        latest_snapshot_id = self._latest_snapshot_id(workspace_id)
        run_metadata = {"workspace_id": workspace_id, "skill_key": skill_key, "snapshot_id": latest_snapshot_id}
        run_id = self.run_manager.create_run(
            user_id=user_id,
            run_type="skill_run",
            source=source,
            requested_action="run_skill",
            target=workspace.get("program_handle"),
            metadata=run_metadata,
        )
        self.run_manager.mark_run_started(run_id, f"Executing bounty skill {skill_key}")

        result = self._execute_skill(workspace_id, skill, run_id)
        workspace_dir = self._workspace_dir(workspace_id)
        result_path = workspace_dir / "skills" / f"{run_id}_{skill_key}.json"
        markdown_path = workspace_dir / "skills" / f"{run_id}_{skill_key}.md"
        self._write_json_artifact(result_path, result)
        self._write_text_artifact(markdown_path, self._render_skill_markdown(workspace, skill, result))

        self.run_manager.add_artifact(
            run_id,
            "bounty_skill_result",
            str(result_path),
            label=f"Skill result: {skill_key}",
            metadata={
                "workspace_id": workspace_id,
                "skill_key": skill_key,
                "previewable": True,
                "content_type": "application/json",
                "artifact_role": "skill_result",
            },
        )
        self.run_manager.add_artifact(
            run_id,
            "bounty_skill_markdown",
            str(markdown_path),
            label=f"Skill markdown: {skill_key}",
            metadata={
                "workspace_id": workspace_id,
                "skill_key": skill_key,
                "previewable": True,
                "content_type": "text/markdown",
                "artifact_role": "skill_summary",
            },
        )
        self.run_manager.mark_run_finished(
            run_id,
            status="success",
            message=f"Skill {skill_key} completed",
            metadata={**run_metadata, "result_summary": result.get("summary")},
        )
        return result

    def _id(self, prefix: str) -> str:
        return f"{prefix}_{uuid.uuid4().hex}"

    def _workspace_dir(self, workspace_id: str) -> Path:
        path = self.reports_dir / workspace_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _write_json_artifact(self, path: Path, payload: Dict[str, Any]):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    def _write_text_artifact(self, path: Path, content: str):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _load_skill_yaml(self, path: Path) -> Dict[str, Any]:
        raw = path.read_text(encoding="utf-8")
        if yaml is not None:
            return yaml.safe_load(raw) or {}
        payload: Dict[str, Any] = {}
        current_key: Optional[str] = None
        current_list: Optional[List[str]] = None
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("- ") and current_key:
                if current_list is None:
                    current_list = []
                    payload[current_key] = current_list
                current_list.append(stripped[2:].strip())
                continue
            if ":" not in stripped:
                continue
            key, value = stripped.split(":", 1)
            current_key = key.strip()
            current_list = None
            value = value.strip()
            payload[current_key] = value if value else []
        return payload

    def _serialize_workspace(self, workspace: Dict[str, Any], include_children: bool) -> Dict[str, Any]:
        metadata = workspace.get("metadata") or {}
        base = {
            "id": workspace.get("id"),
            "user_id": workspace.get("user_id"),
            "name": workspace.get("name"),
            "platform": workspace.get("platform"),
            "program_handle": workspace.get("program_handle"),
            "notes": workspace.get("notes"),
            "metadata": metadata,
            "created_at": workspace.get("created_at"),
            "updated_at": workspace.get("updated_at"),
        }
        if include_children:
            base["assets"] = workspace.get("assets", [])
            base["imports"] = workspace.get("imports", [])
            base["graph"] = workspace.get("graph", {"nodes": [], "edges": [], "assets": [], "imports": []})
            base["findings"] = workspace.get("findings", [])
            base["skills"] = workspace.get("skills", [])
        return base

    def _get_workspace_assets(self, workspace_id: str) -> List[Dict[str, Any]]:
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM workspace_assets WHERE workspace_id = ? ORDER BY asset_type ASC, value ASC",
            (workspace_id,),
        )
        rows = self.db._rows_to_dicts(cursor.fetchall())
        conn.close()
        return rows

    def _get_workspace_imports(self, workspace_id: str) -> List[Dict[str, Any]]:
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM workspace_imports WHERE workspace_id = ? ORDER BY created_at DESC",
            (workspace_id,),
        )
        rows = self.db._rows_to_dicts(cursor.fetchall())
        conn.close()
        return rows

    def _get_graph_nodes(self, workspace_id: str) -> List[Dict[str, Any]]:
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM target_graph_nodes WHERE workspace_id = ? ORDER BY node_type ASC, value ASC",
            (workspace_id,),
        )
        rows = self.db._rows_to_dicts(cursor.fetchall())
        conn.close()
        return rows

    def _get_graph_edges(self, workspace_id: str) -> List[Dict[str, Any]]:
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM target_graph_edges WHERE workspace_id = ? ORDER BY edge_type ASC, first_seen ASC",
            (workspace_id,),
        )
        rows = self.db._rows_to_dicts(cursor.fetchall())
        conn.close()
        return rows

    def _touch_workspace(self, workspace_id: str, metadata_updates: Optional[Dict[str, Any]] = None):
        workspace = self.get_workspace(workspace_id)
        if not workspace:
            return
        metadata = workspace.get("metadata") or {}
        if metadata_updates:
            metadata.update(metadata_updates)
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE bounty_workspaces SET metadata = ?, updated_at = ? WHERE id = ?",
            (json.dumps(metadata), _utc_now(), workspace_id),
        )
        conn.commit()
        conn.close()

    def _insert_workspace_import(
        self,
        import_id: str,
        workspace_id: str,
        run_id: str,
        import_type: str,
        source_label: str,
        source_path: Optional[str],
        source_url: Optional[str],
        content_format: Optional[str],
        snapshot_id: str,
        status: str,
        summary: str,
        metadata: Optional[Dict[str, Any]],
    ):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO workspace_imports
            (id, workspace_id, run_id, import_type, source_label, source_path, source_url, content_format, snapshot_id, status, summary, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                import_id,
                workspace_id,
                run_id,
                import_type,
                source_label,
                source_path,
                source_url,
                content_format,
                snapshot_id,
                status,
                summary,
                json.dumps(metadata or {}),
            ),
        )
        conn.commit()
        conn.close()

    def _parse_import_content(self, import_type: str, content: str, content_format: str) -> Dict[str, Any]:
        if import_type == "scope":
            return {"assets": self._parse_scope_assets(content, content_format)}
        if import_type == "disclosed_reports":
            return {"reports": self._parse_disclosed_reports(content, content_format)}
        if import_type in {"url_list", "burp_sitemap", "js_endpoints"}:
            return {"urls": self._extract_urls_from_text(content)}
        if import_type == "notes":
            return {"notes": content, "urls": self._extract_urls_from_text(content)}
        return {}

    def _build_import_summary(
        self,
        import_type: str,
        parsed: Dict[str, Any],
        source_label: str,
        snapshot_id: str,
    ) -> Dict[str, Any]:
        summary = {
            "source_label": source_label,
            "snapshot_id": snapshot_id,
            "import_type": import_type,
        }
        if "assets" in parsed:
            summary["asset_count"] = len(parsed["assets"])
        if "reports" in parsed:
            summary["report_count"] = len(parsed["reports"])
        if "urls" in parsed:
            summary["url_count"] = len(parsed["urls"])
        if "notes" in parsed:
            summary["has_notes"] = True
        return summary

    def _ingest_import_payload(
        self,
        workspace_id: str,
        import_type: str,
        snapshot_id: str,
        parsed: Dict[str, Any],
        source_label: str,
        source_url: Optional[str],
    ) -> Dict[str, Any]:
        created_nodes = 0
        touched_nodes = 0
        created_edges = 0
        touched_assets = 0
        inserted_reports = 0

        if import_type == "scope":
            for asset in parsed.get("assets", []):
                self._upsert_workspace_asset(
                    workspace_id,
                    asset_type=asset["asset_type"],
                    value=asset["value"],
                    in_scope=True,
                    source=source_label,
                    snapshot_id=snapshot_id,
                    metadata={"source_url": source_url},
                )
                touched_assets += 1
                node = self._upsert_node(
                    workspace_id,
                    node_type=asset["node_type"],
                    value=asset["value"],
                    snapshot_id=snapshot_id,
                    metadata={"import_type": import_type, "source_label": source_label},
                )
                created_nodes += int(node["created"])
                touched_nodes += 1
        elif import_type == "disclosed_reports":
            for report in parsed.get("reports", []):
                self._insert_disclosed_report(workspace_id, report)
                inserted_reports += 1
                if report.get("asset_hint"):
                    node = self._upsert_node(
                        workspace_id,
                        node_type="finding_hint",
                        value=report["asset_hint"],
                        snapshot_id=snapshot_id,
                        metadata={
                            "import_type": import_type,
                            "bug_class": report.get("bug_class"),
                            "root_cause": report.get("root_cause"),
                        },
                    )
                    created_nodes += int(node["created"])
                    touched_nodes += 1
        else:
            created_nodes, touched_nodes, created_edges = self._ingest_urls(
                workspace_id=workspace_id,
                urls=parsed.get("urls", []),
                snapshot_id=snapshot_id,
                import_type=import_type,
                source_label=source_label,
            )

        return {
            "created_nodes": created_nodes,
            "touched_nodes": touched_nodes,
            "created_edges": created_edges,
            "touched_assets": touched_assets,
            "inserted_reports": inserted_reports,
        }

    def _parse_scope_assets(self, content: str, content_format: str) -> List[Dict[str, str]]:
        assets: List[Dict[str, str]] = []
        if content_format == "json":
            try:
                data = json.loads(content)
                items = data if isinstance(data, list) else data.get("assets", [])
                for item in items:
                    value = str(item.get("value") or item.get("asset") or item.get("target") or "").strip()
                    if not value:
                        continue
                    assets.append(self._normalize_scope_asset(value))
                return assets
            except Exception:
                pass
        if content_format == "csv":
            lines = [line.strip() for line in content.splitlines() if line.strip()]
            for line in lines[1:] if lines and "," in lines[0] else lines:
                value = line.split(",")[0].strip()
                if value:
                    assets.append(self._normalize_scope_asset(value))
            return assets
        for line in content.splitlines():
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            assets.append(self._normalize_scope_asset(raw))
        return assets

    def _normalize_scope_asset(self, value: str) -> Dict[str, str]:
        parsed = urlparse(value if "://" in value else f"https://{value}")
        host = parsed.netloc or parsed.path
        node_type = "subdomain" if host.count(".") >= 2 else "host"
        asset_type = "url" if parsed.scheme and parsed.netloc else "host"
        return {"value": value, "node_type": "url" if asset_type == "url" else node_type, "asset_type": asset_type}

    def _parse_disclosed_reports(self, content: str, content_format: str) -> List[Dict[str, Any]]:
        reports: List[Dict[str, Any]] = []
        if content_format == "json":
            try:
                data = json.loads(content)
                items = data if isinstance(data, list) else data.get("reports", [])
                for item in items:
                    normalized = self._normalize_disclosed_report(item)
                    if normalized:
                        reports.append(normalized)
                return reports
            except Exception:
                pass
        chunks = re.split(r"\n\s*\n---+\s*\n|\n\s*\n(?=Title:)", content)
        for chunk in chunks:
            block = chunk.strip()
            if not block:
                continue
            normalized = self._normalize_disclosed_report(block)
            if normalized:
                reports.append(normalized)
        return reports

    def _normalize_disclosed_report(self, report: Any) -> Optional[Dict[str, Any]]:
        if isinstance(report, dict):
            title = str(report.get("title") or report.get("name") or "").strip()
            raw_text = json.dumps(report, ensure_ascii=False)
            summary = str(report.get("summary") or report.get("description") or title).strip()
            url = report.get("url")
            severity = str(report.get("severity") or report.get("impact") or "").strip().lower() or None
            published_at = report.get("published_at") or report.get("date")
            external_id = report.get("id") or report.get("external_id")
            source = report.get("source") or "import"
            asset_hint = str(report.get("asset_hint") or report.get("asset") or report.get("target") or "").strip() or None
        else:
            raw_text = str(report).strip()
            title_match = re.search(r"(?im)^title:\s*(.+)$", raw_text)
            title = title_match.group(1).strip() if title_match else raw_text.splitlines()[0][:120]
            summary = raw_text[:800]
            url_match = re.search(r"https?://[^\s)]+", raw_text)
            url = url_match.group(0) if url_match else None
            severity_match = re.search(r"(?i)\b(critical|high|medium|low|informational|info)\b", raw_text)
            severity = severity_match.group(1).lower() if severity_match else None
            published_at = None
            external_id = None
            source = "import"
            asset_hint = self._guess_asset_hint(raw_text)
        title = title.strip()
        if not title:
            return None
        bug_class = self._guess_bug_class(f"{title}\n{summary}\n{raw_text}")
        root_cause = self._guess_root_cause(f"{title}\n{summary}\n{raw_text}")
        auth_context = self._guess_auth_context(f"{title}\n{summary}\n{raw_text}")
        return {
            "source": source,
            "external_id": external_id,
            "title": title,
            "url": url,
            "severity": severity,
            "bug_class": bug_class,
            "root_cause": root_cause,
            "asset_hint": asset_hint,
            "auth_context": auth_context,
            "summary": summary,
            "published_at": published_at,
            "raw_text": raw_text,
            "metadata": {},
        }

    def _extract_urls_from_text(self, content: str) -> List[str]:
        found = re.findall(r"https?://[^\s\"'<>]+", content)
        seen = set()
        urls: List[str] = []
        for item in found:
            normalized = item.rstrip(").,;")
            if normalized not in seen:
                seen.add(normalized)
                urls.append(normalized)
        return urls

    def _ingest_urls(
        self,
        workspace_id: str,
        urls: Sequence[str],
        snapshot_id: str,
        import_type: str,
        source_label: str,
    ) -> Tuple[int, int, int]:
        created_nodes = 0
        touched_nodes = 0
        created_edges = 0
        for url in urls:
            parsed = urlparse(url)
            if not parsed.netloc:
                continue
            host_node = self._upsert_node(
                workspace_id,
                "subdomain" if parsed.netloc.count(".") >= 2 else "host",
                parsed.netloc,
                snapshot_id,
                {"import_type": import_type, "source_label": source_label},
            )
            url_node = self._upsert_node(
                workspace_id,
                "url",
                url,
                snapshot_id,
                {"import_type": import_type, "source_label": source_label},
            )
            route_value = parsed.path or "/"
            route_node = self._upsert_node(
                workspace_id,
                "api_endpoint" if "/api/" in route_value or route_value.endswith(".json") else "route",
                route_value,
                snapshot_id,
                {"import_type": import_type, "source_label": source_label, "host": parsed.netloc},
            )
            created_nodes += int(host_node["created"]) + int(url_node["created"]) + int(route_node["created"])
            touched_nodes += 3
            created_edges += int(
                self._upsert_edge(
                    workspace_id,
                    host_node["id"],
                    "contains",
                    url_node["id"],
                    snapshot_id,
                    {"import_type": import_type},
                )
            )
            created_edges += int(
                self._upsert_edge(
                    workspace_id,
                    url_node["id"],
                    "derived_from",
                    route_node["id"],
                    snapshot_id,
                    {"import_type": import_type},
                )
            )

            query_params = parse_qsl(parsed.query, keep_blank_values=True)
            for name, _value in query_params:
                if not name:
                    continue
                param_node = self._upsert_node(
                    workspace_id,
                    "param",
                    name,
                    snapshot_id,
                    {"import_type": import_type, "source_label": source_label},
                )
                created_nodes += int(param_node["created"])
                touched_nodes += 1
                created_edges += int(
                    self._upsert_edge(
                        workspace_id,
                        route_node["id"],
                        "accepts_param",
                        param_node["id"],
                        snapshot_id,
                        {"import_type": import_type},
                    )
                )

            if parsed.path.endswith(".js"):
                js_node = self._upsert_node(
                    workspace_id,
                    "js_file",
                    url,
                    snapshot_id,
                    {"import_type": import_type, "source_label": source_label},
                )
                created_nodes += int(js_node["created"])
                touched_nodes += 1
                created_edges += int(
                    self._upsert_edge(
                        workspace_id,
                        host_node["id"],
                        "contains",
                        js_node["id"],
                        snapshot_id,
                        {"import_type": import_type},
                    )
                )
        return created_nodes, touched_nodes, created_edges

    def _upsert_workspace_asset(
        self,
        workspace_id: str,
        asset_type: str,
        value: str,
        in_scope: bool,
        source: str,
        snapshot_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        now = _utc_now()
        normalized_value = self._normalize_value(value)
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM workspace_assets
            WHERE workspace_id = ? AND asset_type = ? AND normalized_value = ?
            """,
            (workspace_id, asset_type, normalized_value),
        )
        row = cursor.fetchone()
        if row:
            current = self.db._rows_to_dicts([row])[0]
            meta = current.get("metadata") or {}
            meta.update(metadata or {})
            meta["last_snapshot_id"] = snapshot_id
            cursor.execute(
                """
                UPDATE workspace_assets
                SET value = ?, in_scope = ?, source = ?, last_seen = ?, metadata = ?
                WHERE id = ?
                """,
                (value, int(in_scope), source, now, json.dumps(meta), current["id"]),
            )
        else:
            cursor.execute(
                """
                INSERT INTO workspace_assets
                (id, workspace_id, asset_type, value, normalized_value, in_scope, source, first_seen, last_seen, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self._id("asset"),
                    workspace_id,
                    asset_type,
                    value,
                    normalized_value,
                    int(in_scope),
                    source,
                    now,
                    now,
                    json.dumps({"first_snapshot_id": snapshot_id, "last_snapshot_id": snapshot_id, **(metadata or {})}),
                ),
            )
        conn.commit()
        conn.close()

    def _upsert_node(
        self,
        workspace_id: str,
        node_type: str,
        value: str,
        snapshot_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if node_type not in NODE_TYPES:
            raise ValueError(f"Unsupported node type: {node_type}")
        now = _utc_now()
        normalized_key = self._normalize_value(value)
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM target_graph_nodes
            WHERE workspace_id = ? AND node_type = ? AND normalized_key = ?
            """,
            (workspace_id, node_type, normalized_key),
        )
        row = cursor.fetchone()
        if row:
            item = self.db._rows_to_dicts([row])[0]
            meta = item.get("metadata") or {}
            meta.update(metadata or {})
            meta["last_snapshot_id"] = snapshot_id
            meta["is_new_since_last_snapshot"] = meta.get("first_snapshot_id") == snapshot_id
            cursor.execute(
                """
                UPDATE target_graph_nodes
                SET value = ?, last_seen = ?, metadata = ?
                WHERE id = ?
                """,
                (value, now, json.dumps(meta), item["id"]),
            )
            conn.commit()
            conn.close()
            return {"id": item["id"], "created": False}

        node_id = self._id("node")
        payload = {"first_snapshot_id": snapshot_id, "last_snapshot_id": snapshot_id, "is_new_since_last_snapshot": True, **(metadata or {})}
        cursor.execute(
            """
            INSERT INTO target_graph_nodes
            (id, workspace_id, node_type, normalized_key, value, first_seen, last_seen, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (node_id, workspace_id, node_type, normalized_key, value, now, now, json.dumps(payload)),
        )
        conn.commit()
        conn.close()
        return {"id": node_id, "created": True}

    def _upsert_edge(
        self,
        workspace_id: str,
        from_node_id: str,
        edge_type: str,
        to_node_id: str,
        snapshot_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        if edge_type not in EDGE_TYPES:
            raise ValueError(f"Unsupported edge type: {edge_type}")
        now = _utc_now()
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM target_graph_edges
            WHERE workspace_id = ? AND from_node_id = ? AND edge_type = ? AND to_node_id = ?
            """,
            (workspace_id, from_node_id, edge_type, to_node_id),
        )
        row = cursor.fetchone()
        if row:
            item = self.db._rows_to_dicts([row])[0]
            meta = item.get("metadata") or {}
            meta.update(metadata or {})
            meta["last_snapshot_id"] = snapshot_id
            cursor.execute(
                "UPDATE target_graph_edges SET last_seen = ?, metadata = ? WHERE id = ?",
                (now, json.dumps(meta), item["id"]),
            )
            conn.commit()
            conn.close()
            return False
        cursor.execute(
            """
            INSERT INTO target_graph_edges
            (id, workspace_id, from_node_id, edge_type, to_node_id, first_seen, last_seen, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self._id("edge"),
                workspace_id,
                from_node_id,
                edge_type,
                to_node_id,
                now,
                now,
                json.dumps({"first_snapshot_id": snapshot_id, "last_snapshot_id": snapshot_id, **(metadata or {})}),
            ),
        )
        conn.commit()
        conn.close()
        return True

    def _insert_disclosed_report(self, workspace_id: str, report: Dict[str, Any]):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO disclosed_reports
            (id, workspace_id, source, external_id, title, url, severity, bug_class, root_cause, asset_hint, auth_context, summary, published_at, raw_text, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self._id("report"),
                workspace_id,
                report.get("source"),
                report.get("external_id"),
                report.get("title"),
                report.get("url"),
                report.get("severity"),
                report.get("bug_class"),
                report.get("root_cause"),
                report.get("asset_hint"),
                report.get("auth_context"),
                report.get("summary"),
                report.get("published_at"),
                report.get("raw_text"),
                json.dumps(report.get("metadata") or {}),
            ),
        )
        conn.commit()
        conn.close()

    def _get_disclosed_reports(self, workspace_id: str) -> List[Dict[str, Any]]:
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM disclosed_reports WHERE workspace_id = ? ORDER BY published_at DESC, title ASC",
            (workspace_id,),
        )
        rows = self.db._rows_to_dicts(cursor.fetchall())
        conn.close()
        return rows

    def _normalize_value(self, value: str) -> str:
        return re.sub(r"\s+", "", str(value).strip().lower())

    def _guess_bug_class(self, text: str) -> str:
        lowered = text.lower()
        patterns = [
            ("idor", ("idor", "insecure direct object", "authorization bypass", "horizontal privilege")),
            ("ssrf", ("ssrf", "server-side request forgery")),
            ("xss", ("xss", "cross-site scripting")),
            ("sqli", ("sql injection", "sqli")),
            ("authz", ("broken access control", "access control", "privilege escalation", "authorization")),
            ("graphql", ("graphql",)),
            ("cache-poisoning", ("cache poisoning",)),
            ("open-redirect", ("open redirect", "redirect bypass")),
            ("csrf", ("csrf", "cross-site request forgery")),
        ]
        for label, needles in patterns:
            if any(needle in lowered for needle in needles):
                return label
        return "unknown"

    def _guess_root_cause(self, text: str) -> str:
        lowered = text.lower()
        if "missing authorization" in lowered or "authorization" in lowered:
            return "authorization_check_missing"
        if "token" in lowered and "predict" in lowered:
            return "predictable_token"
        if "redirect" in lowered:
            return "unsafe_redirect_validation"
        if "graphql" in lowered:
            return "graphql_surface_exposure"
        if "debug" in lowered or "internal" in lowered:
            return "internal_surface_exposure"
        if "cache" in lowered:
            return "cache_key_misuse"
        if "parameter" in lowered or "query" in lowered:
            return "unsafe_parameter_handling"
        return "unknown"

    def _guess_auth_context(self, text: str) -> str:
        lowered = text.lower()
        if "admin" in lowered:
            return "admin"
        if "authenticated" in lowered or "logged in" in lowered:
            return "authenticated"
        if "unauthenticated" in lowered or "guest" in lowered:
            return "unauthenticated"
        if "cross-tenant" in lowered or "tenant" in lowered:
            return "cross_tenant"
        return "unknown"

    def _guess_asset_hint(self, text: str) -> Optional[str]:
        urls = self._extract_urls_from_text(text)
        if urls:
            return urls[0]
        host_match = re.search(r"\b([a-z0-9-]+\.)+[a-z]{2,}\b", text.lower())
        return host_match.group(0) if host_match else None

    def _latest_snapshot_id(self, workspace_id: str) -> Optional[str]:
        imports = self._get_workspace_imports(workspace_id)
        for item in imports:
            snapshot_id = item.get("snapshot_id")
            if snapshot_id:
                return snapshot_id
        return None

    def _archive_findings(self, workspace_id: str):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE novelty_findings SET status = 'archived' WHERE workspace_id = ? AND status != 'archived'",
            (workspace_id,),
        )
        conn.commit()
        conn.close()

    def _insert_finding(self, workspace_id: str, run_id: str, finding: Dict[str, Any]):
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO novelty_findings
            (id, workspace_id, fingerprint, title, category, novelty_score, duplicate_risk_score, confidence, status, rationale, primary_node_id, run_id, metadata, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self._id("finding"),
                workspace_id,
                finding["fingerprint"],
                finding["title"],
                finding["category"],
                finding["novelty_score"],
                finding["duplicate_risk_score"],
                finding["confidence"],
                finding.get("status", "open"),
                finding["rationale"],
                finding.get("primary_node_id"),
                run_id,
                json.dumps(finding.get("metadata") or {}),
                _utc_now(),
            ),
        )
        conn.commit()
        conn.close()

    def _ingest_recon_run_artifacts(self, workspace_id: str):
        runs = self.db.list_runs(workspace_id=workspace_id, limit=200)
        latest_snapshot_id = self._latest_snapshot_id(workspace_id) or self._id("snapshot")
        for run in runs:
            metadata = run.get("metadata") or {}
            artifacts = self.db.get_run_artifacts(run["id"])
            for artifact in artifacts:
                artifact_type = artifact.get("artifact_type") or ""
                if artifact_type not in {"report_json", "report_markdown", "flow_summary_json", "flow_summary_markdown", "workspace_import_raw"}:
                    continue
                path = Path(artifact.get("path") or "")
                if not path.exists():
                    continue
                try:
                    raw = path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                source_label = metadata.get("script") or metadata.get("flow_id") or run.get("requested_action") or "recon_artifact"
                self._ingest_urls(
                    workspace_id=workspace_id,
                    urls=self._extract_urls_from_text(raw),
                    snapshot_id=latest_snapshot_id,
                    import_type="url_list",
                    source_label=source_label,
                )

    def _build_findings(
        self,
        workspace_id: str,
        graph: Dict[str, Any],
        reports: List[Dict[str, Any]],
        latest_snapshot_id: Optional[str],
        run_id: str,
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        nodes = graph.get("nodes", [])
        bug_class_counts = Counter((report.get("bug_class") or "unknown") for report in reports)
        report_asset_hints = [report.get("asset_hint") for report in reports if report.get("asset_hint")]
        findings: List[Dict[str, Any]] = []
        seen_fingerprints = set()

        for node in nodes:
            node_meta = node.get("metadata") or {}
            novelty_score = self._score_novelty(node, latest_snapshot_id, report_asset_hints)
            duplicate_risk_score = self._score_duplicate_risk(node, latest_snapshot_id, bug_class_counts)
            category = self._categorize_finding(node, novelty_score, duplicate_risk_score, latest_snapshot_id)
            rationale = self._finding_rationale(node, novelty_score, duplicate_risk_score, latest_snapshot_id, bug_class_counts)
            fingerprint = hashlib.sha256(f"{workspace_id}:{node['node_type']}:{node['normalized_key']}:{category}".encode("utf-8")).hexdigest()  # type: ignore[name-defined]
            if fingerprint in seen_fingerprints:
                continue
            seen_fingerprints.add(fingerprint)
            findings.append(
                {
                    "fingerprint": fingerprint,
                    "title": self._finding_title(node, category),
                    "category": category,
                    "novelty_score": novelty_score,
                    "duplicate_risk_score": duplicate_risk_score,
                    "confidence": round(max(0.35, min(0.95, novelty_score / 100.0)), 2),
                    "status": "open",
                    "rationale": rationale,
                    "primary_node_id": node["id"],
                    "metadata": {
                        "workspace_id": workspace_id,
                        "run_id": run_id,
                        "node_type": node.get("node_type"),
                        "node_value": node.get("value"),
                        "snapshot_id": latest_snapshot_id,
                        "evidence_links": [{"type": "graph_node", "id": node["id"]}],
                        "is_new_since_last_snapshot": bool(node_meta.get("first_snapshot_id") == latest_snapshot_id),
                    },
                }
            )

        findings.sort(key=lambda item: (-item["novelty_score"], item["duplicate_risk_score"]))
        findings = findings[:40]
        summary = {
            "workspace_id": workspace_id,
            "snapshot_id": latest_snapshot_id,
            "node_count": len(nodes),
            "edge_count": len(graph.get("edges", [])),
            "report_count": len(reports),
            "finding_count": len(findings),
            "category_counts": dict(Counter(item["category"] for item in findings)),
        }
        return findings, summary

    def _score_novelty(self, node: Dict[str, Any], latest_snapshot_id: Optional[str], report_asset_hints: Sequence[str]) -> float:
        meta = node.get("metadata") or {}
        value = (node.get("value") or "").lower()
        score = 35.0
        if meta.get("first_snapshot_id") == latest_snapshot_id and latest_snapshot_id:
            score += 35
        if node.get("node_type") in {"api_endpoint", "js_file"}:
            score += 12
        if node.get("node_type") == "param" and any(hint in value for hint in WEIRD_PARAM_HINTS):
            score += 18
        if node.get("node_type") in {"route", "api_endpoint", "url"} and any(hint in value for hint in INTERESTING_ROUTE_HINTS):
            score += 14
        if value.endswith(".json") or "/v1/" in value or "/v2/" in value:
            score += 8
        if report_asset_hints and not any((hint or "").lower() in value for hint in report_asset_hints):
            score += 7
        return round(min(99.0, score), 2)

    def _score_duplicate_risk(
        self,
        node: Dict[str, Any],
        latest_snapshot_id: Optional[str],
        bug_class_counts: Counter,
    ) -> float:
        meta = node.get("metadata") or {}
        value = (node.get("value") or "").lower()
        score = 20.0
        if meta.get("first_snapshot_id") != latest_snapshot_id:
            score += 20
        if node.get("node_type") in {"route", "url"} and any(token in value for token in ("login", "admin", "robots.txt", "sitemap.xml")):
            score += 35
        if node.get("node_type") == "param" and value in COMMON_PARAM_HINTS:
            score += 35
        if bug_class_counts.get("authz", 0) >= 3 and any(token in value for token in ("admin", "role", "permission")):
            score += 10
        if bug_class_counts.get("xss", 0) >= 2 and node.get("node_type") == "param" and value in {"q", "query", "search"}:
            score += 10
        return round(min(99.0, score), 2)

    def _categorize_finding(
        self,
        node: Dict[str, Any],
        novelty_score: float,
        duplicate_risk_score: float,
        latest_snapshot_id: Optional[str],
    ) -> str:
        meta = node.get("metadata") or {}
        if duplicate_risk_score >= 65:
            return "likely_duplicate"
        if meta.get("first_snapshot_id") == latest_snapshot_id and novelty_score >= 70:
            return "what_changed"
        if novelty_score >= 78 and duplicate_risk_score <= 45:
            return "worth_manual_time"
        return "what_is_weird"

    def _finding_title(self, node: Dict[str, Any], category: str) -> str:
        prefixes = {
            "what_changed": "Cambio detectado",
            "what_is_weird": "Superficie rara",
            "worth_manual_time": "Hipotesis prometedora",
            "likely_duplicate": "Riesgo de duplicado alto",
        }
        return f"{prefixes.get(category, 'Finding')} · {node.get('node_type')} · {node.get('value')}"

    def _finding_rationale(
        self,
        node: Dict[str, Any],
        novelty_score: float,
        duplicate_risk_score: float,
        latest_snapshot_id: Optional[str],
        bug_class_counts: Counter,
    ) -> str:
        meta = node.get("metadata") or {}
        parts = []
        if meta.get("first_snapshot_id") == latest_snapshot_id:
            parts.append("Es nuevo en el snapshot más reciente.")
        if node.get("node_type") in {"api_endpoint", "js_file"}:
            parts.append("Pertenece a una superficie web/API que suele cambiar más rápido que el scope obvio.")
        if node.get("node_type") == "param":
            parts.append("Es un parámetro potencialmente útil para testing manual y correlación de authz.")
        if duplicate_risk_score >= 65:
            parts.append("Se parece demasiado a superficies o patrones muy trillados y conviene tratarlo con cautela.")
        if bug_class_counts:
            saturated = bug_class_counts.most_common(1)[0]
            parts.append(f"Contexto de disclosed reports: {saturated[0]} aparece {saturated[1]} veces en el histórico importado.")
        parts.append(f"Novelty score {novelty_score}/100; duplicate risk {duplicate_risk_score}/100.")
        return " ".join(parts)

    def _execute_skill(self, workspace_id: str, skill: Dict[str, Any], run_id: str) -> Dict[str, Any]:
        graph = self.get_workspace_graph(workspace_id)
        findings = self.list_findings(workspace_id, include_archived=False)
        reports = self._get_disclosed_reports(workspace_id)
        latest_snapshot_id = self._latest_snapshot_id(workspace_id)
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        key = skill.get("skill_key")

        if key == "program_intel":
            payload = {
                "summary": {
                    "assets": len(graph.get("assets", [])),
                    "imports": len(graph.get("imports", [])),
                    "nodes": len(nodes),
                    "edges": len(edges),
                    "disclosed_reports": len(reports),
                    "latest_snapshot_id": latest_snapshot_id,
                },
                "top_asset_types": Counter(asset.get("asset_type") for asset in graph.get("assets", [])).most_common(10),
            }
        elif key == "disclosed_report_graph":
            payload = {
                "summary": {
                    "report_count": len(reports),
                    "bug_classes": Counter(report.get("bug_class") or "unknown" for report in reports),
                    "root_causes": Counter(report.get("root_cause") or "unknown" for report in reports),
                    "auth_contexts": Counter(report.get("auth_context") or "unknown" for report in reports),
                }
            }
        elif key == "delta_recon":
            payload = {
                "summary": {"latest_snapshot_id": latest_snapshot_id},
                "new_nodes": [node for node in nodes if (node.get("metadata") or {}).get("first_snapshot_id") == latest_snapshot_id][:50],
            }
        elif key == "js_api_diff":
            payload = {
                "summary": {"latest_snapshot_id": latest_snapshot_id},
                "js_and_api_nodes": [
                    node for node in nodes
                    if node.get("node_type") in {"js_file", "api_endpoint"}
                    and (node.get("metadata") or {}).get("first_snapshot_id") == latest_snapshot_id
                ][:50],
            }
        elif key == "authz_matrix":
            payload = {
                "summary": {"latest_snapshot_id": latest_snapshot_id},
                "auth_nodes": [node for node in nodes if any(token in str(node.get("value", "")).lower() for token in AUTH_HINTS)][:50],
                "auth_contexts": Counter(report.get("auth_context") or "unknown" for report in reports),
            }
        elif key == "duplicate_risk":
            payload = {
                "summary": {"finding_count": len(findings)},
                "high_duplicate_risk": [finding for finding in findings if finding.get("duplicate_risk_score", 0) >= 65][:25],
            }
        elif key == "report_novelty_gate":
            payload = {
                "summary": {"finding_count": len(findings)},
                "recommended": [
                    finding
                    for finding in findings
                    if finding.get("novelty_score", 0) >= 75 and finding.get("duplicate_risk_score", 100) <= 45
                ][:20],
            }
        else:
            payload = {"summary": {"message": "Skill not yet specialized"}, "nodes": nodes[:20], "findings": findings[:20]}

        payload.update(
            {
                "workspace_id": workspace_id,
                "run_id": run_id,
                "skill_key": key,
                "skill_name": skill.get("name"),
                "goal": skill.get("goal"),
                "latest_snapshot_id": latest_snapshot_id,
            }
        )
        return payload

    def _render_findings_markdown(self, workspace: Dict[str, Any], summary: Dict[str, Any], findings: Sequence[Dict[str, Any]]) -> str:
        lines = [
            f"# Bounty analysis for {workspace.get('name')}",
            "",
            f"- Platform: {workspace.get('platform')}",
            f"- Program: {workspace.get('program_handle')}",
            f"- Snapshot: {summary.get('snapshot_id') or 'n/a'}",
            f"- Findings: {summary.get('finding_count', 0)}",
            "",
            "## Category counts",
        ]
        for key, value in (summary.get("category_counts") or {}).items():
            lines.append(f"- {key}: {value}")
        lines.append("")
        lines.append("## Priority queue")
        for finding in findings[:20]:
            lines.append(f"- {finding['title']}")
            lines.append(f"  - novelty: {finding['novelty_score']}")
            lines.append(f"  - duplicate risk: {finding['duplicate_risk_score']}")
            lines.append(f"  - rationale: {finding['rationale']}")
        return "\n".join(lines)

    def _render_skill_markdown(self, workspace: Dict[str, Any], skill: Dict[str, Any], result: Dict[str, Any]) -> str:
        lines = [
            f"# Skill run: {skill.get('name')}",
            "",
            f"- Workspace: {workspace.get('name')}",
            f"- Program: {workspace.get('program_handle')}",
            f"- Skill key: {skill.get('skill_key')}",
            f"- Goal: {skill.get('goal')}",
            "",
            "## Result",
            "```json",
            json.dumps(result, indent=2, ensure_ascii=False),
            "```",
        ]
        return "\n".join(lines)
