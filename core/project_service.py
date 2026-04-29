#!/usr/bin/env python3
"""
BOFA project service.

Shared project context for SaaS, labs, tooling and bounty workspaces.
"""

from __future__ import annotations

from datetime import datetime
import json
import re
from typing import Any, Dict, List, Optional
import uuid


def _utc_now() -> str:
    return datetime.utcnow().isoformat()


def _safe_slug(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower())
    normalized = normalized.strip("-")
    return normalized or "project"


class ProjectService:
    def __init__(self, database_manager):
        self.db = database_manager

    def _id(self, prefix: str) -> str:
        return f"{prefix}_{uuid.uuid4().hex[:12]}"

    def create_project(
        self,
        owner_user_id: int,
        name: str,
        slug: Optional[str] = None,
        description: str = "",
        project_type: str = "workspace",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        project_slug = _safe_slug(slug or name)
        now = _utc_now()
        payload = metadata or {}
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM projects WHERE slug = ?", (project_slug,))
        if cursor.fetchone():
            conn.close()
            raise ValueError("Project slug already exists")

        project_id = self._id("project")
        member_id = self._id("project_member")
        cursor.execute(
            """
            INSERT INTO projects
            (id, owner_user_id, name, slug, description, project_type, status, metadata, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project_id,
                owner_user_id,
                name,
                project_slug,
                description,
                project_type,
                "active",
                json.dumps(payload),
                now,
                now,
            ),
        )
        cursor.execute(
            """
            INSERT INTO project_members
            (id, project_id, user_id, role, status, metadata, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (member_id, project_id, owner_user_id, "owner", "active", json.dumps({"auto_added": True}), now, now),
        )
        conn.commit()
        conn.close()
        return self.get_project_detail(project_id) or {}

    def list_projects(self, user_id: Optional[int] = None) -> List[Dict[str, Any]]:
        conn = self.db.get_connection()
        cursor = conn.cursor()
        if user_id is None:
            cursor.execute("SELECT * FROM projects ORDER BY updated_at DESC, created_at DESC")
        else:
            cursor.execute(
                """
                SELECT DISTINCT p.*
                FROM projects p
                LEFT JOIN project_members pm ON pm.project_id = p.id
                WHERE p.owner_user_id = ? OR (pm.user_id = ? AND pm.status = 'active')
                ORDER BY p.updated_at DESC, p.created_at DESC
                """,
                (user_id, user_id),
            )
        rows = self.db._rows_to_dicts(cursor.fetchall())
        conn.close()
        return [self._serialize_project(row, include_children=False) for row in rows]

    def get_project(self, project_id: str) -> Optional[Dict[str, Any]]:
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return self.db._rows_to_dicts([row])[0]

    def get_project_detail(self, project_id: str) -> Optional[Dict[str, Any]]:
        project = self.get_project(project_id)
        if not project:
            return None
        project["members"] = self.list_members(project_id)
        project["environments"] = self.list_environments(project_id)
        project["workspaces"] = self.list_linked_workspaces(project_id)
        project["recent_runs"] = self.db.list_runs(project_id=project_id, limit=10)
        project["stats"] = {
            "member_count": len(project["members"]),
            "environment_count": len(project["environments"]),
            "workspace_count": len(project["workspaces"]),
            "recent_run_count": len(project["recent_runs"]),
        }
        return self._serialize_project(project, include_children=True)

    def list_members(self, project_id: str) -> List[Dict[str, Any]]:
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT pm.*, u.username, u.email, u.role AS global_role
            FROM project_members pm
            JOIN users u ON u.id = pm.user_id
            WHERE pm.project_id = ?
            ORDER BY
                CASE pm.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,
                u.username ASC
            """,
            (project_id,),
        )
        rows = self.db._rows_to_dicts(cursor.fetchall())
        conn.close()
        return rows

    def list_environments(self, project_id: str) -> List[Dict[str, Any]]:
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM project_environments WHERE project_id = ? ORDER BY updated_at DESC, created_at DESC",
            (project_id,),
        )
        rows = self.db._rows_to_dicts(cursor.fetchall())
        conn.close()
        return rows

    def list_linked_workspaces(self, project_id: str) -> List[Dict[str, Any]]:
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, user_id, project_id, name, platform, program_handle, notes, metadata, created_at, updated_at
            FROM bounty_workspaces
            WHERE project_id = ?
            ORDER BY updated_at DESC, created_at DESC
            """,
            (project_id,),
        )
        rows = self.db._rows_to_dicts(cursor.fetchall())
        conn.close()
        return rows

    def get_member_role(self, project_id: str, user_id: int) -> Optional[str]:
        project = self.get_project(project_id)
        if not project:
            return None
        if project.get("owner_user_id") == user_id:
            return "owner"
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT role FROM project_members WHERE project_id = ? AND user_id = ? AND status = 'active'",
            (project_id, user_id),
        )
        row = cursor.fetchone()
        conn.close()
        return row["role"] if row else None

    def user_can_access(self, project_id: str, user_id: int, role: Optional[str] = None) -> bool:
        if role == "admin":
            return True
        return self.get_member_role(project_id, user_id) is not None

    def user_can_manage(self, project_id: str, user_id: int, role: Optional[str] = None) -> bool:
        if role == "admin":
            return True
        member_role = self.get_member_role(project_id, user_id)
        return member_role in {"owner", "admin"}

    def add_member(
        self,
        project_id: str,
        actor_user_id: int,
        actor_role: str,
        username: str,
        role: str = "member",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not self.user_can_manage(project_id, actor_user_id, actor_role):
            raise PermissionError("Access denied")
        user = self.db.get_user_by_username(username)
        if not user:
            raise ValueError("User not found")

        now = _utc_now()
        payload = metadata or {}
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM project_members WHERE project_id = ? AND user_id = ?",
            (project_id, user["id"]),
        )
        existing = cursor.fetchone()
        if existing:
            cursor.execute(
                """
                UPDATE project_members
                SET role = ?, status = 'active', metadata = ?, updated_at = ?
                WHERE id = ?
                """,
                (role, json.dumps(payload), now, existing["id"]),
            )
            member_id = existing["id"]
        else:
            member_id = self._id("project_member")
            cursor.execute(
                """
                INSERT INTO project_members
                (id, project_id, user_id, role, status, metadata, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (member_id, project_id, user["id"], role, "active", json.dumps(payload), now, now),
            )
        cursor.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (now, project_id))
        conn.commit()
        conn.close()
        members = self.list_members(project_id)
        return next((member for member in members if member.get("id") == member_id), {})

    def create_environment(
        self,
        project_id: str,
        actor_user_id: int,
        actor_role: str,
        name: str,
        environment_type: str = "web",
        base_url: str = "",
        scope: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not self.user_can_manage(project_id, actor_user_id, actor_role):
            raise PermissionError("Access denied")
        now = _utc_now()
        environment_id = self._id("project_env")
        payload = metadata or {}
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO project_environments
            (id, project_id, name, environment_type, base_url, scope, metadata, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (environment_id, project_id, name, environment_type, base_url, scope, json.dumps(payload), now, now),
        )
        cursor.execute("UPDATE projects SET updated_at = ? WHERE id = ?", (now, project_id))
        conn.commit()
        conn.close()
        environments = self.list_environments(project_id)
        return next((environment for environment in environments if environment.get("id") == environment_id), {})

    def _serialize_project(self, project: Dict[str, Any], include_children: bool) -> Dict[str, Any]:
        base = {
            "id": project.get("id"),
            "owner_user_id": project.get("owner_user_id"),
            "name": project.get("name"),
            "slug": project.get("slug"),
            "description": project.get("description"),
            "project_type": project.get("project_type"),
            "status": project.get("status"),
            "metadata": project.get("metadata") or {},
            "created_at": project.get("created_at"),
            "updated_at": project.get("updated_at"),
        }
        if include_children:
            base["members"] = project.get("members", [])
            base["environments"] = project.get("environments", [])
            base["workspaces"] = project.get("workspaces", [])
            base["recent_runs"] = project.get("recent_runs", [])
            base["stats"] = project.get("stats", {})
        return base
