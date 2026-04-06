#!/usr/bin/env python3
"""
BOFA Extended Systems v2.5.1 - Database Models and Connection
SQLite database manager for BOFA runtime, history and observability.
"""

import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

APP_ROOT = Path(os.getenv("BOFA_APP_ROOT", Path(__file__).resolve().parents[1]))
DEFAULT_DB_PATH = Path(os.getenv("BOFA_DB_PATH", APP_ROOT / "data" / "bofa.db"))


def _utc_now() -> str:
    return datetime.utcnow().isoformat()


class DatabaseManager:
    def __init__(self, db_path: str = str(DEFAULT_DB_PATH)):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_database()

    def get_connection(self):
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_database(self):
        """Initialize database tables."""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS script_executions (
                id TEXT PRIMARY KEY,
                user_id INTEGER,
                module TEXT NOT NULL,
                script_name TEXT NOT NULL,
                parameters TEXT,
                status TEXT DEFAULT 'running',
                output TEXT,
                error_message TEXT,
                execution_time REAL,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                run_id TEXT,
                step_id TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS lab_instances (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lab_id TEXT NOT NULL,
                user_id INTEGER,
                container_id TEXT,
                status TEXT DEFAULT 'stopped',
                port INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                started_at TIMESTAMP,
                stopped_at TIMESTAMP,
                run_id TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_type TEXT NOT NULL,
                metric_value REAL NOT NULL,
                metadata TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                service_name TEXT NOT NULL,
                api_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS learning_progress (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                lesson_id TEXT NOT NULL,
                progress REAL DEFAULT 0,
                completed BOOLEAN DEFAULT 0,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS operation_runs (
                id TEXT PRIMARY KEY,
                user_id INTEGER,
                run_type TEXT NOT NULL,
                source TEXT,
                status TEXT DEFAULT 'queued',
                target TEXT,
                requested_action TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                parent_run_id TEXT,
                metadata TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS run_steps (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                step_type TEXT NOT NULL,
                step_key TEXT,
                module TEXT,
                script_name TEXT,
                status TEXT DEFAULT 'queued',
                step_index INTEGER DEFAULT 0,
                parameters TEXT,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                exit_code INTEGER,
                duration REAL,
                stdout_preview TEXT,
                stderr_preview TEXT,
                error_message TEXT,
                metadata TEXT,
                FOREIGN KEY (run_id) REFERENCES operation_runs (id)
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS run_labs (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                lab_id TEXT NOT NULL,
                container_id TEXT,
                status TEXT DEFAULT 'queued',
                port INTEGER,
                started_at TIMESTAMP,
                stopped_at TIMESTAMP,
                metadata TEXT,
                FOREIGN KEY (run_id) REFERENCES operation_runs (id)
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS run_events (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                scope_type TEXT NOT NULL,
                scope_id TEXT,
                event_type TEXT NOT NULL,
                status TEXT,
                message TEXT,
                payload TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (run_id) REFERENCES operation_runs (id)
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS run_artifacts (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                path TEXT NOT NULL,
                label TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (run_id) REFERENCES operation_runs (id)
            )
            """
        )

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_operation_runs_user_created ON operation_runs (user_id, created_at DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_operation_runs_status_created ON operation_runs (status, created_at DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_run_steps_run_id ON run_steps (run_id, step_index)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_run_labs_run_id ON run_labs (run_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_run_events_run_id ON run_events (run_id, created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_run_artifacts_run_id ON run_artifacts (run_id, created_at)")

        self._ensure_column(cursor, "script_executions", "run_id", "TEXT")
        self._ensure_column(cursor, "script_executions", "step_id", "TEXT")
        self._ensure_column(cursor, "lab_instances", "run_id", "TEXT")

        conn.commit()
        conn.close()

        self.create_default_admin()
        logger.info("Database initialized successfully")

    def _ensure_column(self, cursor, table_name: str, column_name: str, column_type: str):
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = {row[1] for row in cursor.fetchall()}
        if column_name not in columns:
            cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")

    def _to_json(self, value: Optional[Dict[str, Any]]) -> Optional[str]:
        return json.dumps(value) if value is not None else None

    def _rows_to_dicts(self, rows) -> List[Dict[str, Any]]:
        items = [dict(row) for row in rows]
        for item in items:
            for key in ("parameters", "metadata", "payload", "result"):
                if key in item and isinstance(item[key], str):
                    try:
                        item[key] = json.loads(item[key])
                    except Exception:
                        pass
        return items

    def create_default_admin(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", ("admin",))
        if cursor.fetchone():
            conn.close()
            return

        import hashlib

        password_hash = hashlib.sha256("admin123".encode()).hexdigest()
        cursor.execute(
            """
            INSERT INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, ?)
            """,
            ("admin", "admin@bofa.local", password_hash, "admin"),
        )
        conn.commit()
        conn.close()
        logger.info("Default admin user created (admin/admin123)")

    def create_user(self, username: str, email: str, password_hash: str, role: str = "user"):
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO users (username, email, password_hash, role)
                VALUES (?, ?, ?, ?)
                """,
                (username, email, password_hash, role),
            )
            user_id = cursor.lastrowid
            conn.commit()
            return user_id
        except sqlite3.IntegrityError:
            return None
        finally:
            conn.close()

    def get_user_by_username(self, username: str):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,))
        user = cursor.fetchone()
        conn.close()
        return dict(user) if user else None

    def update_last_login(self, user_id: int):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()

    def create_execution(self, execution_id: str, user_id: int, module: str, script_name: str, parameters: dict, run_id: str = None, step_id: str = None):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO script_executions
            (id, user_id, module, script_name, parameters, status, run_id, step_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (execution_id, user_id, module, script_name, json.dumps(parameters), "running", run_id, step_id),
        )
        conn.commit()
        conn.close()

    def update_execution(
        self,
        execution_id: str,
        status: str,
        output: str = None,
        error_message: str = None,
        execution_time: float = None,
    ):
        conn = self.get_connection()
        cursor = conn.cursor()
        completed_at = "CURRENT_TIMESTAMP" if status in {"success", "error", "failed", "cancelled"} else "NULL"
        cursor.execute(
            f"""
            UPDATE script_executions
            SET status = ?, output = COALESCE(?, output), error_message = COALESCE(?, error_message),
                execution_time = COALESCE(?, execution_time), completed_at = {completed_at}
            WHERE id = ?
            """,
            (status, output, error_message, execution_time, execution_id),
        )
        conn.commit()
        conn.close()

    def get_execution_history(self, user_id: int = None, limit: int = 50):
        conn = self.get_connection()
        cursor = conn.cursor()
        if user_id:
            cursor.execute(
                """
                SELECT se.id, se.script_name, se.module, se.parameters, se.status, se.output,
                       se.error_message AS error, se.execution_time, se.started_at AS timestamp,
                       se.run_id, se.step_id
                FROM script_executions se
                WHERE se.user_id = ?
                ORDER BY se.started_at DESC LIMIT ?
                """,
                (user_id, limit),
            )
        else:
            cursor.execute(
                """
                SELECT se.id, se.script_name, se.module, se.parameters, se.status, se.output,
                       se.error_message AS error, se.execution_time, se.started_at AS timestamp,
                       se.run_id, se.step_id
                FROM script_executions se
                ORDER BY se.started_at DESC LIMIT ?
                """,
                (limit,),
            )
        executions = self._rows_to_dicts(cursor.fetchall())
        conn.close()
        return executions

    def create_lab_instance(self, lab_id: str, user_id: int, container_id: str = None, port: int = None, run_id: str = None):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO lab_instances (lab_id, user_id, container_id, port, status, run_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (lab_id, user_id, container_id, port, "starting", run_id),
        )
        instance_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return instance_id

    def update_lab_status(self, lab_id: str, user_id: int, status: str, container_id: str = None, port: int = None):
        conn = self.get_connection()
        cursor = conn.cursor()
        now_field = "started_at = CURRENT_TIMESTAMP" if status == "running" else "stopped_at = CURRENT_TIMESTAMP" if status == "stopped" else ""
        updates = ["status = ?"]
        params: List[Any] = [status]
        if container_id is not None:
            updates.append("container_id = ?")
            params.append(container_id)
        if port is not None:
            updates.append("port = ?")
            params.append(port)
        if now_field:
            updates.append(now_field)
        params.extend([lab_id, user_id])
        cursor.execute(
            f"""
            UPDATE lab_instances
            SET {", ".join(updates)}
            WHERE lab_id = ? AND user_id = ?
            """,
            tuple(params),
        )
        conn.commit()
        conn.close()

    def get_user_labs(self, user_id: int):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM lab_instances
            WHERE user_id = ?
            ORDER BY created_at DESC
            """,
            (user_id,),
        )
        labs = self._rows_to_dicts(cursor.fetchall())
        conn.close()
        return labs

    def add_metric(self, metric_type: str, value: float, metadata: dict = None):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO system_metrics (metric_type, metric_value, metadata)
            VALUES (?, ?, ?)
            """,
            (metric_type, value, json.dumps(metadata) if metadata else None),
        )
        conn.commit()
        conn.close()

    def get_metrics(self, metric_type: str = None, hours: int = 24):
        conn = self.get_connection()
        cursor = conn.cursor()
        since = datetime.now() - timedelta(hours=hours)
        if metric_type:
            cursor.execute(
                """
                SELECT * FROM system_metrics
                WHERE metric_type = ? AND timestamp > ?
                ORDER BY timestamp DESC
                """,
                (metric_type, since),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM system_metrics
                WHERE timestamp > ?
                ORDER BY timestamp DESC
                """,
                (since,),
            )
        metrics = self._rows_to_dicts(cursor.fetchall())
        conn.close()
        return metrics

    def store_api_key(self, user_id: int, service_name: str, api_key: str):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE api_keys SET is_active = 0 WHERE user_id = ? AND service_name = ?",
            (user_id, service_name),
        )
        cursor.execute(
            """
            INSERT INTO api_keys (user_id, service_name, api_key)
            VALUES (?, ?, ?)
            """,
            (user_id, service_name, api_key),
        )
        conn.commit()
        conn.close()

    def get_api_key(self, user_id: int, service_name: str):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT api_key FROM api_keys
            WHERE user_id = ? AND service_name = ? AND is_active = 1
            """,
            (user_id, service_name),
        )
        result = cursor.fetchone()
        conn.close()
        return result["api_key"] if result else None

    def update_lesson_progress(self, user_id: int, lesson_id: str, progress: float):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id FROM learning_progress
            WHERE user_id = ? AND lesson_id = ?
            """,
            (user_id, lesson_id),
        )
        if cursor.fetchone():
            cursor.execute(
                """
                UPDATE learning_progress
                SET progress = ?, completed = ?, completed_at = ?
                WHERE user_id = ? AND lesson_id = ?
                """,
                (progress, progress >= 100, datetime.now() if progress >= 100 else None, user_id, lesson_id),
            )
        else:
            cursor.execute(
                """
                INSERT INTO learning_progress (user_id, lesson_id, progress, completed, completed_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user_id, lesson_id, progress, progress >= 100, datetime.now() if progress >= 100 else None),
            )
        conn.commit()
        conn.close()

    def get_learning_progress(self, user_id: int):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM learning_progress WHERE user_id = ?", (user_id,))
        progress = self._rows_to_dicts(cursor.fetchall())
        conn.close()
        return progress

    def create_run(
        self,
        run_id: str,
        user_id: int,
        run_type: str,
        source: str,
        requested_action: str,
        status: str = "queued",
        target: str = None,
        parent_run_id: str = None,
        metadata: Dict[str, Any] = None,
    ):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO operation_runs
            (id, user_id, run_type, source, status, target, requested_action, parent_run_id, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (run_id, user_id, run_type, source, status, target, requested_action, parent_run_id, self._to_json(metadata)),
        )
        conn.commit()
        conn.close()

    def update_run(
        self,
        run_id: str,
        status: str = None,
        started_at: str = None,
        completed_at: str = None,
        metadata: Dict[str, Any] = None,
    ):
        conn = self.get_connection()
        cursor = conn.cursor()
        updates = []
        params: List[Any] = []
        if status is not None:
            updates.append("status = ?")
            params.append(status)
        if started_at is not None:
            updates.append("started_at = ?")
            params.append(started_at)
        if completed_at is not None:
            updates.append("completed_at = ?")
            params.append(completed_at)
        if metadata is not None:
            updates.append("metadata = ?")
            params.append(self._to_json(metadata))
        if not updates:
            conn.close()
            return
        params.append(run_id)
        cursor.execute(f"UPDATE operation_runs SET {', '.join(updates)} WHERE id = ?", tuple(params))
        conn.commit()
        conn.close()

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM operation_runs WHERE id = ?", (run_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return self._rows_to_dicts([row])[0]

    def list_runs(
        self,
        user_id: Optional[int] = None,
        run_type: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        clauses = []
        params: List[Any] = []
        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(user_id)
        if run_type:
            clauses.append("run_type = ?")
            params.append(run_type)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        cursor.execute(
            f"""
            SELECT * FROM operation_runs
            {where}
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (*params, limit),
        )
        rows = self._rows_to_dicts(cursor.fetchall())
        conn.close()
        return rows

    def create_run_step(
        self,
        step_id: str,
        run_id: str,
        step_type: str,
        step_key: str = None,
        module: str = None,
        script_name: str = None,
        status: str = "queued",
        step_index: int = 0,
        parameters: Dict[str, Any] = None,
        metadata: Dict[str, Any] = None,
    ):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO run_steps
            (id, run_id, step_type, step_key, module, script_name, status, step_index, parameters, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (step_id, run_id, step_type, step_key, module, script_name, status, step_index, self._to_json(parameters), self._to_json(metadata)),
        )
        conn.commit()
        conn.close()

    def update_run_step(
        self,
        step_id: str,
        status: str = None,
        started_at: str = None,
        completed_at: str = None,
        exit_code: int = None,
        duration: float = None,
        stdout_preview: str = None,
        stderr_preview: str = None,
        error_message: str = None,
        metadata: Dict[str, Any] = None,
    ):
        conn = self.get_connection()
        cursor = conn.cursor()
        updates = []
        params: List[Any] = []
        mapping = {
            "status": status,
            "started_at": started_at,
            "completed_at": completed_at,
            "exit_code": exit_code,
            "duration": duration,
            "stdout_preview": stdout_preview,
            "stderr_preview": stderr_preview,
            "error_message": error_message,
        }
        for key, value in mapping.items():
            if value is not None:
                updates.append(f"{key} = ?")
                params.append(value)
        if metadata is not None:
            updates.append("metadata = ?")
            params.append(self._to_json(metadata))
        if not updates:
            conn.close()
            return
        params.append(step_id)
        cursor.execute(f"UPDATE run_steps SET {', '.join(updates)} WHERE id = ?", tuple(params))
        conn.commit()
        conn.close()

    def get_run_steps(self, run_id: str) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM run_steps WHERE run_id = ? ORDER BY step_index ASC, id ASC", (run_id,))
        rows = self._rows_to_dicts(cursor.fetchall())
        conn.close()
        return rows

    def attach_lab_to_run(
        self,
        lab_run_id: str,
        run_id: str,
        lab_id: str,
        status: str = "queued",
        container_id: str = None,
        port: int = None,
        metadata: Dict[str, Any] = None,
    ):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO run_labs
            (id, run_id, lab_id, container_id, status, port, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (lab_run_id, run_id, lab_id, container_id, status, port, self._to_json(metadata)),
        )
        conn.commit()
        conn.close()

    def update_run_lab(
        self,
        lab_run_id: str,
        status: str = None,
        container_id: str = None,
        port: int = None,
        started_at: str = None,
        stopped_at: str = None,
        metadata: Dict[str, Any] = None,
    ):
        conn = self.get_connection()
        cursor = conn.cursor()
        updates = []
        params: List[Any] = []
        mapping = {
            "status": status,
            "container_id": container_id,
            "port": port,
            "started_at": started_at,
            "stopped_at": stopped_at,
        }
        for key, value in mapping.items():
            if value is not None:
                updates.append(f"{key} = ?")
                params.append(value)
        if metadata is not None:
            updates.append("metadata = ?")
            params.append(self._to_json(metadata))
        if not updates:
            conn.close()
            return
        params.append(lab_run_id)
        cursor.execute(f"UPDATE run_labs SET {', '.join(updates)} WHERE id = ?", tuple(params))
        conn.commit()
        conn.close()

    def get_run_labs(self, run_id: str) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM run_labs WHERE run_id = ? ORDER BY started_at DESC, id DESC", (run_id,))
        rows = self._rows_to_dicts(cursor.fetchall())
        conn.close()
        return rows

    def create_run_event(
        self,
        event_id: str,
        run_id: str,
        scope_type: str,
        scope_id: str,
        event_type: str,
        status: str = None,
        message: str = None,
        payload: Dict[str, Any] = None,
    ):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO run_events
            (id, run_id, scope_type, scope_id, event_type, status, message, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (event_id, run_id, scope_type, scope_id, event_type, status, message, self._to_json(payload)),
        )
        conn.commit()
        conn.close()

    def get_run_events(self, run_id: str) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM run_events WHERE run_id = ? ORDER BY created_at ASC, id ASC", (run_id,))
        rows = self._rows_to_dicts(cursor.fetchall())
        conn.close()
        return rows

    def create_run_artifact(
        self,
        artifact_id: str,
        run_id: str,
        artifact_type: str,
        path: str,
        label: str = None,
        metadata: Dict[str, Any] = None,
    ):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO run_artifacts
            (id, run_id, artifact_type, path, label, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (artifact_id, run_id, artifact_type, path, label, self._to_json(metadata)),
        )
        conn.commit()
        conn.close()

    def get_run_artifacts(self, run_id: str) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM run_artifacts WHERE run_id = ? ORDER BY created_at ASC, id ASC", (run_id,))
        rows = self._rows_to_dicts(cursor.fetchall())
        conn.close()
        return rows

    def get_run_detail(self, run_id: str) -> Optional[Dict[str, Any]]:
        run = self.get_run(run_id)
        if not run:
            return None
        run["steps"] = self.get_run_steps(run_id)
        run["labs"] = self.get_run_labs(run_id)
        run["events"] = self.get_run_events(run_id)
        run["artifacts"] = self.get_run_artifacts(run_id)
        return run


db = DatabaseManager()
