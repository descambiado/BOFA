#!/usr/bin/env python3
"""
Unified BOFA runtime manager.
Coordinates operation runs, steps, labs, events and artifacts.
"""

from datetime import datetime
import uuid
from pathlib import Path
from typing import Any, Dict, Optional


FINAL_STATUSES = {"success", "failed", "error", "partial", "cancelled"}


class RunManager:
    def __init__(self, database_manager):
        self.db = database_manager

    def _id(self, prefix: str) -> str:
        return f"{prefix}_{uuid.uuid4().hex}"

    def create_run(
        self,
        user_id: int,
        run_type: str,
        source: str,
        requested_action: str,
        target: Optional[str] = None,
        parent_run_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        status: str = "queued",
    ) -> str:
        run_id = self._id("run")
        self.db.create_run(
            run_id=run_id,
            user_id=user_id,
            run_type=run_type,
            source=source,
            requested_action=requested_action,
            status=status,
            target=target,
            parent_run_id=parent_run_id,
            metadata=metadata or {},
        )
        self.add_event(
            run_id=run_id,
            scope_type="run",
            scope_id=run_id,
            event_type="created",
            status=status,
            message=f"Run created for {requested_action}",
            payload={"run_type": run_type, "source": source, "target": target, "parent_run_id": parent_run_id},
        )
        return run_id

    def mark_run_started(self, run_id: str, message: str = "Run started"):
        self.db.update_run(run_id, status="running", started_at=datetime.utcnow().isoformat())
        self.add_event(run_id, "run", run_id, "status_changed", "running", message)

    def mark_run_cancelling(self, run_id: str, message: str = "Run cancellation requested", payload: Dict[str, Any] = None):
        self.db.update_run(run_id, status="cancelling")
        self.add_event(run_id, "run", run_id, "cancel_requested", "cancelling", message, payload or {})

    def mark_run_finished(self, run_id: str, status: str, message: str = None, metadata: Dict[str, Any] = None):
        self.db.update_run(
            run_id,
            status=status,
            completed_at=datetime.utcnow().isoformat(),
            metadata=metadata,
        )
        self.add_event(
            run_id=run_id,
            scope_type="run",
            scope_id=run_id,
            event_type="status_changed",
            status=status,
            message=message or f"Run finished with status {status}",
            payload=metadata or {},
        )

    def create_step(
        self,
        run_id: str,
        step_type: str,
        step_index: int = 0,
        step_key: str = None,
        module: str = None,
        script_name: str = None,
        parameters: Dict[str, Any] = None,
        metadata: Dict[str, Any] = None,
        status: str = "queued",
    ) -> str:
        step_id = self._id("step")
        self.db.create_run_step(
            step_id=step_id,
            run_id=run_id,
            step_type=step_type,
            step_key=step_key,
            module=module,
            script_name=script_name,
            status=status,
            step_index=step_index,
            parameters=parameters or {},
            metadata=metadata or {},
        )
        self.add_event(
            run_id,
            "step",
            step_id,
            "step_created",
            status,
            f"Step created: {module}/{script_name}" if module and script_name else "Step created",
            {"step_index": step_index, "step_type": step_type},
        )
        return step_id

    def update_step(
        self,
        step_id: str,
        run_id: str,
        status: str = None,
        message: str = None,
        **kwargs,
    ):
        self.db.update_run_step(step_id=step_id, status=status, **kwargs)
        if status:
            self.add_event(
                run_id=run_id,
                scope_type="step",
                scope_id=step_id,
                event_type="status_changed",
                status=status,
                message=message or f"Step status changed to {status}",
                payload={key: value for key, value in kwargs.items() if value is not None},
            )

    def attach_lab(
        self,
        run_id: str,
        lab_id: str,
        status: str = "queued",
        container_id: str = None,
        port: int = None,
        metadata: Dict[str, Any] = None,
    ) -> str:
        run_lab_id = self._id("lab")
        self.db.attach_lab_to_run(
            lab_run_id=run_lab_id,
            run_id=run_id,
            lab_id=lab_id,
            status=status,
            container_id=container_id,
            port=port,
            metadata=metadata or {},
        )
        self.add_event(
            run_id,
            "lab",
            run_lab_id,
            "lab_attached",
            status,
            f"Lab attached: {lab_id}",
            {"lab_id": lab_id, "port": port, "container_id": container_id},
        )
        return run_lab_id

    def update_lab(
        self,
        lab_run_id: str,
        run_id: str,
        status: str,
        message: str = None,
        **kwargs,
    ):
        self.db.update_run_lab(lab_run_id=lab_run_id, status=status, **kwargs)
        self.add_event(
            run_id,
            "lab",
            lab_run_id,
            "status_changed",
            status,
            message or f"Lab status changed to {status}",
            {key: value for key, value in kwargs.items() if value is not None},
        )

    def add_event(
        self,
        run_id: str,
        scope_type: str,
        scope_id: str,
        event_type: str,
        status: str = None,
        message: str = None,
        payload: Dict[str, Any] = None,
    ) -> str:
        event_id = self._id("event")
        self.db.create_run_event(
            event_id=event_id,
            run_id=run_id,
            scope_type=scope_type,
            scope_id=scope_id,
            event_type=event_type,
            status=status,
            message=message,
            payload=payload or {},
        )
        return event_id

    def add_artifact(
        self,
        run_id: str,
        artifact_type: str,
        path: str,
        label: str = None,
        metadata: Dict[str, Any] = None,
    ) -> str:
        artifact_id = self._id("artifact")
        absolute_path = str(Path(path))
        self.db.create_run_artifact(
            artifact_id=artifact_id,
            run_id=run_id,
            artifact_type=artifact_type,
            path=absolute_path,
            label=label,
            metadata=metadata or {},
        )
        self.add_event(
            run_id=run_id,
            scope_type="artifact",
            scope_id=artifact_id,
            event_type="artifact_created",
            status="success",
            message=label or f"Artifact created: {artifact_type}",
            payload={"path": absolute_path, "artifact_type": artifact_type},
        )
        return artifact_id

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        return self.db.get_run_detail(run_id)

    def retry_payload(self, run_id: str) -> Optional[Dict[str, Any]]:
        run = self.db.get_run(run_id)
        if not run:
            return None
        metadata = run.get("metadata") or {}
        detail = self.db.get_run_detail(run_id) or run
        retry_count = int(metadata.get("retry_count", 0)) + 1
        last_non_success_step = None
        for step in detail.get("steps", []):
            if step.get("status") not in {"success"}:
                last_non_success_step = {
                    "id": step.get("id"),
                    "module": step.get("module"),
                    "script_name": step.get("script_name"),
                    "status": step.get("status"),
                    "error_message": step.get("error_message"),
                }
                break
        return {
            "retry_of": run_id,
            "retry_count": retry_count,
            "run_type": run.get("run_type"),
            "source": run.get("source"),
            "requested_action": run.get("requested_action"),
            "target": run.get("target"),
            "metadata": metadata,
            "last_non_success_step": last_non_success_step,
        }
