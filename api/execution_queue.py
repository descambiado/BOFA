"""
Execution Queue Manager for BOFA runtime.
Manages queued script steps with concurrency control and cancellation support.
"""

import asyncio
from collections import deque
from datetime import datetime
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class ExecutionQueue:
    """Manages script-step queue with concurrency control."""

    def __init__(self, max_concurrent: int = 3):
        self.max_concurrent = max_concurrent
        self.queue = deque()
        self.running: Dict[str, Dict[str, Any]] = {}
        self.completed: Dict[str, Dict[str, Any]] = {}
        self.lock = asyncio.Lock()

    async def add_to_queue(
        self,
        execution_id: str,
        run_id: str,
        step_id: str,
        user_id: int,
        module: str,
        script: str,
        parameters: Dict[str, Any],
    ):
        """Add an execution step to queue."""
        async with self.lock:
            queue_item = {
                "execution_id": execution_id,
                "run_id": run_id,
                "step_id": step_id,
                "user_id": user_id,
                "module": module,
                "script": script,
                "parameters": parameters,
                "queued_at": datetime.utcnow().isoformat(),
                "status": "queued",
                "position": len(self.queue) + 1,
            }
            self.queue.append(queue_item)
            logger.info(f"Queued step {step_id} for run {run_id} at position {queue_item['position']}")
            return queue_item

    async def get_next(self) -> Optional[Dict[str, Any]]:
        async with self.lock:
            if len(self.running) >= self.max_concurrent or not self.queue:
                return None
            item = self.queue.popleft()
            item["status"] = "running"
            item["started_at"] = datetime.utcnow().isoformat()
            self.running[item["execution_id"]] = item
            return item

    async def mark_completed(self, execution_id: str, result: Dict[str, Any]):
        async with self.lock:
            if execution_id in self.running:
                item = self.running.pop(execution_id)
                item["completed_at"] = datetime.utcnow().isoformat()
                item["status"] = result.get("status", "success")
                item["result"] = result
                self.completed[execution_id] = item

    async def mark_failed(self, execution_id: str, error: str):
        async with self.lock:
            if execution_id in self.running:
                item = self.running.pop(execution_id)
                item["completed_at"] = datetime.utcnow().isoformat()
                item["status"] = "failed"
                item["error"] = error
                self.completed[execution_id] = item

    async def cancel(self, execution_id: str) -> Optional[Dict[str, Any]]:
        async with self.lock:
            for item in list(self.queue):
                if item["execution_id"] == execution_id:
                    self.queue.remove(item)
                    item["status"] = "cancelled"
                    item["completed_at"] = datetime.utcnow().isoformat()
                    self.completed[execution_id] = item
                    return item
            if execution_id in self.running:
                return self.running[execution_id]
            return None

    async def get_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        async with self.lock:
            if execution_id in self.running:
                return self.running[execution_id]
            if execution_id in self.completed:
                return self.completed[execution_id]
            for item in self.queue:
                if item["execution_id"] == execution_id:
                    item["position"] = list(self.queue).index(item) + 1
                    return item
            return None

    async def get_queue_info(self) -> Dict[str, Any]:
        async with self.lock:
            return {
                "queued": len(self.queue),
                "running": len(self.running),
                "completed": len(self.completed),
                "total": len(self.queue) + len(self.running) + len(self.completed),
                "max_concurrent": self.max_concurrent,
                "queue_items": [
                    {
                        "execution_id": item["execution_id"],
                        "run_id": item["run_id"],
                        "step_id": item["step_id"],
                        "script": item["script"],
                        "position": index + 1,
                        "queued_at": item["queued_at"],
                    }
                    for index, item in enumerate(self.queue)
                ],
                "running_items": [
                    {
                        "execution_id": execution_id,
                        "run_id": item["run_id"],
                        "step_id": item["step_id"],
                        "script": item["script"],
                        "started_at": item.get("started_at"),
                    }
                    for execution_id, item in self.running.items()
                ],
            }


execution_queue = ExecutionQueue(max_concurrent=3)
