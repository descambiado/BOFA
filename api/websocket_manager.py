"""
WebSocket manager for BOFA runtime events.
"""

import asyncio
from datetime import datetime
import json
import logging
from typing import Any, Dict, Set

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    """Manages run-scoped websocket connections."""

    def __init__(self):
        self.connections: Dict[str, Set[WebSocket]] = {}
        self.lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, run_id: str):
        await websocket.accept()
        async with self.lock:
            self.connections.setdefault(run_id, set()).add(websocket)

    async def disconnect(self, websocket: WebSocket, run_id: str):
        async with self.lock:
            if run_id in self.connections:
                self.connections[run_id].discard(websocket)
                if not self.connections[run_id]:
                    del self.connections[run_id]

    async def emit(
        self,
        run_id: str,
        scope_type: str,
        scope_id: str,
        event_type: str,
        status: str = None,
        message: str = None,
        payload: Dict[str, Any] = None,
    ):
        async with self.lock:
            if run_id not in self.connections:
                return
            envelope = json.dumps(
                {
                    "run_id": run_id,
                    "scope_type": scope_type,
                    "scope_id": scope_id,
                    "event_type": event_type,
                    "status": status,
                    "message": message,
                    "payload": payload or {},
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
            disconnected = set()
            for websocket in self.connections[run_id]:
                try:
                    await websocket.send_text(envelope)
                except Exception as exc:
                    logger.error(f"WebSocket send failed: {exc}")
                    disconnected.add(websocket)
            for websocket in disconnected:
                self.connections[run_id].discard(websocket)


ws_manager = WebSocketManager()
