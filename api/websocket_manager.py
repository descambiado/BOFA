"""
WebSocket Manager for BOFA
Manages WebSocket connections for real-time script output streaming
"""
import asyncio
import logging
from typing import Dict, Set
from fastapi import WebSocket
import json

logger = logging.getLogger(__name__)


class WebSocketManager:
    """Manages WebSocket connections for real-time updates"""
    
    def __init__(self):
        # execution_id -> set of websockets
        self.connections: Dict[str, Set[WebSocket]] = {}
        self.lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket, execution_id: str):
        """Register a new WebSocket connection"""
        await websocket.accept()
        async with self.lock:
            if execution_id not in self.connections:
                self.connections[execution_id] = set()
            self.connections[execution_id].add(websocket)
            logger.info(f"🔌 WebSocket connected for execution: {execution_id}")
    
    async def disconnect(self, websocket: WebSocket, execution_id: str):
        """Remove a WebSocket connection"""
        async with self.lock:
            if execution_id in self.connections:
                self.connections[execution_id].discard(websocket)
                if not self.connections[execution_id]:
                    del self.connections[execution_id]
            logger.info(f"🔌 WebSocket disconnected for execution: {execution_id}")
    
    async def send_output(self, execution_id: str, output_type: str, data: str):
        """Send output to all connected clients for an execution"""
        async with self.lock:
            if execution_id not in self.connections:
                return
            
            message = json.dumps({
                'type': output_type,
                'data': data,
                'timestamp': asyncio.get_event_loop().time()
            })
            
            disconnected = set()
            for websocket in self.connections[execution_id]:
                try:
                    await websocket.send_text(message)
                except Exception as e:
                    logger.error(f"Error sending to websocket: {e}")
                    disconnected.add(websocket)
            
            # Remove disconnected websockets
            for ws in disconnected:
                self.connections[execution_id].discard(ws)
    
    async def send_status(self, execution_id: str, status: str, details: Dict = None):
        """Send status update"""
        await self.send_output(execution_id, 'status', json.dumps({
            'status': status,
            'details': details or {}
        }))
    
    async def send_completed(self, execution_id: str, result: Dict):
        """Send completion message"""
        await self.send_output(execution_id, 'completed', json.dumps(result))


# Global WebSocket manager instance
ws_manager = WebSocketManager()
