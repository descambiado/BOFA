import { useCallback, useEffect, useRef, useState } from 'react';

export interface WebSocketMessage {
  run_id: string;
  scope_type: string;
  scope_id?: string;
  event_type: string;
  status?: string;
  message?: string;
  payload?: Record<string, any>;
  timestamp: string;
}

interface UseWebSocketOptions {
  onMessage?: (message: WebSocketMessage) => void;
  onOpen?: () => void;
  onClose?: () => void;
  onError?: (error: Event) => void;
}

export const useWebSocket = (runId: string | null, options: UseWebSocketOptions = {}) => {
  const [isConnected, setIsConnected] = useState(false);
  const [messages, setMessages] = useState<WebSocketMessage[]>([]);
  const ws = useRef<WebSocket | null>(null);

  const connect = useCallback(() => {
    if (!runId) return;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.hostname}:8000/ws/runs/${runId}`;

    try {
      ws.current = new WebSocket(wsUrl);
      ws.current.onopen = () => {
        setIsConnected(true);
        options.onOpen?.();
      };
      ws.current.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data);
          if ((message as any).type === 'pong') return;
          setMessages((prev) => [...prev, message]);
          options.onMessage?.(message);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };
      ws.current.onclose = () => {
        setIsConnected(false);
        options.onClose?.();
      };
      ws.current.onerror = (error) => {
        options.onError?.(error);
      };
    } catch (error) {
      console.error('Failed to create WebSocket:', error);
    }
  }, [runId, options]);

  const disconnect = useCallback(() => {
    if (ws.current) {
      ws.current.close();
      ws.current = null;
    }
  }, []);

  const sendMessage = useCallback((data: any) => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify(data));
    }
  }, []);

  useEffect(() => {
    if (runId) connect();
    return () => disconnect();
  }, [runId, connect, disconnect]);

  return { isConnected, messages, sendMessage, connect, disconnect };
};
