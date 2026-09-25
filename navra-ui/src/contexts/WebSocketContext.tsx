import { createContext, useContext, useEffect, useRef, useCallback, useState, type ReactNode } from 'react';
import { useAuth } from './AuthContext';
import type { UiEvent } from '../hooks/useWebSocket';

interface WsState {
  connected: boolean;
  subscribe: (eventType: string, handler: (event: UiEvent) => void) => () => void;
}

const WebSocketContext = createContext<WsState>({
  connected: false,
  subscribe: () => () => {},
});

type EventHandler = (event: UiEvent) => void;

export function WebSocketProvider({ children }: { children: ReactNode }) {
  const { token } = useAuth();
  const wsRef = useRef<WebSocket | null>(null);
  const handlersRef = useRef<Map<string, Set<EventHandler>>>(new Map());
  const [connected, setConnected] = useState(false);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const retriesRef = useRef(0);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Token is NOT placed in the URL to avoid leaking it into server access logs.
    // It is sent as the first message after the connection opens (see onopen below).
    const url = `${protocol}//${window.location.host}/ws/ui`;
    const ws = new WebSocket(url);

    ws.onopen = () => {
      // Send auth immediately after connect, before any subscriptions are active.
      ws.send(JSON.stringify({ type: 'auth', token }));
      setConnected(true);
      retriesRef.current = 0;
    };

    ws.onmessage = (event) => {
      try {
        const parsed: UiEvent = JSON.parse(event.data as string);
        const handlers = handlersRef.current.get(parsed.type);
        if (handlers) {
          handlers.forEach(fn => fn(parsed));
        }
        const allHandlers = handlersRef.current.get('*');
        if (allHandlers) {
          allHandlers.forEach(fn => fn(parsed));
        }
      } catch {
        // ignore non-JSON messages
      }
    };

    ws.onclose = () => {
      setConnected(false);
      wsRef.current = null;
      const delay = Math.min(1000 * Math.pow(2, retriesRef.current), 30000);
      retriesRef.current++;
      reconnectTimeoutRef.current = window.setTimeout(connect, delay);
    };

    ws.onerror = () => {
      ws.close();
    };

    wsRef.current = ws;
  }, [token]);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      wsRef.current?.close();
    };
  }, [connect]);

  const subscribe = useCallback((eventType: string, handler: EventHandler) => {
    if (!handlersRef.current.has(eventType)) {
      handlersRef.current.set(eventType, new Set());
    }
    handlersRef.current.get(eventType)!.add(handler);

    return () => {
      handlersRef.current.get(eventType)?.delete(handler);
    };
  }, []);

  return (
    <WebSocketContext.Provider value={{ connected, subscribe }}>
      {children}
    </WebSocketContext.Provider>
  );
}

export function useWs() {
  return useContext(WebSocketContext);
}
