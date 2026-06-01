import { createContext, useContext, type ReactNode } from 'react';
import { useWebSocket, type UiEvent } from '../hooks/useWebSocket';

interface WsState {
  connected: boolean;
  subscribe: (eventType: string, handler: (event: UiEvent) => void) => () => void;
}

const WebSocketContext = createContext<WsState>({
  connected: false,
  subscribe: () => () => {},
});

export function WebSocketProvider({ children }: { children: ReactNode }) {
  const ws = useWebSocket();

  return (
    <WebSocketContext.Provider value={ws}>
      {children}
    </WebSocketContext.Provider>
  );
}

export function useWs() {
  return useContext(WebSocketContext);
}
