import { useQuery } from '@tanstack/react-query';
import { fetchJson } from '../../hooks/useApi';
import { useAuth } from '../../contexts/AuthContext';
import { useWs } from '../../contexts/WebSocketContext';
import type { ServerStatus } from '../../types/api';

export function Header() {
  const { token } = useAuth();
  const { connected: wsConnected } = useWs();

  const { data: status } = useQuery({
    queryKey: ['status'],
    queryFn: () => fetchJson<ServerStatus>('/api/status', token),
    refetchInterval: 10_000,
    retry: false,
  });

  const isOnline = !!status;

  return (
    <header className="header">
      <div className="header-brand">
        <div className="logo">S</div>
        <span>smgglrs</span>
      </div>
      <div className="header-right">
        {status && (
          <span style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
            v{status.version}
          </span>
        )}
        <span title={wsConnected ? 'WebSocket connected' : 'WebSocket disconnected'}>
          <span className={`status-dot ${isOnline ? 'online' : 'offline'}`} />
          <span>{isOnline ? status?.name || 'smgglrs' : 'offline'}</span>
        </span>
        {wsConnected && (
          <span style={{ fontSize: '0.75rem', color: 'var(--success)' }}>WS</span>
        )}
      </div>
    </header>
  );
}
