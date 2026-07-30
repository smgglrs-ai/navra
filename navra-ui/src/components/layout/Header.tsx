import { useState, useEffect, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchJson } from '../../hooks/useApi';
import { useAuth } from '../../contexts/AuthContext';
import { useWs } from '../../contexts/WebSocketContext';
import type { ServerStatus } from '../../types/api';

export function Header() {
  const { token } = useAuth();
  const { connected: wsConnected } = useWs();
  const [theme, setTheme] = useState(() => localStorage.getItem('navra_theme') || 'dark');

  const applyTheme = useCallback((t: string) => {
    if (t === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
  }, []);

  useEffect(() => { applyTheme(theme); }, [theme, applyTheme]);

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    localStorage.setItem('navra_theme', next);
  };

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
        <div className="logo">N</div>
        <span>navra</span>
      </div>
      <div className="header-right">
        {status && (
          <span style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
            v{status.version}
          </span>
        )}
        <span title={wsConnected ? 'WebSocket connected' : 'WebSocket disconnected'}>
          <span className={`status-dot ${isOnline ? 'online' : 'offline'}`} />
          <span>{isOnline ? status?.name || 'navra' : 'offline'}</span>
        </span>
        {wsConnected && (
          <span style={{ fontSize: '0.75rem', color: 'var(--success)' }}>WS</span>
        )}
        <button
          onClick={toggleTheme}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          style={{
            background: 'none',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)',
            padding: '4px 8px',
            cursor: 'pointer',
            fontSize: '0.85rem',
            color: 'var(--text-muted)',
          }}
        >
          {theme === 'dark' ? '☀' : '☾'}
        </button>
      </div>
    </header>
  );
}
