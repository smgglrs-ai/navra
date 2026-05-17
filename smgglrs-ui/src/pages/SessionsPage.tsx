import { useQuery } from '@tanstack/react-query';
import { fetchJson } from '../hooks/useApi';
import { useAuth } from '../contexts/AuthContext';
import { Spinner } from '../components/shared/Spinner';
import { EmptyState } from '../components/shared/EmptyState';
import type { ProcessSnapshot } from '../types/api';

export function SessionsPage() {
  const { token } = useAuth();

  const { data: processes, isLoading } = useQuery({
    queryKey: ['process'],
    queryFn: () => fetchJson<ProcessSnapshot[]>('/api/process', token),
    refetchInterval: 5_000,
    retry: false,
  });

  if (isLoading) {
    return <div className="page" style={{ display: 'flex', justifyContent: 'center', paddingTop: '80px' }}><Spinner size="lg" /></div>;
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Sessions</h1>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          {processes?.length ?? 0} active
        </span>
      </div>

      {!processes || processes.length === 0 ? (
        <EmptyState icon="☰" title="No active sessions" description="Agents will appear here when they connect to the gateway." />
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Agent</th>
              <th>Permissions</th>
              <th>Ring</th>
              <th>Calls</th>
              <th>Denied</th>
              <th>Uptime</th>
              <th>Idle</th>
              <th>Active Tools</th>
            </tr>
          </thead>
          <tbody>
            {processes.map(p => (
              <tr key={p.name}>
                <td style={{ fontWeight: 600 }}>{p.name}</td>
                <td className="mono">{p.permissions}</td>
                <td className="mono">{p.ring ?? '—'}</td>
                <td className="mono">{p.call_count}</td>
                <td className="mono" style={{ color: p.denied_count > 0 ? 'var(--danger)' : undefined }}>
                  {p.denied_count}
                </td>
                <td className="mono">{formatUptime(p.uptime_secs)}</td>
                <td className="mono">{formatUptime(p.idle_secs)}</td>
                <td>
                  {p.active_calls.length > 0
                    ? p.active_calls.map(c => (
                        <span key={c} className="badge accent" style={{ marginRight: '4px' }}>{c}</span>
                      ))
                    : <span style={{ color: 'var(--text-dim)' }}>idle</span>
                  }
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function formatUptime(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
}
