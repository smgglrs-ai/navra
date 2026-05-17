import { useQuery } from '@tanstack/react-query';
import { fetchJson } from '../hooks/useApi';
import { useAuth } from '../contexts/AuthContext';
import { Spinner } from '../components/shared/Spinner';
import type { ServerStatus, ProcessSnapshot, BlackboxEntry } from '../types/api';

export function DashboardPage() {
  const { token } = useAuth();

  const { data: status } = useQuery({
    queryKey: ['status'],
    queryFn: () => fetchJson<ServerStatus>('/api/status', token),
    refetchInterval: 5_000,
  });

  const { data: processes } = useQuery({
    queryKey: ['process'],
    queryFn: () => fetchJson<ProcessSnapshot[]>('/api/process', token),
    refetchInterval: 5_000,
    retry: false,
  });

  const { data: audit } = useQuery({
    queryKey: ['audit-recent'],
    queryFn: () => fetchJson<{ entries: BlackboxEntry[]; total: number }>('/api/audit?limit=15', token),
    refetchInterval: 5_000,
    retry: false,
  });

  const totalCalls = processes?.reduce((sum, p) => sum + p.call_count, 0) ?? 0;
  const totalDenied = processes?.reduce((sum, p) => sum + p.denied_count, 0) ?? 0;

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Dashboard</h1>
      </div>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-card-label">Active Sessions</div>
          <div className="stat-card-value">{processes?.length ?? '—'}</div>
          <div className="stat-card-sub">connected agents</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">Tool Calls</div>
          <div className="stat-card-value">{totalCalls.toLocaleString()}</div>
          <div className="stat-card-sub">{totalDenied} denied</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">Models</div>
          <div className="stat-card-value">{status?.models?.length ?? '—'}</div>
          <div className="stat-card-sub">loaded</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">Blackbox Entries</div>
          <div className="stat-card-value">{audit?.total?.toLocaleString() ?? '—'}</div>
          <div className="stat-card-sub">hash-chained audit log</div>
        </div>
      </div>

      <h2 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '12px' }}>Recent Activity</h2>
      {!audit ? (
        <div style={{ padding: '40px', textAlign: 'center' }}><Spinner size="lg" /></div>
      ) : audit.entries.length === 0 ? (
        <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-dim)' }}>
          No tool calls recorded yet
        </div>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Agent</th>
              <th>Tool</th>
              <th>Outcome</th>
              <th>Duration</th>
              <th>IFC</th>
            </tr>
          </thead>
          <tbody>
            {audit.entries.map(entry => (
              <tr key={entry.seq}>
                <td className="mono">{formatTimestamp(entry.timestamp_ms)}</td>
                <td>{entry.agent_name}</td>
                <td className="mono">{entry.tool_name}</td>
                <td>
                  <span className={`badge ${outcomeVariant(entry.outcome)}`}>
                    {entry.outcome}
                  </span>
                </td>
                <td className="mono">{formatDuration(entry.duration_us)}</td>
                <td>
                  <span className={`ifc-label ${ifcClass(entry.ifc_label)}`}>
                    {entry.ifc_label}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function formatTimestamp(ms: number): string {
  return new Date(ms).toLocaleTimeString();
}

function formatDuration(us: number): string {
  if (us < 1000) return `${us}us`;
  if (us < 1_000_000) return `${(us / 1000).toFixed(1)}ms`;
  return `${(us / 1_000_000).toFixed(2)}s`;
}

function outcomeVariant(outcome: string): string {
  if (outcome === 'allowed') return 'success';
  if (outcome.startsWith('denied')) return 'danger';
  return 'warning';
}

function ifcClass(label: string): string {
  if (label.toLowerCase().includes('untrusted')) return 'untrusted';
  if (label.toLowerCase().includes('secret') || label.toLowerCase().includes('confidential')) return 'confidential';
  return 'trusted';
}
