import { useState, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { fetchJson } from '../hooks/useApi';
import { useAuth } from '../contexts/AuthContext';
import { useWs } from '../contexts/WebSocketContext';
import { Spinner } from '../components/shared/Spinner';
import { EmptyState } from '../components/shared/EmptyState';
import type { ProcessSnapshot, AuditResponse } from '../types/api';

export function SessionsPage() {
  const { token } = useAuth();
  const { subscribe } = useWs();
  const queryClient = useQueryClient();
  const [expandedAgent, setExpandedAgent] = useState<string | null>(null);
  const [sortField, setSortField] = useState<'name' | 'call_count' | 'denied_count' | 'uptime_secs'>('name');
  const [sortAsc, setSortAsc] = useState(true);

  const { data: processes, isLoading } = useQuery({
    queryKey: ['process'],
    queryFn: () => fetchJson<ProcessSnapshot[]>('/api/process', token),
    refetchInterval: 30_000,
    retry: false,
  });

  const { data: agentAudit } = useQuery({
    queryKey: ['audit-agent', expandedAgent],
    queryFn: () => fetchJson<AuditResponse>(`/api/audit?limit=10&agent=${expandedAgent}`, token),
    enabled: !!expandedAgent,
    retry: false,
  });

  useEffect(() => {
    const unsub = subscribe('process_update', () => {
      queryClient.invalidateQueries({ queryKey: ['process'] });
    });
    return unsub;
  }, [subscribe, queryClient]);

  const handleSort = (field: typeof sortField) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(true);
    }
  };

  const sorted = [...(processes ?? [])].sort((a, b) => {
    const va = a[sortField];
    const vb = b[sortField];
    if (typeof va === 'string' && typeof vb === 'string') return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
    return sortAsc ? Number(va) - Number(vb) : Number(vb) - Number(va);
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
              <th onClick={() => handleSort('name')} style={{ cursor: 'pointer' }}>Agent {sortField === 'name' ? (sortAsc ? '▲' : '▼') : ''}</th>
              <th>Permissions</th>
              <th>Ring</th>
              <th onClick={() => handleSort('call_count')} style={{ cursor: 'pointer' }}>Calls {sortField === 'call_count' ? (sortAsc ? '▲' : '▼') : ''}</th>
              <th onClick={() => handleSort('denied_count')} style={{ cursor: 'pointer' }}>Denied {sortField === 'denied_count' ? (sortAsc ? '▲' : '▼') : ''}</th>
              <th onClick={() => handleSort('uptime_secs')} style={{ cursor: 'pointer' }}>Uptime {sortField === 'uptime_secs' ? (sortAsc ? '▲' : '▼') : ''}</th>
              <th>Idle</th>
              <th>Active Tools</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map(p => (
              <>
                <tr
                  key={p.name}
                  onClick={() => setExpandedAgent(expandedAgent === p.name ? null : p.name)}
                  style={{ cursor: 'pointer' }}
                >
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
                {expandedAgent === p.name && (
                  <tr key={`${p.name}-detail`}>
                    <td colSpan={8} style={{ background: 'var(--surface)', padding: '12px 16px' }}>
                      <div style={{ fontWeight: 600, fontSize: '0.8rem', marginBottom: '8px', color: 'var(--text-muted)' }}>
                        Recent tool calls for {p.name}
                      </div>
                      {!agentAudit ? (
                        <Spinner size="sm" />
                      ) : agentAudit.entries.length === 0 ? (
                        <span style={{ color: 'var(--text-dim)', fontSize: '0.85rem' }}>No tool calls recorded</span>
                      ) : (
                        <table className="data-table" style={{ fontSize: '0.8rem' }}>
                          <thead>
                            <tr>
                              <th>Time</th>
                              <th>Tool</th>
                              <th>Outcome</th>
                              <th>Duration</th>
                              <th>IFC</th>
                            </tr>
                          </thead>
                          <tbody>
                            {agentAudit.entries.map(e => (
                              <tr key={e.seq}>
                                <td className="mono">{new Date(e.timestamp_ms).toLocaleTimeString()}</td>
                                <td className="mono">{e.tool_name}</td>
                                <td>
                                  <span className={`badge ${e.outcome === 'allowed' ? 'success' : 'danger'}`}>
                                    {e.outcome}
                                  </span>
                                </td>
                                <td className="mono">{formatDuration(e.duration_us)}</td>
                                <td className="mono">{e.ifc_label}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                    </td>
                  </tr>
                )}
              </>
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

function formatDuration(us: number): string {
  if (us < 1000) return `${us}us`;
  if (us < 1_000_000) return `${(us / 1000).toFixed(1)}ms`;
  return `${(us / 1_000_000).toFixed(2)}s`;
}
