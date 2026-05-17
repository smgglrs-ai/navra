import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchJson } from '../hooks/useApi';
import { useAuth } from '../contexts/AuthContext';
import { Spinner } from '../components/shared/Spinner';
import type { AuditResponse } from '../types/api';

const PAGE_SIZE = 50;

export function AuditPage() {
  const { token } = useAuth();
  const [offset, setOffset] = useState(0);
  const [agentFilter, setAgentFilter] = useState('');
  const [toolFilter, setToolFilter] = useState('');
  const [expandedSeq, setExpandedSeq] = useState<number | null>(null);

  const params = new URLSearchParams({
    limit: String(PAGE_SIZE),
    offset: String(offset),
  });
  if (agentFilter) params.set('agent', agentFilter);
  if (toolFilter) params.set('tool', toolFilter);

  const { data, isLoading } = useQuery({
    queryKey: ['audit', offset, agentFilter, toolFilter],
    queryFn: () => fetchJson<AuditResponse>(`/api/audit?${params}`, token),
    refetchInterval: 10_000,
    retry: false,
  });

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Audit Log</h1>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          {data?.total ?? 0} entries
        </span>
      </div>

      <div className="filter-bar">
        <input
          className="filter-input"
          placeholder="Filter by agent..."
          value={agentFilter}
          onChange={e => { setAgentFilter(e.target.value); setOffset(0); }}
        />
        <input
          className="filter-input"
          placeholder="Filter by tool..."
          value={toolFilter}
          onChange={e => { setToolFilter(e.target.value); setOffset(0); }}
        />
      </div>

      {isLoading ? (
        <div style={{ padding: '40px', textAlign: 'center' }}><Spinner size="lg" /></div>
      ) : (
        <>
          <table className="data-table">
            <thead>
              <tr>
                <th>Seq</th>
                <th>Time</th>
                <th>Agent</th>
                <th>Tool</th>
                <th>Outcome</th>
                <th>Duration</th>
                <th>IFC</th>
              </tr>
            </thead>
            <tbody>
              {data?.entries.map(entry => (
                <>
                  <tr
                    key={entry.seq}
                    onClick={() => setExpandedSeq(expandedSeq === entry.seq ? null : entry.seq)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td className="mono">{entry.seq}</td>
                    <td className="mono">{new Date(entry.timestamp_ms).toLocaleString()}</td>
                    <td>{entry.agent_name}</td>
                    <td className="mono">{entry.tool_name}</td>
                    <td>
                      <span className={`badge ${entry.outcome === 'allowed' ? 'success' : 'danger'}`}>
                        {entry.outcome}
                      </span>
                    </td>
                    <td className="mono">{formatDuration(entry.duration_us)}</td>
                    <td className="mono">{entry.ifc_label}</td>
                  </tr>
                  {expandedSeq === entry.seq && (
                    <tr key={`${entry.seq}-detail`}>
                      <td colSpan={7} style={{ background: 'var(--surface)', padding: '16px' }}>
                        <div style={{ marginBottom: '8px' }}>
                          <strong>Arguments:</strong>
                          <pre style={{ marginTop: '4px' }}>{formatJson(entry.tool_args)}</pre>
                        </div>
                        <div>
                          <strong>Result:</strong>
                          <pre style={{ marginTop: '4px' }}>{formatJson(entry.tool_result)}</pre>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>

          {data && (
            <div className="table-pagination">
              <span>
                Showing {offset + 1}–{Math.min(offset + PAGE_SIZE, data.total)} of {data.total}
              </span>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  className="btn"
                  disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                >
                  Previous
                </button>
                <button
                  className="btn"
                  disabled={offset + PAGE_SIZE >= data.total}
                  onClick={() => setOffset(offset + PAGE_SIZE)}
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function formatDuration(us: number): string {
  if (us < 1000) return `${us}us`;
  if (us < 1_000_000) return `${(us / 1000).toFixed(1)}ms`;
  return `${(us / 1_000_000).toFixed(2)}s`;
}

function formatJson(s: string): string {
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return s;
  }
}
