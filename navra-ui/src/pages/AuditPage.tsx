import { useState, useCallback, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { fetchJson } from '../hooks/useApi';
import { useAuth } from '../contexts/AuthContext';
import { useWs } from '../contexts/WebSocketContext';
import { Spinner } from '../components/shared/Spinner';
import type { AuditResponse, BlackboxEntry } from '../types/api';

const PAGE_SIZE = 50;

export function AuditPage() {
  const { token } = useAuth();
  const { subscribe } = useWs();
  const queryClient = useQueryClient();
  const [offset, setOffset] = useState(0);
  const [agentFilter, setAgentFilter] = useState('');
  const [toolFilter, setToolFilter] = useState('');
  const [outcomeFilter, setOutcomeFilter] = useState('');
  const [ifcFilter, setIfcFilter] = useState('');
  const [expandedSeq, setExpandedSeq] = useState<number | null>(null);

  // Subscribe to tool_call_end WS events and refetch audit data
  useEffect(() => {
    const unsub = subscribe('tool_call_end', () => {
      queryClient.invalidateQueries({ queryKey: ['audit'] });
    });
    return unsub;
  }, [subscribe, queryClient]);

  const params = new URLSearchParams({
    limit: String(PAGE_SIZE),
    offset: String(offset),
  });
  if (agentFilter) params.set('agent', agentFilter);
  if (toolFilter) params.set('tool', toolFilter);
  if (outcomeFilter) params.set('outcome', outcomeFilter);
  if (ifcFilter) params.set('ifc_label', ifcFilter);

  const { data, isLoading } = useQuery({
    queryKey: ['audit', offset, agentFilter, toolFilter, outcomeFilter, ifcFilter],
    queryFn: () => fetchJson<AuditResponse>(`/api/audit?${params}`, token),
    retry: false,
  });

  // Trust server for outcome filter. Apply ifc_label client-side as fallback
  // in case the server doesn't support that param yet.
  const entries = data?.entries ?? [];
  const displayed = ifcFilter
    ? entries.filter(e => e.ifc_label.toLowerCase().includes(ifcFilter.toLowerCase()))
    : entries;

  const exportCsv = useCallback(() => {
    if (!data) return;
    const rows = [
      ['seq', 'timestamp', 'agent', 'tool', 'outcome', 'duration_us', 'ifc_label', 'session_id'].join(','),
      ...displayed.map(e =>
        [
          e.seq,
          new Date(e.timestamp_ms).toISOString(),
          e.agent_name,
          e.tool_name,
          e.outcome,
          e.duration_us,
          e.ifc_label,
          e.session_id,
        ].join(',')
      ),
    ].join('\n');
    const blob = new Blob([rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `navra-audit-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [data, displayed]);

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Audit Log</h1>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            {data?.total ?? 0} entries
          </span>
          <button className="btn" onClick={exportCsv} disabled={!data}>
            Export CSV
          </button>
        </div>
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
        <select
          className="filter-input"
          value={outcomeFilter}
          onChange={e => { setOutcomeFilter(e.target.value); setOffset(0); }}
        >
          <option value="">All outcomes</option>
          <option value="allowed">Allowed</option>
          <option value="denied">Denied</option>
        </select>
        <input
          className="filter-input"
          placeholder="Filter by IFC label..."
          value={ifcFilter}
          onChange={e => { setIfcFilter(e.target.value); setOffset(0); }}
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
                <th>IFC Label</th>
                <th>Session</th>
              </tr>
            </thead>
            <tbody>
              {displayed.map(entry => (
                <AuditRow
                  key={entry.seq}
                  entry={entry}
                  expanded={expandedSeq === entry.seq}
                  onToggle={() => setExpandedSeq(expandedSeq === entry.seq ? null : entry.seq)}
                />
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

function AuditRow({ entry, expanded, onToggle }: { entry: BlackboxEntry; expanded: boolean; onToggle: () => void }) {
  return (
    <>
      <tr onClick={onToggle} style={{ cursor: 'pointer' }}>
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
        <td>
          {entry.ifc_label && (
            <span
              className="badge mono"
              style={{
                background: 'var(--indigo-muted, #e8eaf6)',
                color: 'var(--indigo, #3949ab)',
                border: '1px solid var(--indigo-border, #9fa8da)',
              }}
            >
              {entry.ifc_label}
            </span>
          )}
        </td>
        <td className="mono" style={{ color: 'var(--text-muted)' }}>
          {entry.session_id ? entry.session_id.slice(0, 8) : '—'}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={8} style={{ background: 'var(--surface)', padding: '16px' }}>
            <div style={{ marginBottom: '8px' }}>
              <strong>Arguments:</strong>
              <pre style={{ marginTop: '4px' }}>{formatJson(entry.tool_args)}</pre>
            </div>
            <div style={{ marginBottom: '8px' }}>
              <strong>Result:</strong>
              <pre style={{ marginTop: '4px' }}>{formatJson(entry.tool_result)}</pre>
            </div>
            {entry.act_chain && entry.act_chain.length > 0 && (
              <div>
                <strong>Activation chain:</strong>
                <ol style={{ marginTop: '4px', paddingLeft: '20px' }}>
                  {parseActChain(entry.act_chain).map((name, i) => (
                    <li key={i} className="mono" style={{ fontSize: '0.85rem' }}>{name}</li>
                  ))}
                </ol>
              </div>
            )}
          </td>
        </tr>
      )}
    </>
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

function parseActChain(raw: string): string[] {
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed.map((item: unknown) => {
        if (typeof item === 'string') return item;
        if (item && typeof item === 'object' && 'tool_name' in item) {
          return String((item as Record<string, unknown>).tool_name);
        }
        return String(item);
      });
    }
  } catch {
    // not JSON — return as a single entry
  }
  return raw ? [raw] : [];
}
