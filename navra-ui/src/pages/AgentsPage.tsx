import { useQuery } from '@tanstack/react-query';
import { fetchJson } from '../hooks/useApi';
import { useAuth } from '../contexts/AuthContext';
import { Spinner } from '../components/shared/Spinner';
import { EmptyState } from '../components/shared/EmptyState';
import type { AgentInfo, ProcessSnapshot } from '../types/api';

export function AgentsPage() {
  const { token } = useAuth();

  const { data: agents, isLoading } = useQuery({
    queryKey: ['agents'],
    queryFn: () => fetchJson<AgentInfo[]>('/api/agents', token),
    retry: false,
  });

  const { data: processes } = useQuery({
    queryKey: ['process'],
    queryFn: () => fetchJson<ProcessSnapshot[]>('/api/process', token),
    refetchInterval: 10_000,
    retry: false,
  });

  const activeAgents = new Set(processes?.map(p => p.name) ?? []);

  if (isLoading) {
    return <div className="page" style={{ display: 'flex', justifyContent: 'center', paddingTop: '80px' }}><Spinner size="lg" /></div>;
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Agents</h1>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          {agents?.length ?? 0} configured &middot; {activeAgents.size} active
        </span>
      </div>

      {!agents || agents.length === 0 ? (
        <EmptyState
          icon="★"
          title="No agents configured"
          description="Add agent definitions to your config.toml."
        />
      ) : (
        <div className="card-grid">
          {agents.map(a => {
            const isActive = activeAgents.has(a.name);
            const proc = processes?.find(p => p.name === a.name);
            return (
              <div key={a.name} className="agent-card" style={isActive ? { borderColor: 'var(--success)' } : undefined}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <div className="agent-name">{a.name}</div>
                  <span className={`badge ${isActive ? 'success' : ''}`} style={!isActive ? { color: 'var(--text-dim)' } : undefined}>
                    {isActive ? 'active' : 'offline'}
                  </span>
                </div>
                <div className="agent-detail">
                  <span>Permissions</span>
                  <span style={{ fontFamily: 'var(--font-mono)' }}>{a.permissions}</span>
                </div>
                <div className="agent-detail">
                  <span>Ring</span>
                  <span style={{ fontFamily: 'var(--font-mono)' }}>{a.ring ?? '—'}</span>
                </div>
                {isActive && proc && (
                  <>
                    <div className="agent-detail">
                      <span>Calls</span>
                      <span style={{ fontFamily: 'var(--font-mono)' }}>{proc.call_count}</span>
                    </div>
                    <div className="agent-detail">
                      <span>Denied</span>
                      <span style={{ fontFamily: 'var(--font-mono)', color: proc.denied_count > 0 ? 'var(--danger)' : undefined }}>
                        {proc.denied_count}
                      </span>
                    </div>
                  </>
                )}
                {a.safety && (
                  <div className="agent-detail">
                    <span>Safety</span>
                    <span style={{ fontFamily: 'var(--font-mono)' }}>{a.safety}</span>
                  </div>
                )}
                {a.did && (
                  <div className="agent-detail">
                    <span>DID</span>
                    <span className="mono" style={{ fontSize: '0.75rem', maxWidth: '160px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {a.did}
                    </span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
