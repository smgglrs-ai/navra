import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { fetchJson } from '../hooks/useApi';
import { useAuth } from '../contexts/AuthContext';
import { Spinner } from '../components/shared/Spinner';
import { BpmnViewer } from '../components/BpmnViewer';
import type { FlowGraph } from '../types/api';

export function FlowDetailPage() {
  const { flowId } = useParams<{ flowId: string }>();
  const { token } = useAuth();

  const { data: graph, isLoading } = useQuery({
    queryKey: ['flow-graph', flowId],
    queryFn: () => fetchJson<FlowGraph>(`/flows/${flowId}/graph`, token),
    refetchInterval: 5000,
    enabled: !!flowId,
  });

  if (!flowId) return null;

  return (
    <div className="page">
      <div className="page-header">
        <Link to="/flows" className="btn" style={{ marginRight: '12px' }}>&larr; Flows</Link>
        <h1 className="page-title">{graph?.name || flowId}</h1>
        {graph && (
          <span className="badge" style={{ marginLeft: '12px' }}>
            {graph.status}
          </span>
        )}
      </div>

      {isLoading ? (
        <div style={{ display: 'flex', justifyContent: 'center', paddingTop: '80px' }}>
          <Spinner size="lg" />
        </div>
      ) : (
        <BpmnViewer flowId={flowId} token={token} />
      )}

      {graph && graph.nodes.length > 0 && (
        <div style={{ marginTop: '16px' }}>
          <h2 style={{ fontSize: '14px', color: 'var(--text-muted)', marginBottom: '8px' }}>Tasks</h2>
          <div className="flow-list">
            {graph.nodes.map(node => (
              <div key={node.id} className="model-card" style={{ padding: '10px 14px' }}>
                <div>
                  <span className="model-name" style={{ fontSize: '13px' }}>{node.label}</span>
                  <span className="model-meta" style={{ marginLeft: '8px' }}>{node.id}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  {node.duration_ms !== undefined && (
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', fontVariantNumeric: 'tabular-nums' }}>
                      {node.duration_ms < 1000 ? `${node.duration_ms}ms` : `${(node.duration_ms / 1000).toFixed(1)}s`}
                    </span>
                  )}
                  <span className={`badge ${node.status === 'done' ? 'success' : node.status === 'running' ? 'info' : node.status === 'failed' ? 'danger' : ''}`}>
                    {node.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
