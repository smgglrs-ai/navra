import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { fetchJson } from '../hooks/useApi';
import { useAuth } from '../contexts/AuthContext';
import { Spinner } from '../components/shared/Spinner';
import { EmptyState } from '../components/shared/EmptyState';
import type { FlowInfo, FlowRunSummary } from '../types/api';

export function FlowsPage() {
  const { token } = useAuth();

  const { data: flows, isLoading: loadingDefs } = useQuery({
    queryKey: ['flows'],
    queryFn: () => fetchJson<FlowInfo[]>('/api/flows', token),
    retry: false,
  });

  const { data: runs, isLoading: loadingRuns } = useQuery({
    queryKey: ['flow-runs'],
    queryFn: () => fetchJson<FlowRunSummary[]>('/api/flow-runs', token),
    refetchInterval: 5000,
    retry: false,
  });

  const isLoading = loadingDefs || loadingRuns;

  if (isLoading) {
    return <div className="page" style={{ display: 'flex', justifyContent: 'center', paddingTop: '80px' }}><Spinner size="lg" /></div>;
  }

  const hasRuns = runs && runs.length > 0;
  const hasDefs = flows && flows.length > 0;

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Flows</h1>
      </div>

      {hasRuns && (
        <>
          <h2 style={{ fontSize: '14px', color: 'var(--text-muted)', marginBottom: '8px' }}>Running</h2>
          <div className="flow-list" style={{ marginBottom: '24px' }}>
            {runs.map(run => (
              <Link key={run.flow_id} to={`/flows/${run.flow_id}`} style={{ textDecoration: 'none' }}>
                <div className="model-card">
                  <div>
                    <div className="model-name">{run.name}</div>
                    <div className="model-meta">{run.node_count} tasks &middot; {run.elapsed_secs}s</div>
                  </div>
                  <span className={`badge ${run.status === 'completed' ? 'success' : run.status === 'running' ? 'info' : 'danger'}`}>
                    {run.status}
                  </span>
                </div>
              </Link>
            ))}
          </div>
        </>
      )}

      {hasDefs && (
        <>
          <h2 style={{ fontSize: '14px', color: 'var(--text-muted)', marginBottom: '8px' }}>Definitions</h2>
          <div className="flow-list">
            {flows.map(flow => (
              <div key={flow.name} className="model-card">
                <div>
                  <div className="model-name">{flow.name}</div>
                  <div className="model-meta">{flow.tasks} tasks</div>
                </div>
                <button className="btn primary">Run</button>
              </div>
            ))}
          </div>
        </>
      )}

      {!hasRuns && !hasDefs && (
        <EmptyState
          icon="▷"
          title="No flows configured"
          description="Add TOML or BPMN flow definitions to your flow directories."
        />
      )}
    </div>
  );
}
