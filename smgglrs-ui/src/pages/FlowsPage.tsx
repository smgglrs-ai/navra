import { useQuery } from '@tanstack/react-query';
import { fetchJson } from '../hooks/useApi';
import { useAuth } from '../contexts/AuthContext';
import { Spinner } from '../components/shared/Spinner';
import { EmptyState } from '../components/shared/EmptyState';
import type { FlowInfo } from '../types/api';

export function FlowsPage() {
  const { token } = useAuth();

  const { data: flows, isLoading } = useQuery({
    queryKey: ['flows'],
    queryFn: () => fetchJson<FlowInfo[]>('/api/flows', token),
    retry: false,
  });

  if (isLoading) {
    return <div className="page" style={{ display: 'flex', justifyContent: 'center', paddingTop: '80px' }}><Spinner size="lg" /></div>;
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Flows</h1>
      </div>

      {!flows || flows.length === 0 ? (
        <EmptyState
          icon="▷"
          title="No flows configured"
          description="Add TOML flow definitions to your flow directories."
        />
      ) : (
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
      )}
    </div>
  );
}
