import { useQuery } from '@tanstack/react-query';
import { fetchJson } from '../hooks/useApi';
import { useAuth } from '../contexts/AuthContext';
import { Spinner } from '../components/shared/Spinner';
import { EmptyState } from '../components/shared/EmptyState';
import { Badge } from '../components/shared/Badge';
import type { ModelInfo } from '../types/api';

export function ModelsPage() {
  const { token } = useAuth();

  const { data: models, isLoading } = useQuery({
    queryKey: ['models'],
    queryFn: () => fetchJson<ModelInfo[]>('/api/models', token),
    retry: false,
  });

  if (isLoading) {
    return <div className="page" style={{ display: 'flex', justifyContent: 'center', paddingTop: '80px' }}><Spinner size="lg" /></div>;
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Models</h1>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          {models?.length ?? 0} loaded
        </span>
      </div>

      {!models || models.length === 0 ? (
        <EmptyState
          icon="⚙"
          title="No models loaded"
          description="Configure models in config.toml or run smgglrs model pull."
        />
      ) : (
        <div className="card-grid">
          {models.map(m => (
            <div key={m.name} className="model-card">
              <div>
                <div className="model-name">{m.name}</div>
                <div className="model-meta">
                  {m.task}
                  {m.context_size && ` · ${(m.context_size / 1024).toFixed(0)}K ctx`}
                  {m.runtime && ` · ${m.runtime}`}
                </div>
              </div>
              <Badge variant={m.backend as 'onnx' | 'managed' | 'external'}>
                {m.backend}
              </Badge>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
