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

  const byTask = new Map<string, ModelInfo[]>();
  for (const m of models ?? []) {
    const list = byTask.get(m.task) ?? [];
    list.push(m);
    byTask.set(m.task, list);
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Models</h1>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          {models?.length ?? 0} configured
        </span>
      </div>

      {!models || models.length === 0 ? (
        <EmptyState
          icon="⚙"
          title="No models loaded"
          description="Configure models in config.toml or run navra model pull."
        />
      ) : (
        Array.from(byTask.entries()).map(([task, taskModels]) => (
          <div key={task} style={{ marginBottom: '24px' }}>
            <h2 style={{ fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-dim)', marginBottom: '12px' }}>
              {task}
            </h2>
            <div className="card-grid">
              {taskModels.map(m => (
                <div key={m.name} className="model-card" style={{ flexDirection: 'column', alignItems: 'stretch', gap: '8px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div className="model-name">{m.name}</div>
                    <Badge variant={m.backend as 'onnx' | 'managed' | 'external'}>
                      {m.backend}
                    </Badge>
                  </div>
                  <div className="model-meta">
                    {m.context_size && `${(m.context_size / 1024).toFixed(0)}K ctx`}
                    {m.runtime && ` · ${m.runtime}`}
                    {m.source && ` · ${m.source}`}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))
      )}
    </div>
  );
}
