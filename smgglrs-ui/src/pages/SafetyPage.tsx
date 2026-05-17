import { useQuery } from '@tanstack/react-query';
import { fetchJson } from '../hooks/useApi';
import { useAuth } from '../contexts/AuthContext';
import { Spinner } from '../components/shared/Spinner';
import type { SafetyMetrics } from '../types/api';

export function SafetyPage() {
  const { token } = useAuth();

  const { data: metrics, isLoading } = useQuery({
    queryKey: ['safety'],
    queryFn: () => fetchJson<SafetyMetrics>('/api/safety', token),
    refetchInterval: 10_000,
    retry: false,
  });

  if (isLoading) {
    return <div className="page" style={{ display: 'flex', justifyContent: 'center', paddingTop: '80px' }}><Spinner size="lg" /></div>;
  }

  const categories = metrics?.by_category ? Object.entries(metrics.by_category) : [];
  const maxCount = Math.max(1, ...categories.map(([, v]) => v));

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Safety</h1>
      </div>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-card-label">Total Scans</div>
          <div className="stat-card-value">{metrics?.total_scans?.toLocaleString() ?? '—'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">PII Detected</div>
          <div className="stat-card-value" style={{ color: (metrics?.pii_detected ?? 0) > 0 ? 'var(--warning)' : undefined }}>
            {metrics?.pii_detected?.toLocaleString() ?? '—'}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">PII Redacted</div>
          <div className="stat-card-value" style={{ color: 'var(--info)' }}>
            {metrics?.pii_redacted?.toLocaleString() ?? '—'}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-card-label">PII Blocked</div>
          <div className="stat-card-value" style={{ color: (metrics?.pii_blocked ?? 0) > 0 ? 'var(--danger)' : undefined }}>
            {metrics?.pii_blocked?.toLocaleString() ?? '—'}
          </div>
        </div>
      </div>

      {categories.length > 0 && (
        <>
          <h2 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '16px' }}>Detections by Category</h2>
          <div className="card" style={{ padding: '24px' }}>
            <div className="bar-chart">
              {categories
                .sort((a, b) => b[1] - a[1])
                .map(([category, count]) => (
                  <div className="bar-row" key={category}>
                    <div className="bar-label">{category}</div>
                    <div className="bar-track">
                      <div
                        className="bar-fill"
                        style={{
                          width: `${(count / maxCount) * 100}%`,
                          background: categoryColor(category),
                        }}
                      />
                    </div>
                    <div className="bar-value">{count}</div>
                  </div>
                ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function categoryColor(category: string): string {
  const colors: Record<string, string> = {
    'ssn': 'var(--danger)',
    'credit-card': 'var(--danger)',
    'aws-key': 'var(--danger)',
    'email': 'var(--warning)',
    'phone': 'var(--warning)',
    'person': 'var(--info)',
    'location': 'var(--info)',
  };
  return colors[category] || 'var(--accent)';
}
