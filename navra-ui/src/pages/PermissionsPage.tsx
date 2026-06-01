import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchJson } from '../hooks/useApi';
import { useAuth } from '../contexts/AuthContext';
import { Spinner } from '../components/shared/Spinner';
import { EmptyState } from '../components/shared/EmptyState';
import type { PermissionSet } from '../types/api';

export function PermissionsPage() {
  const { token } = useAuth();
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const { data, isLoading } = useQuery({
    queryKey: ['permissions'],
    queryFn: () => fetchJson<{ permission_sets: Record<string, PermissionSet> }>('/api/permissions', token),
    retry: false,
  });

  const toggle = (name: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  if (isLoading) {
    return <div className="page" style={{ display: 'flex', justifyContent: 'center', paddingTop: '80px' }}><Spinner size="lg" /></div>;
  }

  const sets = data?.permission_sets ? Object.entries(data.permission_sets) : [];

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Permissions</h1>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          {sets.length} permission sets
        </span>
      </div>

      {sets.length === 0 ? (
        <EmptyState
          icon="⚿"
          title="No permission sets configured"
          description="Define permission sets in [permissions.*] in config.toml."
        />
      ) : (
        <div className="perm-tree">
          {sets.map(([name, pset]) => (
            <div className="perm-set" key={name}>
              <div className="perm-set-header" onClick={() => toggle(name)}>
                <span>{name}</span>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  {pset.ring !== undefined && (
                    <span className="badge warning">Ring {pset.ring}</span>
                  )}
                  {pset.safety && (
                    <span className="badge success">{pset.safety}</span>
                  )}
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                    {expanded.has(name) ? '▾' : '▸'}
                  </span>
                </div>
              </div>
              {expanded.has(name) && (
                <div className="perm-set-body">
                  {pset.allow && pset.allow.length > 0 && (
                    <div style={{ marginBottom: '8px' }}>
                      <div style={{ fontWeight: 600, marginBottom: '4px', color: 'var(--text-muted)' }}>Allow</div>
                      {pset.allow.map((rule, i) => (
                        <div key={i} className="perm-rule allow">+ {rule}</div>
                      ))}
                    </div>
                  )}
                  {pset.deny && pset.deny.length > 0 && (
                    <div style={{ marginBottom: '8px' }}>
                      <div style={{ fontWeight: 600, marginBottom: '4px', color: 'var(--text-muted)' }}>Deny</div>
                      {pset.deny.map((rule, i) => (
                        <div key={i} className="perm-rule deny">- {rule}</div>
                      ))}
                    </div>
                  )}
                  {pset.tool_rules && pset.tool_rules.length > 0 && (
                    <div style={{ marginBottom: '8px' }}>
                      <div style={{ fontWeight: 600, marginBottom: '4px', color: 'var(--text-muted)' }}>Tool Rules</div>
                      {pset.tool_rules.map((rule, i) => (
                        <div key={i} className={`perm-rule ${rule.policy.toLowerCase()}`}>
                          {rule.policy === 'Allow' ? '+' : rule.policy === 'Deny' ? '-' : '?'} {rule.tool} → {rule.policy}
                        </div>
                      ))}
                    </div>
                  )}
                  {pset.operations && pset.operations.length > 0 && (
                    <div>
                      <div style={{ fontWeight: 600, marginBottom: '4px', color: 'var(--text-muted)' }}>Operations</div>
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                        {pset.operations.join(', ')}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
