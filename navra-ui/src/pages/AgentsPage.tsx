import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { fetchJson } from '../hooks/useApi';
import { mutateApi } from '../hooks/useMutation';
import { useAuth } from '../contexts/AuthContext';
import { Spinner } from '../components/shared/Spinner';
import { EmptyState } from '../components/shared/EmptyState';
import type { AgentInfo, ProcessSnapshot, PermissionSet } from '../types/api';

interface AgentEditForm {
  name: string;
  permissions: string;
  token_hash: string;
}

export function AgentsPage() {
  const { token } = useAuth();
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<AgentEditForm>({ name: '', permissions: '', token_hash: '' });
  const [generatedToken, setGeneratedToken] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

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

  const { data: permData } = useQuery({
    queryKey: ['permissions'],
    queryFn: () => fetchJson<{ permission_sets: Record<string, PermissionSet> }>('/api/permissions', token),
    retry: false,
  });

  const activeAgents = new Set(processes?.map(p => p.name) ?? []);
  const permNames = permData?.permission_sets ? Object.keys(permData.permission_sets) : [];

  const startAdd = () => {
    setEditing('__new__');
    setEditForm({ name: '', permissions: permNames[0] || 'dev', token_hash: '' });
    setGeneratedToken(null);
  };

  const startEdit = (a: AgentInfo) => {
    setEditing(a.name);
    setEditForm({ name: a.name, permissions: a.permissions, token_hash: '' });
    setGeneratedToken(null);
  };

  const generateToken = () => {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    const raw = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    setGeneratedToken(raw);
    crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw)).then(hash => {
      const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
      setEditForm(prev => ({ ...prev, token_hash: hex }));
    });
  };

  const saveAgent = async () => {
    if (!editForm.name || !editForm.permissions) return;
    setSaving(true);
    const body: Record<string, unknown> = {
      name: editForm.name,
      permissions: editForm.permissions,
      token_hash: editForm.token_hash || 'placeholder',
    };
    const resp = await mutateApi(`/api/agents/${editForm.name}`, 'PUT', body, token);
    setSaving(false);
    if (resp.ok) {
      setEditing(null);
      setGeneratedToken(null);
      queryClient.invalidateQueries({ queryKey: ['agents'] });
    }
  };

  const deleteAgent = async (name: string) => {
    if (!confirm(`Delete agent "${name}"?`)) return;
    const resp = await mutateApi(`/api/agents/${name}`, 'DELETE', undefined, token);
    if (resp.ok) {
      queryClient.invalidateQueries({ queryKey: ['agents'] });
    }
  };

  if (isLoading) {
    return <div className="page" style={{ display: 'flex', justifyContent: 'center', paddingTop: '80px' }}><Spinner size="lg" /></div>;
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Agents</h1>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            {agents?.length ?? 0} configured &middot; {activeAgents.size} active
          </span>
          <button className="btn primary" onClick={startAdd}>Add Agent</button>
        </div>
      </div>

      {editing === '__new__' && (
        <div className="card" style={{ marginBottom: '16px', padding: '16px' }}>
          <AgentForm
            form={editForm}
            setForm={setEditForm}
            permNames={permNames}
            generatedToken={generatedToken}
            onGenerate={generateToken}
            onSave={saveAgent}
            onCancel={() => { setEditing(null); setGeneratedToken(null); }}
            saving={saving}
          />
        </div>
      )}

      {!agents || agents.length === 0 ? (
        <EmptyState
          icon="★"
          title="No agents configured"
          description="Add agent definitions using the button above."
        />
      ) : (
        <div className="card-grid">
          {agents.map(a => {
            const isActive = activeAgents.has(a.name);
            const proc = processes?.find(p => p.name === a.name);
            return (
              <div key={a.name} className="agent-card" style={isActive ? { borderColor: 'var(--success)' } : undefined}>
                {editing === a.name ? (
                  <AgentForm
                    form={editForm}
                    setForm={setEditForm}
                    permNames={permNames}
                    generatedToken={generatedToken}
                    onGenerate={generateToken}
                    onSave={saveAgent}
                    onCancel={() => { setEditing(null); setGeneratedToken(null); }}
                    saving={saving}
                    isEdit
                  />
                ) : (
                  <>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <div className="agent-name">{a.name}</div>
                      <div style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
                        <span className={`badge ${isActive ? 'success' : ''}`} style={!isActive ? { color: 'var(--text-dim)' } : undefined}>
                          {isActive ? 'active' : 'offline'}
                        </span>
                        <button className="btn" style={{ padding: '2px 8px', fontSize: '0.7rem' }} onClick={() => startEdit(a)}>Edit</button>
                        <button className="btn danger" style={{ padding: '2px 8px', fontSize: '0.7rem' }} onClick={() => deleteAgent(a.name)}>Delete</button>
                      </div>
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
                          <span style={{ fontFamily: 'var(--font-mono)', color: proc.denied_count > 0 ? 'var(--danger)' : undefined }}>{proc.denied_count}</span>
                        </div>
                      </>
                    )}
                    {a.safety && (
                      <div className="agent-detail">
                        <span>Safety</span>
                        <span style={{ fontFamily: 'var(--font-mono)' }}>{a.safety}</span>
                      </div>
                    )}
                  </>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function AgentForm({ form, setForm, permNames, generatedToken, onGenerate, onSave, onCancel, saving, isEdit }: {
  form: AgentEditForm;
  setForm: (f: AgentEditForm) => void;
  permNames: string[];
  generatedToken: string | null;
  onGenerate: () => void;
  onSave: () => void;
  onCancel: () => void;
  saving: boolean;
  isEdit?: boolean;
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
      <div>
        <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Name</label>
        <input className="filter-input" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} disabled={isEdit} style={{ width: '100%' }} />
      </div>
      <div>
        <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Permission Set</label>
        <select className="filter-input" value={form.permissions} onChange={e => setForm({ ...form, permissions: e.target.value })}>
          {permNames.map(p => <option key={p} value={p}>{p}</option>)}
        </select>
      </div>
      <div>
        <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Token</label>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <button className="btn" onClick={onGenerate} type="button">Generate Token</button>
          {generatedToken && (
            <code style={{ fontSize: '0.7rem', wordBreak: 'break-all', padding: '4px 8px', background: 'var(--surface)', borderRadius: '4px', maxWidth: '300px', overflow: 'hidden' }}>
              {generatedToken}
            </code>
          )}
        </div>
        {generatedToken && (
          <div style={{ fontSize: '0.75rem', color: 'var(--warning)', marginTop: '4px' }}>
            Copy this token now — it will not be shown again.
          </div>
        )}
      </div>
      <div style={{ display: 'flex', gap: '8px', marginTop: '4px' }}>
        <button className="btn primary" onClick={onSave} disabled={saving || !form.name}>
          {saving ? 'Saving...' : 'Save'}
        </button>
        <button className="btn" onClick={onCancel}>Cancel</button>
      </div>
    </div>
  );
}
