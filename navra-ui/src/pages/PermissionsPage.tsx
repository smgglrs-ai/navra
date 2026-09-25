import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { fetchJson } from '../hooks/useApi';
import { mutateApi } from '../hooks/useMutation';
import { useAuth } from '../contexts/AuthContext';
import { Spinner } from '../components/shared/Spinner';
import { EmptyState } from '../components/shared/EmptyState';
import type { AgentInfo, PermissionSet, ToolRule } from '../types/api';

function toolRulesToJson(rules: ToolRule[]): string {
  return JSON.stringify(rules, null, 2);
}

function parseToolRules(text: string): { rules: ToolRule[] | null; error: string | null } {
  const trimmed = text.trim();
  if (!trimmed) return { rules: [], error: null };
  try {
    const parsed = JSON.parse(trimmed);
    if (!Array.isArray(parsed)) return { rules: null, error: 'Must be a JSON array' };
    for (const item of parsed) {
      if (typeof item !== 'object' || item === null) return { rules: null, error: 'Each entry must be an object' };
      if (typeof item.tool !== 'string') return { rules: null, error: 'Each entry must have a "tool" string' };
      if (!['Allow', 'Deny', 'Approve'].includes(item.policy)) return { rules: null, error: 'Each "policy" must be Allow, Deny, or Approve' };
    }
    return { rules: parsed as ToolRule[], error: null };
  } catch (e) {
    return { rules: null, error: `Invalid JSON: ${(e as Error).message}` };
  }
}

export function PermissionsPage() {
  const { token } = useAuth();
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [editing, setEditing] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<Partial<PermissionSet>>({});
  const [toolRulesText, setToolRulesText] = useState('');
  const [toolRulesError, setToolRulesError] = useState<string | null>(null);
  const [newSetName, setNewSetName] = useState('');
  const [saving, setSaving] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ['permissions'],
    queryFn: () => fetchJson<{ permission_sets: Record<string, PermissionSet> }>('/api/permissions', token),
    retry: false,
  });

  const { data: agentsData } = useQuery({
    queryKey: ['agents'],
    queryFn: () => fetchJson<AgentInfo[]>('/api/agents', token),
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

  const openEditForm = (name: string, pset: PermissionSet) => {
    setEditing(name);
    setEditForm({
      ring: pset.ring,
      allow: pset.allow ? [...pset.allow] : [],
      deny: pset.deny ? [...pset.deny] : [],
      safety: pset.safety || 'standard',
      operations: pset.operations ? [...pset.operations] : [],
      tool_rules: pset.tool_rules ? [...pset.tool_rules] : [],
    });
    setToolRulesText(pset.tool_rules && pset.tool_rules.length > 0 ? toolRulesToJson(pset.tool_rules) : '');
    setToolRulesError(null);
  };

  const startEdit = (name: string, pset: PermissionSet) => {
    setNewSetName('');
    openEditForm(name, pset);
  };

  const startNew = () => {
    setEditing('__new__');
    setNewSetName('');
    setEditForm({
      ring: undefined,
      allow: [],
      deny: [],
      safety: 'standard',
      operations: [],
      tool_rules: [],
    });
    setToolRulesText('');
    setToolRulesError(null);
  };

  const saveEdit = async (name: string) => {
    const { rules, error } = parseToolRules(toolRulesText);
    if (error) {
      setToolRulesError(error);
      return;
    }
    setToolRulesError(null);

    const targetName = editing === '__new__' ? newSetName : name;
    if (!targetName.trim()) return;

    const body: Partial<PermissionSet> = {
      ...editForm,
      tool_rules: rules ?? [],
    };

    setSaving(true);
    const resp = await mutateApi(`/api/permissions/${targetName}`, 'PUT', body, token);
    setSaving(false);
    if (resp.ok) {
      setEditing(null);
      setNewSetName('');
      queryClient.invalidateQueries({ queryKey: ['permissions'] });
    }
  };

  const deletePermission = async (name: string) => {
    const using = (agentsData ?? []).filter(a => a.permissions === name).map(a => a.name);
    let msg = `Delete permission set "${name}"?`;
    if (using.length > 0) {
      msg += `\n\nUsed by: ${using.join(', ')}. Delete anyway?`;
    }
    if (!confirm(msg)) return;
    const resp = await mutateApi(`/api/permissions/${name}`, 'DELETE', undefined, token);
    if (resp.ok) {
      queryClient.invalidateQueries({ queryKey: ['permissions'] });
    }
  };

  if (isLoading) {
    return <div className="page" style={{ display: 'flex', justifyContent: 'center', paddingTop: '80px' }}><Spinner size="lg" /></div>;
  }

  const sets = data?.permission_sets ? Object.entries(data.permission_sets) : [];

  const EditForm = ({ name }: { name: string }) => (
    <div className="perm-set-body" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      {editing === '__new__' && (
        <div>
          <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Name</label>
          <input className="filter-input" value={newSetName} onChange={e => setNewSetName(e.target.value)} placeholder="e.g. restricted" style={{ width: '100%' }} />
        </div>
      )}
      <div>
        <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Ring</label>
        <input className="filter-input" type="number" min="0" max="3" value={editForm.ring ?? ''} onChange={e => setEditForm({ ...editForm, ring: e.target.value ? Number(e.target.value) : undefined })} style={{ width: '80px' }} />
      </div>
      <div>
        <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Safety</label>
        <select className="filter-input" value={editForm.safety || 'standard'} onChange={e => setEditForm({ ...editForm, safety: e.target.value })}>
          <option value="standard">standard</option>
          <option value="pseudonymize">pseudonymize</option>
          <option value="secrets-only">secrets-only</option>
          <option value="block">block</option>
          <option value="guardian">guardian</option>
          <option value="guardian-deep">guardian-deep</option>
          <option value="none">none</option>
        </select>
      </div>
      <div>
        <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Allow paths (one per line)</label>
        <textarea className="filter-input" rows={3} value={(editForm.allow ?? []).join('\n')} onChange={e => setEditForm({ ...editForm, allow: e.target.value.split('\n').filter(Boolean) })} style={{ width: '100%', resize: 'vertical' }} />
      </div>
      <div>
        <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Deny paths (one per line)</label>
        <textarea className="filter-input" rows={3} value={(editForm.deny ?? []).join('\n')} onChange={e => setEditForm({ ...editForm, deny: e.target.value.split('\n').filter(Boolean) })} style={{ width: '100%', resize: 'vertical' }} />
      </div>
      <div>
        <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Operations (comma-separated)</label>
        <input className="filter-input" value={(editForm.operations ?? []).join(', ')} onChange={e => setEditForm({ ...editForm, operations: e.target.value.split(',').map(s => s.trim()).filter(Boolean) })} style={{ width: '100%' }} />
      </div>
      <div>
        <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
          Tool Rules (JSON array of <code style={{ fontSize: '0.75rem' }}>{`{"tool":"...","policy":"Allow|Deny|Approve"}`}</code>)
        </label>
        <textarea
          className="filter-input"
          rows={5}
          value={toolRulesText}
          onChange={e => { setToolRulesText(e.target.value); setToolRulesError(null); }}
          style={{ width: '100%', resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}
          placeholder={'[\n  {"tool": "file_read", "policy": "Allow"}\n]'}
        />
        {toolRulesError && (
          <div style={{ fontSize: '0.75rem', color: 'var(--danger)', marginTop: '4px' }}>{toolRulesError}</div>
        )}
      </div>
      <div style={{ display: 'flex', gap: '8px' }}>
        <button className="btn primary" onClick={() => saveEdit(name)} disabled={saving || (editing === '__new__' && !newSetName.trim())}>
          {saving ? 'Saving...' : 'Save'}
        </button>
        <button className="btn" onClick={() => { setEditing(null); setNewSetName(''); setToolRulesError(null); }}>Cancel</button>
      </div>
    </div>
  );

  return (
    <div className="page">
      <div className="page-header">
        <h1 className="page-title">Permissions</h1>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            {sets.length} permission sets
          </span>
          <button className="btn primary" onClick={startNew}>New Permission Set</button>
        </div>
      </div>

      {editing === '__new__' && (
        <div className="perm-set" style={{ marginBottom: '12px' }}>
          <div className="perm-set-header" style={{ cursor: 'default' }}>
            <span style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>New permission set</span>
          </div>
          <EditForm name="" />
        </div>
      )}

      {sets.length === 0 && editing !== '__new__' ? (
        <EmptyState
          icon="⚿"
          title="No permission sets configured"
          description="Define permission sets in config.json or config.toml."
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
                  <button className="btn" style={{ padding: '2px 8px', fontSize: '0.75rem' }} onClick={e => { e.stopPropagation(); startEdit(name, pset); }}>
                    Edit
                  </button>
                  <button className="btn danger" style={{ padding: '2px 8px', fontSize: '0.75rem' }} onClick={e => { e.stopPropagation(); deletePermission(name); }}>
                    Delete
                  </button>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                    {expanded.has(name) ? '▾' : '▸'}
                  </span>
                </div>
              </div>
              {editing === name ? (
                <EditForm name={name} />
              ) : expanded.has(name) && (
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
