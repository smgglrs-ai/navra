import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { fetchJson } from '../hooks/useApi';
import { useAuth } from '../contexts/AuthContext';
import { Spinner } from '../components/shared/Spinner';
import { EmptyState } from '../components/shared/EmptyState';
import type { FlowInfo, FlowRunSummary } from '../types/api';

export function FlowsPage() {
  const { token } = useAuth();
  const queryClient = useQueryClient();
  const [runningFlow, setRunningFlow] = useState<string | null>(null);
  const [openFlowForm, setOpenFlowForm] = useState<string | null>(null);
  const [flowPrompt, setFlowPrompt] = useState('Execute the flow');
  const [cancellingFlow, setCancellingFlow] = useState<string | null>(null);

  const { data: flows, isLoading: loadingDefs } = useQuery({
    queryKey: ['flows'],
    queryFn: () => fetchJson<FlowInfo[]>('/api/flows', token),
    retry: false,
  });

  const { data: runs, isLoading: loadingRuns } = useQuery({
    queryKey: ['flow-runs'],
    queryFn: () => fetchJson<FlowRunSummary[]>('/api/flow-runs', token),
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return 2000;
      const anyRunning = data.some((r: FlowRunSummary) => r.status === 'running');
      return anyRunning ? 2000 : false;
    },
    retry: false,
  });

  const openRunForm = (name: string) => {
    if (openFlowForm === name) {
      setOpenFlowForm(null);
    } else {
      setOpenFlowForm(name);
      setFlowPrompt('Execute the flow');
    }
  };

  const runFlow = async (name: string, prompt: string) => {
    setRunningFlow(name);
    setOpenFlowForm(null);
    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;
      const resp = await fetch(`/api/flows/${name}/run`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ prompt }),
      });
      if (resp.ok) {
        queryClient.invalidateQueries({ queryKey: ['flow-runs'] });
      } else {
        const err = await resp.text();
        alert(`Flow failed: ${err}`);
      }
    } finally {
      setRunningFlow(null);
    }
  };

  const cancelFlow = async (flowId: string) => {
    setCancellingFlow(flowId);
    try {
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;
      await fetch(`/api/flow-runs/${flowId}`, { method: 'DELETE', headers });
      queryClient.invalidateQueries({ queryKey: ['flow-runs'] });
    } finally {
      setCancellingFlow(null);
    }
  };

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
              <div key={run.flow_id}>
                <Link to={`/flows/${run.flow_id}`} style={{ textDecoration: 'none' }}>
                  <div className="model-card">
                    <div>
                      <div className="model-name">{run.name}</div>
                      <div className="model-meta">{run.node_count} tasks &middot; {run.elapsed_secs}s</div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className={`badge ${run.status === 'completed' ? 'success' : run.status === 'running' ? 'info' : 'danger'}`}>
                        {run.status}
                      </span>
                      {run.status === 'running' && (
                        <button
                          className="btn danger"
                          disabled={cancellingFlow === run.flow_id}
                          onClick={e => { e.preventDefault(); cancelFlow(run.flow_id); }}
                          style={{ fontSize: '0.75rem', padding: '2px 8px' }}
                        >
                          {cancellingFlow === run.flow_id ? '...' : 'Cancel'}
                        </button>
                      )}
                    </div>
                  </div>
                </Link>
              </div>
            ))}
          </div>
        </>
      )}

      {hasDefs && (
        <>
          <h2 style={{ fontSize: '14px', color: 'var(--text-muted)', marginBottom: '8px' }}>Definitions</h2>
          <div className="flow-list">
            {flows.map(flow => (
              <div key={flow.name}>
                <div className="model-card">
                  <div>
                    <div className="model-name">{flow.name}</div>
                    <div className="model-meta">{flow.tasks} tasks</div>
                  </div>
                  <button
                    className="btn primary"
                    onClick={() => openRunForm(flow.name)}
                    disabled={runningFlow === flow.name}
                  >
                    {runningFlow === flow.name ? 'Starting...' : 'Run'}
                  </button>
                </div>
                {openFlowForm === flow.name && (
                  <div style={{ padding: '8px 12px 12px', borderTop: '1px solid var(--border)', background: 'var(--surface-alt)' }}>
                    <textarea
                      value={flowPrompt}
                      onChange={e => setFlowPrompt(e.target.value)}
                      rows={3}
                      style={{ width: '100%', boxSizing: 'border-box', fontFamily: 'inherit', fontSize: '0.85rem', padding: '6px 8px', borderRadius: '4px', border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text)', resize: 'vertical' }}
                      placeholder="Enter prompt..."
                    />
                    <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '6px', gap: '8px' }}>
                      <button className="btn" onClick={() => setOpenFlowForm(null)}>Cancel</button>
                      <button className="btn primary" onClick={() => runFlow(flow.name, flowPrompt)}>Submit</button>
                    </div>
                  </div>
                )}
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
