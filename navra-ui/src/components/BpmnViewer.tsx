import { useEffect, useRef, useCallback } from 'react';
import NavigatedViewer from 'bpmn-js/lib/NavigatedViewer';
import '../styles/bpmn.css';

interface BpmnViewerProps {
  flowId: string;
  token: string | null;
}

const STATUS_COLORS: Record<string, { border: string; bg: string }> = {
  done: { border: 'var(--success)', bg: 'var(--success-bg)' },
  running: { border: 'var(--info)', bg: 'var(--info-bg)' },
  failed: { border: 'var(--danger)', bg: 'var(--danger-bg)' },
  pending: { border: 'var(--surface-3)', bg: 'transparent' },
};

export function BpmnViewer({ flowId, token }: BpmnViewerProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const viewerRef = useRef<NavigatedViewer | null>(null);

  const applyOverlays = useCallback((viewer: NavigatedViewer) => {
    const overlays = viewer.get('overlays') as any;
    const elementRegistry = viewer.get('elementRegistry') as any;

    overlays.clear();

    elementRegistry.forEach((element: any) => {
      if (element.type === 'bpmn:ServiceTask' || element.type === 'bpmn:UserTask') {
        const bo = element.businessObject;
        const extensions = bo?.extensionElements?.values || [];
        let status = 'pending';
        for (const ext of extensions) {
          if (ext.$type === 'navra:status' || ext.localName === 'status') {
            status = ext.body || ext.text || 'pending';
            break;
          }
        }

        const colors = STATUS_COLORS[status] || STATUS_COLORS.pending;
        const html = document.createElement('div');
        html.className = `bpmn-status-overlay bpmn-status-${status}`;
        html.style.border = `2px solid ${colors.border}`;
        html.style.backgroundColor = colors.bg;
        html.style.width = `${element.width}px`;
        html.style.height = `${element.height}px`;
        html.style.borderRadius = '8px';
        html.style.pointerEvents = 'none';

        overlays.add(element.id, {
          position: { top: 0, left: 0 },
          html,
        });
      }
    });
  }, []);

  const loadDiagram = useCallback(async (viewer: NavigatedViewer) => {
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    try {
      const resp = await fetch(`/flows/${flowId}/graph/bpmn`, { headers });
      if (!resp.ok) return;
      const xml = await resp.text();
      await viewer.importXML(xml);
      (viewer.get('canvas') as any).zoom('fit-viewport');
      applyOverlays(viewer);
    } catch (e) {
      console.warn('Failed to load BPMN diagram:', e);
    }
  }, [flowId, token, applyOverlays]);

  useEffect(() => {
    if (!containerRef.current) return;

    const viewer = new NavigatedViewer({
      container: containerRef.current,
    });
    viewerRef.current = viewer;
    loadDiagram(viewer);

    // SSE for live updates
    const url = new URL(`/flows/${flowId}/events`, window.location.origin);
    const eventSource = new EventSource(url.toString());
    eventSource.addEventListener('flow_event', () => {
      loadDiagram(viewer);
    });
    eventSource.addEventListener('done', () => {
      loadDiagram(viewer);
      eventSource.close();
    });

    return () => {
      eventSource.close();
      viewer.destroy();
      viewerRef.current = null;
    };
  }, [flowId, loadDiagram]);

  return (
    <div className="bpmn-viewer-container">
      <div ref={containerRef} className="bpmn-canvas" />
    </div>
  );
}
