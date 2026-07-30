import { Component, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <div className="page" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', paddingTop: '80px', gap: '16px' }}>
          <div style={{ fontSize: '2rem', opacity: 0.4 }}>⚠</div>
          <div style={{ fontWeight: 600, color: 'var(--text-muted)' }}>Something went wrong</div>
          <pre style={{ fontSize: '0.8rem', color: 'var(--danger)', maxWidth: '600px', overflow: 'auto', padding: '12px', background: 'var(--surface)', borderRadius: 'var(--radius-sm)' }}>
            {this.state.error.message}
          </pre>
          <button className="btn primary" onClick={() => this.setState({ error: null })}>
            Try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
