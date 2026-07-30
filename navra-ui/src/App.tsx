import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AppShell } from './components/layout/AppShell';
import { ErrorBoundary } from './components/shared/ErrorBoundary';
import { DashboardPage } from './pages/DashboardPage';
import { SessionsPage } from './pages/SessionsPage';
import { AuditPage } from './pages/AuditPage';
import { ChatPage } from './pages/ChatPage';
import { FlowsPage } from './pages/FlowsPage';
import { FlowDetailPage } from './pages/FlowDetailPage';
import { ModelsPage } from './pages/ModelsPage';
import { AgentsPage } from './pages/AgentsPage';
import { SafetyPage } from './pages/SafetyPage';
import { PermissionsPage } from './pages/PermissionsPage';

function Wrap({ children }: { children: React.ReactNode }) {
  return <ErrorBoundary>{children}</ErrorBoundary>;
}

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<Wrap><DashboardPage /></Wrap>} />
          <Route path="sessions" element={<Wrap><SessionsPage /></Wrap>} />
          <Route path="audit" element={<Wrap><AuditPage /></Wrap>} />
          <Route path="chat" element={<Wrap><ChatPage /></Wrap>} />
          <Route path="flows" element={<Wrap><FlowsPage /></Wrap>} />
          <Route path="flows/:flowId" element={<Wrap><FlowDetailPage /></Wrap>} />
          <Route path="models" element={<Wrap><ModelsPage /></Wrap>} />
          <Route path="agents" element={<Wrap><AgentsPage /></Wrap>} />
          <Route path="safety" element={<Wrap><SafetyPage /></Wrap>} />
          <Route path="permissions" element={<Wrap><PermissionsPage /></Wrap>} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
