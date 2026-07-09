import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AppShell } from './components/layout/AppShell';
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

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<DashboardPage />} />
          <Route path="sessions" element={<SessionsPage />} />
          <Route path="audit" element={<AuditPage />} />
          <Route path="chat" element={<ChatPage />} />
          <Route path="flows" element={<FlowsPage />} />
          <Route path="flows/:flowId" element={<FlowDetailPage />} />
          <Route path="models" element={<ModelsPage />} />
          <Route path="agents" element={<AgentsPage />} />
          <Route path="safety" element={<SafetyPage />} />
          <Route path="permissions" element={<PermissionsPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
