import { Outlet } from 'react-router-dom';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import { Footer } from './Footer';

export function AppShell() {
  return (
    <div className="app-shell">
      <Header />
      <Sidebar />
      <main className="main">
        <Outlet />
      </main>
      <Footer />
    </div>
  );
}
