import { NavLink } from 'react-router-dom';

interface NavItem {
  label: string;
  path: string;
  icon: string;
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

const navigation: NavGroup[] = [
  {
    title: 'Operations',
    items: [
      { label: 'Dashboard', path: '/', icon: '▣' },
      { label: 'Sessions', path: '/sessions', icon: '☰' },
      { label: 'Audit Log', path: '/audit', icon: '⚑' },
    ],
  },
  {
    title: 'Workspace',
    items: [
      { label: 'Chat', path: '/chat', icon: '✉' },
      { label: 'Flows', path: '/flows', icon: '▷' },
    ],
  },
  {
    title: 'Configuration',
    items: [
      { label: 'Models', path: '/models', icon: '⚙' },
      { label: 'Agents', path: '/agents', icon: '★' },
      { label: 'Safety', path: '/safety', icon: '⛨' },
      { label: 'Permissions', path: '/permissions', icon: '⚿' },
    ],
  },
];

export function Sidebar() {
  return (
    <nav className="sidebar">
      {navigation.map(group => (
        <div className="sidebar-group" key={group.title}>
          <div className="sidebar-group-label">{group.title}</div>
          {group.items.map(item => (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </div>
      ))}
    </nav>
  );
}
