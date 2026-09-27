/**
 * Application shell: fixed sidebar, top bar with the global intelligence-mode
 * indicator, and the routed content area.
 */
import { useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useApp } from '../api/AppContext';
import { Alert } from './ui';

interface NavItem {
  to: string;
  label: string;
  icon: string;
  hint: string;
  end?: boolean;
}

const NAV: NavItem[] = [
  { to: '/dashboard', label: 'Dashboard', icon: '▦', hint: 'Aggregate CTI metrics and charts' },
  { to: '/investigate', label: 'Investigate', icon: '⌕', hint: 'Submit a new indicator for enrichment' },
  { to: '/history', label: 'History', icon: '↺', hint: 'Reopen or delete past investigations' },
  { to: '/indicators', label: 'Indicators', icon: '◇', hint: 'Indicator library and correlation memory' },
  { to: '/threat-actors', label: 'Threat Actors', icon: '☗', hint: 'Attributed actors, malware and campaigns' },
  { to: '/mitre', label: 'MITRE ATT&CK', icon: '⛨', hint: 'Mapped techniques and the knowledge base' },
  { to: '/reports', label: 'Reports', icon: '⎙', hint: 'Generate and export CTI reports' },
  { to: '/settings', label: 'Settings', icon: '⚙', hint: 'Provider health, mode and profile' },
];

const PAGE_TITLE: Record<string, string> = {
  '/dashboard': 'Threat Dashboard',
  '/investigate': 'IOC Investigation',
  '/history': 'Investigation History',
  '/indicators': 'Indicator Library',
  '/threat-actors': 'Threat Actor Intelligence',
  '/mitre': 'MITRE ATT&CK Coverage',
  '/reports': 'Intelligence Reports',
  '/settings': 'Platform Settings',
};

export const AppShell = () => {
  const { user, registry, demoMode, logout } = useApp();
  const navigate = useNavigate();
  const location = useLocation();
  const [navOpen, setNavOpen] = useState(false);

  const base = `/${location.pathname.split('/')[1] ?? 'dashboard'}`;
  const title = PAGE_TITLE[base] ?? 'ThreatLens';

  return (
    <div className="shell">
      <aside className={`sidebar ${navOpen ? 'open' : ''}`}>
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            ⌾
          </div>
          <div>
            <div className="brand-name">ThreatLens</div>
            <div className="brand-sub">Threat Intelligence Platform</div>
          </div>
        </div>

        <nav className="nav">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              title={item.hint}
              onClick={() => setNavOpen(false)}
              className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
            >
              <span className="nav-icon" aria-hidden="true">
                {item.icon}
              </span>
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-foot">
          <div className="panel" style={{ padding: 12 }}>
            <div className="tiny dim mb-2">Intelligence mode</div>
            <div className="flex items-center gap-2 mb-2">
              <span className={`pulse-dot ${demoMode ? '' : 'live'}`} style={demoMode ? { background: 'var(--demo)' } : undefined} />
              <strong className="small" style={{ color: demoMode ? 'var(--demo)' : 'var(--clean)' }}>
                {registry?.modeLabel ?? '…'}
              </strong>
            </div>
            <div className="tiny dim">
              {demoMode
                ? 'Simulated dataset. Every result is labelled DEMO DATA.'
                : registry?.hasLiveKeys
                  ? 'Real provider intelligence is being queried.'
                  : 'No API keys configured - providers will report as unconfigured.'}
            </div>
            <button className="btn btn-sm btn-block mt-3" type="button" onClick={() => navigate('/settings')}>
              Change mode
            </button>
          </div>

          <div className="analyst-chip">
            <div className="avatar" aria-hidden="true">
              {(user?.displayName ?? '?').slice(0, 2).toUpperCase()}
            </div>
            <div className="grow" style={{ minWidth: 0 }}>
              <div className="small truncate" style={{ color: 'var(--ink-0)' }}>
                {user?.displayName}
              </div>
              <div className="tiny dim truncate">{user?.email}</div>
            </div>
            <button
              className="btn btn-sm btn-ghost"
              type="button"
              onClick={async () => {
                await logout();
                navigate('/login');
              }}
              title="Sign out"
            >
              ⏻
            </button>
          </div>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <button className="btn btn-sm btn-ghost nav-toggle" type="button" onClick={() => setNavOpen((v) => !v)} aria-label="Toggle navigation">
            ☰
          </button>
          <h1 className="topbar-title">{title}</h1>
          <div className="topbar-right">
            <span className={`badge ${demoMode ? 'badge-demo' : 'badge-clean'}`} title={registry?.notice ?? undefined}>
              {demoMode ? 'DEMO DATA' : 'LIVE INTELLIGENCE'}
            </span>
            <NavLink to="/investigate" className="btn btn-sm btn-primary">
              New Investigation
            </NavLink>
          </div>
        </header>

        {demoMode && registry?.notice ? (
          <div className="banner-slot">
            <Alert kind="demo" title="Demonstration mode is active" icon="◈">
              {registry.notice}{' '}
              <NavLink to="/settings">Configure live providers in Settings</NavLink> or{' '}
              <NavLink to="/investigate">open the walkthrough</NavLink>.
            </Alert>
          </div>
        ) : null}

        <main className="content">
          <Outlet />
        </main>

        <footer className="foot">
          <span>
            ThreatLens 1.0.0 — Cyber Threat Intelligence &amp; IOC Investigation Platform (capstone project)
          </span>
          <span className="dim">
            Defensive use only. Risk scores are ThreatLens analysis, not provider verdicts.
          </span>
        </footer>
      </div>
    </div>
  );
};
