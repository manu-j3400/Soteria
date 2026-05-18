/**
 * Layout — wraps authenticated pages (Scanner, Batch, Engine, Graph, About)
 * with the AppSidebar and a content area.
 */
import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import AppSidebar from './AppSidebar';
import { COLORS } from '../theme/colors';

const CRUMB_MAP: Record<string, string> = {
  '/dashboard': 'Overview',
  '/scanner':   'Scanner',
  '/batch':     'Batch Scanner',
  '/engine':    'Model Lab',
};

function Breadcrumbs() {
  const { pathname } = useLocation();
  const label = CRUMB_MAP[pathname] ?? pathname.split('/').filter(Boolean).pop() ?? '';
  return (
    <div style={{
      height: 32, display: 'flex', alignItems: 'center', gap: 6,
      padding: '0 20px', borderBottom: `1px solid ${COLORS.border}`,
      background: '#030712', flexShrink: 0,
      fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
      letterSpacing: '0.08em',
    }}>
      <Link to="/dashboard" style={{ color: COLORS.muted, textDecoration: 'none' }}
        onMouseEnter={e => ((e.target as HTMLElement).style.color = COLORS.sub)}
        onMouseLeave={e => ((e.target as HTMLElement).style.color = COLORS.muted)}
      >
        SOTERIA
      </Link>
      <span style={{ color: COLORS.border }}>/</span>
      <span style={{ color: COLORS.sub }}>{label.toUpperCase()}</span>
    </div>
  );
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="h-screen flex overflow-hidden" style={{ background: '#030712', fontFamily: "'JetBrains Mono', monospace" }}>
      <AppSidebar />
      <main className="flex-1 flex flex-col overflow-hidden md:ml-48">
        <Breadcrumbs />
        <div className="flex-1 overflow-y-auto">
          {children}
        </div>
      </main>
    </div>
  );
}
