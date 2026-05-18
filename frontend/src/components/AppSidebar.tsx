/**
 * AppSidebar — the persistent left rail for all authenticated pages.
 * Design: Weaponized Minimalism · JetBrains Mono · Acid green accent
 */
import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Activity, Brain, Home, Layers, LogOut, Plus } from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import { COLORS } from '../theme/colors';

const NAV = [
  { to: '/dashboard', label: 'Overview',  Icon: Home },
  { to: '/scanner',   label: 'Scanner',   Icon: Activity },
  { to: '/batch',     label: 'Batch',     Icon: Layers },
  { to: '/engine',    label: 'Model Lab', Icon: Brain },
];

const S = {
  sidebar:   { background: '#030712', borderRight: `1px solid ${COLORS.border}`, fontFamily: "'JetBrains Mono', monospace" },
  topBorder: { borderBottom: `1px solid ${COLORS.border}` },
  midBorder: { borderBottom: `1px solid ${COLORS.border2}` },
  botBorder: { borderTop: `1px solid ${COLORS.border}` },
  pill:      { background: COLORS.acid, color: '#000', borderRadius: 0 },
  pillHover: { background: COLORS.acidDim, color: '#000', borderRadius: 0 },
} as const;

export default function AppSidebar() {
  const { pathname } = useLocation();
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [btnHover, setBtnHover] = React.useState(false);
  const [logoutHover, setLogoutHover] = React.useState(false);

  return (
    <aside className="fixed top-0 left-0 bottom-0 w-48 flex flex-col z-50 select-none hidden md:flex" style={S.sidebar}>

      {/* ── Logo ── */}
      <div className="h-14 flex items-center gap-3 px-5 flex-shrink-0" style={S.topBorder}>
        <img src="/soteria-logo.png" alt="Soteria" className="w-5 h-5 object-cover" style={{ borderRadius: 0 }} />
        <span className="text-[11px] font-bold tracking-[0.08em] text-white">SOTERIA</span>
      </div>

      {/* ── Status pill ── */}
      <div className="px-5 py-2 flex-shrink-0" style={S.midBorder}>
        <span
          className="flex items-center gap-2 text-[11px] font-bold"
          style={{
            color: COLORS.acid,
            padding: '3px 8px',
            background: 'rgba(255,255,255,0.05)',
            border: `1px solid ${COLORS.border2}`,
            display: 'inline-flex',
          }}
        >
          <span className="inline-block w-1.5 h-1.5 animate-pulse" style={{ background: COLORS.acid, borderRadius: 0 }} />
          System Live
        </span>
      </div>

      {/* ── Navigation ── */}
      <nav className="flex-1 pt-2 overflow-y-auto">
        {NAV.map(({ to, label, Icon }) => {
          const active = pathname === to || (to !== '/dashboard' && pathname.startsWith(to));
          return (
            <Link key={to} to={to}
              className="relative flex items-center gap-3 px-5 py-[11px] text-[11px] font-bold tracking-[0.06em] transition-all duration-100 no-underline"
              style={{ color: active ? COLORS.text : COLORS.sub, background: active ? COLORS.surface : 'transparent' }}>
              {active && (
                <span className="absolute left-0 top-0 bottom-0 w-[2px]" style={{ background: COLORS.acid }} />
              )}
              <Icon className="w-3.5 h-3.5 flex-shrink-0 opacity-70" />
              {label}
            </Link>
          );
        })}
      </nav>

      {/* ── New Scan CTA ── */}
      <div className="px-4 pb-4 flex-shrink-0">
        <button
          onClick={() => navigate('/scanner')}
          onMouseEnter={() => setBtnHover(true)}
          onMouseLeave={() => setBtnHover(false)}
          aria-label="Start new scan"
          className="w-full flex items-center justify-center gap-2 py-2.5 text-[11px] font-bold tracking-[0.06em] transition-all duration-100"
          style={btnHover ? S.pillHover : S.pill}>
          <Plus className="w-3 h-3" />
          New Scan
        </button>
      </div>

      {/* ── User ── */}
      <div className="px-5 py-4 flex-shrink-0" style={S.botBorder}>
        {user && (
          <>
            <div className="text-[11px] tracking-[0.06em] mb-0.5" style={{ color: COLORS.sub }}>Operator</div>
            <div className="text-[11px] font-bold truncate mb-3" style={{ color: COLORS.text }}>
              {user.email ?? user.name}
            </div>
          </>
        )}
        <button
          onClick={() => { logout(); navigate('/'); }}
          onMouseEnter={() => setLogoutHover(true)}
          onMouseLeave={() => setLogoutHover(false)}
          aria-label="Sign out"
          className="flex items-center gap-2 text-[11px] font-bold tracking-[0.06em] transition-all duration-100"
          style={{ color: logoutHover ? COLORS.red : COLORS.muted }}>
          <LogOut className="w-3 h-3" />
          Sign Out
        </button>
      </div>
    </aside>
  );
}
