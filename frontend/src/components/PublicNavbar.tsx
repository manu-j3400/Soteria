import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';
import { COLORS } from '../theme/colors';

const ACCENT = COLORS.acid;
const BG = COLORS.bg;
const BORDER = COLORS.border;
const MUTED = COLORS.muted;
const SUB = COLORS.sub;
const FONT = "'JetBrains Mono', 'Courier New', monospace";

const NAV_LINKS = [
    { path: '/features',    label: 'FEATURES'    },
    { path: '/how-it-works',label: 'HOW IT WORKS' },
    { path: '/about',       label: 'ABOUT'        },
];

export default function PublicNavbar() {
    const location = useLocation();
    const { isAuthenticated, user, logout } = useAuth();

    const isActive = (path: string) => location.pathname === path;

    return (
        <nav style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            zIndex: 50,
            backgroundColor: BG,
            fontFamily: FONT,
        }}>
            {/* Main Nav Bar */}
            <div style={{
                borderBottom: `1px solid ${BORDER}`,
                height: '72px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0 48px',
                maxWidth: '1280px',
                margin: '0 auto',
                width: '100%',
            }}>
                {/* Logo */}
                <Link to="/" style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                    textDecoration: 'none',
                }}>
                    <img
                        src="/soteria-logo.png"
                        alt="Soteria"
                        style={{
                            height: '30px',
                            width: '30px',
                            borderRadius: '0px',
                            objectFit: 'cover',
                        }}
                    />
                    <span style={{
                        fontSize: '13px',
                        fontFamily: FONT,
                        fontWeight: 700,
                        letterSpacing: '0.2em',
                        color: '#fff',
                        textTransform: 'uppercase',
                    }}>
                        SOTERIA
                    </span>
                    <span style={{
                        fontSize: '11px',
                        color: ACCENT,
                        letterSpacing: '0.1em',
                        marginLeft: '4px',
                    }}>
                        [ LIVE ]
                    </span>
                </Link>

                {/* Nav Links */}
                <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                }}>
                    {NAV_LINKS.map(({ path, label }) => {
                        const active = isActive(path);
                        return (
                            <Link
                                key={path}
                                to={path}
                                style={{
                                    fontSize: '11px',
                                    fontFamily: FONT,
                                    fontWeight: 700,
                                    letterSpacing: '0.14em',
                                    textDecoration: 'none',
                                    color: active ? ACCENT : SUB,
                                    padding: '6px 16px',
                                    display: 'flex',
                                    alignItems: 'center',
                                    transition: 'color 0.15s',
                                }}
                                onMouseEnter={e => {
                                    if (!active) (e.currentTarget as HTMLAnchorElement).style.color = ACCENT;
                                }}
                                onMouseLeave={e => {
                                    if (!active) (e.currentTarget as HTMLAnchorElement).style.color = SUB;
                                }}
                            >
                                {label}
                            </Link>
                        );
                    })}
                </div>

                {/* Auth Controls */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {isAuthenticated && user ? (
                        <>
                            <span style={{
                                fontSize: '11px',
                                fontFamily: FONT,
                                color: '#444',
                                border: `1px solid ${BORDER}`,
                                padding: '5px 12px',
                                letterSpacing: '0.08em',
                            }}>
                                {user.name}
                            </span>
                            <Link
                                to="/dashboard"
                                style={{
                                    fontSize: '11px',
                                    fontFamily: FONT,
                                    fontWeight: 700,
                                    letterSpacing: '0.14em',
                                    textDecoration: 'none',
                                    color: '#000',
                                    backgroundColor: ACCENT,
                                    border: `1px solid ${ACCENT}`,
                                    padding: '6px 16px',
                                    textTransform: 'uppercase',
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '6px',
                                    borderRadius: '0px',
                                    transition: 'opacity 0.15s',
                                }}
                                onMouseEnter={e => (e.currentTarget as HTMLAnchorElement).style.opacity = '0.85'}
                                onMouseLeave={e => (e.currentTarget as HTMLAnchorElement).style.opacity = '1'}
                            >
                                ▶ DASHBOARD
                            </Link>
                            <button
                                onClick={logout}
                                title="Sign out"
                                style={{
                                    fontFamily: FONT,
                                    fontSize: '11px',
                                    letterSpacing: '0.12em',
                                    color: SUB,
                                    backgroundColor: 'transparent',
                                    border: `1px solid ${BORDER}`,
                                    padding: '6px 12px',
                                    cursor: 'pointer',
                                    borderRadius: '0px',
                                    transition: 'color 0.15s, border-color 0.15s',
                                }}
                                onMouseEnter={e => {
                                    (e.currentTarget as HTMLButtonElement).style.color = '#FF4444';
                                    (e.currentTarget as HTMLButtonElement).style.borderColor = '#FF4444';
                                }}
                                onMouseLeave={e => {
                                    (e.currentTarget as HTMLButtonElement).style.color = '#555';
                                    (e.currentTarget as HTMLButtonElement).style.borderColor = '#1E1E1E';
                                }}
                            >
                                ✕ LOGOUT
                            </button>
                        </>
                    ) : (
                        <>
                            <Link
                                to="/login"
                                style={{
                                    fontSize: '11px',
                                    fontFamily: FONT,
                                    fontWeight: 700,
                                    letterSpacing: '0.14em',
                                    textDecoration: 'none',
                                    color: SUB,
                                    backgroundColor: 'transparent',
                                    border: `1px solid ${BORDER}`,
                                    padding: '6px 16px',
                                    textTransform: 'uppercase',
                                    borderRadius: '0px',
                                    transition: 'color 0.15s, border-color 0.15s',
                                }}
                                onMouseEnter={e => {
                                    (e.currentTarget as HTMLAnchorElement).style.color = '#fff';
                                    (e.currentTarget as HTMLAnchorElement).style.borderColor = '#555';
                                }}
                                onMouseLeave={e => {
                                    (e.currentTarget as HTMLAnchorElement).style.color = '#555';
                                    (e.currentTarget as HTMLAnchorElement).style.borderColor = '#1E1E1E';
                                }}
                            >
                                SIGN IN
                            </Link>
                            <Link
                                to="/signup"
                                style={{
                                    fontSize: '11px',
                                    fontFamily: FONT,
                                    fontWeight: 700,
                                    letterSpacing: '0.14em',
                                    textDecoration: 'none',
                                    color: '#000',
                                    backgroundColor: ACCENT,
                                    border: `1px solid ${ACCENT}`,
                                    padding: '6px 18px',
                                    textTransform: 'uppercase',
                                    borderRadius: '0px',
                                    transition: 'opacity 0.15s',
                                }}
                                onMouseEnter={e => (e.currentTarget as HTMLAnchorElement).style.opacity = '0.85'}
                                onMouseLeave={e => (e.currentTarget as HTMLAnchorElement).style.opacity = '1'}
                            >
                                GET STARTED →
                            </Link>
                        </>
                    )}
                </div>
            </div>
        </nav>
    );
}
