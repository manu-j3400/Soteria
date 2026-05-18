import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';
import { COLORS } from '../theme/colors';

const GoogleIcon = () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
        <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
        <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
        <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
        <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
    </svg>
);

const C = {
    acid:    COLORS.acid,
    red:     COLORS.red,
    amber:   COLORS.orange,
    border:  COLORS.border,
    border2: COLORS.border2,
    dim:     COLORS.surface,
    muted:   COLORS.muted,
    text:    COLORS.text,
    sub:     COLORS.sub,
    bg:      COLORS.bg,
};

const MONO = "'JetBrains Mono', monospace";
const SANS = "'Inter', -apple-system, BlinkMacSystemFont, sans-serif";

const PREVIEW_LINES = [
    { text: '$ soteria scan auth.py', color: '#F8FAFC' },
    { text: '  analyzing...', color: '#64748B' },
    { text: '', color: '' },
    { text: '  CRITICAL  SQL injection  L.42', color: '#FF4444' },
    { text: '  HIGH      Hardcoded key  L.17', color: '#FF8C00' },
    { text: '', color: '' },
    { text: '  RISK: HIGH · 2 findings · 1.1s', color: '#00D4FF' },
];

export default function Signup() {
    const { signup, signInWithGoogle } = useAuth();
    const navigate = useNavigate();
    const [name, setName]               = useState('');
    const [email, setEmail]             = useState('');
    const [password, setPassword]       = useState('');
    const [error, setError]             = useState('');
    const [emailExists, setEmailExists] = useState(false);
    const [loading, setLoading]         = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault(); setError(''); setEmailExists(false); setLoading(true);
        try { await signup(name, email, password); navigate('/dashboard'); }
        catch (err: any) {
            const msg: string = err.message || 'Signup failed.';
            if (msg.toLowerCase().includes('already') || msg.toLowerCase().includes('registered') || err.status === 409) setEmailExists(true);
            else setError(msg);
        } finally { setLoading(false); }
    };

    const handleGoogleSignIn = async () => {
        setError(''); setLoading(true);
        try { await signInWithGoogle(); }
        catch (err: unknown) { setError(err instanceof Error ? err.message : 'Google sign-up failed.'); }
        finally { setLoading(false); }
    };

    return (
        <div style={{ minHeight: '100vh', background: C.bg, display: 'flex', fontFamily: SANS, color: C.text, overflow: 'hidden' }}>

            {/* ── LEFT: Brand panel ─────────────────────────────────── */}
            <div style={{
                width: '52%', flexShrink: 0, borderRight: `1px solid ${C.border}`,
                display: 'flex', flexDirection: 'column',
                background: `radial-gradient(ellipse 90% 60% at 10% 50%, rgba(0,212,255,0.07) 0%, transparent 65%)`,
                position: 'relative', overflow: 'hidden',
            }}>
                <div style={{ padding: '16px 32px', borderBottom: `1px solid ${C.border}`, display: 'flex', alignItems: 'center', gap: 10 }}>
                    <Link to="/home" style={{ display: 'flex', alignItems: 'center', gap: 10, textDecoration: 'none' }}>
                        <img src="/soteria-logo.png" alt="Soteria" style={{ width: 26, height: 26, objectFit: 'cover' }} />
                        <span style={{ fontFamily: MONO, fontSize: 13, fontWeight: 700, letterSpacing: '0.15em', color: C.text }}>SOTERIA</span>
                    </Link>
                    <span style={{ fontFamily: MONO, fontSize: 10, color: C.acid, marginLeft: 6 }}>[ FREE ]</span>
                </div>

                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', padding: '48px 56px' }}>
                    <div style={{ marginBottom: 36 }}>
                        <div style={{ fontFamily: MONO, fontSize: 9, color: C.acid, letterSpacing: '0.22em', marginBottom: 16 }}>
                            START FOR FREE · NO CREDIT CARD
                        </div>
                        <h1 style={{
                            fontFamily: MONO, fontSize: 'clamp(26px, 2.8vw, 38px)',
                            fontWeight: 900, lineHeight: 1.08, letterSpacing: '-0.02em',
                            textTransform: 'uppercase', margin: '0 0 16px', color: C.text,
                        }}>
                            YOUR CODE.<br />
                            <span style={{ color: C.acid }}>OUR SCANNER.</span><br />
                            ZERO RISK.
                        </h1>
                        <p style={{ fontFamily: SANS, fontSize: 13, color: C.sub, lineHeight: 1.75, margin: 0, maxWidth: 320 }}>
                            Free account. Full access. Scan your first file in 30 seconds.
                        </p>
                    </div>

                    {/* Terminal preview */}
                    <div style={{ border: `1px solid ${C.border}`, background: C.dim }}>
                        <div style={{ padding: '8px 16px', borderBottom: `1px solid ${C.border}`, display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span style={{ width: 5, height: 5, background: C.acid, display: 'inline-block', borderRadius: '50%' }} />
                            <span style={{ fontFamily: MONO, fontSize: 9, color: C.muted, letterSpacing: '0.1em' }}>SCAN SESSION</span>
                        </div>
                        <div style={{ padding: '16px 20px' }}>
                            {PREVIEW_LINES.map((line, i) => (
                                <div key={i} style={{ fontFamily: MONO, fontSize: 11, lineHeight: 1.8, color: line.color || 'transparent', whiteSpace: 'pre' }}>
                                    {line.text || '\u00A0'}
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                <div style={{ padding: '13px 32px', borderTop: `1px solid ${C.border}`, fontFamily: MONO, fontSize: 9, color: C.muted, letterSpacing: '0.12em' }}>
                    KYBER ENGINE v3.0 · ENSEMBLE + GCN + SNN
                </div>

                <div style={{
                    position: 'absolute', inset: 0, pointerEvents: 'none', opacity: 0.025,
                    backgroundImage: 'linear-gradient(rgba(0,212,255,1) 1px, transparent 1px), linear-gradient(90deg, rgba(0,212,255,1) 1px, transparent 1px)',
                    backgroundSize: '48px 48px',
                }} />
            </div>

            {/* ── RIGHT: Form ───────────────────────────────────────── */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '40px 32px' }}>
                <div style={{ width: '100%', maxWidth: 360 }}>
                    <div style={{ marginBottom: 28 }}>
                        <div style={{ fontFamily: MONO, fontSize: 9, color: C.muted, letterSpacing: '0.18em', marginBottom: 8 }}>NEW ACCOUNT</div>
                        <h2 style={{ fontFamily: SANS, fontSize: 22, fontWeight: 800, color: C.text, margin: '0 0 6px', letterSpacing: '-0.01em' }}>Create account</h2>
                        <p style={{ fontFamily: SANS, fontSize: 13, color: C.sub, margin: 0 }}>
                            Already have one?{' '}
                            <Link to="/login" style={{ color: C.acid, textDecoration: 'none', fontWeight: 700 }}>Sign in</Link>
                        </p>
                    </div>

                    {/* Google */}
                    <button type="button" onClick={handleGoogleSignIn} disabled={loading} style={{
                        width: '100%', padding: '11px 0', background: C.dim,
                        border: `1px solid ${C.border2}`, color: C.text,
                        fontFamily: SANS, fontSize: 13, cursor: loading ? 'not-allowed' : 'pointer',
                        display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10,
                        transition: 'border-color 0.15s', marginBottom: 20,
                    }}
                        onMouseEnter={e => { if (!loading) (e.currentTarget as HTMLElement).style.borderColor = C.acid; }}
                        onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = C.border2; }}
                    >
                        <GoogleIcon />Continue with Google
                    </button>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
                        <div style={{ flex: 1, height: 1, background: C.border }} />
                        <span style={{ fontFamily: SANS, fontSize: 11, color: C.muted }}>or with email</span>
                        <div style={{ flex: 1, height: 1, background: C.border }} />
                    </div>

                    <form onSubmit={handleSubmit}>
                        {[
                            { label: 'Name', type: 'text', val: name, set: setName, placeholder: 'Your name', required: true },
                            { label: 'Email address', type: 'email', val: email, set: setEmail, placeholder: 'operator@domain.com', required: true },
                            { label: 'Password', type: 'password', val: password, set: setPassword, placeholder: 'Min. 6 characters', required: true, minLength: 6 },
                        ].map(({ label, type, val, set, placeholder, required, minLength }) => (
                            <div key={label} style={{ marginBottom: 14 }}>
                                <label style={{ fontFamily: SANS, fontSize: 12, color: C.sub, display: 'block', marginBottom: 6 }}>{label}</label>
                                <input type={type} value={val} onChange={e => set(e.target.value)}
                                    placeholder={placeholder} required={required} minLength={minLength}
                                    style={{ width: '100%', background: C.dim, border: `1px solid ${C.border}`, outline: 'none', padding: '10px 14px', fontFamily: MONO, fontSize: 12, color: C.text, boxSizing: 'border-box' as const, transition: 'border-color 0.15s' }}
                                    onFocus={e => (e.target.style.borderColor = C.acid)}
                                    onBlur={e => (e.target.style.borderColor = C.border)}
                                />
                            </div>
                        ))}

                        {error && (
                            <div style={{ marginBottom: 14, padding: '9px 14px', background: 'rgba(255,68,68,0.06)', border: `1px solid rgba(255,68,68,0.25)`, fontFamily: SANS, fontSize: 12, color: C.red, lineHeight: 1.5 }}>
                                {error}
                            </div>
                        )}

                        {emailExists && (
                            <div style={{ marginBottom: 14, padding: '10px 14px', background: 'rgba(255,140,0,0.06)', border: `1px solid rgba(255,140,0,0.25)`, fontFamily: SANS, fontSize: 12, color: C.amber, lineHeight: 1.8 }}>
                                Email already registered.{' '}
                                <Link to="/login" style={{ color: C.acid, textDecoration: 'none', fontWeight: 700 }}>Sign in</Link>
                                {' '}or{' '}
                                <Link to="/forgot-password" style={{ color: C.acid, textDecoration: 'none', fontWeight: 700 }}>reset password</Link>
                            </div>
                        )}

                        <button type="submit" disabled={loading} style={{
                            width: '100%', padding: '12px 0',
                            background: loading ? C.dim : C.acid,
                            border: `1px solid ${loading ? C.muted : C.acid}`,
                            color: loading ? C.sub : '#000',
                            fontFamily: MONO, fontSize: 11, fontWeight: 700, letterSpacing: '0.12em',
                            cursor: loading ? 'not-allowed' : 'pointer', transition: 'opacity 0.15s',
                            marginTop: 4,
                        }}
                            onMouseEnter={e => { if (!loading) (e.currentTarget as HTMLElement).style.opacity = '0.85'; }}
                            onMouseLeave={e => { (e.currentTarget as HTMLElement).style.opacity = '1'; }}
                        >
                            {loading ? '[ CREATING ACCOUNT... ]' : '[ CREATE ACCOUNT ]'}
                        </button>
                    </form>
                </div>
            </div>
        </div>
    );
}
