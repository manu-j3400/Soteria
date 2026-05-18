import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';

const GoogleIcon = () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
        <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
        <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
        <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
        <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
    </svg>
);

import { COLORS } from '../theme/colors';
const C = {
    acid:   COLORS.acid,
    red:    COLORS.red,
    border: COLORS.border,
    dim:    COLORS.surface,
    muted:  COLORS.muted,
    text:   COLORS.text,
    sub:    COLORS.sub,
};

const MONO = "'JetBrains Mono', monospace";
const SANS = "'Inter', -apple-system, BlinkMacSystemFont, sans-serif";

export default function Login() {
    const { login, signInWithGoogle } = useAuth();
    const navigate = useNavigate();
    const [email, setEmail]             = useState('');
    const [password, setPassword]       = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError]             = useState('');
    const [loading, setLoading]         = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault(); setError(''); setLoading(true);
        try { await login(email, password); navigate('/dashboard'); }
        catch (err: any) {
            const msg: string = err.message || '';
            if (msg.includes('Invalid') || msg.includes('invalid') || msg.includes('credentials')) setError('Wrong email or password.');
            else if (msg.includes('network') || msg.includes('fetch')) setError('Cannot reach server. Check your connection.');
            else setError(msg || 'Sign in failed. Try again.');
        }
        finally { setLoading(false); }
    };

    const handleGoogleSignIn = async () => {
        setError(''); setLoading(true);
        try { await signInWithGoogle(); }
        catch (err: unknown) { setError(err instanceof Error ? err.message : 'Google sign-in failed.'); }
        finally { setLoading(false); }
    };

    return (
        <div style={{
            minHeight: '100vh', background: '#030712', display: 'flex',
            alignItems: 'center', justifyContent: 'center',
            fontFamily: SANS, color: C.text,
        }}>
            {/* Corner marks */}
            <div style={{ position: 'absolute', top: 20, left: 20, fontSize: 11, color: C.muted, letterSpacing: '0.1em', fontFamily: MONO }}>
                SOTERIA / AUTHENTICATE
            </div>
            <div style={{ position: 'absolute', top: 20, right: 20, fontSize: 11, color: C.muted, letterSpacing: '0.1em', fontFamily: MONO }}>
                [ SECURE ]
            </div>

            <div style={{
                width: '100%', maxWidth: 400, border: `1px solid ${C.border}`,
                background: C.dim, padding: 0,
            }}>
                {/* Header strip */}
                <div style={{
                    padding: '14px 20px', borderBottom: `1px solid ${C.border}`,
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                }}>
                    <div style={{ fontFamily: SANS, fontSize: 12, color: C.sub }}>Sign in</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: C.acid, display: 'inline-block' }} />
                        <span style={{ fontFamily: MONO, fontSize: 11, color: C.acid }}>LIVE</span>
                    </div>
                </div>

                {/* Logo + title */}
                <div style={{ padding: '28px 20px 20px', textAlign: 'center', borderBottom: `1px solid ${C.border}` }}>
                    <Link to="/home">
                        <img src="/soteria-logo.png" alt="Soteria" style={{ width: 48, height: 48, objectFit: 'cover', margin: '0 auto 12px', display: 'block' }} />
                    </Link>
                    <div style={{ fontFamily: MONO, fontSize: 16, fontWeight: 700, letterSpacing: '0.06em', marginBottom: 4 }}>SOTERIA</div>
                    <div style={{ fontFamily: SANS, fontSize: 12, color: C.sub }}>Security intelligence platform</div>
                </div>

                {/* Form */}
                <form onSubmit={handleSubmit} style={{ padding: 20 }}>
                    {/* Email */}
                    <div style={{ marginBottom: 12 }}>
                        <label style={{ fontFamily: SANS, fontSize: 12, color: C.sub, display: 'block', marginBottom: 6 }}>Email address</label>
                        <input
                            type="email" value={email} onChange={e => setEmail(e.target.value)}
                            placeholder="operator@domain.com" required
                            style={{
                                width: '100%', background: '#030712', border: `1px solid ${C.border}`,
                                outline: 'none', padding: '9px 12px', fontFamily: MONO,
                                fontSize: 11, color: C.text, boxSizing: 'border-box',
                                transition: 'border-color 0.15s',
                            }}
                            onFocus={e => (e.target.style.borderColor = C.acid)}
                            onBlur={e => (e.target.style.borderColor = C.border)}
                        />
                    </div>

                    {/* Password */}
                    <div style={{ marginBottom: 16 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                            <label style={{ fontFamily: SANS, fontSize: 12, color: C.sub }}>Password</label>
                            <Link to="/forgot-password" style={{ fontFamily: SANS, fontSize: 12, color: C.sub, textDecoration: 'none' }}
                                onMouseEnter={e => ((e.target as HTMLElement).style.color = C.text)}
                                onMouseLeave={e => ((e.target as HTMLElement).style.color = C.sub)}
                            >
                                Forgot?
                            </Link>
                        </div>
                        <div style={{ position: 'relative' }}>
                            <input
                                type={showPassword ? 'text' : 'password'}
                                value={password} onChange={e => setPassword(e.target.value)}
                                placeholder="••••••••" required
                                style={{
                                    width: '100%', background: '#030712', border: `1px solid ${C.border}`,
                                    outline: 'none', padding: '9px 36px 9px 12px',
                                    fontFamily: MONO, fontSize: 11,
                                    color: C.text, boxSizing: 'border-box', transition: 'border-color 0.15s',
                                }}
                                onFocus={e => (e.target.style.borderColor = C.acid)}
                                onBlur={e => (e.target.style.borderColor = C.border)}
                            />
                            <button type="button" onClick={() => setShowPassword(s => !s)}
                                style={{
                                    position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
                                    background: 'none', border: 'none', color: C.muted, cursor: 'pointer',
                                    fontSize: 10, letterSpacing: '0.06em', fontFamily: MONO,
                                }}
                                aria-label={showPassword ? 'Hide password' : 'Show password'}
                            >
                                {showPassword ? 'HIDE' : 'SHOW'}
                            </button>
                        </div>
                    </div>

                    {/* Error */}
                    {error && (
                        <div style={{ marginBottom: 12, padding: '8px 12px', background: 'rgba(255,49,49,0.06)', border: `1px solid rgba(255,49,49,0.3)`, fontFamily: SANS, fontSize: 12, color: C.red }}>
                            {error}
                        </div>
                    )}

                    {/* Submit */}
                    <button
                        type="submit" disabled={loading}
                        style={{
                            width: '100%', padding: '11px 0',
                            background: loading ? C.dim : C.acid,
                            border: `1px solid ${loading ? C.muted : C.acid}`,
                            color: loading ? C.sub : '#000',
                            fontFamily: MONO, fontSize: 11,
                            fontWeight: 700, letterSpacing: '0.1em', cursor: loading ? 'not-allowed' : 'pointer',
                            marginBottom: 12, transition: 'background 0.15s',
                        }}
                    >
                        {loading ? '[ AUTHENTICATING... ]' : '[ SIGN IN ]'}
                    </button>

                    {/* Divider */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '16px 0', color: C.muted }}>
                        <div style={{ flex: 1, height: 1, background: C.border }} />
                        <span style={{ fontFamily: SANS, fontSize: 12 }}>or</span>
                        <div style={{ flex: 1, height: 1, background: C.border }} />
                    </div>

                    {/* Google */}
                    <button
                        type="button" onClick={handleGoogleSignIn} disabled={loading}
                        style={{
                            width: '100%', padding: '10px 0', background: 'transparent',
                            border: `1px solid ${C.border}`, color: C.text,
                            fontFamily: SANS, fontSize: 13,
                            cursor: loading ? 'not-allowed' : 'pointer',
                            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10,
                            transition: 'border-color 0.15s, color 0.15s',
                        }}
                        onMouseEnter={e => { if (!loading) { (e.currentTarget as HTMLElement).style.borderColor = C.sub; } }}
                        onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = C.border; }}
                    >
                        <GoogleIcon />
                        Sign in with Google
                    </button>
                </form>

                {/* Footer */}
                <div style={{ padding: '14px 20px', borderTop: `1px solid ${C.border}`, display: 'flex', justifyContent: 'center' }}>
                    <span style={{ fontFamily: SANS, fontSize: 13, color: C.sub }}>
                        No account?{' '}
                        <Link to="/signup" style={{ color: C.acid, textDecoration: 'none', fontWeight: 700 }}
                            onMouseEnter={e => ((e.target as HTMLElement).style.opacity = '0.7')}
                            onMouseLeave={e => ((e.target as HTMLElement).style.opacity = '1')}
                        >
                            Sign up
                        </Link>
                    </span>
                </div>
            </div>
        </div>
    );
}
