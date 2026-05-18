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
    acid: COLORS.acid, red: COLORS.red, amber: COLORS.orange,
    border: COLORS.border, dim: COLORS.surface, muted: COLORS.muted,
    text: COLORS.text, sub: COLORS.sub,
};

const MONO = "'JetBrains Mono', monospace";
const SANS = "'Inter', -apple-system, BlinkMacSystemFont, sans-serif";

const inputStyle: React.CSSProperties = {
    width: '100%', background: '#030712', border: `1px solid #1E1E1E`,
    outline: 'none', padding: '9px 12px', fontFamily: MONO,
    fontSize: 11, color: '#E5E5E5', boxSizing: 'border-box' as const,
    transition: 'border-color 0.15s',
};

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
        <div style={{
            minHeight: '100vh', background: '#030712', display: 'flex',
            alignItems: 'center', justifyContent: 'center',
            fontFamily: SANS, color: C.text,
        }}>
            <div style={{ position: 'absolute', top: 20, left: 20, fontFamily: MONO, fontSize: 10, color: C.muted, letterSpacing: '0.1em' }}>
                SOTERIA / REGISTER
            </div>
            <div style={{ position: 'absolute', top: 20, right: 20, fontFamily: MONO, fontSize: 10, color: C.muted, letterSpacing: '0.1em' }}>
                [ NEW ACCOUNT ]
            </div>

            <div style={{ width: '100%', maxWidth: 400, border: `1px solid ${C.border}`, background: C.dim }}>
                {/* Header */}
                <div style={{ padding: '14px 20px', borderBottom: `1px solid ${C.border}`, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ fontFamily: SANS, fontSize: 12, color: C.sub }}>Create account</div>
                </div>

                {/* Logo */}
                <div style={{ padding: '28px 20px 20px', textAlign: 'center', borderBottom: `1px solid ${C.border}` }}>
                    <Link to="/home">
                        <img src="/soteria-logo.png" alt="Soteria" style={{ width: 48, height: 48, objectFit: 'cover', margin: '0 auto 12px', display: 'block' }} />
                    </Link>
                    <div style={{ fontFamily: MONO, fontSize: 16, fontWeight: 700, letterSpacing: '0.06em', marginBottom: 4 }}>SOTERIA</div>
                    <div style={{ fontFamily: SANS, fontSize: 12, color: C.sub }}>Security intelligence platform</div>
                </div>

                {/* Form */}
                <form onSubmit={handleSubmit} style={{ padding: 20 }}>
                    {[
                        { label: 'Name', type: 'text', val: name, set: setName, placeholder: 'Your name', required: true },
                        { label: 'Email address', type: 'email', val: email, set: setEmail, placeholder: 'operator@domain.com', required: true },
                        { label: 'Password', type: 'password', val: password, set: setPassword, placeholder: 'Min. 6 characters', required: true, minLength: 6 },
                    ].map(({ label, type, val, set, placeholder, required, minLength }) => (
                        <div key={label} style={{ marginBottom: 12 }}>
                            <label style={{ fontFamily: SANS, fontSize: 12, color: C.sub, display: 'block', marginBottom: 6 }}>{label}</label>
                            <input
                                type={type} value={val} onChange={e => set(e.target.value)}
                                placeholder={placeholder} required={required}
                                minLength={minLength}
                                style={inputStyle}
                                onFocus={e => (e.target.style.borderColor = C.acid)}
                                onBlur={e => (e.target.style.borderColor = C.border)}
                            />
                        </div>
                    ))}

                    {error && (
                        <div style={{ marginBottom: 12, padding: '8px 12px', background: 'rgba(255,49,49,0.06)', border: `1px solid rgba(255,49,49,0.3)`, fontFamily: SANS, fontSize: 12, color: C.red }}>
                            {error}
                        </div>
                    )}

                    {emailExists && (
                        <div style={{ marginBottom: 12, padding: '10px 12px', background: 'rgba(255,140,0,0.06)', border: `1px solid rgba(255,140,0,0.3)`, fontFamily: SANS, fontSize: 12, color: C.amber, lineHeight: 1.8 }}>
                            Email already registered.{' '}
                            <Link to="/login" style={{ color: C.acid, textDecoration: 'none', fontWeight: 700 }}>Sign in</Link>
                            {' '}or{' '}
                            <Link to="/forgot-password" style={{ color: C.acid, textDecoration: 'none', fontWeight: 700 }}>reset your password</Link>
                        </div>
                    )}

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
                        {loading ? '[ CREATING ACCOUNT... ]' : '[ CREATE ACCOUNT ]'}
                    </button>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '16px 0', color: C.muted }}>
                        <div style={{ flex: 1, height: 1, background: C.border }} />
                        <span style={{ fontFamily: SANS, fontSize: 12 }}>or</span>
                        <div style={{ flex: 1, height: 1, background: C.border }} />
                    </div>

                    <button
                        type="button" onClick={handleGoogleSignIn} disabled={loading}
                        style={{
                            width: '100%', padding: '10px 0', background: 'transparent',
                            border: `1px solid ${C.border}`, color: C.text,
                            fontFamily: SANS, fontSize: 13,
                            cursor: loading ? 'not-allowed' : 'pointer',
                            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10,
                            transition: 'border-color 0.15s',
                        }}
                        onMouseEnter={e => { if (!loading) (e.currentTarget as HTMLElement).style.borderColor = C.sub; }}
                        onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = C.border; }}
                    >
                        <GoogleIcon />
                        Sign up with Google
                    </button>
                </form>

                <div style={{ padding: '14px 20px', borderTop: `1px solid ${C.border}`, display: 'flex', justifyContent: 'center' }}>
                    <span style={{ fontFamily: SANS, fontSize: 13, color: C.sub }}>
                        Already have an account?{' '}
                        <Link to="/login" style={{ color: C.acid, textDecoration: 'none', fontWeight: 700 }}>Sign in</Link>
                    </span>
                </div>
            </div>
        </div>
    );
}
