import { useState } from 'react';
import { Link } from 'react-router-dom';
import { supabase } from '@/lib/supabase';

import { COLORS } from '../theme/colors';
const C = {
    acid: COLORS.acid, red: COLORS.red,
    border: COLORS.border, dim: COLORS.surface, muted: COLORS.muted,
    text: COLORS.text, sub: COLORS.sub,
};

export default function ForgotPassword() {
    const [email, setEmail]     = useState('');
    const [sent, setSent]       = useState(false);
    const [error, setError]     = useState('');
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault(); setError(''); setLoading(true);
        const { error: sbError } = await supabase.auth.resetPasswordForEmail(email.trim().toLowerCase(), {
            redirectTo: `${window.location.origin}/reset-password`,
        });
        setLoading(false);
        if (sbError) setError(sbError.message);
        else setSent(true);
    };

    return (
        <div style={{
            minHeight: '100vh', background: '#030712', display: 'flex',
            alignItems: 'center', justifyContent: 'center',
            fontFamily: "'JetBrains Mono', monospace", color: C.text,
        }}>
            <div style={{ position: 'absolute', top: 20, left: 20, fontSize: 9, color: C.muted, letterSpacing: '0.1em' }}>
                SOTERIA / RESET PASSWORD
            </div>

            <div style={{ width: '100%', maxWidth: 400, border: `1px solid ${C.border}`, background: C.dim }}>
                {/* Header */}
                <div style={{ padding: '14px 20px', borderBottom: `1px solid ${C.border}` }}>
                    <div style={{ fontSize: 9, color: C.sub, letterSpacing: '0.12em' }}>PASSWORD RESET</div>
                </div>

                {/* Logo */}
                <div style={{ padding: '28px 20px 20px', textAlign: 'center', borderBottom: `1px solid ${C.border}` }}>
                    <Link to="/home">
                        <img src="/soteria-logo.png" alt="Soteria" style={{ width: 48, height: 48, objectFit: 'cover', margin: '0 auto 12px', display: 'block' }} />
                    </Link>
                    <div style={{ fontSize: 16, fontWeight: 700, letterSpacing: '0.06em', marginBottom: 4 }}>SOTERIA</div>
                    <div style={{ fontSize: 9, color: C.sub, letterSpacing: '0.1em' }}>
                        {sent ? 'CHECK YOUR INBOX' : 'ENTER YOUR EMAIL TO RECEIVE A RESET LINK'}
                    </div>
                </div>

                <div style={{ padding: 20 }}>
                    {sent ? (
                        <div style={{ textAlign: 'center' }}>
                            <div style={{ fontSize: 32, color: C.acid, marginBottom: 16 }}>✓</div>
                            <div style={{ fontSize: 9, color: C.sub, lineHeight: 2, marginBottom: 20 }}>
                                RESET LINK SENT TO{' '}
                                <span style={{ color: C.text }}>{email}</span>.
                                CHECK YOUR SPAM FOLDER IF IT DOESN'T ARRIVE.
                            </div>
                            <Link to="/login" style={{
                                display: 'block', padding: '10px 0', textAlign: 'center',
                                background: 'transparent', border: `1px solid ${C.border}`,
                                color: C.sub, textDecoration: 'none',
                                fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
                                letterSpacing: '0.1em', transition: 'color 0.15s, border-color 0.15s',
                            }}
                            onMouseEnter={e => { (e.target as HTMLElement).style.color = C.text; (e.target as HTMLElement).style.borderColor = C.sub; }}
                            onMouseLeave={e => { (e.target as HTMLElement).style.color = C.sub; (e.target as HTMLElement).style.borderColor = C.border; }}
                            >
                                ← BACK TO SIGN IN
                            </Link>
                        </div>
                    ) : (
                        <form onSubmit={handleSubmit}>
                            <div style={{ marginBottom: 16 }}>
                                <label style={{ fontSize: 8, color: C.sub, letterSpacing: '0.12em', display: 'block', marginBottom: 6 }}>EMAIL ADDRESS</label>
                                <input
                                    type="email" value={email} onChange={e => setEmail(e.target.value)}
                                    placeholder="operator@domain.com" required
                                    style={{
                                        width: '100%', background: '#030712', border: `1px solid ${C.border}`,
                                        outline: 'none', padding: '9px 12px',
                                        fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
                                        color: C.text, boxSizing: 'border-box' as const,
                                        transition: 'border-color 0.15s',
                                    }}
                                    onFocus={e => (e.target.style.borderColor = C.acid)}
                                    onBlur={e => (e.target.style.borderColor = C.border)}
                                />
                            </div>

                            {error && (
                                <div style={{ marginBottom: 12, padding: '8px 12px', background: 'rgba(255,49,49,0.06)', border: `1px solid rgba(255,49,49,0.3)`, fontSize: 9, color: C.red }}>
                                    ! {error}
                                </div>
                            )}

                            <button
                                type="submit" disabled={loading}
                                style={{
                                    width: '100%', padding: '11px 0', marginBottom: 12,
                                    background: loading ? C.dim : C.acid,
                                    border: `1px solid ${loading ? C.muted : C.acid}`,
                                    color: loading ? C.sub : '#000',
                                    fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
                                    fontWeight: 700, letterSpacing: '0.1em', cursor: loading ? 'not-allowed' : 'pointer',
                                    transition: 'background 0.15s',
                                }}
                            >
                                {loading ? '[ SENDING... ]' : '[ SEND RESET LINK ]'}
                            </button>

                            <Link to="/login" style={{
                                display: 'block', textAlign: 'center', fontSize: 9, color: C.sub,
                                textDecoration: 'none', letterSpacing: '0.08em',
                                transition: 'color 0.15s',
                            }}
                            onMouseEnter={e => ((e.target as HTMLElement).style.color = C.text)}
                            onMouseLeave={e => ((e.target as HTMLElement).style.color = C.sub)}
                            >
                                ← BACK TO SIGN IN
                            </Link>
                        </form>
                    )}
                </div>
            </div>
        </div>
    );
}
