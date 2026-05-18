import { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import PublicNavbar from '@/components/PublicNavbar';
import { COLORS } from '../theme/colors';

const C = {
    acid:   COLORS.acid,
    bg:     COLORS.bg,
    dim:    COLORS.surface,
    border: COLORS.border,
    muted:  COLORS.muted,
    sub:    COLORS.sub,
    text:   COLORS.text,
    red:    COLORS.red,
    amber:  COLORS.orange,
};

const MONO: React.CSSProperties = { fontFamily: "'JetBrains Mono', monospace" };
const SANS: React.CSSProperties = { fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif" };

const SCAN_LINES = [
    '$ soteria scan auth.py',
    '  analyzing...',
    '',
    '  FINDINGS',
    '  ─────────────────────────────',
    '  CRITICAL  SQL injection     L.42',
    '            cursor.execute(f"..{uid}")',
    '            → use parameterized query',
    '',
    '  HIGH      Hardcoded secret  L.17',
    '            JWT_SECRET = "abc123"',
    '            → move to env var',
    '',
    '  RISK: HIGH · 2 findings · 0.8s',
];

function Terminal() {
    const [lines, setLines] = useState<string[]>([]);
    const [cursor, setCursor] = useState(true);
    const idx = useRef(0);
    const timerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

    useEffect(() => {
        const tick = () => {
            if (idx.current < SCAN_LINES.length) {
                setLines(prev => [...prev, SCAN_LINES[idx.current]]);
                idx.current++;
                timerRef.current = setTimeout(tick, idx.current < 2 ? 120 : 55);
            } else {
                timerRef.current = setTimeout(() => {
                    setLines([]);
                    idx.current = 0;
                    timerRef.current = setTimeout(tick, 800);
                }, 4000);
            }
        };
        timerRef.current = setTimeout(tick, 600);
        const blink = setInterval(() => setCursor(c => !c), 530);
        return () => { clearTimeout(timerRef.current); clearInterval(blink); };
    }, []);

    return (
        <div style={{ border: `1px solid ${C.border}`, background: COLORS.surface, flexShrink: 0 }}>
            <div style={{
                padding: '7px 14px', borderBottom: `1px solid ${C.border}`,
                display: 'flex', alignItems: 'center', gap: 8,
            }}>
                <span style={{ width: 5, height: 5, background: C.acid, display: 'inline-block', borderRadius: '50%' }} />
                <span style={{ ...MONO, fontSize: 10, color: C.muted, letterSpacing: '0.1em' }}>
                    SOTERIA · SCAN SESSION
                </span>
            </div>
            <div style={{ padding: '18px 20px', minHeight: 280 }}>
                {lines.map((line, i) => {
                    const safe    = line ?? '';
                    const isCrit  = safe.includes('CRITICAL');
                    const isHigh  = safe.includes('HIGH') && !safe.includes('RISK');
                    const isRisk  = safe.includes('RISK:');
                    const isCmd   = safe.startsWith('$');
                    const isArrow = safe.trim().startsWith('→');
                    return (
                        <div key={i} style={{
                            ...MONO, fontSize: 11, lineHeight: 1.75,
                            color: isCrit ? C.red
                                 : isHigh  ? C.amber
                                 : isRisk  ? C.acid
                                 : isCmd   ? C.text
                                 : isArrow ? C.acid
                                 : C.sub,
                            whiteSpace: 'pre',
                        }}>
                            {safe || '\u00A0'}
                        </div>
                    );
                })}
                {lines.length < SCAN_LINES.length && (
                    <span style={{
                        display: 'inline-block', width: 7, height: 14,
                        background: cursor ? C.acid : 'transparent',
                        verticalAlign: 'text-bottom',
                    }} />
                )}
            </div>
        </div>
    );
}

export default function LandingPage() {
    return (
        <div style={{ minHeight: '100vh', background: C.bg, color: C.text, overflowX: 'hidden' }}>
            <PublicNavbar />

            {/* ── HERO ─────────────────────────────────────────────────────── */}
            <section style={{ padding: '96px 24px 80px', maxWidth: 1200, margin: '0 auto' }}>
                <div style={{
                    display: 'grid',
                    gridTemplateColumns: '1fr 440px',
                    gap: 72, alignItems: 'flex-start',
                }}>
                    <div>
                        <h1 style={{
                            ...MONO,
                            fontSize: 'clamp(38px, 5vw, 68px)',
                            fontWeight: 900, lineHeight: 1.0,
                            letterSpacing: '-0.025em',
                            textTransform: 'uppercase',
                            margin: '0 0 28px',
                        }}>
                            <span style={{ display: 'block' }}>PREVENTING YOUR</span>
                            <span style={{ display: 'block' }}>APPLICATION</span>
                            <span style={{ display: 'block', color: C.red }}>FROM TURNING AGAINST YOU</span>
                        </h1>

                        <p style={{
                            ...SANS,
                            fontSize: 15, color: C.sub, lineHeight: 1.75,
                            maxWidth: 420, marginBottom: 36, fontWeight: 400,
                        }}>
                            Paste your code. Get a verdict in under 2 seconds — with the exact
                            vulnerable line and patched code handed back to you.
                        </p>

                        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 56 }}>
                            <Link to="/scanner" style={{ textDecoration: 'none' }}>
                                <button style={{
                                    ...MONO, fontSize: 11, fontWeight: 700, letterSpacing: '0.1em',
                                    padding: '12px 28px', background: C.acid, color: '#000',
                                    border: `1px solid ${C.acid}`, cursor: 'pointer',
                                    transition: 'opacity 0.15s',
                                }}
                                    onMouseEnter={e => ((e.currentTarget as HTMLElement).style.opacity = '0.85')}
                                    onMouseLeave={e => ((e.currentTarget as HTMLElement).style.opacity = '1')}
                                >
                                    SCAN YOUR CODE →
                                </button>
                            </Link>
                            <Link to="/signup" style={{ textDecoration: 'none' }}>
                                <button style={{
                                    ...MONO, fontSize: 11, letterSpacing: '0.1em',
                                    padding: '12px 24px', background: 'transparent',
                                    color: C.muted, border: `1px solid ${C.border}`, cursor: 'pointer',
                                    transition: 'color 0.15s, border-color 0.15s',
                                }}
                                    onMouseEnter={e => {
                                        (e.currentTarget as HTMLElement).style.color = C.text;
                                        (e.currentTarget as HTMLElement).style.borderColor = C.sub;
                                    }}
                                    onMouseLeave={e => {
                                        (e.currentTarget as HTMLElement).style.color = C.muted;
                                        (e.currentTarget as HTMLElement).style.borderColor = C.border;
                                    }}
                                >
                                    CREATE ACCOUNT
                                </button>
                            </Link>
                        </div>

                        <div style={{
                            display: 'flex', gap: 0,
                            borderTop: `1px solid ${C.border}`, paddingTop: 24,
                        }}>
                            {[
                                { val: '700+', lbl: 'vulnerability patterns' },
                                { val: '< 2s', lbl: 'per scan'              },
                                { val: '8',    lbl: 'languages'             },
                            ].map((s, i) => (
                                <div key={s.lbl} style={{
                                    paddingRight: 28, marginRight: 28,
                                    borderRight: i < 2 ? `1px solid ${C.border}` : 'none',
                                }}>
                                    <div style={{ ...MONO, fontSize: 26, fontWeight: 700, color: C.text, letterSpacing: '-0.02em', lineHeight: 1 }}>
                                        {s.val}
                                    </div>
                                    <div style={{ ...SANS, fontSize: 12, color: C.muted, marginTop: 4 }}>
                                        {s.lbl}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    <Terminal />
                </div>
            </section>

            {/* ── WHAT IT CATCHES ──────────────────────────────────────────── */}
            <section style={{
                borderTop: `1px solid ${C.border}`,
                background: C.dim,
                padding: '72px 24px',
            }}>
                <div style={{ maxWidth: 1200, margin: '0 auto' }}>
                    <div style={{
                        display: 'flex', alignItems: 'baseline', gap: 20,
                        marginBottom: 40,
                    }}>
                        <h2 style={{
                            ...SANS,
                            fontSize: 'clamp(18px, 2vw, 24px)', fontWeight: 700,
                            color: C.text, margin: 0,
                        }}>
                            What it catches
                        </h2>
                        <span style={{ ...SANS, fontSize: 13, color: C.muted }}>
                            by vulnerability class
                        </span>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 0, border: `1px solid ${C.border}` }}>
                        {[
                            {
                                cat: 'INJECTION',
                                items: [
                                    'SQL via f-string, concatenation, execute()',
                                    'Command injection via os.system / subprocess',
                                    'XSS via innerHTML, v-html, dangerouslySetInnerHTML',
                                    'LDAP, XPath, and template injection',
                                ],
                            },
                            {
                                cat: 'SECRETS',
                                items: [
                                    'Hardcoded passwords, tokens, and API keys',
                                    'Common key prefixes: sk-, xoxb-, AIza, SG.',
                                    'PEM private key blocks',
                                    'AWS credentials and session tokens',
                                ],
                            },
                            {
                                cat: 'CRYPTOGRAPHY',
                                items: [
                                    'MD5 / SHA1 used for password hashing',
                                    'AES in ECB mode',
                                    'JWT none algorithm acceptance',
                                    'Weak random number generation in security contexts',
                                ],
                            },
                            {
                                cat: 'RUNTIME',
                                items: [
                                    'eval() and exec() on user-controlled input',
                                    'Path traversal (../, ..\\ )',
                                    'Unsafe deserialization (pickle, yaml.load)',
                                    'Prototype pollution in JavaScript',
                                ],
                            },
                        ].map((cat, i) => (
                            <div
                                key={cat.cat}
                                style={{
                                    background: i % 2 === 1 ? '#0A0A0A' : 'transparent',
                                    padding: '24px',
                                    borderRight: i % 2 === 0 ? `1px solid ${C.border}` : 'none',
                                    borderBottom: i < 2 ? `1px solid ${C.border}` : 'none',
                                }}
                            >
                                <div style={{ ...MONO, fontSize: 11, fontWeight: 700, color: C.text, letterSpacing: '0.06em', marginBottom: 16 }}>
                                    {cat.cat}
                                </div>
                                <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 8 }}>
                                    {cat.items.map(item => (
                                        <li key={item} style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                                            <span style={{ ...MONO, color: C.muted, flexShrink: 0, marginTop: 2, fontSize: 10 }}>—</span>
                                            <span style={{ ...SANS, fontSize: 13, color: C.sub, lineHeight: 1.5 }}>{item}</span>
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        ))}
                    </div>

                    <div style={{ marginTop: 14, ...SANS, fontSize: 13, color: C.muted }}>
                        + hundreds of additional patterns across Python, Go, Rust, Java, TypeScript, and more.
                    </div>
                </div>
            </section>

            {/* ── CTA ──────────────────────────────────────────────────────── */}
            <section style={{ padding: '80px 24px', maxWidth: 1200, margin: '0 auto' }}>
                <p style={{ ...SANS, fontSize: 13, color: C.muted, margin: '0 0 16px' }}>
                    No credit card. No install. No onboarding call.
                </p>
                <h2 style={{
                    ...SANS,
                    fontSize: 'clamp(22px, 3vw, 38px)', fontWeight: 700,
                    color: C.text, margin: '0 0 28px', lineHeight: 1.2,
                }}>
                    Paste the code you're not sure about.
                </h2>
                <div style={{ display: 'flex', gap: 10 }}>
                    <Link to="/scanner" style={{ textDecoration: 'none' }}>
                        <button style={{
                            ...MONO, fontSize: 11, fontWeight: 700, letterSpacing: '0.1em',
                            padding: '13px 32px', background: C.acid, color: '#000',
                            border: `1px solid ${C.acid}`, cursor: 'pointer',
                            transition: 'opacity 0.15s',
                        }}
                            onMouseEnter={e => ((e.currentTarget as HTMLElement).style.opacity = '0.85')}
                            onMouseLeave={e => ((e.currentTarget as HTMLElement).style.opacity = '1')}
                        >
                            OPEN SCANNER →
                        </button>
                    </Link>
                    <Link to="/signup" style={{ textDecoration: 'none' }}>
                        <button style={{
                            ...MONO, fontSize: 11, letterSpacing: '0.1em',
                            padding: '13px 28px', background: 'transparent',
                            color: C.muted, border: `1px solid ${C.border}`, cursor: 'pointer',
                            transition: 'color 0.15s, border-color 0.15s',
                        }}
                            onMouseEnter={e => {
                                (e.currentTarget as HTMLElement).style.color = C.text;
                                (e.currentTarget as HTMLElement).style.borderColor = C.sub;
                            }}
                            onMouseLeave={e => {
                                (e.currentTarget as HTMLElement).style.color = C.muted;
                                (e.currentTarget as HTMLElement).style.borderColor = C.border;
                            }}
                        >
                            CREATE FREE ACCOUNT
                        </button>
                    </Link>
                </div>
            </section>

            {/* ── FOOTER ───────────────────────────────────────────────────── */}
            <footer style={{ borderTop: `1px solid ${C.border}`, padding: '28px 24px' }}>
                <div style={{
                    maxWidth: 1200, margin: '0 auto',
                    display: 'flex', alignItems: 'center',
                    justifyContent: 'space-between', flexWrap: 'wrap', gap: 20,
                }}>
                    <Link to="/" style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 10 }}>
                        <img src="/soteria-logo.png" alt="Soteria" style={{ width: 24, height: 24, objectFit: 'cover' }} />
                        <span style={{ ...MONO, fontSize: 12, fontWeight: 700, letterSpacing: '0.15em', color: C.text }}>SOTERIA</span>
                    </Link>

                    <div style={{ display: 'flex', gap: 24, alignItems: 'center' }}>
                        {[
                            { to: '/features',    label: 'Features'  },
                            { to: '/how-it-works',label: 'How it works' },
                            { to: '/changelog',   label: 'Changelog' },
                            { to: '/about',       label: 'About'     },
                        ].map(l => (
                            <Link key={l.to} to={l.to} style={{
                                ...SANS, fontSize: 13, color: C.muted, textDecoration: 'none',
                                transition: 'color 0.15s',
                            }}
                                onMouseEnter={e => ((e.target as HTMLElement).style.color = C.text)}
                                onMouseLeave={e => ((e.target as HTMLElement).style.color = C.muted)}
                            >
                                {l.label}
                            </Link>
                        ))}
                    </div>

                    <div style={{ ...SANS, fontSize: 12, color: '#333' }}>
                        © {new Date().getFullYear()} Soteria
                    </div>
                </div>
            </footer>
        </div>
    );
}
