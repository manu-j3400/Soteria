import React from 'react';
import { Link } from 'react-router-dom';
import { ScanLine, Brain, Github, Database } from 'lucide-react';
import PublicNavbar from '../components/PublicNavbar';
import { COLORS } from '../theme/colors';

const C = {
    bg:      COLORS.bg,
    accent:  COLORS.acid,
    danger:  COLORS.red,
    amber:   COLORS.orange,
    text:    COLORS.text,
    subdued: COLORS.sub,
    muted:   COLORS.muted,
    border:  COLORS.border,
    font:    "'JetBrains Mono', monospace",
};

const MONO: React.CSSProperties = { fontFamily: "'JetBrains Mono', monospace" };
const SANS: React.CSSProperties = { fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif" };

const cellStyle: React.CSSProperties = {
    borderRight: `1px solid ${C.border}`,
    padding: '0 16px',
    display: 'flex',
    alignItems: 'center',
    height: '36px',
    fontFamily: C.font,
    fontSize: '11px',
    color: C.subdued,
    whiteSpace: 'nowrap',
};

export default function FeaturesPage() {
    return (
        <div style={{ minHeight: '100vh', background: C.bg, color: C.text, overflowX: 'hidden', paddingTop: 72 }}>
            <PublicNavbar />

            {/* HERO */}
            <section style={{ padding: '64px 48px 48px', borderBottom: `1px solid ${C.border}` }}>
                <div style={{ maxWidth: '680px' }}>
                    <h1 style={{ ...SANS, fontSize: 'clamp(32px, 5vw, 60px)', fontWeight: 900, letterSpacing: '-0.02em', lineHeight: 1.05, margin: '0 0 20px' }}>
                        Built to find what you missed.
                    </h1>
                    <p style={{ ...SANS, fontSize: '15px', color: C.subdued, lineHeight: 1.8, margin: 0 }}>
                        Soteria combines multiple layers of static and behavioral analysis
                        with an AI explainer — so you know not just what's wrong, but why it matters
                        and exactly how to fix it.
                    </p>
                </div>
            </section>

            {/* REAL-TIME SCANNING */}
            <section style={{ borderBottom: `1px solid ${C.border}`, display: 'grid', gridTemplateColumns: '1fr 1fr' }}>
                <div style={{ padding: '40px 48px', borderRight: `1px solid ${C.border}` }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
                        <ScanLine size={14} style={{ color: C.danger }} />
                        <span style={{ ...MONO, fontSize: '10px', color: C.danger, fontWeight: 700, letterSpacing: '0.15em' }}>REAL-TIME SCANNING</span>
                    </div>
                    <h3 style={{ ...SANS, fontSize: '22px', fontWeight: 800, color: C.text, marginBottom: '14px', lineHeight: 1.15 }}>
                        Sub-second. In-browser.
                    </h3>
                    <p style={{ ...SANS, fontSize: '14px', color: C.subdued, lineHeight: 1.8, margin: '0 0 24px' }}>
                        Paste any code and get a verdict in under 2 seconds. SQL injection, XSS,
                        command injection, SSRF, path traversal, and hundreds more patterns —
                        across Python, Go, Rust, JavaScript, TypeScript, Java, and more.
                    </p>
                    <div style={{ display: 'flex', gap: '28px' }}>
                        <div>
                            <div style={{ ...MONO, fontSize: '24px', fontWeight: 900, color: C.danger }}>700+</div>
                            <div style={{ ...SANS, fontSize: '12px', color: C.muted, marginTop: '4px' }}>vulnerability patterns</div>
                        </div>
                        <div>
                            <div style={{ ...MONO, fontSize: '24px', fontWeight: 900, color: C.text }}>&lt; 2s</div>
                            <div style={{ ...SANS, fontSize: '12px', color: C.muted, marginTop: '4px' }}>per scan</div>
                        </div>
                        <div>
                            <div style={{ ...MONO, fontSize: '24px', fontWeight: 900, color: C.accent }}>8</div>
                            <div style={{ ...SANS, fontSize: '12px', color: C.muted, marginTop: '4px' }}>languages</div>
                        </div>
                    </div>
                </div>

                {/* Code preview panel */}
                <div style={{ padding: '40px 48px', background: COLORS.surface, ...MONO, fontSize: '12px', lineHeight: 1.9 }}>
                    <div style={{ border: `1px solid ${C.border}`, padding: '20px' }}>
                        <div><span style={{ color: C.accent }}>$</span> soteria scan auth_handler.py</div>
                        <div style={{ color: C.muted }}>  analyzing...</div>
                        <div style={{ color: C.danger, fontWeight: 700, marginTop: '8px' }}>  MALICIOUS — 2 CRITICAL</div>
                        <div style={{ color: C.amber }}>    L44: unsanitized SQL query</div>
                        <div style={{ color: C.amber }}>    L67: shell injection via user input</div>
                        <div style={{ color: C.accent, marginTop: '4px' }}>  completed in 1.3s</div>
                    </div>
                </div>
            </section>

            {/* AI EXPLANATIONS */}
            <section style={{ borderBottom: `1px solid ${C.border}`, display: 'grid', gridTemplateColumns: '1fr 1fr' }}>
                <div style={{ padding: '40px 48px', borderRight: `1px solid ${C.border}` }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
                        <Brain size={14} style={{ color: C.accent }} />
                        <span style={{ ...MONO, fontSize: '10px', color: C.accent, fontWeight: 700, letterSpacing: '0.15em' }}>AI EXPLANATIONS</span>
                    </div>
                    <h3 style={{ ...SANS, fontSize: '22px', fontWeight: 800, color: C.text, marginBottom: '14px', lineHeight: 1.15 }}>
                        Not just a flag. An explanation.
                    </h3>
                    <p style={{ ...SANS, fontSize: '14px', color: C.subdued, lineHeight: 1.8, margin: '0 0 20px' }}>
                        Every finding streams a plain-English breakdown: what the vulnerability is,
                        how an attacker would exploit it, and the patched version of your code.
                        First word back in under 400ms.
                    </p>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                        {[
                            'Streams in real time — no waiting for a full response',
                            'Patched code snippet included with every finding',
                            'References the exact lines from your file',
                        ].map((item, i) => (
                            <div key={i} style={{ display: 'flex', gap: '10px', ...SANS, fontSize: '13px', color: C.subdued }}>
                                <span style={{ color: C.accent, ...MONO, flexShrink: 0 }}>→</span>
                                {item}
                            </div>
                        ))}
                    </div>
                </div>

                <div style={{ padding: '40px 48px', background: COLORS.surface }}>
                    <div style={{ marginBottom: '16px' }}>
                        <div style={{ ...MONO, fontSize: '10px', color: C.muted, letterSpacing: '0.1em', marginBottom: '12px' }}>EXAMPLE EXPLANATION</div>
                        <div style={{ ...SANS, fontSize: '13px', color: C.subdued, lineHeight: 1.8, borderLeft: `2px solid ${C.accent}`, paddingLeft: '14px' }}>
                            "The query on line 44 passes user input directly into a SQL string.
                            An attacker can inject arbitrary SQL — for example, returning all rows
                            or dropping tables. Fix: use parameterized queries."
                        </div>
                    </div>
                    <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: '14px', ...MONO, fontSize: '10px', color: C.muted }}>
                        <div>SEVERITY: CRITICAL</div>
                        <div>CWE-89: SQL Injection</div>
                    </div>
                </div>
            </section>

            {/* GITHUB + HISTORY */}
            <section style={{ borderBottom: `1px solid ${C.border}`, display: 'grid', gridTemplateColumns: '1fr 1fr' }}>
                <div style={{ padding: '40px 48px', borderRight: `1px solid ${C.border}` }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
                        <Github size={14} style={{ color: C.text }} />
                        <span style={{ ...MONO, fontSize: '10px', color: C.text, fontWeight: 700, letterSpacing: '0.15em' }}>GITHUB INTEGRATION</span>
                    </div>
                    <h3 style={{ ...SANS, fontSize: '22px', fontWeight: 800, color: C.text, marginBottom: '14px', lineHeight: 1.15 }}>
                        Scan entire repos.
                    </h3>
                    <p style={{ ...SANS, fontSize: '14px', color: C.subdued, lineHeight: 1.8, margin: '0 0 20px' }}>
                        Connect once via GitHub OAuth. Clone and scan any repo — no credentials
                        embedded anywhere. Pull requests can be automatically checked on every push.
                    </p>
                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                        {['my-flask-app', 'react-portfolio', 'node-api'].map((repo, i) => (
                            <div
                                key={repo}
                                style={{ ...MONO, border: `1px solid ${C.border}`, padding: '6px 12px', fontSize: '11px', color: C.subdued, display: 'flex', alignItems: 'center', gap: '8px' }}
                            >
                                <div style={{ width: '6px', height: '6px', background: i === 0 ? C.accent : i === 1 ? C.text : C.danger }} />
                                {repo}
                            </div>
                        ))}
                    </div>
                </div>

                <div style={{ padding: '40px 48px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
                        <Database size={14} style={{ color: C.amber }} />
                        <span style={{ ...MONO, fontSize: '10px', color: C.amber, fontWeight: 700, letterSpacing: '0.15em' }}>SCAN HISTORY</span>
                    </div>
                    <h3 style={{ ...SANS, fontSize: '22px', fontWeight: 800, color: C.text, marginBottom: '14px', lineHeight: 1.15 }}>
                        Every scan. Searchable.
                    </h3>
                    <p style={{ ...SANS, fontSize: '14px', color: C.subdued, lineHeight: 1.8, margin: '0 0 20px' }}>
                        Full scan history — filterable by verdict, exportable to CSV.
                        Webhook alerts fire on malicious results. Identical code doesn't get re-scanned.
                    </p>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                        {[
                            'CSV export — your data, always',
                            'Webhook alerts on malicious results',
                            'Instant results on identical code re-scans',
                        ].map((item, i) => (
                            <div key={i} style={{ display: 'flex', gap: '10px', ...SANS, fontSize: '13px', color: C.subdued }}>
                                <span style={{ color: C.amber, ...MONO, flexShrink: 0 }}>→</span>
                                {item}
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* CTA */}
            <section style={{ padding: '64px 48px' }}>
                <div style={{ borderLeft: `3px solid ${C.accent}`, paddingLeft: '28px', maxWidth: '540px' }}>
                    <h2 style={{ ...SANS, fontSize: 'clamp(24px, 3.5vw, 44px)', fontWeight: 900, lineHeight: 1.1, margin: '0 0 24px' }}>
                        Scan your code.<br />
                        <span style={{ color: C.accent }}>Know what's in it.</span>
                    </h2>
                    <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                        <Link
                            to="/signup"
                            style={{
                                display: 'inline-block',
                                border: `1px solid ${C.accent}`,
                                background: C.accent,
                                color: '#000',
                                ...MONO,
                                fontSize: '12px',
                                fontWeight: 700,
                                letterSpacing: '0.15em',
                                padding: '12px 28px',
                                textDecoration: 'none',
                                textTransform: 'uppercase',
                            }}
                        >
                            START FREE
                        </Link>
                        <Link
                            to="/how-it-works"
                            style={{
                                display: 'inline-block',
                                border: `1px solid ${C.border}`,
                                color: C.subdued,
                                ...MONO,
                                fontSize: '12px',
                                fontWeight: 700,
                                letterSpacing: '0.15em',
                                padding: '12px 28px',
                                textDecoration: 'none',
                                textTransform: 'uppercase',
                            }}
                        >
                            HOW IT WORKS
                        </Link>
                    </div>
                </div>
            </section>

            {/* FOOTER */}
            <footer style={{ borderTop: `1px solid ${C.border}`, padding: '0', display: 'flex', alignItems: 'stretch', height: '36px' }}>
                <div style={{ ...cellStyle, borderLeft: `1px solid ${C.border}` }}>
                    <Link to="/" style={{ color: C.text, textDecoration: 'none', fontWeight: 700, letterSpacing: '0.15em', fontSize: '11px' }}>SOTERIA</Link>
                </div>
                <div style={{ ...cellStyle }}>
                    <span style={{ color: C.muted }}>© {new Date().getFullYear()} Soteria</span>
                </div>
                <div style={{ flex: 1 }} />
                <div style={{ ...cellStyle, borderLeft: `1px solid ${C.border}`, borderRight: 'none' }}>
                    <Link to="/about" style={{ color: C.subdued, textDecoration: 'none', fontSize: '11px' }}>About</Link>
                </div>
                <div style={{ ...cellStyle, borderLeft: `1px solid ${C.border}`, borderRight: 'none' }}>
                    <a href="https://github.com/manujawahar/ACID" target="_blank" rel="noopener noreferrer" style={{ color: C.subdued, textDecoration: 'none', fontSize: '11px' }}>Open source</a>
                </div>
            </footer>
        </div>
    );
}
