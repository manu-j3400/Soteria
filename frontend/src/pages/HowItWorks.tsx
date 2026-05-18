import React from 'react';
import { Link } from 'react-router-dom';
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

export default function HowItWorks() {
    return (
        <div style={{ minHeight: '100vh', background: C.bg, color: C.text, overflowX: 'hidden', paddingTop: 76 }}>
            <PublicNavbar />

            {/* PAGE TITLE STRIP */}
            <div style={{ borderBottom: `1px solid ${C.border}`, display: 'flex', alignItems: 'stretch', height: '36px' }}>
                <div style={{ ...cellStyle, borderLeft: `1px solid ${C.border}`, color: C.text, fontWeight: 700, letterSpacing: '0.1em', fontSize: '11px' }}>
                    HOW IT WORKS
                </div>
                <div style={{ ...cellStyle, color: C.accent }}>[ LIVE ]</div>
                <div style={{ flex: 1, borderRight: `1px solid ${C.border}` }} />
                <div style={{ ...cellStyle, borderRight: 'none' }}>UTC {new Date().toISOString().slice(11, 19)}</div>
            </div>

            {/* HERO */}
            <section style={{ padding: '64px 48px 48px', borderBottom: `1px solid ${C.border}` }}>
                <div style={{ maxWidth: '680px' }}>
                    <h1 style={{ ...SANS, fontSize: 'clamp(32px, 5vw, 60px)', fontWeight: 900, letterSpacing: '-0.02em', lineHeight: 1.05, margin: '0 0 20px' }}>
                        From paste to verdict<br />in under 2 seconds.
                    </h1>
                    <p style={{ ...SANS, fontSize: '15px', color: C.subdued, lineHeight: 1.8, margin: 0 }}>
                        Three steps. No configuration. No agent to install.
                    </p>
                </div>
            </section>

            {/* 3 STEPS */}
            {[
                {
                    num: '01',
                    accent: C.accent,
                    title: 'Paste your code',
                    body: 'Drop any file into the scanner or paste directly. Python, JavaScript, Go, Rust, TypeScript, Java, SQL — 30+ file extensions accepted. Drag and drop works too.',
                    points: [
                        'No account needed to try it',
                        'Language is detected automatically',
                        'Supports files up to thousands of lines',
                    ],
                },
                {
                    num: '02',
                    accent: C.amber,
                    title: 'We analyze it',
                    body: 'Soteria runs multiple layers of analysis simultaneously — pattern matching, behavioral profiling, and structural inspection. Each layer catches a different class of threat.',
                    points: [
                        'Hundreds of vulnerability patterns checked',
                        'Behavioral signals that pattern matching misses',
                        'Cross-language aware — a flag in PHP isn\'t a flag in Python',
                    ],
                },
                {
                    num: '03',
                    accent: C.text,
                    title: 'Get the verdict',
                    body: 'You see exactly which lines are vulnerable, what the risk is, and how to fix it — in plain English, streamed back in real time. No waiting, no report to download.',
                    points: [
                        'Exact line numbers, not file-level warnings',
                        'Patched code snippet with every finding',
                        'Severity level: Critical / High / Medium / Low',
                    ],
                },
            ].map((step, i) => (
                <section
                    key={step.num}
                    style={{
                        borderBottom: `1px solid ${C.border}`,
                        display: 'grid',
                        gridTemplateColumns: '1fr 1fr',
                    }}
                >
                    <div style={{ padding: '44px 48px', borderRight: `1px solid ${C.border}` }}>
                        <div style={{ ...MONO, fontSize: '48px', fontWeight: 900, color: C.muted, lineHeight: 1, marginBottom: '16px' }}>{step.num}</div>
                        <h2 style={{ ...SANS, fontSize: '24px', fontWeight: 800, color: step.accent, marginBottom: '16px', lineHeight: 1.15 }}>
                            {step.title}
                        </h2>
                        <p style={{ ...SANS, fontSize: '14px', color: C.subdued, lineHeight: 1.8, margin: 0 }}>
                            {step.body}
                        </p>
                    </div>
                    <div style={{ padding: '44px 48px', background: i % 2 === 1 ? COLORS.surface : 'transparent', display: 'flex', alignItems: 'flex-start' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', paddingTop: '72px' }}>
                            {step.points.map((pt, j) => (
                                <div key={j} style={{ display: 'flex', gap: '12px', ...SANS, fontSize: '14px', color: C.subdued }}>
                                    <span style={{ color: step.accent, ...MONO, flexShrink: 0 }}>→</span>
                                    {pt}
                                </div>
                            ))}
                        </div>
                    </div>
                </section>
            ))}

            {/* CTA */}
            <section style={{ padding: '64px 48px' }}>
                <div style={{ borderLeft: `3px solid ${C.accent}`, paddingLeft: '28px' }}>
                    <p style={{ ...SANS, fontSize: '15px', color: C.subdued, margin: '0 0 20px' }}>
                        Ready to see it in action?
                    </p>
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
