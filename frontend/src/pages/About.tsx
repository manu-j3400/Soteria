import React from 'react';
import { Github, Linkedin, Globe, Mail } from 'lucide-react';
import { Link } from 'react-router-dom';
import PublicNavbar from '../components/PublicNavbar';
import { COLORS } from '../theme/colors';

const C = {
    bg:      COLORS.bg,
    accent:  COLORS.acid,
    text:    COLORS.text,
    subdued: COLORS.sub,
    muted:   COLORS.muted,
    border:  COLORS.border,
    surface: COLORS.surface,
};

const MONO: React.CSSProperties = { fontFamily: "'JetBrains Mono', monospace" };
const SANS: React.CSSProperties = { fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif" };

const SKILLS = [
    'Python', 'TypeScript', 'React', 'Flask',
    'PyTorch', 'Graph Neural Networks', 'C/C++',
    'SQLite', 'REST APIs', 'Linux', 'Git',
];

const INTERESTS = [
    { label: 'Security Engineering',    desc: 'Static analysis, vulnerability research, offensive/defensive tooling' },
    { label: 'Machine Learning',        desc: 'Graph networks, neural ensembles, behavioral modeling'               },
    { label: 'Systems Programming',     desc: 'Low-level code, eBPF, kernel interfaces, performance'               },
    { label: 'Developer Tooling',       desc: 'Tools that make engineers faster and more confident'                },
];

const LINKS = [
    { href: 'https://www.mjawahar.com',             icon: <Globe size={14} />,    label: 'mjawahar.com'              },
    { href: 'https://github.com/manu-j3400',        icon: <Github size={14} />,   label: 'github.com/manu-j3400'     },
    { href: 'https://linkedin.com/in/manu-jawahar', icon: <Linkedin size={14} />, label: 'linkedin.com/in/manu-jawahar' },
];

export default function About() {
    return (
        <div style={{ minHeight: '100vh', background: C.bg, color: C.text, overflowX: 'hidden', paddingTop: 72 }}>
            <PublicNavbar />

            {/* HERO — WHO AM I */}
            <section style={{
                borderBottom: `1px solid ${C.border}`,
                display: 'grid', gridTemplateColumns: '280px 1fr',
            }}>
                {/* Left: Avatar + links */}
                <div style={{
                    borderRight: `1px solid ${C.border}`,
                    padding: '56px 40px',
                    display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '24px',
                }}>
                    {/* Avatar */}
                    <div style={{
                        width: '100px', height: '100px',
                        border: `1px solid ${C.accent}`,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        background: C.surface,
                        position: 'relative',
                    }}>
                        <span style={{ ...MONO, fontSize: '32px', fontWeight: 900, color: C.accent, letterSpacing: '-0.04em' }}>MJ</span>
                        {/* Active dot */}
                        <div style={{
                            position: 'absolute', bottom: -4, right: -4,
                            width: '12px', height: '12px',
                            background: C.accent, border: `2px solid ${C.bg}`,
                        }} />
                    </div>

                    <div style={{ textAlign: 'center' }}>
                        <div style={{ ...SANS, fontSize: '20px', fontWeight: 800, color: C.text, letterSpacing: '-0.01em' }}>
                            Manu Jawahar
                        </div>
                        <div style={{ ...MONO, fontSize: '10px', color: C.accent, marginTop: '8px', letterSpacing: '0.14em' }}>
                            SOFTWARE ENGINEER
                        </div>
                        <div style={{ ...MONO, fontSize: '10px', color: C.muted, marginTop: '4px', letterSpacing: '0.1em' }}>
                            CSE @ UC IRVINE
                        </div>
                    </div>

                    {/* Links */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', width: '100%' }}>
                        {LINKS.map((link) => (
                            <a
                                key={link.label}
                                href={link.href}
                                target="_blank"
                                rel="noopener noreferrer"
                                style={{
                                    display: 'flex', alignItems: 'center', gap: '10px',
                                    border: `1px solid ${C.border}`, padding: '9px 14px',
                                    color: C.subdued, textDecoration: 'none',
                                    ...SANS, fontSize: '12px',
                                    transition: 'color 0.15s, border-color 0.15s',
                                }}
                                onMouseEnter={e => {
                                    (e.currentTarget as HTMLAnchorElement).style.color = C.accent;
                                    (e.currentTarget as HTMLAnchorElement).style.borderColor = C.accent;
                                }}
                                onMouseLeave={e => {
                                    (e.currentTarget as HTMLAnchorElement).style.color = C.subdued;
                                    (e.currentTarget as HTMLAnchorElement).style.borderColor = C.border;
                                }}
                            >
                                {link.icon}
                                {link.label}
                            </a>
                        ))}
                    </div>
                </div>

                {/* Right: Bio */}
                <div style={{ padding: '56px 64px' }}>
                    <div style={{ ...MONO, fontSize: '10px', color: C.accent, letterSpacing: '0.22em', marginBottom: '20px' }}>
                        ABOUT ME
                    </div>
                    <h1 style={{
                        ...SANS, fontSize: 'clamp(26px, 3.5vw, 46px)',
                        fontWeight: 900, lineHeight: 1.07,
                        letterSpacing: '-0.02em', margin: '0 0 32px',
                    }}>
                        I build tools that make<br />
                        <span style={{ color: C.accent }}>code safer to ship.</span>
                    </h1>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '18px', maxWidth: '540px' }}>
                        <p style={{ ...SANS, fontSize: '15px', color: C.text, lineHeight: 1.8, margin: 0 }}>
                            I'm a Computer Science & Engineering student at UC Irvine with a focus on
                            security engineering and applied machine learning. I care about building things
                            that are fast, correct, and hard to break.
                        </p>
                        <p style={{ ...SANS, fontSize: '14px', color: C.subdued, lineHeight: 1.8, margin: 0 }}>
                            Soteria started as a frustration — watching developers (myself included) blindly
                            ship AI-generated code without understanding whether it was actually secure. So I
                            built a scanner: multi-model, fast, and free. It grew into a full ML pipeline with
                            graph neural networks, entropy profiling, and a spiking neural network temporal layer.
                        </p>
                        <p style={{ ...SANS, fontSize: '14px', color: C.subdued, lineHeight: 1.8, margin: 0 }}>
                            Outside of that I'm interested in systems programming, eBPF, and building tools
                            that feel fast. I like working close to the metal when I can.
                        </p>
                    </div>
                </div>
            </section>

            {/* INTERESTS */}
            <section style={{ borderBottom: `1px solid ${C.border}`, padding: '56px 48px' }}>
                <div style={{ ...MONO, fontSize: '10px', color: C.accent, letterSpacing: '0.22em', marginBottom: '36px' }}>
                    WHAT I WORK ON
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1px', background: C.border }}>
                    {INTERESTS.map((item) => (
                        <div key={item.label} style={{ background: C.bg, padding: '28px 32px' }}>
                            <div style={{ ...MONO, fontSize: '12px', fontWeight: 700, color: C.text, letterSpacing: '0.08em', marginBottom: '8px' }}>
                                {item.label}
                            </div>
                            <div style={{ ...SANS, fontSize: '13px', color: C.subdued, lineHeight: 1.7 }}>
                                {item.desc}
                            </div>
                        </div>
                    ))}
                </div>
            </section>

            {/* SKILLS */}
            <section style={{ borderBottom: `1px solid ${C.border}`, padding: '48px 48px' }}>
                <div style={{ ...MONO, fontSize: '10px', color: C.accent, letterSpacing: '0.22em', marginBottom: '28px' }}>
                    TECH STACK
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                    {SKILLS.map((skill) => (
                        <span key={skill} style={{
                            ...MONO, fontSize: '11px', letterSpacing: '0.08em',
                            color: C.subdued, border: `1px solid ${C.border}`,
                            padding: '6px 14px',
                        }}>
                            {skill}
                        </span>
                    ))}
                </div>
            </section>

            {/* CONTACT */}
            <section style={{ padding: '56px 48px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '24px' }}>
                <div>
                    <div style={{ ...MONO, fontSize: '10px', color: C.accent, letterSpacing: '0.22em', marginBottom: '12px' }}>
                        GET IN TOUCH
                    </div>
                    <h3 style={{ ...SANS, fontSize: 'clamp(20px, 2.5vw, 30px)', fontWeight: 900, margin: 0, letterSpacing: '-0.01em' }}>
                        Open to collabs and conversations.
                    </h3>
                </div>
                <div style={{ display: 'flex', gap: '12px' }}>
                    <a
                        href="https://linkedin.com/in/manu-jawahar"
                        target="_blank" rel="noopener noreferrer"
                        style={{
                            ...MONO, fontSize: '11px', fontWeight: 700, letterSpacing: '0.1em',
                            color: '#000', background: C.accent,
                            padding: '13px 24px', textDecoration: 'none',
                            display: 'flex', alignItems: 'center', gap: '8px',
                            transition: 'opacity 0.15s',
                        }}
                        onMouseEnter={e => (e.currentTarget as HTMLAnchorElement).style.opacity = '0.85'}
                        onMouseLeave={e => (e.currentTarget as HTMLAnchorElement).style.opacity = '1'}
                    >
                        <Linkedin size={13} /> LINKEDIN
                    </a>
                    <a
                        href="https://github.com/manu-j3400"
                        target="_blank" rel="noopener noreferrer"
                        style={{
                            ...MONO, fontSize: '11px', fontWeight: 700, letterSpacing: '0.1em',
                            color: C.subdued, background: 'transparent',
                            border: `1px solid ${C.border}`,
                            padding: '13px 24px', textDecoration: 'none',
                            display: 'flex', alignItems: 'center', gap: '8px',
                            transition: 'color 0.15s, border-color 0.15s',
                        }}
                        onMouseEnter={e => {
                            (e.currentTarget as HTMLAnchorElement).style.color = C.text;
                            (e.currentTarget as HTMLAnchorElement).style.borderColor = C.subdued;
                        }}
                        onMouseLeave={e => {
                            (e.currentTarget as HTMLAnchorElement).style.color = C.subdued;
                            (e.currentTarget as HTMLAnchorElement).style.borderColor = C.border;
                        }}
                    >
                        <Github size={13} /> GITHUB
                    </a>
                </div>
            </section>

            {/* FOOTER */}
            <footer style={{
                borderTop: `1px solid ${C.border}`,
                padding: '20px 48px',
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            }}>
                <Link to="/" style={{ ...MONO, color: C.text, textDecoration: 'none', fontWeight: 700, letterSpacing: '0.15em', fontSize: '11px' }}>
                    SOTERIA
                </Link>
                <span style={{ ...MONO, fontSize: '11px', color: C.muted }}>© {new Date().getFullYear()} Manu Jawahar</span>
                <a
                    href="https://github.com/manujawahar/ACID"
                    target="_blank" rel="noopener noreferrer"
                    style={{ ...SANS, color: C.subdued, textDecoration: 'none', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}
                >
                    <Github size={13} /> Open source
                </a>
            </footer>
        </div>
    );
}
