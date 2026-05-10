import React, { useState, useCallback, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useSearchParams } from 'react-router-dom';
import { API_BASE_URL } from '../lib/api';

interface BatchFileItem { filename: string; code: string; size: number; }
interface ScanResult {
    filename: string; status: 'malicious' | 'clean' | 'error';
    message: string; risk_level: string; confidence: number;
    language: string; nodes_scanned?: number;
}
interface BatchSummary {
    total_files: number; threats: number; clean: number;
    project_score: number; project_grade: string;
}
type ScanState = 'idle' | 'scanning' | 'done';

import { COLORS } from '../theme/colors';
const C = {
    acid:   COLORS.acid,
    red:    COLORS.red,
    amber:  COLORS.orange,
    dim:    COLORS.surface,
    border: COLORS.border,
    muted:  COLORS.muted,
    text:   COLORS.text,
    sub:    COLORS.sub,
};

const riskColor = (r: string) =>
    r === 'CRITICAL' ? C.red : r === 'HIGH' ? C.amber : r === 'MEDIUM' ? '#FFD700' : C.acid;

const gradeColor = (g: string) =>
    g === 'A' ? C.acid : g === 'B' ? '#5AE65A' : g === 'C' ? '#FFD700' : g === 'D' ? C.amber : C.red;

export default function BatchScanner() {
    const [files, setFiles]           = useState<BatchFileItem[]>([]);
    const [results, setResults]       = useState<ScanResult[]>([]);
    const [summary, setSummary]       = useState<BatchSummary | null>(null);
    const [scanState, setScanState]   = useState<ScanState>('idle');
    const [dragActive, setDragActive] = useState(false);
    const [repoUrl, setRepoUrl]       = useState('');
    const [githubToken, setGithubToken] = useState<string | null>(localStorage.getItem('github_token'));
    const [repos, setRepos]           = useState<any[]>([]);
    const [isFetchingRepos, setIsFetchingRepos] = useState(false);
    const [expandedRow, setExpandedRow] = useState<number | null>(null);
    const [searchParams, setSearchParams] = useSearchParams();
    const inputRef = useRef<HTMLInputElement>(null);
    const oauthError = searchParams.get('error');

    useEffect(() => {
        if (oauthError) {
            const t = setTimeout(() => setSearchParams({}, { replace: true }), 4000);
            return () => clearTimeout(t);
        }
    }, [oauthError, setSearchParams]);

    useEffect(() => {
        if (!githubToken) return;
        const fetchRepos = async () => {
            setIsFetchingRepos(true);
            try {
                const res = await fetch(`${API_BASE_URL}/github/repos`, { headers: { Authorization: `Bearer ${githubToken}` } });
                if (res.ok) setRepos(await res.json());
                else if (res.status === 401) { localStorage.removeItem('github_token'); setGithubToken(null); }
            } catch { /* silent */ }
            finally { setIsFetchingRepos(false); }
        };
        fetchRepos();
    }, [githubToken]);

    const handleGithubConnect = async () => {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        const codeVerifier = btoa(String.fromCharCode(...array)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        const encoder = new TextEncoder();
        const digest = await crypto.subtle.digest('SHA-256', encoder.encode(codeVerifier));
        const codeChallenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        const res = await fetch(`${API_BASE_URL}/github/pkce/state`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code_challenge: codeChallenge }),
        });
        if (!res.ok) return;
        const { state } = await res.json();
        sessionStorage.setItem('oauth_cv', codeVerifier);
        const siteUrl = import.meta.env.VITE_SITE_URL || window.location.origin;
        const redirectUri = encodeURIComponent(`${siteUrl}/auth/github/callback`);
        window.location.href = `https://github.com/login/oauth/authorize?client_id=Ov23li9feGBY4uoDs8du&scope=repo&state=${encodeURIComponent(state)}&redirect_uri=${redirectUri}`;
    };

    const readFile = (file: File): Promise<BatchFileItem> =>
        new Promise((resolve, reject) => {
            const r = new FileReader();
            r.onload = () => resolve({ filename: file.name, code: r.result as string, size: file.size });
            r.onerror = reject;
            r.readAsText(file);
        });

    const handleFiles = useCallback(async (fileList: FileList | File[]) => {
        const validExts = ['.py','.js','.ts','.tsx','.jsx','.java','.c','.cpp','.h','.hpp','.cs','.go','.rb','.php','.rs','.swift','.kt','.scala','.sh','.sql','.html','.css','.vue','.svelte'];
        const valid = Array.from(fileList).filter(f => {
            const ext = '.' + f.name.split('.').pop()?.toLowerCase();
            return validExts.includes(ext) && f.size < 50000;
        });
        const read = await Promise.all(valid.map(readFile));
        setFiles(prev => {
            const existing = new Set(prev.map(f => f.filename));
            return [...prev, ...read.filter(f => !existing.has(f.filename))];
        });
    }, []);

    const handleDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault(); setDragActive(false);
        const items = Array.from(e.dataTransfer.items);
        const fs = items.filter(i => i.kind === 'file').map(i => i.getAsFile()).filter(Boolean) as File[];
        handleFiles(fs);
    }, [handleFiles]);

    const removeFile = (fn: string) => setFiles(prev => prev.filter(f => f.filename !== fn));

    const runBatchScan = async () => {
        if (files.length === 0) return;
        setScanState('scanning'); setResults([]); setSummary(null);
        try {
            const res = await fetch(`${API_BASE_URL}/batch-scan`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ files: files.map(f => ({ filename: f.filename, code: f.code })) })
            });
            if (!res.ok) throw new Error();
            const data = await res.json();
            setResults(data.results); setSummary(data.summary); setScanState('done');
        } catch { setScanState('idle'); }
    };

    const runGithubScan = async () => {
        if (!repoUrl) return;
        setScanState('scanning'); setResults([]); setSummary(null);
        try {
            const res = await fetch(`${API_BASE_URL}/github-scan`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ repo_url: repoUrl, access_token: githubToken })
            });
            if (!res.ok) throw new Error();
            const data = await res.json();
            setResults(data.results); setSummary(data.summary); setScanState('done');
        } catch { setScanState('idle'); }
    };

    const resetScan = () => { setFiles([]); setResults([]); setSummary(null); setScanState('idle'); };

    const threatCount  = results.filter(r => r.status === 'malicious').length;
    const cleanCount   = results.filter(r => r.status === 'clean').length;

    return (
        <div style={{
            minHeight: '100vh', background: '#000',
            fontFamily: "'JetBrains Mono', monospace",
            color: C.text,
        }}>
            {/* ── TOP STATUS STRIP ─────────────────────────────────────────── */}
            <div style={{
                display: 'flex', alignItems: 'center', height: 36,
                borderBottom: `1px solid ${C.border}`, fontSize: 10, letterSpacing: '0.08em',
            }}>
                <BCell style={{ minWidth: 200, fontWeight: 700 }}>BATCH SCANNER</BCell>
                {scanState === 'idle' && files.length > 0 && (
                    <BCell>{files.length} FILE{files.length !== 1 ? 'S' : ''} QUEUED</BCell>
                )}
                {scanState === 'scanning' && (
                    <BCell style={{ color: C.amber }}>[ SCANNING{files.length > 0 ? ` ${files.length} FILES` : ' REPO'} ]</BCell>
                )}
                {scanState === 'done' && summary && (
                    <>
                        <BCell>GRADE: <span style={{ color: gradeColor(summary.project_grade), fontWeight: 700 }}>{summary.project_grade}</span></BCell>
                        <BCell>SCORE: <span style={{ color: C.text }}>{summary.project_score}/100</span></BCell>
                        <BCell>THREATS: <span style={{ color: threatCount > 0 ? C.red : C.acid, fontWeight: 700 }}>{threatCount}</span></BCell>
                        <BCell>CLEAN: <span style={{ color: C.acid }}>{cleanCount}</span></BCell>
                    </>
                )}
                {oauthError && (
                    <BCell style={{ color: C.red }}>! GITHUB AUTH ERROR</BCell>
                )}
                {scanState === 'done' && (
                    <BCell style={{ marginLeft: 'auto' }}>
                        <button
                            onClick={resetScan}
                            style={{ color: C.sub, background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'inherit', fontSize: 10, letterSpacing: '0.08em' }}
                            onMouseEnter={e => (e.currentTarget.style.color = C.text)}
                            onMouseLeave={e => (e.currentTarget.style.color = C.sub)}
                        >
                            [ NEW SCAN ]
                        </button>
                    </BCell>
                )}
            </div>

            <div style={{ padding: '24px 32px', maxWidth: 1200, margin: '0 auto' }}>

                {/* ── IDLE STATE ─────────────────────────────────────────────── */}
                {scanState === 'idle' && (
                    <>
                        {/* GitHub integration */}
                        <div style={{ border: `1px solid ${C.border}`, marginBottom: 16, padding: 20 }}>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
                                <div>
                                    <div style={{ fontSize: 9, color: C.sub, letterSpacing: '0.12em', marginBottom: 4 }}>GITHUB INTEGRATION</div>
                                    <div style={{ fontSize: 10, color: C.sub, lineHeight: 1.6 }}>
                                        Connect to scan private repos directly from your codebases.
                                    </div>
                                </div>
                                {!githubToken ? (
                                    <button
                                        onClick={handleGithubConnect}
                                        style={{
                                            padding: '8px 20px', background: 'transparent',
                                            border: `1px solid ${C.sub}`, color: C.text,
                                            fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
                                            letterSpacing: '0.1em', cursor: 'pointer', whiteSpace: 'nowrap',
                                            transition: 'border-color 0.15s, color 0.15s',
                                        }}
                                        onMouseEnter={e => { e.currentTarget.style.borderColor = C.acid; e.currentTarget.style.color = C.acid; }}
                                        onMouseLeave={e => { e.currentTarget.style.borderColor = C.sub; e.currentTarget.style.color = C.text; }}
                                    >
                                        [ CONNECT GITHUB ]
                                    </button>
                                ) : (
                                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                                        {isFetchingRepos ? (
                                            <span style={{ fontSize: 9, color: C.sub }}>LOADING REPOS...</span>
                                        ) : (
                                            <select
                                                value={repoUrl}
                                                onChange={e => setRepoUrl(e.target.value)}
                                                style={{
                                                    background: C.dim, border: `1px solid ${C.border}`,
                                                    color: C.text, padding: '6px 10px', outline: 'none',
                                                    fontFamily: "'JetBrains Mono', monospace", fontSize: 9,
                                                    minWidth: 240,
                                                }}
                                            >
                                                <option value="">SELECT REPOSITORY...</option>
                                                {repos.map((r: any) => (
                                                    <option key={r.id} value={r.clone_url}>{r.full_name}{r.private ? ' [PRIVATE]' : ''}</option>
                                                ))}
                                            </select>
                                        )}
                                        <button
                                            onClick={runGithubScan}
                                            disabled={!repoUrl || isFetchingRepos}
                                            style={{
                                                padding: '6px 16px', background: repoUrl ? C.acid : C.dim,
                                                border: `1px solid ${repoUrl ? C.acid : C.muted}`,
                                                color: repoUrl ? '#000' : C.muted,
                                                fontFamily: "'JetBrains Mono', monospace", fontSize: 9,
                                                letterSpacing: '0.1em', cursor: repoUrl ? 'pointer' : 'not-allowed',
                                                fontWeight: 700, transition: 'background 0.15s',
                                            }}
                                        >
                                            [ SCAN REPO ]
                                        </button>
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* Drop zone */}
                        <div
                            onDrop={handleDrop}
                            onDragOver={e => { e.preventDefault(); setDragActive(true); }}
                            onDragLeave={() => setDragActive(false)}
                            onClick={() => inputRef.current?.click()}
                            style={{
                                border: `2px dashed ${dragActive ? C.acid : C.border}`,
                                padding: '48px 32px', textAlign: 'center', cursor: 'pointer',
                                background: dragActive ? 'rgba(173,255,47,0.04)' : 'transparent',
                                transition: 'border-color 0.15s, background 0.15s',
                                marginBottom: 16,
                            }}
                        >
                            <input
                                ref={inputRef} type="file" multiple style={{ display: 'none' }}
                                onChange={e => e.target.files && handleFiles(e.target.files)}
                                accept=".py,.js,.ts,.tsx,.jsx,.java,.c,.cpp,.h,.cs,.go,.rb,.php,.rs,.swift,.kt,.sh,.sql,.html,.css,.vue,.svelte"
                            />
                            <div style={{ fontSize: 32, color: dragActive ? C.acid : C.muted, marginBottom: 12 }}>⬇</div>
                            <div style={{ fontSize: 11, color: dragActive ? C.acid : C.text, letterSpacing: '0.1em', marginBottom: 6, fontWeight: 700 }}>
                                {dragActive ? 'DROP FILES TO QUEUE' : 'DRAG & DROP CODE FILES'}
                            </div>
                            <div style={{ fontSize: 9, color: C.sub }}>
                                .py .js .ts .java .c .cpp .go .rb .php .rs + MORE · MAX 50 FILES · 50KB/FILE
                            </div>
                        </div>

                        {/* Queued files */}
                        {files.length > 0 && (
                            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                                    <span style={{ fontSize: 9, color: C.sub, letterSpacing: '0.12em' }}>
                                        {files.length} FILE{files.length !== 1 ? 'S' : ''} QUEUED
                                    </span>
                                    <div style={{ display: 'flex', gap: 8 }}>
                                        <button
                                            onClick={resetScan}
                                            style={{ fontSize: 9, color: C.sub, background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'inherit', letterSpacing: '0.08em' }}
                                        >
                                            [ CLEAR ]
                                        </button>
                                        <button
                                            onClick={runBatchScan}
                                            style={{
                                                padding: '6px 20px', background: C.acid, border: `1px solid ${C.acid}`,
                                                color: '#000', fontFamily: "'JetBrains Mono', monospace",
                                                fontSize: 10, letterSpacing: '0.1em', cursor: 'pointer',
                                                fontWeight: 700,
                                            }}
                                        >
                                            [ SCAN ALL FILES ]
                                        </button>
                                    </div>
                                </div>
                                <div style={{ border: `1px solid ${C.border}` }}>
                                    {files.map((f, i) => (
                                        <div key={f.filename} style={{
                                            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                            padding: '8px 14px',
                                            borderBottom: i < files.length - 1 ? `1px solid ${C.border}` : 'none',
                                        }}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                                                <span style={{ fontSize: 9, color: C.sub }}>›</span>
                                                <span style={{ fontSize: 10, color: C.text }}>{f.filename}</span>
                                                <span style={{ fontSize: 8, color: C.muted }}>{(f.size / 1024).toFixed(1)} KB</span>
                                            </div>
                                            <button
                                                onClick={() => removeFile(f.filename)}
                                                style={{ color: C.muted, background: 'none', border: 'none', cursor: 'pointer', fontSize: 12 }}
                                                onMouseEnter={e => (e.currentTarget.style.color = C.red)}
                                                onMouseLeave={e => (e.currentTarget.style.color = C.muted)}
                                                aria-label={`Remove ${f.filename}`}
                                                title="Remove file"
                                            >
                                                ×
                                            </button>
                                        </div>
                                    ))}
                                </div>
                            </motion.div>
                        )}
                    </>
                )}

                {/* ── SCANNING STATE ─────────────────────────────────────────── */}
                {scanState === 'scanning' && (
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                        style={{ textAlign: 'center', padding: '80px 0' }}
                    >
                        <div style={{ fontSize: 9, color: C.amber, letterSpacing: '0.12em', lineHeight: 2 }}>
                            <div>{'>'} INITIALIZING BATCH PIPELINE...</div>
                            <div>{'>'} {repoUrl && files.length === 0 ? 'CLONING REPOSITORY...' : `PROCESSING ${files.length} FILES...`}</div>
                            <div>{'>'} RUNNING SOTERIA ML ENSEMBLE...</div>
                            <div style={{ marginTop: 12, color: C.acid }}>
                                {'>'} ANALYZING<span style={{ animation: 'blink 1s step-end infinite' }}>...</span>
                            </div>
                        </div>
                    </motion.div>
                )}

                {/* ── RESULTS STATE ──────────────────────────────────────────── */}
                {scanState === 'done' && summary && (
                    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>

                        {/* Summary row */}
                        <div style={{ display: 'flex', borderBottom: `1px solid ${C.border}`, marginBottom: 20 }}>
                            <SummaryCell label="PROJECT GRADE" value={summary.project_grade} valueStyle={{ color: gradeColor(summary.project_grade), fontSize: 28, fontWeight: 700 }} />
                            <SummaryCell label="SCORE" value={`${summary.project_score}/100`} />
                            <SummaryCell label="FILES SCANNED" value={String(summary.total_files)} />
                            <SummaryCell label="THREATS" value={String(summary.threats)} valueStyle={{ color: summary.threats > 0 ? C.red : C.acid, fontWeight: 700 }} />
                            <SummaryCell label="CLEAN" value={String(summary.clean)} valueStyle={{ color: C.acid }} />
                        </div>

                        {/* Results table */}
                        <div style={{ fontSize: 9, color: C.sub, letterSpacing: '0.12em', marginBottom: 10 }}>
                            PER-FILE RESULTS — {results.length} FILES
                        </div>
                        <div style={{ border: `1px solid ${C.border}` }}>
                            {/* Table header */}
                            <div style={{
                                display: 'grid', gridTemplateColumns: '2fr 80px 90px 80px 90px',
                                padding: '6px 14px', borderBottom: `1px solid ${C.border}`,
                                fontSize: 8, color: C.sub, letterSpacing: '0.1em',
                            }}>
                                <span>FILE</span>
                                <span>LANG</span>
                                <span>RISK</span>
                                <span>CONF</span>
                                <span>VERDICT</span>
                            </div>
                            {results.map((r, i) => (
                                <React.Fragment key={i}>
                                    <div
                                        onClick={() => setExpandedRow(expandedRow === i ? null : i)}
                                        style={{
                                            display: 'grid', gridTemplateColumns: '2fr 80px 90px 80px 90px',
                                            padding: '8px 14px', alignItems: 'center',
                                            borderBottom: `1px solid ${C.border}`,
                                            cursor: 'pointer', transition: 'background 0.1s',
                                            background: expandedRow === i ? C.dim : 'transparent',
                                        }}
                                        onMouseEnter={e => { if (expandedRow !== i) e.currentTarget.style.background = '#080808'; }}
                                        onMouseLeave={e => { if (expandedRow !== i) e.currentTarget.style.background = 'transparent'; }}
                                    >
                                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 10, color: C.text, overflow: 'hidden' }}>
                                            <span style={{ color: C.sub, fontSize: 8 }}>{expandedRow === i ? '▾' : '▸'}</span>
                                            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.filename}</span>
                                        </div>
                                        <span style={{ fontSize: 8, color: C.sub }}>{r.language?.toUpperCase()}</span>
                                        <span style={{ fontSize: 8, color: riskColor(r.risk_level), fontWeight: 700, border: `1px solid ${riskColor(r.risk_level)}`, padding: '1px 4px', display: 'inline-block', opacity: 0.85 }}>
                                            {r.risk_level}
                                        </span>
                                        <span style={{ fontSize: 9, color: C.text }}>{r.confidence}%</span>
                                        <span style={{ fontSize: 9, color: r.status === 'malicious' ? C.red : r.status === 'clean' ? C.acid : C.sub, fontWeight: 700 }}>
                                            {r.status === 'malicious' ? '[ THREAT ]' : r.status === 'clean' ? '[ CLEAN ]' : '[ ERROR ]'}
                                        </span>
                                    </div>

                                    <AnimatePresence>
                                        {expandedRow === i && (
                                            <motion.div
                                                initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }}
                                                exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.15 }}
                                                style={{ overflow: 'hidden', borderBottom: `1px solid ${C.border}`, background: C.dim }}
                                            >
                                                <div style={{ padding: '16px 20px', display: 'grid', gridTemplateColumns: '1fr 220px', gap: 20 }}>
                                                    <div>
                                                        <div style={{ fontSize: 8, color: C.sub, letterSpacing: '0.1em', marginBottom: 8 }}>ANALYSIS</div>
                                                        <div style={{ fontSize: 9, color: C.sub, lineHeight: 1.7 }}>{r.message}</div>
                                                        <div style={{
                                                            marginTop: 10, padding: '8px 12px', fontSize: 8, lineHeight: 1.6,
                                                            border: `1px solid ${r.status === 'malicious' ? 'rgba(255,49,49,0.3)' : 'rgba(173,255,47,0.2)'}`,
                                                            background: r.status === 'malicious' ? 'rgba(255,49,49,0.05)' : 'rgba(173,255,47,0.03)',
                                                            color: r.status === 'malicious' ? '#FF8080' : '#A0D080',
                                                        }}>
                                                            {r.status === 'malicious'
                                                                ? '! ACTION REQUIRED — Review and address the identified vulnerability.'
                                                                : '✓ PASSED — No security issues found in this file.'}
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <div style={{ fontSize: 8, color: C.sub, letterSpacing: '0.1em', marginBottom: 8 }}>FILE INFO</div>
                                                        {[
                                                            { k: 'LANGUAGE', v: r.language },
                                                            { k: 'CONFIDENCE', v: `${r.confidence}%` },
                                                            { k: 'RISK LEVEL', v: r.risk_level },
                                                            ...(r.nodes_scanned ? [{ k: 'NODES', v: String(r.nodes_scanned) }] : []),
                                                        ].map(({ k, v }) => (
                                                            <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '3px 0', fontSize: 9 }}>
                                                                <span style={{ color: C.sub }}>{k}</span>
                                                                <span style={{ color: C.text }}>{v}</span>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            </motion.div>
                                        )}
                                    </AnimatePresence>
                                </React.Fragment>
                            ))}
                        </div>
                    </motion.div>
                )}
            </div>

            <style>{`
                @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0; } }
            `}</style>
        </div>
    );
}

function BCell({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
    return (
        <div style={{
            display: 'flex', alignItems: 'center', height: '100%',
            padding: '0 14px', borderRight: '1px solid #1E1E1E',
            fontSize: 10, color: '#707070', letterSpacing: '0.08em',
            gap: 6, whiteSpace: 'nowrap', ...style,
        }}>
            {children}
        </div>
    );
}

function SummaryCell({ label, value, valueStyle }: { label: string; value: string; valueStyle?: React.CSSProperties }) {
    return (
        <div style={{ flex: 1, padding: '16px 20px', borderRight: '1px solid #1E1E1E' }}>
            <div style={{ fontSize: 8, color: '#404040', letterSpacing: '0.12em', marginBottom: 6 }}>{label}</div>
            <div style={{ fontSize: 18, color: '#E5E5E5', fontFamily: "'JetBrains Mono', monospace", ...valueStyle }}>{value}</div>
        </div>
    );
}
