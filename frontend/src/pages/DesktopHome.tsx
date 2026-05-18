/**
 * DesktopHome — Soteria OS Dashboard
 * Design: Weaponized Minimalism · JetBrains Mono · 0px radius · White accent #FFFFFF
 * Layout: Fixed sidebar + status strip + dual-panel command view
 */
import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import {
  Download, Check, GitCompare, X, Bell, BellOff,
  ChevronRight, Activity, Layers, Brain
} from 'lucide-react';
import { useGame } from '@/context/GameContext';
import { useAuth } from '@/context/AuthContext';
import { API_BASE_URL } from '@/lib/api';
import AppSidebar from '@/components/AppSidebar';

/* ─── Types ──────────────────────────────────────────────────────────── */
interface ContribStats {
  total: number;
  malicious: number;
  clean: number;
  by_language: { language: string; count: number }[];
  last_collected: string | null;
}

interface DriftData {
  status: 'ok' | 'insufficient_data';
  total_samples?: number;
  baseline_samples?: number;
  recent_window?: number;
  kl_divergence?: number;
  drift_alert?: boolean;
  recent_mean?: number;
  baseline_mean?: number;
  samples?: number;
}

interface SecurityScoreData {
  score: number;
  grade: string;
  total_scans: number;
  threats: number;
  clean: number;
  languages: Record<string, number>;
  risk_distribution: Record<string, number>;
  daily_trend: { day: string; total: number; threats: number; avg_confidence: number }[];
  recent_scans?: {
    id: number; timestamp: string; language: string;
    risk_level: string; confidence: number; malicious: number; reason: string;
  }[];
}

/* ─── Design tokens ──────────────────────────────────────────────────── */
import { COLORS } from '../theme/colors';
const C = {
  acid:  COLORS.acid,
  red:   COLORS.red,
  amber: COLORS.orange,
  gold:  '#FFD700',
  dim:   COLORS.surface2,
  mid:   COLORS.border2,
  muted: COLORS.muted,
  faint: COLORS.surface,
  text:  COLORS.text,
  sub:   COLORS.sub,
} as const;

const MONO: React.CSSProperties = { fontFamily: "'JetBrains Mono', monospace" };

/* ─── Risk helpers ───────────────────────────────────────────────────── */
function riskColor(r: string): string {
  return r === 'CRITICAL' ? C.red : r === 'HIGH' ? C.amber : r === 'MEDIUM' ? C.gold : C.acid;
}
function riskLabel(r: string): string {
  return r === 'CRITICAL' ? 'CRIT' : r === 'HIGH' ? 'HIGH' : r === 'MEDIUM' ? 'MED' : 'PASS';
}

/* ─── ASCII bar (10 chars wide) ──────────────────────────────────────── */
function AsciiBar({ value, max, color }: { value: number; max: number; color: string }) {
  const filled = max > 0 ? Math.round((value / max) * 10) : 0;
  return (
    <span style={{ ...MONO, letterSpacing: '0.05em', color: C.faint }}>
      <span style={{ color }}>{('█').repeat(filled)}</span>
      {('░').repeat(10 - filled)}
    </span>
  );
}

/* ─── Sparkline SVG ──────────────────────────────────────────────────── */
function Sparkline({ data, color }: { data: number[]; color: string }) {
  if (data.length < 2) return <span style={{ color: C.faint, ...MONO }}>─ ─ ─ ─ ─</span>;
  const W = 72, H = 18;
  const max = Math.max(...data, 1);
  const pts = data.map((v, i) =>
    `${(i / (data.length - 1)) * W},${H - (v / max) * (H - 2) - 1}`
  ).join(' ');
  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: 72, height: 18, display: 'inline-block', verticalAlign: 'middle' }}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5"
        strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/* ─── Status cell ────────────────────────────────────────────────────── */
function StatusCell({ label, value, accent }: { label: string; value: string | number; accent?: string }) {
  return (
    <div className="flex items-center gap-3 px-5 h-full" style={{ borderRight: `1px solid ${C.dim}` }}>
      <span className="text-[9px] tracking-[0.18em]" style={{ color: C.muted }}>{label}</span>
      <span className="text-[11px] font-bold tracking-[0.1em]" style={{ color: accent ?? C.text, ...MONO }}>{value}</span>
    </div>
  );
}

/* ─── Panel header ───────────────────────────────────────────────────── */
function PanelHeader({ children }: { children: React.ReactNode }) {
  return (
    <div className="px-5 py-3 flex items-center justify-between flex-shrink-0"
      style={{ borderBottom: `1px solid ${C.dim}` }}>
      {children}
    </div>
  );
}

/* ─── Metric row ─────────────────────────────────────────────────────── */
function MetricRow({ label, value, color }: { label: string; value: number | string; color?: string }) {
  return (
    <div className="flex items-center justify-between px-5 py-2" style={{ borderBottom: `1px solid ${C.faint}` }}>
      <span className="text-[10px] tracking-[0.12em]" style={{ color: C.muted }}>{label}</span>
      <span className="text-[13px] font-bold tabular-nums" style={{ color: color ?? C.text, ...MONO }}>{value}</span>
    </div>
  );
}

/* ─── Scan row ───────────────────────────────────────────────────────── */
function ScanRow({
  scan, selected, onToggle,
}: {
  scan: NonNullable<SecurityScoreData['recent_scans']>[0];
  selected: boolean;
  onToggle: () => void;
}) {
  const rc = riskColor(scan.risk_level);
  const ts = new Date(scan.timestamp);
  const age = (() => {
    const h = Math.floor((Date.now() - ts.getTime()) / 3600000);
    return h < 1 ? '<1h' : h < 24 ? `${h}h` : `${Math.floor(h / 24)}d`;
  })();

  return (
    <motion.div
      initial={{ opacity: 0, x: -4 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.15 }}
      onClick={onToggle}
      className="flex items-center gap-3 px-5 py-2.5 cursor-pointer transition-colors duration-100"
      style={{
        borderBottom: `1px solid ${C.faint}`,
        background: selected ? '#0D1829' : 'transparent',
      }}
      onMouseEnter={e => { if (!selected) (e.currentTarget as HTMLDivElement).style.background = '#060E1E'; }}
      onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.background = selected ? '#0D1829' : 'transparent'; }}>

      {/* Selection indicator */}
      <span className="w-2 h-2 flex-shrink-0 flex items-center justify-center" style={{ ...MONO }}>
        {selected
          ? <span className="text-[10px] font-bold" style={{ color: C.acid }}>✓</span>
          : <span style={{ color: C.faint }}>·</span>}
      </span>

      {/* ID */}
      <span className="text-[9px] tabular-nums w-10 flex-shrink-0" style={{ color: C.muted, ...MONO }}>
        #{scan.id}
      </span>

      {/* Age */}
      <span className="text-[9px] w-8 flex-shrink-0 tabular-nums" style={{ color: C.muted, ...MONO }}>
        {age}
      </span>

      {/* Risk badge */}
      <span className="text-[9px] font-bold tracking-widest w-11 flex-shrink-0" style={{ color: rc, ...MONO }}>
        [{riskLabel(scan.risk_level)}]
      </span>

      {/* Language */}
      <span className="text-[9px] w-14 flex-shrink-0 truncate" style={{ color: C.sub, ...MONO }}>
        {scan.language}
      </span>

      {/* Confidence bar */}
      <div className="flex-1 flex items-center gap-2 min-w-0">
        <div className="flex-1 h-px relative" style={{ background: C.faint }}>
          <div className="absolute top-0 left-0 h-full" style={{ width: `${scan.confidence}%`, background: rc, opacity: 0.7 }} />
        </div>
        <span className="text-[9px] tabular-nums flex-shrink-0" style={{ color: C.muted, ...MONO }}>
          {scan.confidence}%
        </span>
      </div>
    </motion.div>
  );
}

/* ─── Loading skeleton ───────────────────────────────────────────────── */
function SkeletonRow() {
  return (
    <div className="flex items-center gap-3 px-5 py-2.5" style={{ borderBottom: `1px solid ${C.faint}` }}>
      <div className="w-2 h-2" style={{ background: C.faint }} />
      <div className="h-2 w-8" style={{ background: '#0D0D0D' }} />
      <div className="h-2 flex-1" style={{ background: '#0D0D0D' }} />
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════════════
   MAIN COMPONENT
══════════════════════════════════════════════════════════════════════ */
export default function DesktopHome() {
  const navigate = useNavigate();
  const { key: locationKey } = useLocation();
  const { xp, level, streak } = useGame();
  const { token, user } = useAuth();

  const [data, setData] = useState<SecurityScoreData | null>(null);
  const [loading, setLoading] = useState(true);
  const [compareIds, setCompareIds] = useState<number[]>([]);
  const [compareResult, setCompareResult] = useState<any>(null);
  const [compareLoading, setCompareLoading] = useState(false);
  const [compareError, setCompareError] = useState<string | null>(null);
  const [webhookUrl, setWebhookUrl] = useState('');
  const [webhookSaved, setWebhookSaved] = useState(false);
  const [showWebhook, setShowWebhook] = useState(false);
  const [contrib, setContrib] = useState<ContribStats | null>(null);
  const [drift, setDrift] = useState<DriftData | null>(null);

  /* Fetch score */
  useEffect(() => {
    const timeout = setTimeout(() => setLoading(false), 5000);
    (async () => {
      try {
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;
        const res = await fetch(`${API_BASE_URL}/security-score`, { headers });
        if (res.ok) setData(await res.json());
      } catch {}
      finally { setLoading(false); clearTimeout(timeout); }
    })();
    return () => clearTimeout(timeout);
  }, [token, locationKey]);

  /* Fetch webhook */
  useEffect(() => {
    if (!token) return;
    fetch(`${API_BASE_URL}/api/settings/webhook`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.json()).then(d => setWebhookUrl(d.webhook_url || '')).catch(() => {});
  }, [token]);

  /* Fetch personal training contributions */
  useEffect(() => {
    if (!token) return;
    fetch(`${API_BASE_URL}/api/training-data/stats/me`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.ok ? r.json() : null)
      .then(d => d && setContrib(d))
      .catch(() => {});
  }, [token]);

  /* Fetch model drift */
  useEffect(() => {
    if (!token) return;
    fetch(`${API_BASE_URL}/api/model/drift`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.ok ? r.json() : null)
      .then(d => d && setDrift(d))
      .catch(() => {});
  }, [token]);

  /* Compare */
  const toggleCompare = (id: number) => {
    setCompareResult(null); setCompareError(null);
    setCompareIds(p => p.includes(id) ? p.filter(x => x !== id) : p.length >= 2 ? [p[1], id] : [...p, id]);
  };
  const handleCompare = async () => {
    if (compareIds.length !== 2 || !token) return;
    setCompareLoading(true); setCompareResult(null); setCompareError(null);
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/scan-history/compare?id1=${compareIds[0]}&id2=${compareIds[1]}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      const d = await res.json();
      res.ok ? setCompareResult(d) : setCompareError(d.error || 'Compare failed');
    } catch { setCompareError('Network error'); }
    finally { setCompareLoading(false); }
  };

  /* Export CSV */
  const handleExportCSV = async () => {
    if (!token) return;
    const res = await fetch(`${API_BASE_URL}/api/scan-history/export`, { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) return;
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `soteria_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
  };

  /* Save webhook */
  const handleSaveWebhook = async () => {
    if (!token) return;
    await fetch(`${API_BASE_URL}/api/settings/webhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ webhook_url: webhookUrl }),
    });
    setWebhookSaved(true);
    setTimeout(() => setWebhookSaved(false), 2000);
  };

  /* Computed values */
  const total = data?.total_scans ?? 0;
  const threats = data?.threats ?? 0;
  const clean = data?.clean ?? 0;
  const cleanRate = total > 0 ? ((clean / total) * 100).toFixed(1) : '—';
  const grade = data?.grade ?? '—';
  const score = data?.score ?? 0;
  const gradeColor = { A: C.acid, B: '#4ADE80', C: C.gold, D: C.amber, F: C.red }[grade] ?? C.muted;

  const maxLang = data ? Math.max(...Object.values(data.languages), 1) : 1;
  const maxRisk = data ? Math.max(...Object.values(data.risk_distribution), 1) : 1;
  const trendData = data?.daily_trend?.map(d => d.total) ?? [];

  return (
    <div className="h-screen flex overflow-hidden" style={{ background: '#030712', ...MONO, color: C.text }}>
      <AppSidebar />

      {/* ── Main content area ── */}
      <div className="flex-1 flex flex-col overflow-hidden" style={{ marginLeft: '12rem' }}>

        {/* ══ STATUS STRIP ══════════════════════════════════════════════════ */}
        <header className="flex items-center h-9 flex-shrink-0 sticky top-0 z-40"
          style={{ background: '#030712', borderBottom: `1px solid ${C.dim}` }}>

          <div className="flex items-center gap-2 px-5 h-full" style={{ borderRight: `1px solid ${C.dim}` }}>
            <span className="w-1.5 h-1.5 animate-pulse flex-shrink-0"
              style={{ background: loading ? C.amber : C.acid, borderRadius: 0 }} />
            <span className="text-[9px] font-bold tracking-[0.2em]"
              style={{ color: loading ? C.amber : C.acid }}>
              {loading ? 'LOADING' : 'LIVE'}
            </span>
          </div>

          <StatusCell label="SCANS" value={loading ? '...' : total.toLocaleString()} />
          <StatusCell label="THREATS" value={loading ? '...' : threats} accent={threats > 0 ? C.red : C.muted} />
          <StatusCell label="CLEAN RATE" value={loading ? '...' : `${cleanRate}%`} accent={C.acid} />
          <StatusCell label="GRADE" value={loading ? '...' : grade} accent={gradeColor} />
          <StatusCell label="XP" value={`${xp.toLocaleString()} · ${level}`} accent={C.gold} />

          <div className="flex items-center gap-2 px-5 ml-auto h-full" style={{ borderLeft: `1px solid ${C.dim}` }}>
            <span className="text-[9px] tracking-[0.12em]" style={{ color: C.muted }}>
              {user?.name ?? user?.email ?? 'OPERATOR'}
            </span>
          </div>
        </header>

        {/* ══ COMMAND PANELS ════════════════════════════════════════════════ */}
        <div className="flex flex-1 min-h-0">

          {/* ── LEFT PANEL: Security Posture ──────────────────────────────── */}
          <div className="flex flex-col w-64 flex-shrink-0 overflow-y-auto"
            style={{ borderRight: `1px solid ${C.dim}` }}>

            {/* Score */}
            <PanelHeader>
              <span className="text-[10px] font-bold tracking-[0.18em]" style={{ color: C.muted }}>SECURITY POSTURE</span>
              {!loading && (
                <span className="text-[10px] font-bold tracking-[0.06em]" style={{ color: C.sub }}>
                  {score}/100
                </span>
              )}
            </PanelHeader>

            {/* Grade display */}
            <div className="px-5 py-5 flex items-center gap-5"
              style={{ borderBottom: `1px solid ${C.dim}` }}>
              {loading ? (
                <div className="w-16 h-16" style={{ background: '#0A0A0A' }} />
              ) : (
                <div className="flex flex-col items-center justify-center w-16 h-16 flex-shrink-0"
                  style={{ border: `2px solid ${gradeColor}`, position: 'relative' }}>
                  <span className="text-3xl font-black" style={{ color: gradeColor, ...MONO, lineHeight: 1 }}>
                    {grade}
                  </span>
                  {/* Corner marks */}
                  <span className="absolute top-0.5 left-0.5 w-1.5 h-1.5" style={{ borderTop: `1px solid ${gradeColor}`, borderLeft: `1px solid ${gradeColor}`, opacity: 0.6 }} />
                  <span className="absolute bottom-0.5 right-0.5 w-1.5 h-1.5" style={{ borderBottom: `1px solid ${gradeColor}`, borderRight: `1px solid ${gradeColor}`, opacity: 0.6 }} />
                </div>
              )}
              <div className="flex flex-col gap-1.5">
                <div>
                  <div className="text-[9px] tracking-[0.14em]" style={{ color: C.muted }}>7-DAY TREND</div>
                  <div className="mt-1">
                    <Sparkline data={trendData} color={gradeColor} />
                  </div>
                </div>
                <div className="text-[9px]" style={{ color: C.sub }}>
                  {streak}d streak · {level}
                </div>
              </div>
            </div>

            {/* Scan stats */}
            <div style={{ borderBottom: `1px solid ${C.dim}` }}>
              <div className="px-5 pt-3 pb-1">
                <span className="text-[9px] tracking-[0.2em] font-bold" style={{ color: C.faint }}>SCAN STATS</span>
              </div>
              <MetricRow label="TOTAL SCANS" value={loading ? '...' : total.toLocaleString()} />
              <MetricRow label="THREATS FOUND" value={loading ? '...' : threats} color={threats > 0 ? C.red : undefined} />
              <MetricRow label="CLEAN SCANS" value={loading ? '...' : clean.toLocaleString()} color={C.acid} />
              <MetricRow label="CLEAN RATE" value={loading ? '...' : `${cleanRate}%`} color={C.acid} />
            </div>

            {/* Risk distribution */}
            <div style={{ borderBottom: `1px solid ${C.dim}` }}>
              <div className="px-5 pt-3 pb-1">
                <span className="text-[9px] tracking-[0.2em] font-bold" style={{ color: C.faint }}>RISK DISTRIBUTION</span>
              </div>
              {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(r => {
                const count = data?.risk_distribution?.[r] ?? 0;
                const rc = riskColor(r);
                return (
                  <div key={r} className="flex items-center gap-3 px-5 py-1.5"
                    style={{ borderBottom: `1px solid ${C.faint}` }}>
                    <span className="text-[9px] font-bold tracking-widest w-14 flex-shrink-0"
                      style={{ color: rc, ...MONO }}>{r === 'CRITICAL' ? 'CRIT' : r}</span>
                    <AsciiBar value={count} max={maxRisk} color={rc} />
                    <span className="text-[10px] font-bold tabular-nums ml-auto"
                      style={{ color: count > 0 ? rc : C.faint, ...MONO }}>{count}</span>
                  </div>
                );
              })}
            </div>

            {/* Language breakdown */}
            {!loading && data && Object.keys(data.languages).length > 0 && (
              <div style={{ borderBottom: `1px solid ${C.dim}` }}>
                <div className="px-5 pt-3 pb-1">
                  <span className="text-[9px] tracking-[0.2em] font-bold" style={{ color: C.faint }}>LANGUAGES</span>
                </div>
                {Object.entries(data.languages).slice(0, 6).map(([lang, count]) => {
                  const pct = Math.round((count / total) * 100);
                  return (
                    <div key={lang} className="flex items-center gap-3 px-5 py-1.5"
                      style={{ borderBottom: `1px solid ${C.faint}` }}>
                      <span className="text-[9px] font-bold w-16 truncate flex-shrink-0"
                        style={{ color: C.sub, ...MONO }}>{lang}</span>
                      <AsciiBar value={count} max={maxLang} color="#4A4A4A" />
                      <span className="text-[9px] tabular-nums ml-auto"
                        style={{ color: C.muted, ...MONO }}>{pct}%</span>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Training corpus contributions */}
            {contrib && (
              <div style={{ borderBottom: `1px solid ${C.dim}` }}>
                <div className="px-5 pt-3 pb-1 flex items-center justify-between">
                  <span className="text-[9px] tracking-[0.2em] font-bold" style={{ color: C.faint }}>MY CONTRIBUTIONS</span>
                  {contrib.total > 0 && (
                    <span className="text-[8px]" style={{ color: C.sub, ...MONO }}>{contrib.total} SAMPLES</span>
                  )}
                </div>
                {contrib.total === 0 ? (
                  <div className="px-5 py-2 text-[9px]" style={{ color: C.sub, ...MONO }}>
                    Run scans to contribute
                  </div>
                ) : (
                  <>
                    {/* Label balance mini-bars */}
                    <div className="flex items-center gap-3 px-5 py-1.5" style={{ borderBottom: `1px solid ${C.faint}` }}>
                      <span className="text-[9px] font-bold w-14 flex-shrink-0" style={{ color: C.red, ...MONO }}>THREAT</span>
                      <AsciiBar value={contrib.malicious} max={contrib.total} color={C.red} />
                      <span className="text-[9px] tabular-nums ml-auto" style={{ color: C.red, ...MONO }}>{contrib.malicious}</span>
                    </div>
                    <div className="flex items-center gap-3 px-5 py-1.5" style={{ borderBottom: `1px solid ${C.faint}` }}>
                      <span className="text-[9px] font-bold w-14 flex-shrink-0" style={{ color: C.acid, ...MONO }}>CLEAN</span>
                      <AsciiBar value={contrib.clean} max={contrib.total} color={C.acid} />
                      <span className="text-[9px] tabular-nums ml-auto" style={{ color: C.acid, ...MONO }}>{contrib.clean}</span>
                    </div>
                    {/* Per-language breakdown */}
                    {contrib.by_language.slice(0, 4).map(({ language, count }) => (
                      <div key={language} className="flex items-center gap-3 px-5 py-1" style={{ borderBottom: `1px solid ${C.faint}` }}>
                        <span className="text-[8px] font-bold w-14 truncate flex-shrink-0" style={{ color: C.sub, ...MONO }}>{language}</span>
                        <AsciiBar value={count} max={contrib.total} color="#3A3A3A" />
                        <span className="text-[8px] tabular-nums ml-auto" style={{ color: C.sub, ...MONO }}>{count}</span>
                      </div>
                    ))}
                    {contrib.last_collected && (
                      <div className="px-5 py-1.5 text-[8px]" style={{ color: C.sub, ...MONO }}>
                        LAST: {new Date(contrib.last_collected).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {/* Model drift */}
            {drift && (
              <div style={{ borderBottom: `1px solid ${C.dim}` }}>
                <div className="px-5 pt-3 pb-1 flex items-center justify-between">
                  <span className="text-[9px] tracking-[0.2em] font-bold" style={{ color: C.faint }}>MODEL DRIFT</span>
                  <span
                    className="w-1.5 h-1.5 flex-shrink-0"
                    style={{
                      background: drift.status === 'insufficient_data'
                        ? C.faint
                        : drift.drift_alert ? C.red : C.acid,
                      borderRadius: 0,
                    }}
                  />
                </div>
                {drift.status === 'insufficient_data' ? (
                  <div className="px-5 py-2 text-[9px]" style={{ color: C.sub, ...MONO }}>
                    CALIBRATING — {drift.samples ?? 0}/100 SAMPLES
                  </div>
                ) : (
                  <>
                    <div className="flex items-center justify-between px-5 py-1.5" style={{ borderBottom: `1px solid ${C.faint}` }}>
                      <span className="text-[9px] tracking-[0.1em]" style={{ color: C.muted }}>KL DIVERGENCE</span>
                      <span className="text-[10px] font-bold tabular-nums" style={{
                        color: (drift.kl_divergence ?? 0) > 0.5 ? C.red : C.acid,
                        ...MONO,
                      }}>
                        {(drift.kl_divergence ?? 0).toFixed(4)}
                      </span>
                    </div>
                    <div className="flex items-center justify-between px-5 py-1.5" style={{ borderBottom: `1px solid ${C.faint}` }}>
                      <span className="text-[9px] tracking-[0.1em]" style={{ color: C.muted }}>BASELINE → RECENT</span>
                      <span className="text-[9px] tabular-nums" style={{ color: C.sub, ...MONO }}>
                        {(drift.baseline_mean ?? 0).toFixed(4)} → {(drift.recent_mean ?? 0).toFixed(4)}
                      </span>
                    </div>
                    <div className="flex items-center justify-between px-5 py-1.5" style={{ borderBottom: `1px solid ${C.faint}` }}>
                      <span className="text-[9px] tracking-[0.1em]" style={{ color: C.muted }}>SAMPLES</span>
                      <span className="text-[9px] tabular-nums" style={{ color: C.sub, ...MONO }}>
                        {drift.total_samples} (base: {drift.baseline_samples}, win: {drift.recent_window})
                      </span>
                    </div>
                    {drift.drift_alert && (
                      <div className="px-5 py-1.5 text-[9px] font-bold tracking-widest" style={{ color: C.red, ...MONO }}>
                        ⚠ DRIFT ALERT — KL &gt; 0.5
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {/* Quick navigate */}
            <div className="px-4 py-4 flex flex-col gap-2 mt-auto">
              <div className="text-[9px] tracking-[0.2em] px-1 mb-1" style={{ color: C.faint }}>QUICK NAVIGATE</div>
              {[
                { to: '/scanner', label: 'SCANNER', icon: Activity, color: '#6366f1' },
                { to: '/batch',   label: 'BATCH',   icon: Layers,   color: '#8b5cf6' },
                { to: '/engine',  label: 'MODEL LAB',icon: Brain,   color: '#06b6d4' },
              ].map(({ to, label, icon: Icon, color }) => (
                <button key={to} onClick={() => navigate(to)}
                  className="flex items-center justify-between px-3 py-2 text-[10px] font-bold tracking-[0.1em] transition-all duration-100 group"
                  style={{ border: `1px solid ${C.faint}`, background: 'transparent', color: C.muted }}
                  onMouseEnter={e => {
                    (e.currentTarget as HTMLButtonElement).style.borderColor = color;
                    (e.currentTarget as HTMLButtonElement).style.color = C.text;
                  }}
                  onMouseLeave={e => {
                    (e.currentTarget as HTMLButtonElement).style.borderColor = C.faint;
                    (e.currentTarget as HTMLButtonElement).style.color = C.muted;
                  }}>
                  <div className="flex items-center gap-2">
                    <Icon className="w-3 h-3" />
                    {label}
                  </div>
                  <ChevronRight className="w-3 h-3 opacity-40" />
                </button>
              ))}
            </div>
          </div>

          {/* ── RIGHT PANEL: Scan History ─────────────────────────────────── */}
          <div className="flex-1 flex flex-col min-w-0 overflow-hidden">

            {/* Toolbar */}
            <PanelHeader>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-bold tracking-[0.18em]" style={{ color: C.muted }}>SCAN HISTORY</span>
                {data?.recent_scans?.length ? (
                  <span className="text-[9px]" style={{ color: C.faint }}>
                    {compareIds.length > 0 && `${compareIds.length} SELECTED`}
                  </span>
                ) : null}
              </div>

              <div className="flex items-center gap-1">
                {/* Compare */}
                {compareIds.length === 2 && (
                  <button onClick={handleCompare} disabled={compareLoading}
                    className="flex items-center gap-1.5 px-3 py-1 text-[9px] font-bold tracking-widest transition-all duration-100"
                    style={{ border: `1px solid ${C.mid}`, color: '#818cf8', background: 'transparent' }}>
                    <GitCompare className="w-3 h-3" />
                    {compareLoading ? '...' : 'COMPARE'}
                  </button>
                )}
                {compareIds.length > 0 && (
                  <button onClick={() => { setCompareIds([]); setCompareResult(null); }}
                    className="px-2 py-1 text-[9px] transition-colors duration-100"
                    style={{ border: `1px solid ${C.faint}`, color: C.muted, background: 'transparent' }}>
                    <X className="w-3 h-3" />
                  </button>
                )}
                {/* Export */}
                <button onClick={handleExportCSV}
                  className="flex items-center gap-1.5 px-3 py-1 text-[9px] font-bold tracking-widest transition-all duration-100"
                  style={{ border: `1px solid ${C.faint}`, color: C.muted, background: 'transparent' }}
                  onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.color = C.text; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.color = C.muted; }}>
                  <Download className="w-3 h-3" />
                  EXPORT
                </button>
                {/* Webhook toggle */}
                <button onClick={() => setShowWebhook(s => !s)}
                  className="flex items-center gap-1.5 px-3 py-1 text-[9px] font-bold tracking-widest transition-all duration-100"
                  style={{
                    border: `1px solid ${showWebhook ? '#818cf8' : C.faint}`,
                    color: showWebhook ? '#818cf8' : C.muted,
                    background: 'transparent',
                  }}>
                  {webhookUrl ? <Bell className="w-3 h-3" /> : <BellOff className="w-3 h-3" />}
                  WEBHOOK
                </button>
              </div>
            </PanelHeader>

            {/* Webhook drawer */}
            <AnimatePresence>
              {showWebhook && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.15 }}
                  className="overflow-hidden flex-shrink-0"
                  style={{ borderBottom: `1px solid ${C.dim}` }}>
                  <div className="flex items-center gap-3 px-5 py-3">
                    <span className="text-[9px] tracking-[0.14em] flex-shrink-0" style={{ color: C.muted }}>
                      WEBHOOK URL
                    </span>
                    <input
                      type="url"
                      value={webhookUrl}
                      onChange={e => setWebhookUrl(e.target.value)}
                      placeholder="https://hooks.slack.com/..."
                      className="flex-1 bg-transparent text-[10px] outline-none px-3 py-1.5 font-bold"
                      style={{
                        ...MONO,
                        border: `1px solid ${C.dim}`,
                        color: C.text,
                        borderRadius: 0,
                      }}
                    />
                    <button onClick={handleSaveWebhook}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-[9px] font-bold tracking-widest transition-all duration-100"
                      style={{
                        background: webhookSaved ? C.acid : 'transparent',
                        border: `1px solid ${webhookSaved ? C.acid : C.mid}`,
                        color: webhookSaved ? '#000' : C.muted,
                        borderRadius: 0,
                      }}>
                      {webhookSaved ? <><Check className="w-3 h-3" /> SAVED</> : 'SAVE'}
                    </button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Compare result */}
            <AnimatePresence>
              {(compareResult || compareError) && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.15 }}
                  className="overflow-hidden flex-shrink-0"
                  style={{ borderBottom: `1px solid ${C.dim}` }}>
                  <div className="px-5 py-3 text-[10px]"
                    style={{ background: compareError ? '#1A0000' : '#0A0A0A', ...MONO }}>
                    {compareError ? (
                      <span style={{ color: C.red }}>ERR: {compareError}</span>
                    ) : compareResult && (
                      <span style={{ color: '#818cf8' }}>
                        #{compareResult.id1} → #{compareResult.id2} &nbsp;
                        <span style={{ color: riskColor(compareResult.risk_level_2), fontWeight: 700 }}>
                          [{compareResult.risk_level_2}]
                        </span>
                        &nbsp;{compareResult.risk_changed ? '△ RISK CHANGED' : '— NO CHANGE'}
                      </span>
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Column headers */}
            <div className="flex items-center gap-3 px-5 py-2 flex-shrink-0"
              style={{ borderBottom: `1px solid ${C.dim}`, background: '#040A14' }}>
              <span className="w-2 flex-shrink-0" />
              <span className="text-[8px] tracking-[0.2em] w-10 flex-shrink-0" style={{ color: C.faint }}>ID</span>
              <span className="text-[8px] tracking-[0.2em] w-8 flex-shrink-0"  style={{ color: C.faint }}>AGE</span>
              <span className="text-[8px] tracking-[0.2em] w-11 flex-shrink-0" style={{ color: C.faint }}>RISK</span>
              <span className="text-[8px] tracking-[0.2em] w-14 flex-shrink-0" style={{ color: C.faint }}>LANG</span>
              <span className="text-[8px] tracking-[0.2em] flex-1"             style={{ color: C.faint }}>CONFIDENCE</span>
            </div>

            {/* Scan list */}
            <div className="flex-1 overflow-y-auto">
              {loading ? (
                [...Array(8)].map((_, i) => <SkeletonRow key={i} />)
              ) : data?.recent_scans?.length ? (
                data.recent_scans.map((scan, i) => (
                  <ScanRow
                    key={scan.id ?? i}
                    scan={scan}
                    selected={compareIds.includes(scan.id)}
                    onToggle={() => toggleCompare(scan.id)}
                  />
                ))
              ) : (
                /* Empty state — terminal prompt style */
                <div className="flex flex-col justify-center items-start px-5 py-10">
                  <div className="text-[11px]" style={{ color: C.muted, ...MONO }}>
                    <span style={{ color: C.acid }}>soteria@scanner</span>
                    <span style={{ color: C.sub }}>:~$</span>
                    <span className="ml-2 text-[#444]">ls -la ./scan-history</span>
                  </div>
                  <div className="mt-2 text-[11px]" style={{ color: C.faint, ...MONO }}>
                    total 0
                  </div>
                  <div className="mt-3 text-[11px]" style={{ color: C.muted, ...MONO }}>
                    No scans found. Run your first scan to begin.
                  </div>
                  <button onClick={() => navigate('/scanner')}
                    className="mt-5 flex items-center gap-2 px-4 py-2 text-[10px] font-bold tracking-[0.14em] transition-all duration-100"
                    style={{ background: C.acid, color: '#000', border: 'none', borderRadius: 0 }}>
                    → OPEN SCANNER
                  </button>
                </div>
              )}
            </div>

            {/* Bottom info strip */}
            <div className="flex items-center gap-5 px-5 py-2 flex-shrink-0"
              style={{ borderTop: `1px solid ${C.dim}` }}>
              <span className="text-[9px]" style={{ color: C.faint, ...MONO }}>
                {data?.recent_scans?.length ?? 0} RECORDS
              </span>
              <span className="text-[9px]" style={{ color: C.faint, ...MONO }}>
                SELECT 2 TO COMPARE
              </span>
              <span className="text-[9px] ml-auto" style={{ color: C.faint, ...MONO }}>
                KYBER ENGINE v3.0
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
