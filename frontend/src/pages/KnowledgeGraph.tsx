import { useRef, useEffect, useState, useCallback } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { motion, AnimatePresence } from 'framer-motion';

interface HistoryItem {
    id: string; timestamp: string; verdict: 'malicious' | 'clean';
    riskLevel: string; codePreview: string; fullCode: string;
    language?: string; confidence?: number; nodesScanned?: number;
}
interface GraphNode {
    id: string; label: string; group: string; color: string;
    size: number; type: 'hub' | 'scan' | 'verdict' | 'language';
    data?: HistoryItem;
}
interface GraphLink { source: string; target: string; color: string; }

const ACID   = '#FFFFFF';
const RED    = '#FF3131';
const AMBER  = '#FF8C00';
const BORDER = '#1E1E1E';

const RISK_COLORS: Record<string, string> = {
    CRITICAL: RED, HIGH: AMBER, MEDIUM: '#FFD700', LOW: ACID, INVALID: '#404040',
};

function buildGraphFromHistory(history: HistoryItem[]): { nodes: GraphNode[]; links: GraphLink[] } {
    if (history.length === 0) return { nodes: [], links: [] };
    const nodes: GraphNode[] = [];
    const links: GraphLink[] = [];
    const langSet = new Set<string>();
    const verdictSet = new Set<string>();

    nodes.push({ id: 'hub', label: 'SOTERIA', group: 'hub', color: ACID, size: 14, type: 'hub' });

    for (const item of history) {
        if (!verdictSet.has(item.verdict)) {
            verdictSet.add(item.verdict);
            nodes.push({ id: `verdict-${item.verdict}`, label: item.verdict === 'malicious' ? 'THREATS' : 'CLEAN', group: 'verdict', color: item.verdict === 'malicious' ? RED : ACID, size: 10, type: 'verdict' });
            links.push({ source: 'hub', target: `verdict-${item.verdict}`, color: (item.verdict === 'malicious' ? RED : ACID) + '30' });
        }
    }
    for (const item of history) {
        const lang = item.language || 'unknown';
        if (!langSet.has(lang)) {
            langSet.add(lang);
            nodes.push({ id: `lang-${lang}`, label: lang.toUpperCase(), group: 'language', color: '#5599FF', size: 8, type: 'language' });
            links.push({ source: 'hub', target: `lang-${lang}`, color: '#5599FF30' });
        }
    }
    for (const item of history) {
        const lang = item.language || 'unknown';
        const riskColor = RISK_COLORS[item.riskLevel] || '#404040';
        nodes.push({ id: `scan-${item.id}`, label: item.codePreview, group: 'scan', color: riskColor, size: 5, type: 'scan', data: item });
        links.push({ source: `verdict-${item.verdict}`, target: `scan-${item.id}`, color: riskColor + '30' });
        links.push({ source: `lang-${lang}`, target: `scan-${item.id}`, color: '#5599FF20' });
    }
    return { nodes, links };
}

export default function KnowledgeGraph() {
    const fgRef = useRef<any>(null);
    const [history, setHistory] = useState<HistoryItem[]>([]);
    const [graphData, setGraphData] = useState<{ nodes: GraphNode[]; links: GraphLink[] }>({ nodes: [], links: [] });
    const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

    useEffect(() => {
        const saved = localStorage.getItem('soteria_audit_v2');
        if (saved) { try { setHistory(JSON.parse(saved)); } catch { } }
    }, []);

    useEffect(() => { setGraphData(buildGraphFromHistory(history)); }, [history]);

    useEffect(() => {
        if (graphData.nodes.length > 0) setTimeout(() => fgRef.current?.zoomToFit(400, 80), 500);
    }, [graphData]);

    const handleNodeClick = useCallback((node: any) => {
        const n = node as GraphNode;
        if (n.type === 'scan') setSelectedNode(n);
        fgRef.current?.centerAt(node.x, node.y, 800);
        fgRef.current?.zoom(5, 800);
    }, []);

    const nodeCanvasObject = useCallback((node: any, ctx: CanvasRenderingContext2D) => {
        const n = node as GraphNode & { x: number; y: number };
        const size = n.size || 5;
        // Hard square node for terminal aesthetic
        ctx.shadowColor = n.type === 'hub' ? ACID : 'transparent';
        ctx.shadowBlur = n.type === 'hub' ? 12 : 0;
        ctx.fillStyle = n.color + (n.type === 'scan' ? '80' : 'CC');
        ctx.fillRect(n.x - size, n.y - size, size * 2, size * 2);
        ctx.strokeStyle = n.color;
        ctx.lineWidth = n.type === 'hub' ? 2 : 1;
        ctx.strokeRect(n.x - size, n.y - size, size * 2, size * 2);
        ctx.shadowBlur = 0;
        if (n.type !== 'scan') {
            ctx.font = `bold ${n.type === 'hub' ? 5 : 4}px 'JetBrains Mono', monospace`;
            ctx.textAlign = 'center';
            ctx.fillStyle = '#E5E5E5';
            ctx.fillText(n.label, n.x, n.y + size + 8);
        }
    }, []);

    const refreshGraph = () => {
        const saved = localStorage.getItem('soteria_audit_v2');
        if (saved) { try { setHistory(JSON.parse(saved)); } catch { } }
    };

    const totalScans = history.length;
    const threats    = history.filter(h => h.verdict === 'malicious').length;
    const languages  = new Set(history.map(h => h.language || 'unknown')).size;

    return (
        <div style={{ minHeight: '100vh', background: '#030712', fontFamily: "'JetBrains Mono', monospace", position: 'relative', overflow: 'hidden' }}>

            {/* ── TOP STATUS STRIP ─────────────────────────────────────────── */}
            <div style={{
                position: 'absolute', top: 0, left: 0, right: 0, zIndex: 20,
                display: 'flex', alignItems: 'center', height: 36,
                borderBottom: `1px solid ${BORDER}`, background: 'rgba(0,0,0,0.9)',
                fontSize: 10, letterSpacing: '0.08em',
            }}>
                <GCell style={{ fontWeight: 700 }}>INTELLIGENCE MAP</GCell>
                <GCell>NODES: <span style={{ color: '#E5E5E5' }}>{graphData.nodes.length}</span></GCell>
                <GCell>SCANS: <span style={{ color: '#E5E5E5' }}>{totalScans}</span></GCell>
                <GCell>THREATS: <span style={{ color: threats > 0 ? RED : ACID, fontWeight: threats > 0 ? 700 : 400 }}>{threats}</span></GCell>
                <GCell>LANGS: <span style={{ color: '#E5E5E5' }}>{languages}</span></GCell>
                <GCell style={{ marginLeft: 'auto' }}>
                    <button
                        onClick={refreshGraph}
                        style={{ color: '#707070', background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'inherit', fontSize: 10, letterSpacing: '0.08em' }}
                        onMouseEnter={e => (e.currentTarget.style.color = '#E5E5E5')}
                        onMouseLeave={e => (e.currentTarget.style.color = '#707070')}
                    >
                        [ REFRESH ]
                    </button>
                </GCell>
            </div>

            {/* Controls */}
            <div style={{ position: 'absolute', bottom: 20, right: 20, zIndex: 20, display: 'flex', flexDirection: 'column', gap: 4 }}>
                {[
                    { label: '+', action: () => fgRef.current?.zoom(fgRef.current.zoom() * 1.5, 400) },
                    { label: '−', action: () => fgRef.current?.zoom(fgRef.current.zoom() / 1.5, 400) },
                    { label: '⊞', action: () => fgRef.current?.zoomToFit(400, 80) },
                ].map(({ label, action }) => (
                    <button
                        key={label}
                        onClick={action}
                        style={{
                            width: 32, height: 32, background: 'rgba(0,0,0,0.85)',
                            border: `1px solid ${BORDER}`, color: '#707070',
                            fontFamily: "'JetBrains Mono', monospace", fontSize: 14, cursor: 'pointer',
                            transition: 'color 0.1s, border-color 0.1s',
                        }}
                        onMouseEnter={e => { e.currentTarget.style.color = ACID; e.currentTarget.style.borderColor = ACID; }}
                        onMouseLeave={e => { e.currentTarget.style.color = '#707070'; e.currentTarget.style.borderColor = BORDER; }}
                    >
                        {label}
                    </button>
                ))}
            </div>

            {/* Legend */}
            <div style={{ position: 'absolute', bottom: 20, left: 20, zIndex: 20, fontSize: 8, letterSpacing: '0.1em', background: 'rgba(0,0,0,0.85)', border: `1px solid ${BORDER}`, padding: '12px 14px' }}>
                <div style={{ color: '#404040', marginBottom: 6 }}>RISK LEVELS</div>
                {Object.entries(RISK_COLORS).map(([level, color]) => (
                    <div key={level} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                        <div style={{ width: 8, height: 8, background: color }} />
                        <span style={{ color: '#707070' }}>{level}</span>
                    </div>
                ))}
            </div>

            {/* Node detail panel */}
            <AnimatePresence>
                {selectedNode?.data && (
                    <motion.div
                        initial={{ opacity: 0, x: 40 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 40 }}
                        style={{
                            position: 'absolute', top: 56, right: 20, zIndex: 30, width: 320,
                            background: 'rgba(0,0,0,0.95)', border: `1px solid ${BORDER}`,
                        }}
                    >
                        {/* Header */}
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', borderBottom: `1px solid ${BORDER}` }}>
                            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                                <span style={{ fontSize: 8, color: RISK_COLORS[selectedNode.data.riskLevel] || '#404040', border: `1px solid ${RISK_COLORS[selectedNode.data.riskLevel] || '#404040'}`, padding: '1px 4px', fontWeight: 700 }}>
                                    {selectedNode.data.riskLevel}
                                </span>
                                {selectedNode.data.language && (
                                    <span style={{ fontSize: 8, color: '#5599FF' }}>{selectedNode.data.language.toUpperCase()}</span>
                                )}
                            </div>
                            <button onClick={() => setSelectedNode(null)} style={{ color: '#404040', background: 'none', border: 'none', cursor: 'pointer', fontSize: 14 }}
                                onMouseEnter={e => (e.currentTarget.style.color = '#E5E5E5')}
                                onMouseLeave={e => (e.currentTarget.style.color = '#404040')}
                                aria-label="Close node details"
                                title="Close"
                            >×</button>
                        </div>
                        {/* Verdict */}
                        <div style={{ padding: '10px 14px', borderBottom: `1px solid ${BORDER}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontSize: 11, color: selectedNode.data.verdict === 'malicious' ? RED : ACID, fontWeight: 700 }}>
                                {selectedNode.data.verdict === 'malicious' ? '[ THREAT DETECTED ]' : '[ CLEAN ]'}
                            </span>
                            <span style={{ fontSize: 8, color: '#404040' }}>{selectedNode.data.timestamp}</span>
                        </div>
                        {/* Confidence */}
                        {selectedNode.data.confidence != null && (
                            <div style={{ padding: '8px 14px', borderBottom: `1px solid ${BORDER}` }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 8, color: '#707070', marginBottom: 4 }}>
                                    <span>CONFIDENCE</span>
                                    <span style={{ color: '#E5E5E5' }}>{selectedNode.data.confidence}%</span>
                                </div>
                                <div style={{ height: 2, background: '#1A1A1A' }}>
                                    <div style={{ height: '100%', width: `${selectedNode.data.confidence}%`, background: ACID }} />
                                </div>
                            </div>
                        )}
                        {/* Code preview */}
                        <div style={{ padding: '10px 14px', maxHeight: 200, overflow: 'auto' }}>
                            <div style={{ fontSize: 8, color: '#404040', letterSpacing: '0.1em', marginBottom: 6 }}>CODE PREVIEW</div>
                            <pre style={{ fontSize: 9, color: '#707070', fontFamily: "'JetBrains Mono', monospace", whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0 }}>
                                {selectedNode.data.fullCode.substring(0, 500)}
                                {selectedNode.data.fullCode.length > 500 && '\n\n... (truncated)'}
                            </pre>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Empty state */}
            {totalScans === 0 && (
                <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 10 }}>
                    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} style={{ textAlign: 'center' }}>
                        <div style={{ fontSize: 9, color: '#404040', letterSpacing: '0.12em', lineHeight: 2.2 }}>
                            <div>{'>'} NO SCAN HISTORY FOUND</div>
                            <div>{'>'} ANALYZE CODE IN THE SCANNER TO BUILD YOUR INTELLIGENCE MAP</div>
                            <div>{'>'} EACH SCAN CREATES A NODE — PATTERNS EMERGE ACROSS LANGUAGES AND RISK LEVELS</div>
                        </div>
                    </motion.div>
                </div>
            )}

            {/* Graph canvas */}
            {totalScans > 0 && (
                <div style={{ width: '100%', height: '100%', paddingTop: 36 }}>
                    <ForceGraph2D
                        ref={fgRef}
                        graphData={graphData}
                        nodeLabel={(node: any) => {
                            const n = node as GraphNode;
                            if (n.type === 'scan' && n.data) return `${n.data.riskLevel} | ${n.data.codePreview}`;
                            return n.label;
                        }}
                        nodeCanvasObject={nodeCanvasObject}
                        linkColor={(link: any) => link.color || 'rgba(255,255,255,0.05)'}
                        linkWidth={1}
                        backgroundColor="#000000"
                        enableNodeDrag={true}
                        d3AlphaDecay={0.02}
                        d3VelocityDecay={0.08}
                        onNodeClick={handleNodeClick}
                    />
                </div>
            )}
        </div>
    );
}

function GCell({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
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
