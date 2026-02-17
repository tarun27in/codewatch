import { useState, useEffect, useMemo } from 'react';
import type { GraphNode, GraphEdge, SecurityGraph, NodeType, Severity } from '../types/graph';
import { NODE_COLORS, NODE_LABELS, SEVERITY_COLORS } from '../types/graph';
import { getSourceContext, lookupCVEs, type CVEEntry, getAIRemediation } from '../api/client';
import { loadAISettings } from './AISettingsModal';

interface Props {
  node: GraphNode;
  graph: SecurityGraph;
  onClose: () => void;
  onNavigate: (node: GraphNode) => void;
}

const icons: Record<NodeType, string> = {
  entry_point: '\u21D2',
  service: '\u2B22',
  external_api: '\u2601',
  data_store: '\u26C1',
  secret: '\u26BF',
  vulnerability: '\u26A0',
  auth_boundary: '\u26D4',
  dependency: '\u25A3',
  file: '\u2B1A',
};

interface SourceLine {
  number: number;
  text: string;
}

export default function DeepDivePanel({ node, graph, onClose, onNavigate }: Props) {
  const [sourceLines, setSourceLines] = useState<SourceLine[] | null>(null);
  const [sourceLoading, setSourceLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'connections' | 'source' | 'related' | 'cves' | 'ai'>('overview');
  const [cveResults, setCveResults] = useState<CVEEntry[] | null>(null);
  const [cveLoading, setCveLoading] = useState(false);
  const [cveError, setCveError] = useState<string | null>(null);
  const [aiResult, setAiResult] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  const color = NODE_COLORS[node.node_type] || '#6B7280';
  const icon = icons[node.node_type] || '';

  // Find upstream/downstream connections
  const { upstream, downstream } = useMemo(() => {
    const up: { edge: GraphEdge; node: GraphNode }[] = [];
    const down: { edge: GraphEdge; node: GraphNode }[] = [];

    for (const edge of graph.edges) {
      if (edge.target === node.id) {
        const sourceNode = graph.nodes.find((n) => n.id === edge.source);
        if (sourceNode) up.push({ edge, node: sourceNode });
      }
      if (edge.source === node.id) {
        const targetNode = graph.nodes.find((n) => n.id === edge.target);
        if (targetNode) down.push({ edge, node: targetNode });
      }
    }
    return { upstream: up, downstream: down };
  }, [node.id, graph]);

  // Find related findings (same file)
  const relatedFindings = useMemo(() => {
    if (!node.file_path) return [];
    return graph.nodes.filter(
      (n) => n.id !== node.id && n.file_path === node.file_path
    );
  }, [node, graph.nodes]);

  // Parse embedded source snippet or fall back to API
  useEffect(() => {
    // Try embedded snippet first
    if (node.source_snippet) {
      const parsed = parseSnippet(node.source_snippet);
      if (parsed.length > 0) {
        setSourceLines(parsed);
        setSourceLoading(false);
        return;
      }
    }

    // Fall back to API if no embedded snippet
    if (!node.file_path || node.line_number <= 0) {
      setSourceLines(null);
      return;
    }
    setSourceLoading(true);
    getSourceContext(node.file_path, node.line_number, 8)
      .then((data) => {
        setSourceLines(data.lines.map((text: string, i: number) => ({
          number: data.start_line + i,
          text,
        })));
      })
      .catch(() => setSourceLines(null))
      .finally(() => setSourceLoading(false));
  }, [node.file_path, node.line_number, node.source_snippet]);

  // Auto-fetch CVEs for dependency nodes
  const isDep = node.node_type === 'dependency';
  useEffect(() => {
    if (!isDep) {
      setCveResults(null);
      setCveError(null);
      return;
    }
    setCveLoading(true);
    setCveError(null);
    const ecosystem = (node.metadata?.ecosystem as string) || 'npm';
    const version = (node.metadata?.version as string) || undefined;
    lookupCVEs(node.label, version, ecosystem)
      .then((res) => setCveResults(res.vulns))
      .catch(() => setCveError('Failed to fetch CVE data'))
      .finally(() => setCveLoading(false));
  }, [node.id, node.label, isDep, node.metadata]);

  // Reset AI state when node changes
  useEffect(() => {
    setAiResult(null);
    setAiError(null);
    setAiLoading(false);
  }, [node.id]);

  const handleAIRemediation = async () => {
    if (aiResult || aiLoading) return;
    const settings = loadAISettings();
    if (!settings || !settings.apiKey) {
      setAiError('Configure AI settings first (gear icon in the top bar)');
      return;
    }
    setAiLoading(true);
    setAiError(null);
    try {
      // Build source context string — prefer embedded snippet, fall back to parsed lines
      const srcCtx = node.source_snippet
        || (sourceLines ? sourceLines.map((l) => `${l.number}: ${l.text}`).join('\n') : undefined);

      const resp = await getAIRemediation({
        provider: settings.provider,
        api_key: settings.apiKey,
        model: settings.model,
        node: {
          label: node.label,
          node_type: node.node_type,
          severity: node.severity,
          description: node.description,
          file_path: node.file_path,
          line_number: node.line_number,
          metadata: node.metadata,
        },
        source_context: srcCtx,
      });
      setAiResult(resp.remediation);
    } catch (err) {
      setAiError(err instanceof Error ? err.message : 'AI remediation failed');
    } finally {
      setAiLoading(false);
    }
  };

  const hasSeverity = !!node.severity;

  const tabs = [
    { id: 'overview' as const, label: 'Overview' },
    { id: 'connections' as const, label: `Connections (${upstream.length + downstream.length})` },
    { id: 'source' as const, label: 'Source' },
    { id: 'related' as const, label: `Related (${relatedFindings.length})` },
    ...(isDep ? [{ id: 'cves' as const, label: `CVEs${cveResults ? ` (${cveResults.length})` : ''}` }] : []),
    ...(hasSeverity ? [{ id: 'ai' as const, label: `AI Fix${aiResult ? ' \u2713' : ''}` }] : []),
  ];

  return (
    <div
      className="w-[480px] h-full border-l z-30 flex flex-col shrink-0"
      style={{ background: 'var(--bg-panel)', borderColor: 'var(--border-primary)' }}
    >
      {/* Header */}
      <div className="shrink-0 border-b px-5 py-4" style={{ borderColor: 'var(--border-primary)', background: 'var(--bg-secondary)' }}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3 min-w-0">
            <span className="text-2xl" style={{ color }}>{icon}</span>
            <div className="min-w-0">
              <h2 className="text-base font-bold truncate" style={{ color: 'var(--text-primary)' }}>
                {node.label}
              </h2>
              <div className="flex items-center gap-2 mt-0.5">
                <span className="text-xs px-2 py-0.5 rounded-full font-medium" style={{ background: `${color}25`, color }}>
                  {NODE_LABELS[node.node_type]}
                </span>
                {node.severity && (
                  <span
                    className="text-[10px] font-bold px-1.5 py-0.5 rounded text-white uppercase"
                    style={{ background: SEVERITY_COLORS[node.severity as Severity] }}
                  >
                    {node.severity}
                  </span>
                )}
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-xl leading-none px-2 py-1 rounded-lg transition-colors shrink-0"
            style={{ color: 'var(--text-muted)' }}
            onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
            onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
          >
            &times;
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="shrink-0 flex border-b px-2" style={{ borderColor: 'var(--border-primary)' }}>
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className="px-3 py-2.5 text-sm font-medium transition-colors relative"
            style={{
              color: activeTab === tab.id ? color : 'var(--text-muted)',
            }}
          >
            {tab.label}
            {activeTab === tab.id && (
              <div className="absolute bottom-0 left-0 right-0 h-0.5" style={{ background: color }} />
            )}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto styled-scrollbar px-5 py-4 space-y-4">
        {activeTab === 'overview' && (
          <>
            {/* Description */}
            {node.description && (
              <Section title="Description">
                <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                  {node.description}
                </p>
              </Section>
            )}

            {/* File path */}
            {node.file_path && (
              <Section title="Location">
                <p className="text-sm font-mono rounded px-3 py-2 break-all" style={{ background: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}>
                  {node.file_path}
                  {node.line_number > 0 && <span className="text-blue-400">:{node.line_number}</span>}
                </p>
              </Section>
            )}

            {/* Inline source preview (compact — 5 lines centered on target) */}
            {sourceLines && sourceLines.length > 0 && node.line_number > 0 && (
              <Section title="Code Preview">
                <SourceCodeBlock lines={sourceLines} targetLine={node.line_number} color={color} maxLines={5} />
                <button
                  onClick={() => setActiveTab('source')}
                  className="mt-1.5 text-xs transition-colors"
                  style={{ color: 'var(--text-muted)' }}
                  onMouseEnter={(e) => (e.currentTarget.style.color = color)}
                  onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-muted)')}
                >
                  View full source context &rarr;
                </button>
              </Section>
            )}

            {/* Metadata */}
            {Object.keys(node.metadata).length > 0 && (
              <Section title="Metadata">
                <div className="space-y-2">
                  {Object.entries(node.metadata).map(([key, value]) => (
                    <div key={key} className="flex items-start gap-3 text-sm">
                      <span className="shrink-0 font-medium min-w-[100px]" style={{ color: 'var(--text-muted)' }}>{key}</span>
                      <span className="break-all" style={{ color: 'var(--text-primary)' }}>
                        {typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value)}
                      </span>
                    </div>
                  ))}
                </div>
              </Section>
            )}

            {/* Quick stats */}
            <Section title="Graph Connections">
              <div className="grid grid-cols-2 gap-3">
                <StatCard label="Upstream" value={upstream.length} color="#3B82F6" />
                <StatCard label="Downstream" value={downstream.length} color="#10B981" />
                <StatCard label="Same File" value={relatedFindings.length} color="#8B5CF6" />
                <StatCard label="Total Edges" value={upstream.length + downstream.length} color="#EAB308" />
              </div>
            </Section>
          </>
        )}

        {activeTab === 'connections' && (
          <>
            {upstream.length > 0 && (
              <Section title={`Upstream (${upstream.length})`}>
                <div className="space-y-1">
                  {upstream.map(({ edge, node: connNode }) => (
                    <ConnectionItem
                      key={edge.id}
                      node={connNode}
                      edgeLabel={edge.label || edge.edge_type}
                      direction="from"
                      onClick={() => onNavigate(connNode)}
                    />
                  ))}
                </div>
              </Section>
            )}

            {downstream.length > 0 && (
              <Section title={`Downstream (${downstream.length})`}>
                <div className="space-y-1">
                  {downstream.map(({ edge, node: connNode }) => (
                    <ConnectionItem
                      key={edge.id}
                      node={connNode}
                      edgeLabel={edge.label || edge.edge_type}
                      direction="to"
                      onClick={() => onNavigate(connNode)}
                    />
                  ))}
                </div>
              </Section>
            )}

            {upstream.length === 0 && downstream.length === 0 && (
              <p className="text-sm text-center py-8" style={{ color: 'var(--text-muted)' }}>
                No connections found for this node.
              </p>
            )}
          </>
        )}

        {activeTab === 'source' && (
          <>
            {sourceLoading ? (
              <div className="flex items-center justify-center py-8">
                <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
              </div>
            ) : sourceLines && sourceLines.length > 0 ? (
              <>
                {/* File info card */}
                {node.file_path && (
                  <div className="rounded-lg border p-3 space-y-1.5" style={{ background: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                    <div className="flex items-center gap-2">
                      <span className="text-sm" style={{ color }}>
                        {icon}
                      </span>
                      <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                        {node.file_path.split('/').pop()}
                      </span>
                      {node.severity && (
                        <span
                          className="text-[10px] font-bold px-1.5 py-0.5 rounded text-white uppercase ml-auto"
                          style={{ background: SEVERITY_COLORS[node.severity as Severity] }}
                        >
                          {node.severity}
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] font-mono break-all" style={{ color: 'var(--text-muted)' }}>
                      {node.file_path}
                    </p>
                    <div className="flex items-center gap-3 text-[11px]" style={{ color: 'var(--text-secondary)' }}>
                      {node.line_number > 0 && (
                        <span>
                          Line <span className="font-bold" style={{ color }}>{node.line_number}</span>
                        </span>
                      )}
                      <span>&middot;</span>
                      <span>{NODE_LABELS[node.node_type]}</span>
                    </div>
                  </div>
                )}

                {/* Issue annotation */}
                {node.description && (
                  <div
                    className="rounded-lg px-3 py-2 text-xs leading-relaxed flex items-start gap-2"
                    style={{ background: `${color}12`, border: `1px solid ${color}30`, color: 'var(--text-secondary)' }}
                  >
                    <span style={{ color }} className="shrink-0 mt-0.5">{'\u25B6'}</span>
                    <span><strong style={{ color: 'var(--text-primary)' }}>{node.label}</strong> &mdash; {node.description}</span>
                  </div>
                )}

                {/* Source code with highlighted line */}
                <SourceCodeBlock lines={sourceLines} targetLine={node.line_number} color={color} />

                <p className="text-[11px] italic" style={{ color: 'var(--text-muted)' }}>
                  {node.line_number > 0
                    ? `Line ${node.line_number} highlighted \u2014 showing ${sourceLines.length} lines of context`
                    : `Showing ${sourceLines.length} lines`
                  }
                </p>
              </>
            ) : (
              <p className="text-sm text-center py-8" style={{ color: 'var(--text-muted)' }}>
                {node.file_path ? 'Could not load source context.' : 'No file path associated with this node.'}
              </p>
            )}
          </>
        )}

        {activeTab === 'related' && (
          <>
            {relatedFindings.length > 0 ? (
              <Section title={`Findings in ${node.file_path?.split('/').pop()}`}>
                <div className="space-y-1">
                  {relatedFindings.map((rn) => (
                    <button
                      key={rn.id}
                      onClick={() => onNavigate(rn)}
                      className="w-full text-left px-3 py-2.5 rounded-lg flex items-center gap-3 transition-colors"
                      style={{ background: 'transparent' }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
                      onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                    >
                      <span style={{ color: NODE_COLORS[rn.node_type] }}>{icons[rn.node_type]}</span>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                          {rn.label}
                        </p>
                        <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>
                          Line {rn.line_number} &middot; {NODE_LABELS[rn.node_type]}
                        </p>
                      </div>
                      {rn.severity && (
                        <span
                          className="text-[10px] font-bold px-1.5 py-0.5 rounded text-white uppercase shrink-0"
                          style={{ background: SEVERITY_COLORS[rn.severity as Severity] }}
                        >
                          {rn.severity}
                        </span>
                      )}
                    </button>
                  ))}
                </div>
              </Section>
            ) : (
              <p className="text-sm text-center py-8" style={{ color: 'var(--text-muted)' }}>
                No other findings in this file.
              </p>
            )}
          </>
        )}

        {activeTab === 'cves' && isDep && (
          <>
            {cveLoading ? (
              <div className="flex items-center justify-center py-8">
                <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
                <span className="ml-3 text-sm" style={{ color: 'var(--text-muted)' }}>Checking OSV.dev...</span>
              </div>
            ) : cveError ? (
              <p className="text-sm text-center py-8 text-red-400">{cveError}</p>
            ) : cveResults && cveResults.length > 0 ? (
              <Section title={`${cveResults.length} Known Vulnerabilities`}>
                <div className="space-y-3">
                  {cveResults.map((cve) => (
                    <div
                      key={cve.id}
                      className="rounded-lg border p-3"
                      style={{ background: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
                    >
                      <div className="flex items-center gap-2 mb-1">
                        {cve.url ? (
                          <a
                            href={cve.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-sm font-bold text-blue-400 hover:underline"
                          >
                            {cve.id}
                          </a>
                        ) : (
                          <span className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>{cve.id}</span>
                        )}
                        {cve.severity && (
                          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded text-white uppercase" style={{ background: '#F97316' }}>
                            {cve.severity}
                          </span>
                        )}
                      </div>
                      <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                        {cve.summary}
                      </p>
                      <div className="flex items-center gap-4 mt-2 text-xs" style={{ color: 'var(--text-muted)' }}>
                        {cve.affected_versions && <span>Affected: {cve.affected_versions}</span>}
                        {cve.fixed_version && <span className="text-green-400">Fixed in: {cve.fixed_version}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </Section>
            ) : (
              <div className="text-center py-8">
                <p className="text-sm text-green-400 font-medium">No known CVEs found</p>
                <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                  Checked against OSV.dev database
                </p>
              </div>
            )}
          </>
        )}

        {activeTab === 'ai' && hasSeverity && (
          <>
            {aiResult ? (
              <Section title="AI Remediation">
                <div
                  className="text-sm leading-relaxed"
                  style={{ color: 'var(--text-secondary)' }}
                  dangerouslySetInnerHTML={{ __html: renderMarkdownSimple(aiResult) }}
                />
              </Section>
            ) : aiLoading ? (
              <div className="flex items-center justify-center py-8">
                <div className="w-6 h-6 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
                <span className="ml-3 text-sm" style={{ color: 'var(--text-muted)' }}>Analyzing with AI...</span>
              </div>
            ) : (
              <div className="text-center py-8">
                <p className="text-sm mb-4" style={{ color: 'var(--text-secondary)' }}>
                  Get AI-powered remediation advice for this finding.
                </p>
                <button
                  onClick={handleAIRemediation}
                  className="px-5 py-2.5 rounded-lg text-sm font-medium transition-colors border"
                  style={{
                    background: 'linear-gradient(135deg, rgba(139,92,246,0.15), rgba(59,130,246,0.15))',
                    borderColor: 'rgba(139,92,246,0.3)',
                    color: '#A78BFA',
                  }}
                >
                  <span className="mr-1.5">&#x2728;</span>
                  Analyze with AI
                </button>
                {aiError && (
                  <p className="mt-3 text-xs text-red-400">{aiError}</p>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

/** Minimal markdown → HTML for AI responses */
function renderMarkdownSimple(md: string): string {
  return md
    .replace(/```(\w*)\n([\s\S]*?)```/g, '<pre style="background:var(--bg-tertiary);padding:0.75rem;border-radius:0.5rem;overflow-x:auto;font-size:0.75rem;margin:0.5rem 0"><code>$2</code></pre>')
    .replace(/`([^`]+)`/g, '<code style="background:var(--bg-tertiary);padding:0.125rem 0.375rem;border-radius:0.25rem;font-size:0.8em">$1</code>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/^#### (.+)$/gm, '<p style="font-weight:600;margin-top:0.75rem;margin-bottom:0.25rem;font-size:0.8rem;color:var(--text-primary)">$1</p>')
    .replace(/^### (.+)$/gm, '<p style="font-weight:700;margin-top:1rem;margin-bottom:0.25rem;font-size:0.85rem;color:var(--text-primary)">$1</p>')
    .replace(/^## (.+)$/gm, '<p style="font-weight:700;margin-top:1rem;margin-bottom:0.25rem;font-size:0.9rem;color:var(--text-primary)">$1</p>')
    .replace(/^\d+\.\s+(.+)$/gm, '<li style="margin-left:1rem;margin-bottom:0.25rem">$1</li>')
    .replace(/^[-*]\s+(.+)$/gm, '<li style="margin-left:1rem;margin-bottom:0.25rem">$1</li>')
    .replace(/\n\n/g, '<br/><br/>');
}

/** Parse the backend-formatted snippet string into SourceLine[].
 *  Format: "   10     def foo():\n   11 >>> bar()" */
function parseSnippet(snippet: string): SourceLine[] {
  const lines: SourceLine[] = [];
  for (const raw of snippet.split('\n')) {
    // Match: optional spaces, line number, optional marker (>>>), then content
    const match = raw.match(/^\s*(\d+)(?: >>>|    ) (.*)$/);
    if (match) {
      lines.push({ number: parseInt(match[1], 10), text: match[2] });
    }
  }
  return lines;
}

// --- Subcomponents ---

function SourceCodeBlock({
  lines,
  targetLine,
  color,
  maxLines,
}: {
  lines: SourceLine[];
  targetLine: number;
  color: string;
  maxLines?: number;
}) {
  let displayLines = lines;
  if (maxLines && lines.length > maxLines) {
    // Center around target line
    const targetIdx = lines.findIndex((l) => l.number === targetLine);
    const center = targetIdx >= 0 ? targetIdx : Math.floor(lines.length / 2);
    const half = Math.floor(maxLines / 2);
    const start = Math.max(0, Math.min(center - half, lines.length - maxLines));
    displayLines = lines.slice(start, start + maxLines);
  }

  const isTarget = (num: number) => num === targetLine;

  return (
    <div className="rounded-lg overflow-hidden border" style={{ borderColor: 'var(--border-primary)' }}>
      <pre className="text-xs overflow-x-auto p-3 m-0" style={{ background: 'var(--bg-tertiary)' }}>
        {displayLines.map((line) => (
          <div
            key={line.number}
            className="flex leading-5"
            style={{
              background: isTarget(line.number) ? `${color}20` : 'transparent',
              borderLeft: isTarget(line.number) ? `3px solid ${color}` : '3px solid transparent',
            }}
          >
            <span
              className="w-5 text-center select-none shrink-0 text-[10px]"
              style={{ color: isTarget(line.number) ? color : 'transparent' }}
            >
              {isTarget(line.number) ? '\u25B6' : ''}
            </span>
            <span
              className="w-10 text-right pr-3 select-none shrink-0"
              style={{ color: isTarget(line.number) ? color : 'var(--text-muted)', fontWeight: isTarget(line.number) ? 700 : 400 }}
            >
              {line.number}
            </span>
            <code style={{ color: 'var(--text-primary)', fontWeight: isTarget(line.number) ? 600 : 400 }}>{line.text || ' '}</code>
          </div>
        ))}
      </pre>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-xs uppercase font-semibold tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>
        {title}
      </h3>
      {children}
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="rounded-lg px-3 py-2.5 border" style={{ background: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <p className="text-lg font-bold" style={{ color }}>{value}</p>
      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{label}</p>
    </div>
  );
}

function ConnectionItem({
  node: connNode,
  edgeLabel,
  direction,
  onClick,
}: {
  node: GraphNode;
  edgeLabel: string;
  direction: 'from' | 'to';
  onClick: () => void;
}) {
  const color = NODE_COLORS[connNode.node_type] || '#6B7280';
  const icon = icons[connNode.node_type] || '';

  return (
    <button
      onClick={onClick}
      className="w-full text-left px-3 py-2.5 rounded-lg flex items-center gap-3 transition-colors"
      style={{ background: 'transparent' }}
      onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
      onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
    >
      <span className="text-xs shrink-0" style={{ color: 'var(--text-muted)' }}>
        {direction === 'from' ? '\u2190' : '\u2192'}
      </span>
      <span style={{ color }}>{icon}</span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
          {connNode.label}
        </p>
        <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>
          {edgeLabel.replace(/_/g, ' ')} &middot; {NODE_LABELS[connNode.node_type]}
        </p>
      </div>
    </button>
  );
}
