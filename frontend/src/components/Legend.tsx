import { useState } from 'react';
import { NODE_COLORS, NODE_LABELS, type NodeType } from '../types/graph';

const TYPES: NodeType[] = [
  'entry_point', 'service', 'external_api', 'data_store',
  'secret', 'vulnerability', 'auth_boundary', 'dependency',
];

const NODE_DESCRIPTIONS: Record<NodeType, string> = {
  entry_point: 'API routes, HTTP handlers, and endpoints exposed to users or other services. Check these for authentication and input validation.',
  service: 'Core application modules, classes, or packages that contain business logic.',
  external_api: 'Outbound calls to third-party APIs or services. Data leaving your app crosses a trust boundary here.',
  data_store: 'Databases, caches, file storage, and other places where data is persisted. Ensure encryption and access controls.',
  secret: 'API keys, passwords, tokens, and other credentials found in source code. These should be moved to a secrets manager.',
  vulnerability: 'Security issues detected in the code: injection risks, misconfigurations, unsafe patterns, and more.',
  auth_boundary: 'Authentication and authorization checkpoints. Code that controls who can access what.',
  dependency: 'Third-party packages and libraries your code depends on. Check these for known CVEs.',
  file: 'Source files in the scanned codebase.',
};

const EDGE_INFO = [
  { type: 'data_flow', color: '#3B82F6', label: 'Data Flow', desc: 'Data moves between these components' },
  { type: 'has_vulnerability', color: '#DC2626', label: 'Has Vulnerability', desc: 'This component has a security finding' },
  { type: 'uses_secret', color: '#EF4444', label: 'Uses Secret', desc: 'This component references a secret/credential' },
  { type: 'depends_on', color: '#6B7280', label: 'Depends On', desc: 'Package/library dependency relationship' },
  { type: 'connects_to', color: '#10B981', label: 'Connects To', desc: 'Network or API connection to external service' },
  { type: 'authentication', color: '#EAB308', label: 'Auth Check', desc: 'Authentication/authorization is enforced here' },
];

export default function Legend() {
  const [expanded, setExpanded] = useState(false);
  const [hoveredType, setHoveredType] = useState<string | null>(null);

  return (
    <div
      className="absolute bottom-4 left-4 backdrop-blur border rounded-lg z-10 transition-all"
      style={{
        background: 'var(--bg-panel)',
        borderColor: 'var(--border-primary)',
        maxWidth: expanded ? 360 : 260,
        maxHeight: expanded ? '70vh' : 'auto',
      }}
    >
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-4 py-2.5 transition-colors"
        style={{ color: 'var(--text-primary)' }}
      >
        <span className="text-xs uppercase font-semibold tracking-wider" style={{ color: 'var(--text-muted)' }}>
          Legend
        </span>
        <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}>
          {expanded ? 'Collapse' : 'Expand'}
        </span>
      </button>

      {/* Compact view */}
      {!expanded && (
        <div className="px-4 pb-3">
          <div className="grid grid-cols-2 gap-x-5 gap-y-1.5">
            {TYPES.map((type) => (
              <div key={type} className="flex items-center gap-2">
                <div className="w-3 h-3 rounded" style={{ background: NODE_COLORS[type] }} />
                <span className="text-xs" style={{ color: 'var(--text-primary)' }}>{NODE_LABELS[type]}</span>
              </div>
            ))}
          </div>
          <p className="text-[10px] mt-2 italic" style={{ color: 'var(--text-muted)' }}>
            Click to learn what each type means
          </p>
        </div>
      )}

      {/* Expanded view */}
      {expanded && (
        <div className="overflow-y-auto styled-scrollbar" style={{ maxHeight: 'calc(70vh - 40px)' }}>
          {/* Node types */}
          <div className="px-4 pb-3">
            <p className="text-[10px] uppercase font-semibold tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>
              Node Types
            </p>
            <div className="space-y-1">
              {TYPES.map((type) => (
                <div
                  key={type}
                  className="rounded-lg px-3 py-2 transition-colors cursor-default"
                  style={{
                    background: hoveredType === type ? 'var(--bg-hover)' : 'transparent',
                  }}
                  onMouseEnter={() => setHoveredType(type)}
                  onMouseLeave={() => setHoveredType(null)}
                >
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded shrink-0" style={{ background: NODE_COLORS[type] }} />
                    <span className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>
                      {NODE_LABELS[type]}
                    </span>
                  </div>
                  {hoveredType === type && (
                    <p className="text-[11px] mt-1 ml-5 leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                      {NODE_DESCRIPTIONS[type]}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Edge types */}
          <div className="px-4 pb-4 border-t pt-3" style={{ borderColor: 'var(--border-primary)' }}>
            <p className="text-[10px] uppercase font-semibold tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>
              Relationships (Edges)
            </p>
            <div className="space-y-1">
              {EDGE_INFO.map((edge) => (
                <div
                  key={edge.type}
                  className="rounded-lg px-3 py-2 transition-colors cursor-default"
                  style={{
                    background: hoveredType === edge.type ? 'var(--bg-hover)' : 'transparent',
                  }}
                  onMouseEnter={() => setHoveredType(edge.type)}
                  onMouseLeave={() => setHoveredType(null)}
                >
                  <div className="flex items-center gap-2">
                    <div className="w-5 h-0.5 shrink-0 rounded" style={{ background: edge.color }} />
                    <span className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>
                      {edge.label}
                    </span>
                  </div>
                  {hoveredType === edge.type && (
                    <p className="text-[11px] mt-1 ml-7 leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                      {edge.desc}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Tips */}
          <div className="px-4 pb-4 border-t pt-3" style={{ borderColor: 'var(--border-primary)' }}>
            <p className="text-[10px] uppercase font-semibold tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>
              Tips
            </p>
            <ul className="space-y-1.5 text-[11px]" style={{ color: 'var(--text-secondary)' }}>
              <li className="flex gap-2"><span className="shrink-0">{'\u{1F5B1}'}</span> Right-click any node for actions</li>
              <li className="flex gap-2"><span className="shrink-0">{'\u{1F50D}'}</span> Hover a node to trace its connections</li>
              <li className="flex gap-2"><span className="shrink-0">{'\u{1F3AF}'}</span> Use Focus mode to reduce noise</li>
              <li className="flex gap-2"><span className="shrink-0">{'\u{2728}'}</span> AI remediation available for findings</li>
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
