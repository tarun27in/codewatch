import type { GraphNode } from '../types/graph';
import { NODE_COLORS, NODE_LABELS, SEVERITY_COLORS } from '../types/graph';

interface Props {
  node: GraphNode | null;
  onClose: () => void;
}

export default function NodeDetail({ node, onClose }: Props) {
  if (!node) return null;

  const color = NODE_COLORS[node.node_type];

  return (
    <div
      className="absolute top-0 right-0 w-96 h-full backdrop-blur border-l z-20 overflow-y-auto styled-scrollbar"
      style={{ background: 'var(--bg-panel)', borderColor: 'var(--border-primary)' }}
    >
      {/* Header */}
      <div
        className="sticky top-0 border-b p-5 flex items-center justify-between"
        style={{ background: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}
      >
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="w-3.5 h-3.5 rounded shrink-0" style={{ background: color }} />
          <span className="text-sm uppercase font-semibold tracking-wider" style={{ color }}>
            {NODE_LABELS[node.node_type]}
          </span>
        </div>
        <button
          onClick={onClose}
          className="text-xl leading-none"
          style={{ color: 'var(--text-muted)' }}
        >
          &times;
        </button>
      </div>

      <div className="p-5 space-y-5">
        {/* Title */}
        <div>
          <h3 className="text-base font-bold break-all" style={{ color: 'var(--text-primary)' }}>{node.label}</h3>
          {node.description && (
            <p className="text-sm mt-1.5 leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{node.description}</p>
          )}
        </div>

        {/* Severity */}
        {node.severity && (
          <div>
            <Label>Severity</Label>
            <span
              className="inline-block px-2.5 py-1 rounded text-sm font-bold text-white uppercase"
              style={{ background: SEVERITY_COLORS[node.severity] }}
            >
              {node.severity}
            </span>
          </div>
        )}

        {/* File location */}
        {node.file_path && (
          <div>
            <Label>Location</Label>
            <p
              className="text-sm font-mono rounded-lg px-3 py-2 break-all"
              style={{ background: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}
            >
              {node.file_path}
              {node.line_number > 0 && <span className="text-blue-400">:{node.line_number}</span>}
            </p>
          </div>
        )}

        {/* Metadata */}
        {Object.keys(node.metadata).length > 0 && (
          <div>
            <Label>Details</Label>
            <div className="space-y-2">
              {Object.entries(node.metadata).map(([key, value]) => (
                <div key={key} className="flex items-start gap-2 text-sm">
                  <span className="shrink-0 font-medium" style={{ color: 'var(--text-muted)' }}>{key}:</span>
                  <span className="break-all" style={{ color: 'var(--text-primary)' }}>
                    {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function Label({ children }: { children: React.ReactNode }) {
  return <p className="text-xs uppercase font-semibold tracking-wider mb-1.5" style={{ color: 'var(--text-muted)' }}>{children}</p>;
}
