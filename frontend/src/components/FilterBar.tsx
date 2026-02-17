import type { NodeType } from '../types/graph';
import { NODE_COLORS, NODE_LABELS } from '../types/graph';

const ALL_TYPES: NodeType[] = [
  'entry_point', 'service', 'external_api', 'data_store',
  'secret', 'vulnerability', 'auth_boundary', 'dependency',
];

interface Props {
  activeFilters: Set<NodeType>;
  onToggle: (type: NodeType) => void;
  onReset: () => void;
  onFocus?: () => void;
  typeCounts?: Record<string, number>;
  isFocused?: boolean;
}

export default function FilterBar({ activeFilters, onToggle, onReset, onFocus, typeCounts, isFocused }: Props) {
  const allActive = activeFilters.size === ALL_TYPES.length;

  return (
    <div
      className="backdrop-blur border-b px-5 py-2.5 flex items-center gap-2.5 overflow-x-auto"
      style={{ background: 'var(--bg-panel)', borderColor: 'var(--border-primary)' }}
    >
      <span className="text-sm shrink-0 mr-1 font-medium" style={{ color: 'var(--text-muted)' }}>View:</span>

      {/* Focus mode: show only important nodes */}
      {onFocus && (
        <button
          onClick={onFocus}
          className={`px-3 py-1.5 rounded-full text-sm font-medium transition-colors shrink-0 ${
            isFocused
              ? 'bg-blue-600/30 text-blue-400 border border-blue-500/50'
              : 'border border-transparent'
          }`}
          style={!isFocused ? { background: 'var(--bg-card)', color: 'var(--text-secondary)' } : undefined}
        >
          Focus
        </button>
      )}

      <button
        onClick={onReset}
        className={`px-3 py-1.5 rounded-full text-sm font-medium transition-colors shrink-0 ${
          allActive
            ? 'border'
            : 'border border-transparent'
        }`}
        style={allActive
          ? { background: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--border-primary)' }
          : { background: 'var(--bg-card)', color: 'var(--text-secondary)' }
        }
      >
        All
      </button>

      <div className="w-px h-5 shrink-0" style={{ background: 'var(--border-primary)' }} />

      {ALL_TYPES.map((type) => {
        const active = activeFilters.has(type);
        const color = NODE_COLORS[type];
        const count = typeCounts?.[type] || 0;
        return (
          <button
            key={type}
            onClick={() => onToggle(type)}
            className="px-3 py-1.5 rounded-full text-sm font-medium transition-all shrink-0 flex items-center gap-1.5"
            style={{
              background: active ? `${color}30` : 'var(--bg-card)',
              color: active ? color : 'var(--text-muted)',
              border: `1px solid ${active ? color : 'transparent'}`,
            }}
          >
            {NODE_LABELS[type]}
            {count > 0 && (
              <span
                className="text-xs px-1.5 py-0 rounded-full font-bold"
                style={{
                  background: active ? `${color}40` : 'var(--bg-tertiary)',
                  color: active ? color : 'var(--text-secondary)',
                }}
              >
                {count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}
