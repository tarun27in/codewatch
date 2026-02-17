import { useEffect, useRef } from 'react';
import type { GraphNode, NodeType } from '../types/graph';
import { NODE_COLORS } from '../types/graph';

interface Props {
  node: GraphNode;
  x: number;
  y: number;
  onClose: () => void;
  onDeepDive: (node: GraphNode) => void;
  onShowConnections: (node: GraphNode) => void;
  onCopyId: (node: GraphNode) => void;
  onExportNode: (node: GraphNode) => void;
  onCheckCVEs?: (node: GraphNode) => void;
}

interface MenuItem {
  label: string;
  icon: string;
  action: () => void;
  divider?: boolean;
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

export default function ContextMenu({ node, x, y, onClose, onDeepDive, onShowConnections, onCopyId, onExportNode, onCheckCVEs }: Props) {
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as HTMLElement)) {
        onClose();
      }
    };
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    const handleScroll = () => onClose();

    document.addEventListener('mousedown', handleClick);
    document.addEventListener('keydown', handleKey);
    document.addEventListener('scroll', handleScroll, true);
    return () => {
      document.removeEventListener('mousedown', handleClick);
      document.removeEventListener('keydown', handleKey);
      document.removeEventListener('scroll', handleScroll, true);
    };
  }, [onClose]);

  // Adjust position to stay within viewport
  useEffect(() => {
    if (!menuRef.current) return;
    const rect = menuRef.current.getBoundingClientRect();
    const pad = 8;
    if (rect.right > window.innerWidth - pad) {
      menuRef.current.style.left = `${x - rect.width}px`;
    }
    if (rect.bottom > window.innerHeight - pad) {
      menuRef.current.style.top = `${y - rect.height}px`;
    }
  }, [x, y]);

  const color = NODE_COLORS[node.node_type] || '#6B7280';
  const icon = icons[node.node_type] || '';

  const items: MenuItem[] = [
    { label: 'Deep Dive', icon: '\uD83D\uDD0D', action: () => { onDeepDive(node); onClose(); } },
    { label: 'Show Connections', icon: '\uD83D\uDD17', action: () => { onShowConnections(node); onClose(); } },
    ...(node.node_type === 'dependency' && onCheckCVEs
      ? [{ label: 'Check CVEs', icon: '\uD83D\uDEE1', action: () => { onCheckCVEs(node); onClose(); } }]
      : []),
    { label: 'Copy Node ID', icon: '\uD83D\uDCCB', action: () => { onCopyId(node); onClose(); } },
    { label: 'Export Node JSON', icon: '\uD83D\uDCE5', action: () => { onExportNode(node); onClose(); } },
  ];

  return (
    <div
      ref={menuRef}
      className="fixed z-50 min-w-[200px] rounded-lg border shadow-xl overflow-hidden"
      style={{
        left: x,
        top: y,
        background: 'var(--bg-secondary)',
        borderColor: 'var(--border-primary)',
      }}
    >
      {/* Header */}
      <div className="px-3 py-2.5 border-b flex items-center gap-2" style={{ borderColor: 'var(--border-primary)' }}>
        <span style={{ color }}>{icon}</span>
        <span className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>
          {node.label}
        </span>
        {node.severity && (
          <span
            className="text-[10px] font-bold px-1.5 py-0.5 rounded text-white uppercase ml-auto shrink-0"
            style={{ background: color }}
          >
            {node.severity}
          </span>
        )}
      </div>

      {/* Menu items */}
      <div className="py-1">
        {items.map((item, i) => (
          <button
            key={i}
            onClick={item.action}
            className="w-full text-left px-3 py-2 text-sm flex items-center gap-2.5 transition-colors"
            style={{ color: 'var(--text-primary)', background: 'transparent' }}
            onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
            onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
          >
            <span className="text-base w-5 text-center">{item.icon}</span>
            <span>{item.label}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
