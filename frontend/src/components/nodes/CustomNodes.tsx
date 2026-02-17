import { memo } from 'react';
import { Handle, Position } from '@xyflow/react';
import type { NodeType } from '../../types/graph';
import { NODE_COLORS, SEVERITY_COLORS } from '../../types/graph';

interface CustomNodeData {
  label: string;
  nodeType: NodeType;
  severity?: string;
  description?: string;
  filePath?: string;
  lineNumber?: number;
  metadata?: Record<string, unknown>;
  // Summary node fields
  isSummary?: boolean;
  count?: number;
  items?: string[];
}

const icons: Record<NodeType, string> = {
  entry_point: '\u21D2',    // ⇒
  service: '\u2B22',        // ⬢
  external_api: '\u2601',   // ☁
  data_store: '\u26C1',     // ⛁
  secret: '\u26BF',         // ⚿
  vulnerability: '\u26A0',  // ⚠
  auth_boundary: '\u26D4',  // ⛔
  dependency: '\u25A3',     // ▣
  file: '\u2B1A',           // ⬚
};

function BaseNode({ data, selected }: { data: CustomNodeData; selected?: boolean }) {
  const color = NODE_COLORS[data.nodeType] || '#6B7280';
  const icon = icons[data.nodeType] || '';
  const severityColor = data.severity ? SEVERITY_COLORS[data.severity as keyof typeof SEVERITY_COLORS] : undefined;

  const isVuln = data.nodeType === 'vulnerability';
  const borderWidth = selected ? 3 : isVuln ? 2 : 1;
  const borderColor = selected ? 'var(--text-primary)' : isVuln && severityColor ? severityColor : color;

  // Summary node: compact card showing count
  if (data.isSummary) {
    return (
      <div
        className="relative px-4 py-3 rounded-xl shadow-lg cursor-pointer transition-all hover:shadow-xl hover:scale-[1.03]"
        style={{
          background: `${color}15`,
          border: `2px dashed ${color}80`,
          minWidth: 160,
        }}
      >
        <Handle type="target" position={Position.Left} className="!w-2.5 !h-2.5 !bg-gray-500" />
        <div className="flex items-center gap-2.5">
          <span className="text-2xl" style={{ color }}>{icon}</span>
          <div>
            <span className="text-lg font-bold block" style={{ color }}>
              {data.count}
            </span>
            <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{data.label}</span>
          </div>
        </div>
        {data.items && data.items.length > 0 && (
          <div className="mt-2 pt-2" style={{ borderTop: '1px solid var(--border-primary)' }}>
            {data.items.slice(0, 3).map((item, i) => (
              <p key={i} className="text-[11px] truncate" style={{ color: 'var(--text-muted)' }}>{item}</p>
            ))}
            {data.items.length > 3 && (
              <p className="text-[11px] italic" style={{ color: 'var(--text-muted)' }}>+{data.items.length - 3} more</p>
            )}
          </div>
        )}
        <p className="text-[10px] mt-1.5 italic" style={{ color: 'var(--text-muted)' }}>Click filter to expand</p>
        <Handle type="source" position={Position.Right} className="!w-2.5 !h-2.5 !bg-gray-500" />
      </div>
    );
  }

  return (
    <div
      className="relative px-3.5 py-2.5 rounded-lg shadow-lg min-w-[150px] max-w-[220px] cursor-pointer transition-all hover:shadow-xl hover:scale-[1.03]"
      style={{
        background: `${color}18`,
        border: `${borderWidth}px solid ${borderColor}`,
        backdropFilter: 'blur(8px)',
      }}
    >
      <Handle type="target" position={Position.Left} className="!w-2.5 !h-2.5 !bg-gray-500" />
      <div className="flex items-center gap-2">
        <span className="text-lg shrink-0" style={{ color }}>{icon}</span>
        <span
          className="text-sm font-semibold truncate"
          style={{ color }}
          title={data.label}
        >
          {data.label}
        </span>
      </div>
      {data.description && (
        <p className="text-[11px] mt-0.5 truncate" style={{ color: 'var(--text-secondary)' }} title={data.description}>
          {data.description}
        </p>
      )}
      {data.severity && (
        <span
          className="absolute -top-2 -right-2 text-[10px] font-bold px-1.5 py-0.5 rounded-full text-white uppercase"
          style={{ background: severityColor || '#6B7280' }}
        >
          {data.severity}
        </span>
      )}
      <Handle type="source" position={Position.Right} className="!w-2.5 !h-2.5 !bg-gray-500" />
    </div>
  );
}

export const EntryPointNode = memo(({ data, selected }: { data: CustomNodeData; selected?: boolean }) => (
  <BaseNode data={data} selected={selected} />
));
EntryPointNode.displayName = 'EntryPointNode';

export const ServiceNode = memo(({ data, selected }: { data: CustomNodeData; selected?: boolean }) => (
  <BaseNode data={data} selected={selected} />
));
ServiceNode.displayName = 'ServiceNode';

export const ExternalApiNode = memo(({ data, selected }: { data: CustomNodeData; selected?: boolean }) => (
  <BaseNode data={data} selected={selected} />
));
ExternalApiNode.displayName = 'ExternalApiNode';

export const DataStoreNode = memo(({ data, selected }: { data: CustomNodeData; selected?: boolean }) => (
  <BaseNode data={data} selected={selected} />
));
DataStoreNode.displayName = 'DataStoreNode';

export const SecretNode = memo(({ data, selected }: { data: CustomNodeData; selected?: boolean }) => (
  <BaseNode data={data} selected={selected} />
));
SecretNode.displayName = 'SecretNode';

export const VulnerabilityNode = memo(({ data, selected }: { data: CustomNodeData; selected?: boolean }) => (
  <BaseNode data={data} selected={selected} />
));
VulnerabilityNode.displayName = 'VulnerabilityNode';

export const AuthBoundaryNode = memo(({ data, selected }: { data: CustomNodeData; selected?: boolean }) => (
  <BaseNode data={data} selected={selected} />
));
AuthBoundaryNode.displayName = 'AuthBoundaryNode';

export const DependencyNode = memo(({ data, selected }: { data: CustomNodeData; selected?: boolean }) => (
  <BaseNode data={data} selected={selected} />
));
DependencyNode.displayName = 'DependencyNode';

export const nodeTypes = {
  entryPointNode: EntryPointNode,
  serviceNode: ServiceNode,
  externalApiNode: ExternalApiNode,
  dataStoreNode: DataStoreNode,
  secretNode: SecretNode,
  vulnerabilityNode: VulnerabilityNode,
  authBoundaryNode: AuthBoundaryNode,
  dependencyNode: DependencyNode,
};

export function getNodeTypeKey(nodeType: NodeType): string {
  const map: Record<NodeType, string> = {
    entry_point: 'entryPointNode',
    service: 'serviceNode',
    external_api: 'externalApiNode',
    data_store: 'dataStoreNode',
    secret: 'secretNode',
    vulnerability: 'vulnerabilityNode',
    auth_boundary: 'authBoundaryNode',
    dependency: 'dependencyNode',
    file: 'entryPointNode',
  };
  return map[nodeType] || 'entryPointNode';
}
