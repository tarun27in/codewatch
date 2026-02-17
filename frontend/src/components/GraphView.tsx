import { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  useReactFlow,
  ReactFlowProvider,
  type Node,
  type Edge,
  type NodeMouseHandler,
  MarkerType,
  ConnectionLineType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import type { SecurityGraph, GraphNode as GNode, NodeType } from '../types/graph';
import { NODE_COLORS, NODE_LABELS } from '../types/graph';
import { layoutGraph } from '../utils/layout';
import { useTheme } from '../hooks/useTheme';
import { nodeTypes, getNodeTypeKey } from './nodes/CustomNodes';
import StatsBar from './StatsBar';
import FilterBar from './FilterBar';
import Legend from './Legend';
import NodeDetail from './NodeDetail';
import FindingsPanel from './FindingsPanel';
import ContextMenu from './ContextMenu';
import DeepDivePanel from './DeepDivePanel';
import AISettingsModal from './AISettingsModal';
import WelcomeOverlay, { shouldShowWelcome, dismissWelcome } from './WelcomeOverlay';
import { exportJSON, exportMarkdown, exportSARIF } from '../utils/export';

interface Props {
  graph: SecurityGraph;
  scanPath: string;
  onBack: () => void;
  onClearAndExit: () => void;
  onRescan?: () => void;
  rescanning?: boolean;
}

const EDGE_COLORS: Record<string, string> = {
  data_flow: '#3B82F6',
  authentication: '#EAB308',
  uses_secret: '#EF4444',
  connects_to: '#10B981',
  belongs_to: '#8B5CF6',
  has_vulnerability: '#DC2626',
  depends_on: '#6B7280',
  imports: '#475569',
};

// Types shown by default (high-signal)
const DEFAULT_VISIBLE: Set<NodeType> = new Set([
  'service', 'vulnerability', 'entry_point', 'external_api', 'data_store', 'auth_boundary',
]);

// Types collapsed into summary nodes when hidden
const COLLAPSIBLE_TYPES: NodeType[] = ['dependency', 'secret'];

// Edge types hidden when their target type is collapsed
const HIDDEN_EDGE_TYPES = new Set(['depends_on', 'uses_secret']);

interface ContextMenuState {
  node: GNode;
  x: number;
  y: number;
}

function GraphViewInner({ graph, scanPath, onBack, onClearAndExit, onRescan, rescanning }: Props) {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const allTypes = new Set<NodeType>([
    'entry_point', 'service', 'external_api', 'data_store',
    'secret', 'vulnerability', 'auth_boundary', 'dependency',
  ]);
  const [activeFilters, setActiveFilters] = useState<Set<NodeType>>(new Set(DEFAULT_VISIBLE));
  const [selectedNode, setSelectedNode] = useState<GNode | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [showFindings, setShowFindings] = useState(true);
  const [findingsCollapsed, setFindingsCollapsed] = useState(false);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const [deepDiveNode, setDeepDiveNode] = useState<GNode | null>(null);
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [showAISettings, setShowAISettings] = useState(false);
  const [showWelcome, setShowWelcome] = useState(() => shouldShowWelcome());
  const searchInputRef = useRef<HTMLInputElement>(null);
  const exportRef = useRef<HTMLDivElement>(null);
  const { fitView, setCenter } = useReactFlow();

  // Count nodes per type for filter bar badges
  const typeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const n of graph.nodes) {
      counts[n.node_type] = (counts[n.node_type] || 0) + 1;
    }
    return counts;
  }, [graph.nodes]);

  // Find service node ID for connecting summary nodes
  const primaryServiceId = useMemo(() => {
    const svc = graph.nodes.find((n) => n.node_type === 'service');
    return svc?.id || null;
  }, [graph.nodes]);

  // Build React Flow nodes/edges from graph data
  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => {
    const visibleNodeIds = new Set(
      graph.nodes
        .filter((n) => activeFilters.has(n.node_type))
        .map((n) => n.id)
    );

    const rfNodes: Node[] = graph.nodes
      .filter((n) => visibleNodeIds.has(n.id))
      .map((n) => ({
        id: n.id,
        type: getNodeTypeKey(n.node_type),
        position: { x: 0, y: 0 },
        data: {
          label: n.label,
          nodeType: n.node_type,
          severity: n.severity,
          description: n.description,
          filePath: n.file_path,
          lineNumber: n.line_number,
          metadata: n.metadata,
        },
      }));

    // Add summary nodes for collapsed types that have items
    for (const type of COLLAPSIBLE_TYPES) {
      if (activeFilters.has(type)) continue;
      const items = graph.nodes.filter((n) => n.node_type === type);
      if (items.length === 0) continue;

      const summaryId = `summary-${type}`;
      rfNodes.push({
        id: summaryId,
        type: getNodeTypeKey(type),
        position: { x: 0, y: 0 },
        data: {
          label: NODE_LABELS[type] + 's',
          nodeType: type,
          isSummary: true,
          count: items.length,
          items: items.slice(0, 5).map((n) => n.label),
        },
      });
    }

    // Build edges — skip hidden edge types unless both endpoints are visible
    const rfEdges: Edge[] = graph.edges
      .filter((e) => {
        if (HIDDEN_EDGE_TYPES.has(e.edge_type) && !visibleNodeIds.has(e.target)) {
          return false;
        }
        return visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target);
      })
      .map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.label || undefined,
        type: 'smoothstep',
        animated: false,
        style: {
          stroke: EDGE_COLORS[e.edge_type] || '#475569',
          strokeWidth: e.edge_type === 'has_vulnerability' ? 2.5 : 1.5,
          opacity: 0.5,
        },
        labelStyle: { fontSize: 11, fill: '#9CA3AF', fontWeight: 500 },
        labelBgStyle: { fill: '#111827', fillOpacity: 0.85 },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          width: 16,
          height: 16,
          color: EDGE_COLORS[e.edge_type] || '#475569',
        },
      }));

    // Connect summary nodes to service
    if (primaryServiceId && visibleNodeIds.has(primaryServiceId)) {
      for (const type of COLLAPSIBLE_TYPES) {
        if (activeFilters.has(type)) continue;
        const count = graph.nodes.filter((n) => n.node_type === type).length;
        if (count === 0) continue;
        const summaryId = `summary-${type}`;
        const edgeType = type === 'dependency' ? 'depends_on' : 'uses_secret';
        rfEdges.push({
          id: `e-summary-${type}`,
          source: primaryServiceId,
          target: summaryId,
          label: type === 'dependency' ? `${count} deps` : `${count} secrets`,
          type: 'smoothstep',
          animated: false,
          style: {
            stroke: EDGE_COLORS[edgeType] || '#6B7280',
            strokeWidth: 1.5,
            opacity: 0.4,
            strokeDasharray: '6 3',
          },
          labelStyle: { fontSize: 11, fill: '#6B7280', fontWeight: 500 },
          labelBgStyle: { fill: '#111827', fillOpacity: 0.85 },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            width: 14,
            height: 14,
            color: '#6B7280',
          },
        });
      }
    }

    return layoutGraph(rfNodes, rfEdges);
  }, [graph, activeFilters, primaryServiceId]);

  // Search: find matching node IDs
  const searchMatchIds = useMemo(() => {
    if (!searchQuery.trim()) return new Set<string>();
    const q = searchQuery.toLowerCase();
    return new Set(
      graph.nodes
        .filter(
          (n) =>
            n.label.toLowerCase().includes(q) ||
            n.description?.toLowerCase().includes(q) ||
            n.file_path?.toLowerCase().includes(q)
        )
        .map((n) => n.id)
    );
  }, [graph.nodes, searchQuery]);

  // Build adjacency map for hover path highlighting
  const adjacency = useMemo(() => {
    const adj: Record<string, Set<string>> = {};
    for (const e of initialEdges) {
      if (!adj[e.source]) adj[e.source] = new Set();
      if (!adj[e.target]) adj[e.target] = new Set();
      adj[e.source].add(e.target);
      adj[e.target].add(e.source);
    }
    return adj;
  }, [initialEdges]);

  // Find all connected nodes (upstream + downstream) via BFS
  const connectedNodeIds = useMemo(() => {
    if (!hoveredNodeId) return null;
    const visited = new Set<string>([hoveredNodeId]);
    const queue = [hoveredNodeId];
    while (queue.length > 0) {
      const current = queue.shift()!;
      for (const neighbor of adjacency[current] || []) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push(neighbor);
        }
      }
    }
    return visited;
  }, [hoveredNodeId, adjacency]);

  // Connected edge IDs for hover highlighting
  const connectedEdgeIds = useMemo(() => {
    if (!connectedNodeIds) return null;
    return new Set(
      initialEdges
        .filter((e) => connectedNodeIds.has(e.source) && connectedNodeIds.has(e.target))
        .map((e) => e.id)
    );
  }, [connectedNodeIds, initialEdges]);

  // Apply search + hover classes to nodes
  const styledNodes = useMemo(() => {
    let result = initialNodes;

    // Search highlighting takes priority
    if (searchMatchIds.size > 0) {
      result = result.map((n) => ({
        ...n,
        className: searchMatchIds.has(n.id) ? 'search-match' : 'search-dim',
      }));
    }
    // Hover path highlighting
    else if (connectedNodeIds) {
      result = result.map((n) => ({
        ...n,
        className: connectedNodeIds.has(n.id) ? 'path-highlight' : 'path-dim',
      }));
    }

    return result;
  }, [initialNodes, searchMatchIds, connectedNodeIds]);

  // Apply hover highlighting to edges
  const styledEdges = useMemo(() => {
    if (!connectedEdgeIds || searchMatchIds.size > 0) return initialEdges;
    return initialEdges.map((e) => {
      const isConnected = connectedEdgeIds.has(e.id);
      return {
        ...e,
        style: {
          ...e.style,
          strokeWidth: isConnected ? (e.style?.strokeWidth === 2.5 ? 3.5 : 2.5) : 0.5,
          opacity: isConnected ? 0.9 : 0.08,
        },
        labelStyle: {
          ...e.labelStyle,
          opacity: isConnected ? 1 : 0,
        },
      };
    });
  }, [initialEdges, connectedEdgeIds, searchMatchIds]);

  const [nodes, setNodes, onNodesChange] = useNodesState(styledNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(styledEdges);

  // Track previous layout to detect full graph rebuilds vs style-only changes
  const prevLayoutRef = useRef(initialNodes);

  useEffect(() => {
    const layoutChanged = prevLayoutRef.current !== initialNodes;
    prevLayoutRef.current = initialNodes;

    if (layoutChanged) {
      // Full graph rebuild (filter change) — reset positions
      setNodes(styledNodes);
    } else {
      // Style-only change (hover/search) — preserve dragged positions
      setNodes((currentNodes) =>
        currentNodes.map((n) => {
          const styled = styledNodes.find((s) => s.id === n.id);
          if (!styled) return n;
          return { ...n, className: styled.className };
        })
      );
    }
    setEdges(styledEdges);
  }, [styledNodes, styledEdges, initialNodes, setNodes, setEdges]);

  const handleNodeClick: NodeMouseHandler = useCallback((_event, node) => {
    if (node.id.startsWith('summary-')) {
      const type = node.id.replace('summary-', '') as NodeType;
      setActiveFilters((prev) => {
        const next = new Set(prev);
        next.add(type);
        return next;
      });
      return;
    }
    const graphNode = graph.nodes.find((n) => n.id === node.id) || null;
    setSelectedNode(graphNode);

    // Center/zoom on clicked node
    setCenter(node.position.x + 90, node.position.y + 30, {
      zoom: 1.5,
      duration: 500,
    });
  }, [graph, setCenter]);

  // Right-click context menu handler
  const handleNodeContextMenu = useCallback((event: React.MouseEvent, node: Node) => {
    event.preventDefault();
    if (node.id.startsWith('summary-')) return;
    const graphNode = graph.nodes.find((n) => n.id === node.id);
    if (graphNode) {
      setContextMenu({ node: graphNode, x: event.clientX, y: event.clientY });
    }
  }, [graph.nodes]);

  // Context menu actions
  const handleDeepDive = useCallback((node: GNode) => {
    setDeepDiveNode(node);
  }, []);

  const handleShowConnections = useCallback((node: GNode) => {
    setHoveredNodeId(node.id);
    // Ensure node type is visible
    if (!activeFilters.has(node.node_type)) {
      setActiveFilters((prev) => {
        const next = new Set(prev);
        next.add(node.node_type);
        return next;
      });
    }
    // Center on node
    const rfNode = nodes.find((n) => n.id === node.id);
    if (rfNode) {
      setCenter(rfNode.position.x + 90, rfNode.position.y + 30, {
        zoom: 1.2,
        duration: 500,
      });
    }
  }, [activeFilters, nodes, setCenter]);

  const handleCopyId = useCallback((node: GNode) => {
    navigator.clipboard.writeText(node.id);
  }, []);

  const handleExportNode = useCallback((node: GNode) => {
    const json = JSON.stringify(node, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `node-${node.label.replace(/[^a-zA-Z0-9]/g, '_')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, []);

  // Check CVEs for a dependency node — open deep dive panel
  const handleCheckCVEs = useCallback((node: GNode) => {
    setDeepDiveNode(node);
  }, []);

  // Deep dive navigate to another node
  const handleDeepDiveNavigate = useCallback((node: GNode) => {
    setDeepDiveNode(node);
    // Ensure node type visible and center
    if (!activeFilters.has(node.node_type)) {
      setActiveFilters((prev) => {
        const next = new Set(prev);
        next.add(node.node_type);
        return next;
      });
    }
    setTimeout(() => {
      const rfNode = nodes.find((n) => n.id === node.id);
      if (rfNode) {
        setCenter(rfNode.position.x + 90, rfNode.position.y + 30, {
          zoom: 1.5,
          duration: 500,
        });
      }
    }, 100);
  }, [activeFilters, nodes, setCenter]);

  // Navigate to a node from the findings panel
  const handleFindingClick = useCallback((graphNode: GNode) => {
    setSelectedNode(graphNode);

    // Ensure the node's type is visible
    if (!activeFilters.has(graphNode.node_type)) {
      setActiveFilters((prev) => {
        const next = new Set(prev);
        next.add(graphNode.node_type);
        return next;
      });
    }

    // Zoom to the node (with a small delay to let filter update settle)
    setTimeout(() => {
      const rfNode = nodes.find((n) => n.id === graphNode.id);
      if (rfNode) {
        setCenter(rfNode.position.x + 90, rfNode.position.y + 30, {
          zoom: 1.5,
          duration: 500,
        });
      }
    }, 100);
  }, [activeFilters, nodes, setCenter]);

  const handleToggleFilter = useCallback((type: NodeType) => {
    setActiveFilters((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  }, []);

  const handleResetFilters = useCallback(() => {
    setActiveFilters(new Set(allTypes));
  }, []);

  const handleFocusMode = useCallback(() => {
    setActiveFilters(new Set(DEFAULT_VISIBLE));
  }, []);

  const handleSearchSubmit = useCallback((e: React.FormEvent) => {
    e.preventDefault();
    if (searchMatchIds.size > 0) {
      const firstMatchId = [...searchMatchIds][0];
      const matchNode = nodes.find((n) => n.id === firstMatchId);
      if (matchNode) {
        setCenter(matchNode.position.x + 90, matchNode.position.y + 30, {
          zoom: 1.5,
          duration: 500,
        });
        const graphNode = graph.nodes.find((n) => n.id === firstMatchId) || null;
        setSelectedNode(graphNode);
      }
    }
  }, [searchMatchIds, nodes, setCenter, graph.nodes]);

  const handleNodeMouseEnter: NodeMouseHandler = useCallback((_event, node) => {
    setHoveredNodeId(node.id);
  }, []);

  const handleNodeMouseLeave: NodeMouseHandler = useCallback(() => {
    setHoveredNodeId(null);
  }, []);

  const handlePaneClick = useCallback(() => {
    setHoveredNodeId(null);
    setSelectedNode(null);
    setContextMenu(null);
    setShowExportMenu(false);
  }, []);

  const handleFitView = useCallback(() => {
    fitView({ padding: 0.15, duration: 400 });
  }, [fitView]);

  const visibleCount = initialNodes.length;
  const totalCount = graph.nodes.length;
  const isDefaultView = activeFilters.size === DEFAULT_VISIBLE.size &&
    [...DEFAULT_VISIBLE].every((t) => activeFilters.has(t));

  return (
    <div className="h-screen flex flex-col" style={{ background: 'var(--bg-primary)' }}>
      {/* Stats bar */}
      <StatsBar stats={graph.stats} scanPath={scanPath} onOpenAISettings={() => setShowAISettings(true)} />

      {/* Filter bar */}
      <FilterBar
        activeFilters={activeFilters}
        onToggle={handleToggleFilter}
        onReset={handleResetFilters}
        onFocus={handleFocusMode}
        typeCounts={typeCounts}
        isFocused={isDefaultView}
      />

      {/* Graph + Panels */}
      <div className="flex-1 flex relative overflow-hidden">
        {/* Graph canvas */}
        <div className="flex-1 relative min-w-0">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={handleNodeClick}
            onNodeContextMenu={handleNodeContextMenu}
            onNodeMouseEnter={handleNodeMouseEnter}
            onNodeMouseLeave={handleNodeMouseLeave}
            onPaneClick={handlePaneClick}
            nodeTypes={nodeTypes}
            connectionLineType={ConnectionLineType.SmoothStep}
            fitView
            fitViewOptions={{ padding: 0.15 }}
            minZoom={0.05}
            maxZoom={4}
            proOptions={{ hideAttribution: true }}
          >
            <Background color={isDark ? '#1F2937' : '#CBD5E1'} gap={20} size={1} />
            <Controls className={isDark
              ? '!bg-gray-800 !border-gray-700 !rounded-lg [&>button]:!bg-gray-800 [&>button]:!border-gray-700 [&>button]:!text-gray-300 [&>button:hover]:!bg-gray-700'
              : '!bg-white !border-gray-300 !rounded-lg [&>button]:!bg-white [&>button]:!border-gray-300 [&>button]:!text-gray-600 [&>button:hover]:!bg-gray-100'
            } />
            <MiniMap
              className={isDark ? '!bg-gray-900 !border-gray-800 !rounded-lg' : '!bg-white !border-gray-300 !rounded-lg'}
              nodeColor={(n) => {
                const data = n.data as { nodeType?: NodeType };
                return NODE_COLORS[data?.nodeType || 'file'] || '#475569';
              }}
              maskColor={isDark ? 'rgba(0,0,0,0.7)' : 'rgba(255,255,255,0.7)'}
              pannable
              zoomable
            />
          </ReactFlow>

          {/* Top toolbar */}
          <div className="absolute top-4 left-4 right-4 z-10 flex items-center gap-3 pointer-events-none">
            {/* Left group: Navigation */}
            <div className="flex items-center gap-1.5 pointer-events-auto rounded-xl border shadow-lg px-1.5 h-10"
              style={{ background: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <button
                onClick={onBack}
                className="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors"
                style={{ color: 'var(--text-primary)' }}
                onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
                onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
              >
                &larr; New Scan
              </button>
              {onRescan && (
                <>
                  <div className="w-px h-5" style={{ background: 'var(--border-primary)' }} />
                  <button
                    onClick={onRescan}
                    disabled={rescanning}
                    className="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors flex items-center gap-1.5 disabled:opacity-50"
                    style={{ color: rescanning ? 'var(--text-muted)' : 'var(--text-primary)' }}
                    onMouseEnter={(e) => { if (!rescanning) e.currentTarget.style.background = 'var(--bg-hover)'; }}
                    onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                    title={rescanning ? 'Scanning...' : 'Rescan the same codebase'}
                  >
                    <svg className={`w-3.5 h-3.5${rescanning ? ' animate-spin' : ''}`} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M1 1v5h5" />
                      <path d="M3.51 10a5 5 0 1 0 .49-5.18L1 6" />
                    </svg>
                    {rescanning ? 'Scanning...' : 'Rescan'}
                  </button>
                </>
              )}
              <div className="w-px h-5" style={{ background: 'var(--border-primary)' }} />
              <button
                onClick={() => {
                  if (window.confirm('This will delete all scan data from the server and return to the home screen. Continue?')) {
                    onClearAndExit();
                  }
                }}
                className="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors"
                style={{ color: 'var(--text-muted)' }}
                onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
                onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                title="Delete scan data from server memory and exit"
              >
                Clear &amp; Exit
              </button>
            </div>

            {/* Center group: Search */}
            <div className="pointer-events-auto rounded-xl border shadow-lg px-3 h-10 flex items-center gap-2 flex-1 max-w-md min-w-[200px]"
              style={{ background: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <form onSubmit={handleSearchSubmit} className="flex items-center flex-1 gap-2">
                <svg className="w-4 h-4 shrink-0" viewBox="0 0 20 20" fill="currentColor" style={{ color: 'var(--text-muted)' }}>
                  <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd" />
                </svg>
                <input
                  ref={searchInputRef}
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search nodes, files, vulnerabilities..."
                  className="bg-transparent text-sm focus:outline-none flex-1 min-w-0"
                  style={{ color: 'var(--text-primary)' }}
                />
                {searchQuery && (
                  <>
                    <span className="text-[11px] font-medium shrink-0 px-1.5 py-0.5 rounded"
                      style={{ background: searchMatchIds.size > 0 ? 'rgba(234,179,8,0.15)' : 'var(--bg-tertiary)', color: searchMatchIds.size > 0 ? '#EAB308' : 'var(--text-muted)' }}>
                      {searchMatchIds.size} found
                    </span>
                    <button
                      type="button"
                      onClick={() => { setSearchQuery(''); searchInputRef.current?.focus(); }}
                      className="w-5 h-5 rounded flex items-center justify-center shrink-0 transition-colors"
                      style={{ color: 'var(--text-muted)' }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
                      onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                    >
                      &times;
                    </button>
                  </>
                )}
              </form>
            </div>

            {/* Spacer */}
            <div className="flex-1 min-w-0" />

            {/* Right group: View controls & actions */}
            <div className="flex items-center gap-1.5 pointer-events-auto rounded-xl border shadow-lg px-1.5 h-10"
              style={{ background: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              {/* Node count */}
              <span className="px-2.5 py-1 text-xs font-medium shrink-0" style={{ color: 'var(--text-muted)' }}>
                {visibleCount}{visibleCount !== totalCount ? ` / ${totalCount}` : ''} nodes
              </span>

              <div className="w-px h-5" style={{ background: 'var(--border-primary)' }} />

              <button
                onClick={handleFitView}
                className="px-2.5 py-1.5 rounded-lg text-sm font-medium transition-colors"
                style={{ color: 'var(--text-primary)' }}
                onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
                onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                title="Fit all nodes in view"
              >
                Fit View
              </button>

              <div className="w-px h-5" style={{ background: 'var(--border-primary)' }} />

              {/* Export dropdown */}
              <div className="relative" ref={exportRef}>
                <button
                  onClick={() => setShowExportMenu(!showExportMenu)}
                  className="px-2.5 py-1.5 rounded-lg text-sm font-medium transition-colors flex items-center gap-1"
                  style={{ color: 'var(--text-primary)' }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
                  onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                  title="Export report"
                >
                  Export
                  <svg className="w-3 h-3" viewBox="0 0 12 12" fill="currentColor" style={{ opacity: 0.5 }}>
                    <path d="M3 5l3 3 3-3" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" />
                  </svg>
                </button>
                {showExportMenu && (
                  <div
                    className="absolute top-full mt-1 right-0 min-w-[140px] rounded-lg border shadow-lg overflow-hidden z-50"
                    style={{ background: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}
                  >
                    <button
                      onClick={() => { exportJSON(graph, scanPath); setShowExportMenu(false); }}
                      className="w-full text-left px-3 py-2 text-sm transition-colors"
                      style={{ color: 'var(--text-primary)', background: 'transparent' }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
                      onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                    >
                      JSON
                    </button>
                    <button
                      onClick={() => { exportMarkdown(graph, scanPath); setShowExportMenu(false); }}
                      className="w-full text-left px-3 py-2 text-sm transition-colors"
                      style={{ color: 'var(--text-primary)', background: 'transparent' }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
                      onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                    >
                      Markdown
                    </button>
                    <button
                      onClick={() => { exportSARIF(graph, scanPath); setShowExportMenu(false); }}
                      className="w-full text-left px-3 py-2 text-sm transition-colors"
                      style={{ color: 'var(--text-primary)', background: 'transparent' }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
                      onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                    >
                      SARIF
                    </button>
                  </div>
                )}
              </div>

              <div className="w-px h-5" style={{ background: 'var(--border-primary)' }} />

              {/* Toggle findings panel */}
              <button
                onClick={() => setShowFindings(!showFindings)}
                className="px-2.5 py-1.5 rounded-lg text-sm font-medium transition-colors"
                style={
                  showFindings
                    ? { background: 'rgba(37,99,235,0.15)', color: '#60A5FA' }
                    : { color: 'var(--text-secondary)' }
                }
                onMouseEnter={(e) => { if (!showFindings) e.currentTarget.style.background = 'var(--bg-hover)'; }}
                onMouseLeave={(e) => { if (!showFindings) e.currentTarget.style.background = 'transparent'; }}
                title={showFindings ? 'Hide findings panel' : 'Show findings panel'}
              >
                Findings
              </button>

              <div className="w-px h-5" style={{ background: 'var(--border-primary)' }} />

              {/* Help button */}
              <button
                onClick={() => setShowWelcome(true)}
                className="w-7 h-7 rounded-lg text-xs font-bold transition-colors flex items-center justify-center"
                style={{ color: 'var(--text-muted)' }}
                onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
                onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                title="Quick Start Guide"
              >
                ?
              </button>
            </div>
          </div>

          {/* Legend */}
          <Legend />

          {/* Node detail (shown when no side panel and a node is selected) */}
          {!showFindings && !deepDiveNode && selectedNode && (
            <NodeDetail node={selectedNode} onClose={() => setSelectedNode(null)} />
          )}
        </div>

        {/* Right panels — split-view layout (DeepDive | Findings) */}
        <div className="shrink-0 flex h-full">
          {/* Deep Dive panel */}
          {deepDiveNode && (
            <DeepDivePanel
              node={deepDiveNode}
              graph={graph}
              onClose={() => setDeepDiveNode(null)}
              onNavigate={handleDeepDiveNavigate}
            />
          )}

          {/* Findings panel */}
          {showFindings && (
            <FindingsPanel
              graph={graph}
              onFindingClick={handleFindingClick}
              onDeepDive={handleDeepDive}
              collapsed={findingsCollapsed}
              onToggleCollapse={() => setFindingsCollapsed(!findingsCollapsed)}
            />
          )}
        </div>
      </div>

      {/* Context menu */}
      {contextMenu && (
        <ContextMenu
          node={contextMenu.node}
          x={contextMenu.x}
          y={contextMenu.y}
          onClose={() => setContextMenu(null)}
          onDeepDive={handleDeepDive}
          onShowConnections={handleShowConnections}
          onCopyId={handleCopyId}
          onExportNode={handleExportNode}
          onCheckCVEs={handleCheckCVEs}
        />
      )}

      {/* AI Settings Modal */}
      <AISettingsModal open={showAISettings} onClose={() => setShowAISettings(false)} />

      {/* Welcome overlay for first-time users */}
      {showWelcome && (
        <WelcomeOverlay onDismiss={() => { setShowWelcome(false); dismissWelcome(); }} />
      )}
    </div>
  );
}

export default function GraphView(props: Props) {
  return (
    <ReactFlowProvider>
      <GraphViewInner {...props} />
    </ReactFlowProvider>
  );
}
