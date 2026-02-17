import Dagre from '@dagrejs/dagre';
import type { Node, Edge } from '@xyflow/react';
import type { NodeType } from '../types/graph';

// Cluster order for visual hierarchy (left → right)
const CLUSTER_ORDER: NodeType[] = [
  'entry_point',
  'service',
  'external_api',
  'data_store',
  'secret',
  'vulnerability',
  'auth_boundary',
  'dependency',
];

export function layoutGraph(
  nodes: Node[],
  edges: Edge[],
): { nodes: Node[]; edges: Edge[] } {
  if (nodes.length === 0) return { nodes, edges };

  // Auto-select: use clustered for large graphs (>40 nodes)
  if (nodes.length > 40) {
    return clusteredLayout(nodes, edges);
  }
  return dagreLayout(nodes, edges);
}

function dagreLayout(nodes: Node[], edges: Edge[]): { nodes: Node[]; edges: Edge[] } {
  const g = new Dagre.graphlib.Graph().setDefaultEdgeLabel(() => ({}));

  g.setGraph({
    rankdir: 'LR',
    nodesep: 80,
    ranksep: 150,
    edgesep: 40,
    marginx: 50,
    marginy: 50,
  });

  nodes.forEach((node) => {
    g.setNode(node.id, { width: 230, height: 80 });
  });

  edges.forEach((edge) => {
    g.setEdge(edge.source, edge.target);
  });

  Dagre.layout(g);

  const layoutedNodes = nodes.map((node) => {
    const pos = g.node(node.id);
    return {
      ...node,
      position: {
        x: pos.x - 100,
        y: pos.y - 32,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
}

function clusteredLayout(nodes: Node[], edges: Edge[]): { nodes: Node[]; edges: Edge[] } {
  // Group nodes by their type
  const clusters = new Map<string, Node[]>();
  for (const node of nodes) {
    const data = node.data as { nodeType?: NodeType };
    const type = data?.nodeType || 'file';
    if (!clusters.has(type)) clusters.set(type, []);
    clusters.get(type)!.push(node);
  }

  const layoutedNodes: Node[] = [];

  const clusterPadding = 140;
  const nodeWidth = 230;
  const nodeHeight = 80;
  const nodeGapX = 40;
  const nodeGapY = 36;
  const maxColsPerCluster = 3;
  const clusterHeaderHeight = 50; // space for cluster label

  let clusterX = 0;

  // Position clusters left-to-right in visual hierarchy order
  const orderedTypes = CLUSTER_ORDER.filter((t) => clusters.has(t));
  for (const t of clusters.keys()) {
    if (!orderedTypes.includes(t as NodeType)) orderedTypes.push(t as NodeType);
  }

  for (const type of orderedTypes) {
    const clusterNodes = clusters.get(type);
    if (!clusterNodes) continue;

    const cols = Math.min(maxColsPerCluster, clusterNodes.length);

    for (let i = 0; i < clusterNodes.length; i++) {
      const col = i % cols;
      const row = Math.floor(i / cols);
      layoutedNodes.push({
        ...clusterNodes[i],
        position: {
          x: clusterX + col * (nodeWidth + nodeGapX),
          y: clusterHeaderHeight + row * (nodeHeight + nodeGapY),
        },
      });
    }

    const clusterWidth = cols * (nodeWidth + nodeGapX);
    clusterX += clusterWidth + clusterPadding;
  }

  // Center each cluster vertically
  const maxY = Math.max(...layoutedNodes.map((n) => n.position.y), 0);
  const centerY = maxY / 2;

  for (const type of orderedTypes) {
    const typeNodes = layoutedNodes.filter((n) => {
      const d = n.data as { nodeType?: NodeType };
      return d?.nodeType === type;
    });
    if (typeNodes.length === 0) continue;

    const minY = Math.min(...typeNodes.map((n) => n.position.y));
    const localMaxY = Math.max(...typeNodes.map((n) => n.position.y));
    const localCenter = (localMaxY - minY) / 2;
    const offset = centerY - localCenter - minY;

    for (const n of typeNodes) {
      n.position.y += offset;
    }
  }

  return { nodes: layoutedNodes, edges };
}
