export type NodeType =
  | 'entry_point'
  | 'service'
  | 'external_api'
  | 'data_store'
  | 'secret'
  | 'vulnerability'
  | 'auth_boundary'
  | 'dependency'
  | 'file';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type EdgeType =
  | 'data_flow'
  | 'authentication'
  | 'uses_secret'
  | 'connects_to'
  | 'belongs_to'
  | 'has_vulnerability'
  | 'depends_on'
  | 'imports';

export interface GraphNode {
  id: string;
  label: string;
  node_type: NodeType;
  severity?: Severity;
  file_path?: string;
  line_number: number;
  description?: string;
  metadata: Record<string, unknown>;
  parent_id?: string;
  source_snippet?: string;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  edge_type: EdgeType;
  label?: string;
  metadata: Record<string, unknown>;
}

export interface GraphStats {
  total_files_scanned: number;
  total_nodes: number;
  total_edges: number;
  entry_points: number;
  external_apis: number;
  data_stores: number;
  secrets: number;
  vulnerabilities: number;
  dependencies: number;
  risk_score: number;
  severity_counts: Record<string, number>;
  languages_detected: string[];
}

export interface SecurityGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: GraphStats;
}

export type ScanStatus = 'pending' | 'scanning' | 'building_graph' | 'complete' | 'error';

export interface ScanResult {
  scan_id: string;
  status: ScanStatus;
  progress: number;
  message: string;
  scan_path?: string;
  started_at?: string;
  completed_at?: string;
  error?: string;
}

export const NODE_COLORS: Record<NodeType, string> = {
  entry_point: '#3B82F6',
  service: '#8B5CF6',
  external_api: '#F97316',
  data_store: '#10B981',
  secret: '#EF4444',
  vulnerability: '#DC2626',
  auth_boundary: '#EAB308',
  dependency: '#6B7280',
  file: '#475569',
};

export const NODE_LABELS: Record<NodeType, string> = {
  entry_point: 'Entry Point',
  service: 'Service',
  external_api: 'External API',
  data_store: 'Data Store',
  secret: 'Secret',
  vulnerability: 'Vulnerability',
  auth_boundary: 'Trust Boundary',
  dependency: 'Dependency',
  file: 'File',
};

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#DC2626',
  high: '#F97316',
  medium: '#EAB308',
  low: '#3B82F6',
  info: '#6B7280',
};
