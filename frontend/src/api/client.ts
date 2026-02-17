import axios from 'axios';
import type { ScanResult, SecurityGraph } from '../types/graph';

const api = axios.create({ baseURL: '/api' });

export interface DirEntry {
  name: string;
  path: string;
  is_dir: boolean;
}

export interface BrowseResponse {
  current: string;
  parent: string | null;
  entries: DirEntry[];
}

export async function browsePath(path: string = '~'): Promise<BrowseResponse> {
  const { data } = await api.get<BrowseResponse>('/browse', { params: { path } });
  return data;
}

export async function startScan(path?: string, githubUrl?: string): Promise<ScanResult> {
  const { data } = await api.post<ScanResult>('/scan', {
    path: path || undefined,
    github_url: githubUrl || undefined,
  });
  return data;
}

export async function getScanStatus(scanId: string): Promise<ScanResult> {
  const { data } = await api.get<ScanResult>(`/scan/${scanId}`);
  return data;
}

export async function getGraph(scanId: string): Promise<SecurityGraph> {
  const { data } = await api.get<SecurityGraph>(`/graph/${scanId}`);
  return data;
}

export interface SourceContextResponse {
  lines: string[];
  start_line: number;
  file_path: string;
}

export async function getSourceContext(path: string, line: number, context: number = 5): Promise<SourceContextResponse> {
  const { data } = await api.get<SourceContextResponse>('/source', {
    params: { path, line, context },
  });
  return data;
}

export interface CVEEntry {
  id: string;
  summary: string;
  severity?: string;
  affected_versions?: string;
  fixed_version?: string;
  url?: string;
}

export interface CVELookupResponse {
  package_name: string;
  version?: string;
  vulns: CVEEntry[];
}

export async function lookupCVEs(packageName: string, version?: string, ecosystem: string = 'npm'): Promise<CVELookupResponse> {
  const { data } = await api.post<CVELookupResponse>('/cve-lookup', {
    package_name: packageName,
    version: version || undefined,
    ecosystem,
  });
  return data;
}

export interface RemediateRequest {
  provider: string;
  api_key: string;
  model: string;
  node: Record<string, unknown>;
  source_context?: string;
}

export interface RemediateResponse {
  remediation: string;
}

export async function getAIRemediation(req: RemediateRequest): Promise<RemediateResponse> {
  const { data } = await api.post<RemediateResponse>('/remediate', req);
  return data;
}

export async function deleteScan(scanId: string): Promise<void> {
  await api.delete(`/scan/${scanId}`);
}
