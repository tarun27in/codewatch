/**
 * Parse imported report files (JSON, SARIF, Markdown) into a SecurityGraph-compatible object.
 */

import type { SecurityGraph, GraphNode, GraphEdge, GraphStats, Severity, NodeType } from '../types/graph';

interface ImportResult {
  scan_path?: string;
  scanPath?: string;
  stats: GraphStats;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/**
 * Detect file format and parse into graph data.
 */
export function parseImportedFile(content: string, filename: string): ImportResult {
  const ext = filename.toLowerCase().split('.').pop() || '';

  // SARIF files
  if (ext === 'sarif' || content.includes('"$schema"') && content.includes('sarif')) {
    return parseSARIF(content);
  }

  // Markdown files
  if (ext === 'md' || ext === 'markdown') {
    return parseMarkdown(content);
  }

  // JSON (our native format)
  const data = JSON.parse(content);

  // Check if it's a SARIF JSON without .sarif extension
  if (data.$schema && data.version === '2.1.0' && data.runs) {
    return parseSARIF(content);
  }

  // Native JSON format — validate required fields
  if (!data.nodes || !data.edges || !data.stats) {
    throw new Error('Invalid JSON report: missing nodes, edges, or stats');
  }

  return data as ImportResult;
}

/**
 * Parse SARIF 2.1.0 format into SecurityGraph data.
 */
function parseSARIF(content: string): ImportResult {
  const sarif = JSON.parse(content);

  if (!sarif.runs || sarif.runs.length === 0) {
    throw new Error('Invalid SARIF: no runs found');
  }

  const run = sarif.runs[0];
  const results = run.results || [];
  const rules = run.tool?.driver?.rules || [];
  const invocation = run.invocations?.[0] || {};

  // Build rule lookup
  const ruleMap: Record<string, { shortDescription?: { text: string }; defaultConfiguration?: { level: string }; properties?: Record<string, unknown> }> = {};
  for (const rule of rules) {
    ruleMap[rule.id] = rule;
  }

  const nodes: GraphNode[] = [];
  const severityCounts: Record<string, number> = {};
  let vulnCount = 0;
  let secretCount = 0;
  let entryCount = 0;
  let apiCount = 0;
  let storeCount = 0;
  let depCount = 0;

  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    const rule = ruleMap[result.ruleId] || {};
    const props = result.properties || {};
    const ruleProps = rule.properties || {};

    // Map SARIF level back to severity
    const level = result.level || rule.defaultConfiguration?.level || 'note';
    const severity: Severity = level === 'error'
      ? ((ruleProps.severity as Severity) || 'high')
      : level === 'warning' ? 'medium' : 'low';

    // Determine node type from properties or ruleId
    const nodeType: NodeType = (props.nodeType as NodeType) || inferNodeType(result.ruleId || '', severity);

    // Count by type
    if (nodeType === 'vulnerability') vulnCount++;
    else if (nodeType === 'secret') secretCount++;
    else if (nodeType === 'entry_point') entryCount++;
    else if (nodeType === 'external_api') apiCount++;
    else if (nodeType === 'data_store') storeCount++;
    else if (nodeType === 'dependency') depCount++;

    if (severity) severityCounts[severity] = (severityCounts[severity] || 0) + 1;

    const location = result.locations?.[0]?.physicalLocation;
    const filePath = location?.artifactLocation?.uri || '';
    const lineNumber = location?.region?.startLine || 0;

    nodes.push({
      id: props.nodeId as string || `sarif-${i}`,
      label: rule.shortDescription?.text || result.message?.text || `Finding ${i + 1}`,
      node_type: nodeType,
      severity,
      file_path: filePath,
      line_number: lineNumber,
      description: result.message?.text || '',
      metadata: { ...props, source: 'sarif-import' },
    });
  }

  const scanPath = invocation.properties?.scanPath || 'SARIF import';

  const stats: GraphStats = {
    total_files_scanned: invocation.properties?.filesScanned || 0,
    total_nodes: nodes.length,
    total_edges: 0,
    entry_points: entryCount,
    external_apis: apiCount,
    data_stores: storeCount,
    secrets: secretCount,
    vulnerabilities: vulnCount,
    dependencies: depCount,
    risk_score: invocation.properties?.riskScore || 0,
    severity_counts: severityCounts,
    languages_detected: [],
  };

  return { scan_path: scanPath as string, stats, nodes, edges: [] };
}

/**
 * Parse Markdown report format back into SecurityGraph data.
 */
function parseMarkdown(content: string): ImportResult {
  const nodes: GraphNode[] = [];
  const severityCounts: Record<string, number> = {};
  let scanPath = 'Markdown import';
  let riskScore = 0;
  let filesScanned = 0;
  let entryPoints = 0;
  let externalApis = 0;
  let dataStores = 0;
  let secrets = 0;
  let vulns = 0;
  let deps = 0;

  // Extract scanned path and risk score from header
  const headerMatch = content.match(/\*\*Scanned\*\*:\s*`([^`]+)`.*\*\*Risk Score\*\*:\s*([\d.]+)/);
  if (headerMatch) {
    scanPath = headerMatch[1];
    riskScore = parseFloat(headerMatch[2]) || 0;
  }

  // Extract summary table values
  const tableRows = content.match(/\|\s*([^|]+)\s*\|\s*(\d+)\s*\|/g) || [];
  for (const row of tableRows) {
    const match = row.match(/\|\s*([^|]+)\s*\|\s*(\d+)\s*\|/);
    if (!match) continue;
    const metric = match[1].trim().toLowerCase();
    const value = parseInt(match[2]);
    if (metric.includes('files scanned')) filesScanned = value;
    else if (metric.includes('entry point')) entryPoints = value;
    else if (metric.includes('external api')) externalApis = value;
    else if (metric.includes('data store')) dataStores = value;
    else if (metric.includes('secret')) secrets = value;
    else if (metric.includes('vulnerabilit')) vulns = value;
    else if (metric.includes('dependenc')) deps = value;
  }

  // Extract severity counts
  const sevRows = content.match(/\|\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*\|\s*(\d+)\s*\|/gi) || [];
  for (const row of sevRows) {
    const match = row.match(/\|\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*\|\s*(\d+)\s*\|/i);
    if (match) {
      severityCounts[match[1].toLowerCase()] = parseInt(match[2]);
    }
  }

  // Extract findings from "### N. [SEVERITY] Label" pattern
  const findingPattern = /###\s*\d+\.\s*\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(.+)/gi;
  let findingMatch;
  let nodeIdx = 0;

  while ((findingMatch = findingPattern.exec(content)) !== null) {
    const severity = findingMatch[1].toLowerCase() as Severity;
    const label = findingMatch[2].trim();

    // Try to extract file path from the next few lines
    const afterMatch = content.substring(findingMatch.index, findingMatch.index + 500);
    const fileMatch = afterMatch.match(/\*\*File\*\*:\s*`([^`]+)`/);
    const descMatch = afterMatch.match(/\*\*Description\*\*:\s*(.+)/);
    const typeMatch = afterMatch.match(/\*\*Type\*\*:\s*(.+)/);

    const filePath = fileMatch?.[1] || '';
    const lineMatch = filePath.match(/:(\d+)$/);
    const lineNumber = lineMatch ? parseInt(lineMatch[1]) : 0;
    const cleanPath = filePath.replace(/:\d+$/, '');

    const nodeType = inferNodeTypeFromLabel(typeMatch?.[1] || '', label, severity);

    nodes.push({
      id: `md-${nodeIdx++}`,
      label,
      node_type: nodeType,
      severity,
      file_path: cleanPath,
      line_number: lineNumber,
      description: descMatch?.[1]?.trim() || '',
      metadata: { source: 'markdown-import' },
    });
  }

  // Also extract bullet-point findings: "- **Label** [SEVERITY] — `path`"
  const bulletPattern = /^-\s*\*\*(.+?)\*\*\s*(?:\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\])?\s*(?:—|-)?\s*(?:`([^`]*)`)?/gm;
  let bulletMatch;

  while ((bulletMatch = bulletPattern.exec(content)) !== null) {
    const label = bulletMatch[1].trim();
    const severity = (bulletMatch[2]?.toLowerCase() as Severity) || undefined;
    const filePath = bulletMatch[3] || '';

    // Skip if we already captured this finding in the numbered section
    if (nodes.some((n) => n.label === label)) continue;

    const lineMatch = filePath.match(/:(\d+)$/);
    const lineNumber = lineMatch ? parseInt(lineMatch[1]) : 0;
    const cleanPath = filePath.replace(/:\d+$/, '');

    if (severity) {
      nodes.push({
        id: `md-${nodeIdx++}`,
        label,
        node_type: inferNodeTypeFromLabel('', label, severity),
        severity,
        file_path: cleanPath,
        line_number: lineNumber,
        description: '',
        metadata: { source: 'markdown-import' },
      });
    }
  }

  const stats: GraphStats = {
    total_files_scanned: filesScanned,
    total_nodes: nodes.length,
    total_edges: 0,
    entry_points: entryPoints,
    external_apis: externalApis,
    data_stores: dataStores,
    secrets,
    vulnerabilities: vulns,
    dependencies: deps,
    risk_score: riskScore,
    severity_counts: severityCounts,
    languages_detected: [],
  };

  return { scan_path: scanPath, stats, nodes, edges: [] };
}

function inferNodeType(ruleId: string, severity: Severity): NodeType {
  if (ruleId.includes('secret')) return 'secret';
  if (ruleId.includes('vulnerability')) return 'vulnerability';
  if (ruleId.includes('entry_point')) return 'entry_point';
  if (ruleId.includes('external_api')) return 'external_api';
  if (ruleId.includes('data_store')) return 'data_store';
  if (ruleId.includes('dependency')) return 'dependency';
  if (severity === 'critical' || severity === 'high') return 'vulnerability';
  return 'vulnerability';
}

function inferNodeTypeFromLabel(typeLabel: string, label: string, severity?: Severity): NodeType {
  const t = typeLabel.toLowerCase();
  const l = label.toLowerCase();
  if (t.includes('vulnerability') || l.includes('vuln')) return 'vulnerability';
  if (t.includes('secret') || l.includes('secret') || l.includes('key') || l.includes('token') || l.includes('password')) return 'secret';
  if (t.includes('entry') || l.includes('endpoint') || l.includes('route')) return 'entry_point';
  if (t.includes('external') || l.includes('api') || l.includes('url')) return 'external_api';
  if (t.includes('data') || l.includes('database') || l.includes('storage') || l.includes('bucket')) return 'data_store';
  if (t.includes('depend') || l.includes('package') || l.includes('dep')) return 'dependency';
  return 'vulnerability';
}
