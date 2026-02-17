import type { SecurityGraph, GraphNode, Severity } from '../types/graph';
import { NODE_LABELS, SEVERITY_COLORS } from '../types/graph';

// SARIF severity mapping
const SARIF_LEVEL: Record<string, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

const SEV_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

function downloadFile(content: string, filename: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportJSON(graph: SecurityGraph, scanPath: string) {
  const report = {
    scan_path: scanPath,
    generated_at: new Date().toISOString(),
    stats: graph.stats,
    nodes: graph.nodes,
    edges: graph.edges,
  };
  downloadFile(JSON.stringify(report, null, 2), 'security-report.json', 'application/json');
}

export function exportMarkdown(graph: SecurityGraph, scanPath: string) {
  const now = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const { stats } = graph;

  const lines: string[] = [];

  lines.push('# Security Scan Report');
  lines.push('');
  lines.push(`**Scanned**: \`${scanPath}\` | **Date**: ${now} | **Risk Score**: ${stats.risk_score.toFixed(1)}/10`);
  lines.push('');

  // Summary table
  lines.push('## Summary');
  lines.push('');
  lines.push('| Metric | Count |');
  lines.push('|--------|-------|');
  lines.push(`| Files Scanned | ${stats.total_files_scanned} |`);
  lines.push(`| Entry Points | ${stats.entry_points} |`);
  lines.push(`| External APIs | ${stats.external_apis} |`);
  lines.push(`| Data Stores | ${stats.data_stores} |`);
  lines.push(`| Secrets | ${stats.secrets} |`);
  lines.push(`| Vulnerabilities | ${stats.vulnerabilities} |`);
  lines.push(`| Dependencies | ${stats.dependencies} |`);
  lines.push('');

  // Severity breakdown
  if (Object.keys(stats.severity_counts).length > 0) {
    lines.push('### Severity Breakdown');
    lines.push('');
    lines.push('| Severity | Count |');
    lines.push('|----------|-------|');
    for (const [sev, count] of Object.entries(stats.severity_counts)) {
      lines.push(`| ${sev.toUpperCase()} | ${count} |`);
    }
    lines.push('');
  }

  // Languages
  if (stats.languages_detected.length > 0) {
    lines.push(`**Languages**: ${stats.languages_detected.join(', ')}`);
    lines.push('');
  }

  // Critical and High findings
  const criticalHigh = graph.nodes
    .filter((n) => n.severity === 'critical' || n.severity === 'high')
    .sort((a, b) => (SEV_ORDER[a.severity || 'info'] ?? 5) - (SEV_ORDER[b.severity || 'info'] ?? 5));

  if (criticalHigh.length > 0) {
    lines.push('## Critical & High Findings');
    lines.push('');
    criticalHigh.forEach((node, i) => {
      lines.push(`### ${i + 1}. [${(node.severity || 'unknown').toUpperCase()}] ${node.label}`);
      lines.push('');
      lines.push(`- **Type**: ${NODE_LABELS[node.node_type]}`);
      if (node.file_path) {
        lines.push(`- **File**: \`${node.file_path}${node.line_number > 0 ? `:${node.line_number}` : ''}\``);
      }
      if (node.description) {
        lines.push(`- **Description**: ${node.description}`);
      }
      lines.push('');
    });
  }

  // All findings by category
  const categories: { type: string; label: string }[] = [
    { type: 'vulnerability', label: 'Vulnerabilities' },
    { type: 'secret', label: 'Exposed Secrets' },
    { type: 'entry_point', label: 'Entry Points' },
    { type: 'external_api', label: 'External Connections' },
    { type: 'data_store', label: 'Data Stores' },
    { type: 'dependency', label: 'Dependencies' },
  ];

  lines.push('## All Findings by Category');
  lines.push('');

  for (const cat of categories) {
    const nodes = graph.nodes
      .filter((n) => n.node_type === cat.type)
      .sort((a, b) => (SEV_ORDER[a.severity || 'info'] ?? 5) - (SEV_ORDER[b.severity || 'info'] ?? 5));

    if (nodes.length === 0) continue;

    lines.push(`### ${cat.label} (${nodes.length})`);
    lines.push('');

    for (const node of nodes) {
      const sev = node.severity ? ` [${node.severity.toUpperCase()}]` : '';
      const loc = node.file_path ? ` — \`${node.file_path}${node.line_number > 0 ? `:${node.line_number}` : ''}\`` : '';
      lines.push(`- **${node.label}**${sev}${loc}`);
      if (node.description) {
        lines.push(`  ${node.description}`);
      }
    }
    lines.push('');
  }

  // Graph connections summary
  lines.push('## Graph Connections');
  lines.push('');
  lines.push(`Total edges: ${graph.edges.length}`);
  lines.push('');

  const edgeTypeCounts: Record<string, number> = {};
  for (const e of graph.edges) {
    edgeTypeCounts[e.edge_type] = (edgeTypeCounts[e.edge_type] || 0) + 1;
  }
  lines.push('| Edge Type | Count |');
  lines.push('|-----------|-------|');
  for (const [type, count] of Object.entries(edgeTypeCounts)) {
    lines.push(`| ${type.replace(/_/g, ' ')} | ${count} |`);
  }
  lines.push('');

  lines.push('---');
  lines.push('*Generated by Security Knowledge Graph*');

  downloadFile(lines.join('\n'), 'security-report.md', 'text/markdown');
}

export function exportSARIF(graph: SecurityGraph, scanPath: string) {
  // Build SARIF 2.1.0 compliant output
  const rules: Record<string, { id: string; shortDescription: { text: string }; fullDescription?: { text: string }; defaultConfiguration: { level: string }; properties?: Record<string, unknown> }> = {};
  const results: Array<Record<string, unknown>> = [];

  // Only include nodes that have severity (findings)
  const findingNodes = graph.nodes.filter((n) => n.severity);

  for (const node of findingNodes) {
    const ruleId = `skg/${node.node_type}/${(node.metadata?.vuln_type as string) || node.label.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;

    if (!rules[ruleId]) {
      rules[ruleId] = {
        id: ruleId,
        shortDescription: { text: node.label },
        fullDescription: node.description ? { text: node.description } : undefined,
        defaultConfiguration: { level: SARIF_LEVEL[node.severity || 'info'] || 'note' },
        properties: {
          severity: node.severity,
          nodeType: node.node_type,
        },
      };
    }

    const result: Record<string, unknown> = {
      ruleId,
      level: SARIF_LEVEL[node.severity || 'info'] || 'note',
      message: { text: node.description || node.label },
      locations: node.file_path
        ? [
            {
              physicalLocation: {
                artifactLocation: { uri: node.file_path, uriBaseId: '%SRCROOT%' },
                region: node.line_number > 0 ? { startLine: node.line_number } : undefined,
              },
            },
          ]
        : [],
      properties: {
        nodeId: node.id,
        nodeType: node.node_type,
        ...node.metadata,
      },
    };

    results.push(result);
  }

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Security Knowledge Graph',
            version: '0.1.0',
            informationUri: 'https://github.com/tarun27in/codewatch',
            rules: Object.values(rules),
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: new Date().toISOString(),
            properties: {
              scanPath,
              riskScore: graph.stats.risk_score,
              totalNodes: graph.stats.total_nodes,
              totalEdges: graph.stats.total_edges,
              filesScanned: graph.stats.total_files_scanned,
            },
          },
        ],
      },
    ],
  };

  downloadFile(JSON.stringify(sarif, null, 2), 'security-report.sarif', 'application/sarif+json');
}
