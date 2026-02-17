import { useState, useMemo } from 'react';
import type { GraphNode, SecurityGraph, Severity, NodeType } from '../types/graph';
import { NODE_COLORS, NODE_LABELS, SEVERITY_COLORS } from '../types/graph';
import { getAIRemediation } from '../api/client';
import { loadAISettings } from './AISettingsModal';

/** Minimal markdown → HTML for AI responses */
function renderMarkdown(md: string): string {
  return md
    // Code blocks
    .replace(/```(\w*)\n([\s\S]*?)```/g, '<pre style="background:var(--bg-tertiary);padding:0.75rem;border-radius:0.5rem;overflow-x:auto;font-size:0.75rem;margin:0.5rem 0"><code>$2</code></pre>')
    // Inline code
    .replace(/`([^`]+)`/g, '<code style="background:var(--bg-tertiary);padding:0.125rem 0.375rem;border-radius:0.25rem;font-size:0.8em">$1</code>')
    // Bold
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    // Headers
    .replace(/^#### (.+)$/gm, '<p style="font-weight:600;margin-top:0.75rem;margin-bottom:0.25rem;font-size:0.8rem;color:var(--text-primary)">$1</p>')
    .replace(/^### (.+)$/gm, '<p style="font-weight:700;margin-top:1rem;margin-bottom:0.25rem;font-size:0.85rem;color:var(--text-primary)">$1</p>')
    .replace(/^## (.+)$/gm, '<p style="font-weight:700;margin-top:1rem;margin-bottom:0.25rem;font-size:0.9rem;color:var(--text-primary)">$1</p>')
    // Numbered lists
    .replace(/^\d+\.\s+(.+)$/gm, '<li style="margin-left:1rem;margin-bottom:0.25rem">$1</li>')
    // Bullet lists
    .replace(/^[-*]\s+(.+)$/gm, '<li style="margin-left:1rem;margin-bottom:0.25rem">$1</li>')
    // Paragraphs (double newline)
    .replace(/\n\n/g, '<br/><br/>');
}

interface Props {
  graph: SecurityGraph;
  onFindingClick: (node: GraphNode) => void;
  onDeepDive?: (node: GraphNode) => void;
  collapsed?: boolean;
  onToggleCollapse?: () => void;
}

// Severity ordering for sort
const SEV_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

// Finding categories for grouping
type FindingCategory = 'vulnerability' | 'secret' | 'entry_point' | 'external_api' | 'data_store' | 'dependency';

const CATEGORY_LABELS: Record<FindingCategory, string> = {
  vulnerability: 'Vulnerabilities',
  secret: 'Exposed Secrets',
  entry_point: 'Unprotected Entry Points',
  external_api: 'External Connections',
  data_store: 'Data Stores',
  dependency: 'Risky Dependencies',
};

const FINDING_CATEGORIES: FindingCategory[] = [
  'vulnerability', 'secret', 'entry_point', 'external_api', 'data_store', 'dependency',
];

// Generate remediation steps based on finding type and metadata
function getRemediation(node: GraphNode): { impact: string; steps: string[] } {
  const meta = node.metadata || {};
  const desc = (node.description || '').toLowerCase();
  const label = node.label.toLowerCase();

  // Vulnerability findings
  if (node.node_type === 'vulnerability') {
    // Historical secrets found in git history
    if (meta.vuln_type === 'historical_secret') {
      return {
        impact: 'This secret is exposed in git history even though it was removed from the current codebase. Anyone with repo access can retrieve it.',
        steps: [
          'Rotate the credential immediately — assume it has been compromised',
          'Use git-filter-repo or BFG Repo-Cleaner to purge the secret from git history',
          'Force-push the cleaned history to all remotes',
          'Enable pre-commit hooks (e.g., git-secrets, detect-secrets) to prevent future leaks',
          'Set up automated secret scanning in CI/CD (GitHub secret scanning, GitLeaks, TruffleHog)',
        ],
      };
    }
    if (desc.includes('no auth') || desc.includes('unauthenticated') || desc.includes('missing auth')) {
      return {
        impact: 'Unauthenticated endpoints can be accessed by anyone, leading to unauthorized data access or actions.',
        steps: [
          'Add authentication middleware (e.g., Depends(get_current_user) for FastAPI, passport.js for Express)',
          'Implement role-based access control (RBAC) if different permission levels are needed',
          `Review the route at ${node.file_path}:${node.line_number} and determine the required auth level`,
          'Add rate limiting to prevent brute-force attacks',
          'Write integration tests that verify 401/403 responses for unauthenticated requests',
        ],
      };
    }
    if (desc.includes('tls') || desc.includes('verify=false') || desc.includes('ssl')) {
      return {
        impact: 'Disabling TLS verification allows man-in-the-middle attacks, exposing transmitted data.',
        steps: [
          'Remove verify=False from HTTP client calls',
          'Configure proper CA certificate bundles for internal services',
          'If using self-signed certs for development, use environment-specific config instead of disabling verification',
          'Add SSL/TLS configuration validation to your CI pipeline',
        ],
      };
    }
    if (desc.includes('eval') || desc.includes('exec') || desc.includes('code injection')) {
      return {
        impact: 'Code injection vulnerabilities allow attackers to execute arbitrary code on your server.',
        steps: [
          `Remove eval()/exec() usage at ${node.file_path}:${node.line_number}`,
          'Use safe alternatives: ast.literal_eval() for Python, JSON.parse() for JS',
          'If dynamic code execution is required, use a sandboxed environment',
          'Add input validation and sanitization before any dynamic evaluation',
          'Implement Content Security Policy (CSP) headers to mitigate XSS',
        ],
      };
    }
    if (desc.includes('shell=true') || desc.includes('subprocess') || desc.includes('command injection')) {
      return {
        impact: 'Command injection allows attackers to execute OS commands, potentially compromising the entire server.',
        steps: [
          'Replace shell=True with shell=False and pass arguments as a list',
          'Use shlex.quote() to escape user-provided arguments',
          'Validate and whitelist allowed commands/arguments',
          'Consider using higher-level Python libraries instead of subprocess calls',
          'Audit all subprocess/exec calls for user-input injection points',
        ],
      };
    }
    if (desc.includes('innerhtml') || desc.includes('dangerouslysetinnerhtml') || desc.includes('xss')) {
      return {
        impact: 'XSS vulnerabilities allow attackers to inject malicious scripts into your web pages.',
        steps: [
          'Replace innerHTML/dangerouslySetInnerHTML with safe text rendering',
          'Use a sanitization library like DOMPurify for any HTML content',
          'Implement Content Security Policy (CSP) headers',
          'Enable automatic output encoding in your template engine',
          'Use React\'s built-in JSX escaping — avoid bypassing it',
        ],
      };
    }
    if (desc.includes('http://') || desc.includes('non-https') || desc.includes('insecure')) {
      return {
        impact: 'Non-HTTPS connections transmit data in plaintext, vulnerable to interception.',
        steps: [
          'Replace http:// URLs with https:// equivalents',
          'Configure HSTS headers to enforce HTTPS',
          'Update internal service communication to use TLS',
          'Add automated checks for non-HTTPS URLs in CI pipeline',
        ],
      };
    }
    if (desc.includes('todo') || desc.includes('fixme') || desc.includes('hack')) {
      return {
        impact: 'Security TODOs indicate known issues that haven\'t been addressed yet.',
        steps: [
          `Review the TODO at ${node.file_path}:${node.line_number}`,
          'Create a tracking ticket for each security TODO',
          'Prioritize based on exposure and severity',
          'Remove resolved TODOs and verify the fix',
        ],
      };
    }
    if (meta.vuln_type === 'sql_injection' || desc.includes('sql injection') || desc.includes('parameterized')) {
      return {
        impact: 'SQL injection allows attackers to read, modify, or delete database contents and potentially execute OS commands.',
        steps: [
          `Replace string interpolation at ${node.file_path}:${node.line_number} with parameterized queries`,
          'Use ORM methods (e.g., SQLAlchemy, Prisma, Sequelize) instead of raw SQL where possible',
          'If raw SQL is needed, use query parameters (?, $1, :param) instead of string formatting',
          'Add input validation and type checking before any database operations',
          'Enable SQL query logging in development to catch injection patterns early',
        ],
      };
    }
    if (meta.vuln_type === 'weak_cryptography' || desc.includes('md5') || desc.includes('sha-1') || desc.includes('math.random') || desc.includes('random.random')) {
      return {
        impact: 'Weak cryptographic functions can be broken, allowing password cracking, hash collisions, or predictable random values.',
        steps: [
          `Replace the weak algorithm at ${node.file_path}:${node.line_number}`,
          'For hashing: use SHA-256, SHA-3, or bcrypt/argon2 for passwords',
          'For random values: use crypto.getRandomValues() (JS) or secrets module (Python)',
          'For encryption: use AES-256-GCM instead of DES/RC4/Blowfish',
          'Audit all crypto usage in the codebase for similar patterns',
        ],
      };
    }
    if (meta.vuln_type === 'debug_enabled' || desc.includes('debug mode') || desc.includes('debug=true')) {
      return {
        impact: 'Debug mode exposes stack traces, internal state, and may allow code execution (Flask debugger).',
        steps: [
          `Disable debug mode at ${node.file_path}:${node.line_number}`,
          'Use environment variables to control debug settings (never hardcode True)',
          'Ensure production deployments set DEBUG=False / NODE_ENV=production',
          'Configure a proper error handler that returns generic messages to users',
        ],
      };
    }
    if (meta.vuln_type === 'path_traversal' || desc.includes('path traversal') || desc.includes('directory traversal')) {
      return {
        impact: 'Path traversal allows attackers to read or write files outside intended directories, potentially accessing sensitive system files.',
        steps: [
          `Validate file paths at ${node.file_path}:${node.line_number} before use`,
          'Use os.path.realpath() / path.resolve() and verify the result is within allowed directory',
          'Never construct file paths from user input with string concatenation',
          'Use allowlists for permitted file paths or directories',
        ],
      };
    }
    if (meta.vuln_type === 'insecure_deserialization' || desc.includes('pickle') || desc.includes('deserialization')) {
      return {
        impact: 'Insecure deserialization can lead to remote code execution — attackers craft malicious payloads that execute when deserialized.',
        steps: [
          `Replace the unsafe deserialization at ${node.file_path}:${node.line_number}`,
          'Use JSON for data serialization instead of pickle/marshal',
          'For YAML: use yaml.safe_load() instead of yaml.load()',
          'If pickle is required, use hmac signing to verify data integrity before loading',
          'Never deserialize untrusted data from user input or external sources',
        ],
      };
    }
    if (meta.vuln_type === 'ssrf' || desc.includes('ssrf')) {
      return {
        impact: 'SSRF allows attackers to make the server send requests to internal services, accessing metadata endpoints or private networks.',
        steps: [
          `Validate and sanitize the URL at ${node.file_path}:${node.line_number}`,
          'Maintain an allowlist of permitted hostnames/IP ranges',
          'Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.169.254)',
          'Use a URL parser to resolve the hostname before making the request',
          'Disable HTTP redirects or validate redirect targets',
        ],
      };
    }
    if (meta.vuln_type === 'sensitive_data_logged' || desc.includes('sensitive data') || desc.includes('log output')) {
      return {
        impact: 'Logging sensitive data (passwords, tokens) exposes credentials in log files, monitoring tools, and log aggregation services.',
        steps: [
          `Remove sensitive data from the log statement at ${node.file_path}:${node.line_number}`,
          'Use structured logging and exclude sensitive fields from log output',
          'Implement a log redaction filter for known sensitive patterns',
          'Review log retention policies — rotate and encrypt log files',
        ],
      };
    }
    if (meta.vuln_type === 'open_redirect' || desc.includes('open redirect') || desc.includes('redirect')) {
      return {
        impact: 'Open redirects are used in phishing attacks — attackers craft URLs that redirect victims to malicious sites.',
        steps: [
          `Validate the redirect URL at ${node.file_path}:${node.line_number}`,
          'Only allow redirects to relative paths or an allowlist of trusted domains',
          'Never use user input directly as the redirect target',
          'Log redirect attempts to detect abuse',
        ],
      };
    }
    if (meta.vuln_type === 'missing_security_header' || desc.includes('security header') || desc.includes('helmet')) {
      return {
        impact: 'Missing security headers leave the application vulnerable to XSS, clickjacking, and MIME sniffing attacks.',
        steps: [
          'Install and use the helmet middleware: npm install helmet && app.use(helmet())',
          'Or manually set headers: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options',
          'Configure CORS headers to restrict allowed origins',
          'Test headers with securityheaders.com or Mozilla Observatory',
        ],
      };
    }
    if (meta.vuln_type === 'prototype_pollution' || desc.includes('prototype pollution')) {
      return {
        impact: 'Prototype pollution allows attackers to modify Object.prototype, affecting all objects and potentially bypassing security checks.',
        steps: [
          `Fix the vulnerable pattern at ${node.file_path}:${node.line_number}`,
          'Use Object.create(null) for lookup objects to avoid prototype chain',
          'Validate and sanitize object keys — block __proto__, constructor, prototype',
          'Replace lodash merge/defaultsDeep with safer alternatives or add key filtering',
        ],
      };
    }
    // Generic vulnerability
    return {
      impact: 'This security issue could compromise application security if left unaddressed.',
      steps: [
        `Investigate the finding at ${node.file_path}:${node.line_number}`,
        'Assess the blast radius — what data/systems could be affected',
        'Implement the appropriate fix based on the vulnerability type',
        'Add tests to prevent regression',
        'Document the fix in your security changelog',
      ],
    };
  }

  // Secret findings
  if (node.node_type === 'secret') {
    if (desc.includes('hardcoded') || desc.includes('api_key') || desc.includes('password')) {
      return {
        impact: 'Hardcoded secrets in source code can be leaked through version control, logs, or error messages.',
        steps: [
          'Move the secret to environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager)',
          `Remove the hardcoded value from ${node.file_path}`,
          'Rotate the compromised credential immediately',
          'Add the secret pattern to .gitignore and pre-commit hooks',
          'Audit git history for previously committed secrets (use tools like truffleHog or git-secrets)',
        ],
      };
    }
    if (desc.includes('env') || meta.var_name) {
      return {
        impact: 'Environment variable secrets need proper management to prevent accidental exposure.',
        steps: [
          'Ensure .env files are in .gitignore',
          'Use a secrets manager for production deployments',
          'Document required environment variables in a .env.example file (without values)',
          'Rotate secrets on a regular schedule',
          'Implement least-privilege access for service accounts',
        ],
      };
    }
    return {
      impact: 'Exposed secrets can lead to unauthorized access to external services and data.',
      steps: [
        'Move secrets to a secure secrets manager',
        'Rotate the exposed credential',
        'Implement secret scanning in CI/CD pipeline',
        'Use short-lived tokens where possible',
      ],
    };
  }

  // Entry point findings
  if (node.node_type === 'entry_point') {
    const hasAuth = meta.has_auth === true;
    if (!hasAuth) {
      return {
        impact: 'Entry points without authentication allow unrestricted access to application functionality.',
        steps: [
          `Add authentication to ${node.label} at ${node.file_path}:${node.line_number}`,
          'Determine if the endpoint should be public or protected',
          'If public, add rate limiting and input validation',
          'If protected, add auth middleware and document the required permissions',
          'Add API documentation specifying the auth requirements',
        ],
      };
    }
    return {
      impact: 'Entry points are the attack surface of your application — review each for proper security controls.',
      steps: [
        'Verify input validation on all parameters',
        'Ensure proper error handling (no stack traces in responses)',
        'Add rate limiting to prevent abuse',
        'Review authorization — can users only access their own data?',
      ],
    };
  }

  // External API findings
  if (node.node_type === 'external_api') {
    return {
      impact: 'External API connections create trust boundaries — data leaving your application needs protection.',
      steps: [
        'Verify TLS is used for all external connections',
        'Implement request timeouts to prevent hanging connections',
        'Add circuit breakers for resilience',
        'Log external API calls for audit trails',
        'Validate and sanitize data received from external APIs before use',
      ],
    };
  }

  // Data store findings
  if (node.node_type === 'data_store') {
    return {
      impact: 'Data stores contain sensitive information — improper access controls can lead to data breaches.',
      steps: [
        'Ensure connections use TLS/SSL encryption',
        'Use parameterized queries — never concatenate user input into queries',
        'Implement least-privilege database accounts',
        'Enable audit logging on the database',
        'Encrypt sensitive data at rest',
        'Set up automated backups and test restore procedures',
      ],
    };
  }

  // Dependency findings
  if (node.node_type === 'dependency') {
    const risk = meta.risk as string || '';
    return {
      impact: `This dependency has known security considerations: ${risk || node.description || 'review for proper usage'}.`,
      steps: [
        `Review usage of ${node.label} in your codebase`,
        'Check for known CVEs at https://nvd.nist.gov/ or https://snyk.io/vuln/',
        'Update to the latest patched version if available',
        'Consider alternatives if the package is unmaintained',
        'Add dependency scanning (Dependabot, Snyk, or pip-audit) to CI',
      ],
    };
  }

  // Default
  return {
    impact: 'Review this finding to ensure it meets your security standards.',
    steps: [
      `Investigate at ${node.file_path || 'unknown location'}`,
      'Assess security impact',
      'Apply appropriate fix',
      'Verify with tests',
    ],
  };
}

export default function FindingsPanel({ graph, onFindingClick, onDeepDive, collapsed, onToggleCollapse }: Props) {
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [expandedCategory, setExpandedCategory] = useState<Set<string>>(new Set());
  const [aiResults, setAiResults] = useState<Record<string, string>>({});
  const [aiLoading, setAiLoading] = useState<string | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);

  const handleAIRemediation = async (node: GraphNode) => {
    const settings = loadAISettings();
    if (!settings || !settings.apiKey) {
      setAiError('Configure AI settings first (gear icon in the top bar)');
      return;
    }
    if (aiResults[node.id]) return; // already cached

    setAiLoading(node.id);
    setAiError(null);
    try {
      const resp = await getAIRemediation({
        provider: settings.provider,
        api_key: settings.apiKey,
        model: settings.model,
        node: {
          label: node.label,
          node_type: node.node_type,
          severity: node.severity,
          description: node.description,
          file_path: node.file_path,
          line_number: node.line_number,
          metadata: node.metadata,
        },
      });
      setAiResults((prev) => ({ ...prev, [node.id]: resp.remediation }));
    } catch (err) {
      setAiError(err instanceof Error ? err.message : 'AI remediation failed');
    } finally {
      setAiLoading(null);
    }
  };

  // Build categorized, severity-sorted findings
  const categorizedFindings = useMemo(() => {
    const result: Record<string, GraphNode[]> = {};

    for (const cat of FINDING_CATEGORIES) {
      const nodes = graph.nodes
        .filter((n) => {
          if (cat === 'vulnerability') return n.node_type === 'vulnerability';
          if (cat === 'secret') return n.node_type === 'secret';
          if (cat === 'entry_point') return n.node_type === 'entry_point';
          if (cat === 'external_api') return n.node_type === 'external_api';
          if (cat === 'data_store') return n.node_type === 'data_store';
          if (cat === 'dependency') return n.node_type === 'dependency' && n.severity != null;
          return false;
        })
        .sort((a, b) => {
          const sa = SEV_ORDER[a.severity || 'info'] ?? 5;
          const sb = SEV_ORDER[b.severity || 'info'] ?? 5;
          return sa - sb;
        });

      if (nodes.length > 0) {
        result[cat] = nodes;
      }
    }
    return result;
  }, [graph.nodes]);

  // Top recommendations summary
  const topFindings = useMemo(() => {
    const all = graph.nodes
      .filter((n) => n.severity && n.severity !== 'info')
      .sort((a, b) => {
        const sa = SEV_ORDER[a.severity || 'info'] ?? 5;
        const sb = SEV_ORDER[b.severity || 'info'] ?? 5;
        return sa - sb;
      });
    return all.slice(0, 5);
  }, [graph.nodes]);

  const totalFindings = Object.values(categorizedFindings).reduce((sum, arr) => sum + arr.length, 0);

  const toggleCategory = (cat: string) => {
    setExpandedCategory((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  };

  const handleFindingClick = (node: GraphNode) => {
    setExpandedFinding(expandedFinding === node.id ? null : node.id);
    onFindingClick(node);
  };

  // Collapsed state — show thin sidebar
  if (collapsed) {
    return (
      <div
        className="w-[40px] h-full border-l z-20 flex flex-col items-center py-4 cursor-pointer shrink-0"
        style={{ background: 'var(--bg-panel)', borderColor: 'var(--border-primary)' }}
        onClick={onToggleCollapse}
        title="Expand findings panel"
      >
        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{'\u25C0'}</span>
        <span
          className="mt-3 text-xs font-bold px-1.5 py-0.5 rounded"
          style={{ color: 'var(--text-primary)', background: 'var(--bg-tertiary)' }}
        >
          {totalFindings}
        </span>
        <span
          className="mt-1 text-[10px] font-medium"
          style={{ color: 'var(--text-muted)', writingMode: 'vertical-lr' }}
        >
          Findings
        </span>
      </div>
    );
  }

  return (
    <div
      className="w-[420px] h-full backdrop-blur border-l z-20 flex flex-col shrink-0"
      style={{ background: 'var(--bg-panel)', borderColor: 'var(--border-primary)' }}
    >
      {/* Header */}
      <div className="shrink-0 border-b px-5 py-4" style={{ background: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold" style={{ color: 'var(--text-primary)' }}>Security Findings</h2>
          {onToggleCollapse && (
            <button
              onClick={onToggleCollapse}
              className="w-7 h-7 rounded flex items-center justify-center transition-colors"
              style={{ color: 'var(--text-secondary)', background: 'transparent' }}
              onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
              onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
              title="Collapse findings panel"
            >
              {'\u25B6'}
            </button>
          )}
        </div>
        <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
          {totalFindings} finding{totalFindings !== 1 ? 's' : ''} across {Object.keys(categorizedFindings).length} categories
        </p>

        {/* Quick severity summary */}
        <div className="flex items-center gap-2 mt-3">
          {(['critical', 'high', 'medium', 'low'] as Severity[]).map((sev) => {
            const count = graph.nodes.filter((n) => n.severity === sev).length;
            if (count === 0) return null;
            return (
              <span
                key={sev}
                className="px-2.5 py-1 rounded-lg text-xs font-bold text-white uppercase"
                style={{ background: SEVERITY_COLORS[sev] }}
              >
                {count} {sev}
              </span>
            );
          })}
        </div>
      </div>

      {/* Scrollable content */}
      <div className="flex-1 overflow-y-auto styled-scrollbar">
        {/* Top Recommendations */}
        {topFindings.length > 0 && (
          <div className="px-5 py-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
            <h3 className="text-xs uppercase font-semibold tracking-wider mb-3" style={{ color: 'var(--text-muted)' }}>
              Top Recommendations
            </h3>
            <div className="space-y-2">
              {topFindings.map((node, i) => (
                <button
                  key={node.id}
                  onClick={() => handleFindingClick(node)}
                  className="w-full text-left flex items-start gap-3 px-3 py-2.5 rounded-lg transition-colors group"
                  style={{ background: 'transparent' }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
                  onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                >
                  <span
                    className="shrink-0 w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold text-white mt-0.5"
                    style={{ background: SEVERITY_COLORS[node.severity || 'info'] }}
                  >
                    {i + 1}
                  </span>
                  <div className="min-w-0">
                    <p className="text-sm font-medium truncate group-hover:text-blue-400 transition-colors" style={{ color: 'var(--text-primary)' }}>
                      {node.label}
                    </p>
                    <p className="text-xs truncate mt-0.5" style={{ color: 'var(--text-muted)' }}>
                      {node.description || NODE_LABELS[node.node_type]}
                    </p>
                  </div>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Categorized findings */}
        {FINDING_CATEGORIES.map((cat) => {
          const nodes = categorizedFindings[cat];
          if (!nodes) return null;
          const isOpen = expandedCategory.has(cat);
          const color = NODE_COLORS[cat as NodeType] || '#6B7280';

          return (
            <div key={cat} className="border-b" style={{ borderColor: 'var(--border-primary)' }}>
              {/* Category header */}
              <button
                onClick={() => toggleCategory(cat)}
                className="w-full flex items-center justify-between px-5 py-3 transition-colors"
                style={{ background: 'transparent' }}
                onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
                onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
              >
                <div className="flex items-center gap-2.5">
                  <div className="w-2.5 h-2.5 rounded" style={{ background: color }} />
                  <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                    {CATEGORY_LABELS[cat]}
                  </span>
                  <span className="text-xs px-2 py-0.5 rounded-full font-bold" style={{ background: `${color}30`, color }}>
                    {nodes.length}
                  </span>
                </div>
                <span className="text-sm" style={{ color: 'var(--text-muted)' }}>{isOpen ? '\u25B2' : '\u25BC'}</span>
              </button>

              {/* Finding items */}
              {isOpen && (
                <div className="pb-2">
                  {nodes.map((node) => {
                    const isExpanded = expandedFinding === node.id;
                    const remediation = isExpanded ? getRemediation(node) : null;

                    return (
                      <div key={node.id}>
                        <button
                          onClick={() => handleFindingClick(node)}
                          className="w-full text-left px-5 py-2.5 transition-colors flex items-start gap-3"
                          style={{ background: isExpanded ? 'var(--bg-hover)' : 'transparent' }}
                          onMouseEnter={(e) => { if (!isExpanded) e.currentTarget.style.background = 'var(--bg-hover)'; }}
                          onMouseLeave={(e) => { if (!isExpanded) e.currentTarget.style.background = 'transparent'; }}
                        >
                          {/* Severity indicator */}
                          {node.severity ? (
                            <span
                              className="shrink-0 mt-1 w-2 h-2 rounded-full"
                              style={{ background: SEVERITY_COLORS[node.severity] }}
                            />
                          ) : (
                            <span className="shrink-0 mt-1 w-2 h-2 rounded-full" style={{ background: 'var(--text-muted)' }} />
                          )}
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2">
                              <p className="text-sm truncate font-medium" style={{ color: 'var(--text-primary)' }}>{node.label}</p>
                              {node.severity && node.severity !== 'info' && (
                                <span
                                  className="text-[10px] font-bold px-1.5 py-0.5 rounded text-white uppercase shrink-0"
                                  style={{ background: SEVERITY_COLORS[node.severity] }}
                                >
                                  {node.severity}
                                </span>
                              )}
                            </div>
                            {node.file_path && (
                              <p className="text-xs font-mono truncate mt-0.5" style={{ color: 'var(--text-muted)' }}>
                                {node.file_path}{node.line_number > 0 ? `:${node.line_number}` : ''}
                              </p>
                            )}
                          </div>
                          <span className="text-xs shrink-0 mt-1" style={{ color: 'var(--text-muted)' }}>
                            {isExpanded ? '\u25B2' : '\u25BC'}
                          </span>
                        </button>

                        {/* Expanded remediation panel */}
                        {isExpanded && remediation && (
                          <div className="px-5 pt-2 pb-4">
                            <div className="ml-5 rounded-lg p-5 space-y-4" style={{ background: 'var(--bg-card)' }}>
                              {/* Description */}
                              {node.description && (
                                <div>
                                  <p className="text-xs uppercase font-semibold tracking-wider mb-1" style={{ color: 'var(--text-muted)' }}>Finding</p>
                                  <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{node.description}</p>
                                </div>
                              )}

                              {/* Impact */}
                              <div>
                                <p className="text-xs uppercase font-semibold tracking-wider mb-1" style={{ color: 'var(--text-muted)' }}>Impact</p>
                                <p className="text-sm leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{remediation.impact}</p>
                              </div>

                              {/* Location */}
                              {node.file_path && (
                                <div>
                                  <p className="text-xs uppercase font-semibold tracking-wider mb-1" style={{ color: 'var(--text-muted)' }}>Location</p>
                                  <p className="text-sm font-mono rounded px-3 py-1.5 break-all" style={{ color: 'var(--text-secondary)', background: 'var(--bg-tertiary)' }}>
                                    {node.file_path}
                                    {node.line_number > 0 && <span className="text-blue-400">:{node.line_number}</span>}
                                  </p>
                                </div>
                              )}

                              {/* Remediation steps */}
                              <div>
                                <p className="text-xs uppercase font-semibold tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>How to Fix</p>
                                <ol className="space-y-2">
                                  {remediation.steps.map((step, idx) => (
                                    <li key={idx} className="flex gap-2.5 text-sm">
                                      <span className="shrink-0 w-5 h-5 rounded-full bg-blue-600/20 text-blue-400 flex items-center justify-center text-xs font-bold">
                                        {idx + 1}
                                      </span>
                                      <span className="leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{step}</span>
                                    </li>
                                  ))}
                                </ol>
                              </div>

                              {/* Metadata */}
                              {Object.keys(node.metadata).length > 0 && (
                                <div>
                                  <p className="text-xs uppercase font-semibold tracking-wider mb-1" style={{ color: 'var(--text-muted)' }}>Details</p>
                                  <div className="space-y-1">
                                    {Object.entries(node.metadata).map(([key, value]) => (
                                      <div key={key} className="flex items-start gap-2 text-xs">
                                        <span className="shrink-0 font-medium" style={{ color: 'var(--text-muted)' }}>{key}:</span>
                                        <span className="break-all" style={{ color: 'var(--text-secondary)' }}>
                                          {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                                        </span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {/* Deep Dive button */}
                              {onDeepDive && (
                                <div className="border-t pt-3" style={{ borderColor: 'var(--border-secondary)' }}>
                                  <button
                                    onClick={(e) => { e.stopPropagation(); onDeepDive(node); }}
                                    className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors border"
                                    style={{
                                      background: 'transparent',
                                      borderColor: 'var(--border-primary)',
                                      color: 'var(--text-secondary)',
                                    }}
                                    onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-hover)')}
                                    onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                                  >
                                    {'\u2197'} Open in Deep Dive
                                  </button>
                                </div>
                              )}

                              {/* AI Remediation */}
                              <div className="border-t pt-4" style={{ borderColor: 'var(--border-secondary)' }}>
                                {aiResults[node.id] ? (
                                  <div>
                                    <p className="text-xs uppercase font-semibold tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>AI Remediation</p>
                                    <div
                                      className="text-sm leading-relaxed prose prose-sm max-w-none"
                                      style={{ color: 'var(--text-secondary)' }}
                                      dangerouslySetInnerHTML={{ __html: renderMarkdown(aiResults[node.id]) }}
                                    />
                                  </div>
                                ) : (
                                  <button
                                    onClick={(e) => { e.stopPropagation(); handleAIRemediation(node); }}
                                    disabled={aiLoading === node.id}
                                    className="w-full flex items-center justify-center gap-2 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors border"
                                    style={{
                                      background: 'linear-gradient(135deg, rgba(139,92,246,0.1), rgba(59,130,246,0.1))',
                                      borderColor: 'rgba(139,92,246,0.3)',
                                      color: '#A78BFA',
                                    }}
                                  >
                                    {aiLoading === node.id ? (
                                      <>
                                        <span className="w-4 h-4 border-2 border-purple-400 border-t-transparent rounded-full animate-spin" />
                                        Analyzing...
                                      </>
                                    ) : (
                                      <>
                                        <span>&#x2728;</span>
                                        Get AI Remediation
                                      </>
                                    )}
                                  </button>
                                )}
                                {aiError && aiLoading !== node.id && !aiResults[node.id] && (
                                  <p className="mt-2 text-xs text-red-400">{aiError}</p>
                                )}
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}

        {totalFindings === 0 && (
          <div className="px-5 py-10 text-center">
            <p className="text-lg text-green-400 font-semibold">No findings detected</p>
            <p className="text-sm mt-2" style={{ color: 'var(--text-muted)' }}>Your codebase looks clean!</p>
          </div>
        )}
      </div>
    </div>
  );
}
