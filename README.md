<p align="center">
  <h1 align="center">CodeWatch</h1>
  <p align="center">
    Scan any codebase. Visualize its security architecture. Find what's exposed.
  </p>
</p>

<p align="center">
  <a href="#features">Features</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#detection-coverage">Detection</a> &bull;
  <a href="#ai-remediation">AI Remediation</a> &bull;
  <a href="#export">Export</a> &bull;
  <a href="#api">API</a> &bull;
  <a href="#contributing">Contributing</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/React_18-TypeScript-3178C6?logo=react" alt="React">
  <img src="https://img.shields.io/badge/FastAPI-Python_3.11+-009688?logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/React_Flow-Graph_Viz-FF0072" alt="React Flow">
  <img src="https://img.shields.io/badge/Tailwind_CSS-Styling-06B6D4?logo=tailwindcss" alt="Tailwind">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
</p>

---

Point it at any local folder or GitHub repo URL and get an **interactive security knowledge graph** in seconds. See your entry points, data flows, secrets, vulnerabilities, and trust boundaries — all connected and explorable in a force-directed graph.

> **No database. No cloud. No telemetry.** Everything runs locally and stays in memory.

<!-- Add a screenshot here: ![Demo](docs/demo.png) -->

## Features

**Scanning**
- Scan local directories or clone from GitHub URL
- Multi-language support: Python (AST-based), JavaScript/TypeScript, Go, Java, Rust, YAML, Docker, Terraform, and more
- Git history scanning for secrets that were committed then removed
- Dependency analysis with CVE lookup via [OSV.dev](https://osv.dev)
- Real-time progress tracking during scan

**Visualization**
- Interactive graph with pan, zoom, drag, and click-to-inspect
- Auto-layout powered by Dagre (hierarchical mode)
- Node filtering by type (entry points, secrets, vulnerabilities, etc.)
- Full-text search across all nodes
- Right-click context menu with deep-dive analysis
- Color-coded nodes and edges by category
- Dark and light mode

**Analysis**
- Risk score (0-10) with weighted severity calculation
- Findings panel with severity sorting and remediation guidance
- Deep-dive panel showing connections, source context, and related findings
- AI-powered remediation via Claude, GPT, or Gemini (bring your own key)
- Source code context viewer with line highlighting

**Export**
- JSON (full graph data, re-importable)
- Markdown (human-readable security report)
- SARIF (for CI/CD integration)
- Import previously exported JSON reports

## Quick Start

### Option 1: Docker Compose

```bash
git clone https://github.com/tarun27in/codewatch.git
cd codewatch
docker compose up
```

Open **http://localhost:5173** and scan away.

### Option 2: Manual Setup

**Backend** (Python 3.11+):

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**Frontend** (Node 18+):

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173**, enter a folder path or GitHub URL, and click **Scan**.

## How It Works

```
                    +-----------+
                    |  Codebase |
                    +-----+-----+
                          |
                    +-----v-----+
                    | File Walker|  Discovers files, detects languages
                    +-----+-----+
                          |
            +-------------+-------------+
            |             |             |
      +-----v---+  +-----v----+  +-----v------+
      |  Python  |  |JavaScript|  |  Generic   |  + Config, Dependency,
      | Analyzer |  | Analyzer |  |  Analyzer  |    Terraform, Git History
      |(AST-based)  |(regex)   |  |(regex)     |
      +-----+---+  +-----+----+  +-----+------+
            |             |             |
            +-------------+-------------+
                          |
                    +-----v------+
                    |Graph Builder|  Findings -> Nodes + Edges
                    +-----+------+
                          |
                    +-----v-----+
                    | React Flow |  Interactive visualization
                    +-----------+
```

**Analyzers run in parallel per-file.** Each analyzer produces `Finding` objects with a node type, severity, file path, line number, and metadata. The graph builder deduplicates, connects related findings, and calculates the risk score.

## Detection Coverage

### Node Types

| Type | Color | Detects |
|------|-------|---------|
| Entry Point | Blue | HTTP routes, webhooks, exposed ports, CLI commands |
| Service | Purple | FastAPI/Express/Flask apps, Docker Compose services |
| External API | Orange | Outbound HTTP calls, third-party API URLs |
| Data Store | Green | Database connections (Postgres, MongoDB, Redis, OpenSearch) |
| Secret | Red | API keys, passwords, tokens, private keys, env var references |
| Vulnerability | Red border | Injection, XSS, TLS bypass, missing auth, insecure patterns |
| Auth Boundary | Yellow | K8s NetworkPolicy, security contexts, RBAC |
| Dependency | Gray | npm/pip/cargo/go packages with risk annotations |

### Vulnerability Detection (20+ categories)

| Category | Severity | Examples |
|----------|----------|---------|
| SQL Injection | Critical | f-string queries, template literal interpolation, string concat |
| Insecure Deserialization | Critical | pickle, yaml.load without SafeLoader, marshal |
| Code Injection | High | eval(), exec(), new Function() |
| Command Injection | High | subprocess with shell=True |
| XSS | High | innerHTML, dangerouslySetInnerHTML, document.write |
| SSRF | High | HTTP requests with user-controlled URLs |
| Path Traversal | High | File operations with string concatenation |
| Sensitive Data Logging | High | Passwords/tokens in log statements |
| Prototype Pollution | High | Object.assign/lodash merge with user input |
| TLS Bypass | Medium | verify=False, rejectUnauthorized: false |
| Weak Cryptography | Medium | MD5, SHA-1, Math.random(), DES/RC4 |
| Debug Mode | Medium | DEBUG=True, NODE_ENV=development |
| Open Redirects | Medium | Redirects with user-controlled URLs |
| Missing Security Headers | Medium | No CSP, HSTS, or X-Frame-Options |
| Missing Auth | Medium | Unprotected HTTP endpoints |
| Hardcoded Secrets | High | API keys, tokens, private keys in source |
| Historical Secrets | High | Secrets found in git history (committed then removed) |
| Insecure TLS Config | Medium | Certificate verification disabled |
| Container Misconfig | Medium | Privileged containers, host network, no security context |
| Terraform Issues | Medium | Public S3 buckets, overly permissive IAM |

### Language Support

| Language | Analysis Method | Depth |
|----------|----------------|-------|
| Python | AST parsing + regex | Routes, imports, DB connections, auth patterns, deserialization |
| JavaScript/TypeScript | Regex + string tracking | Routes, API calls, XSS, SQL injection, security headers |
| Go, Java, Rust, Ruby, PHP, C# | Regex (generic) | Secrets, URLs, patterns, dependencies |
| YAML | Structure-aware | Docker Compose, K8s manifests, GitHub Actions |
| Dockerfile | Instruction parsing | Base images, exposed ports, security misconfigs |
| Terraform | Block parsing | Resources, IAM policies, storage configs |
| JSON | Key-value | package.json deps, tsconfig, configs |

## AI Remediation

Click any vulnerability node and get AI-powered remediation advice. Supports three providers — bring your own API key:

| Provider | Models |
|----------|--------|
| Anthropic | Claude Sonnet 4.5, Claude Haiku 4.5 |
| OpenAI | GPT-4o, GPT-4o-mini |
| Google | Gemini 2.0 Flash, Gemini 2.5 Pro |

Configure in the AI Settings modal (gear icon). Keys are stored in your browser's localStorage only — never sent to our backend.

## Export

| Format | Use Case |
|--------|----------|
| **JSON** | Full graph data. Re-import later to view without rescanning. |
| **Markdown** | Human-readable security report with findings, risk score, and remediation. |
| **SARIF** | Standard format for CI/CD integration (GitHub Code Scanning, VS Code, etc.) |

## API

All endpoints are under `/api`:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Start a scan. Body: `{ "path": "/local/path" }` or `{ "github_url": "..." }` |
| `GET` | `/api/scan/{id}` | Poll scan status and progress |
| `GET` | `/api/scans` | List all scans |
| `DELETE` | `/api/scan/{id}` | Delete scan data from memory |
| `GET` | `/api/graph/{id}` | Get the security knowledge graph |
| `GET` | `/api/browse?path=~` | Browse filesystem directories |
| `GET` | `/api/source?path=...&line=N` | Get source code context |
| `POST` | `/api/cve-lookup` | Lookup CVEs via OSV.dev |
| `POST` | `/api/remediate` | Get AI remediation (requires provider + API key) |

## Architecture

```
codewatch/
├── backend/                          # Python FastAPI
│   ├── app/
│   │   ├── main.py                   # App setup, CORS, router registration
│   │   ├── models.py                 # Pydantic models (Finding, GraphNode, GraphEdge)
│   │   ├── config.py                 # Settings (CORS origins, file limits)
│   │   ├── routers/                  # API endpoints
│   │   │   ├── scan.py               # Scan CRUD
│   │   │   ├── graph.py              # Graph retrieval
│   │   │   ├── browse.py             # Filesystem browser
│   │   │   ├── source.py             # Source code context
│   │   │   ├── cve.py                # CVE lookup (OSV.dev)
│   │   │   └── remediate.py          # AI remediation (Claude/GPT/Gemini)
│   │   ├── scanner/
│   │   │   ├── orchestrator.py       # Scan pipeline coordinator
│   │   │   ├── file_walker.py        # Recursive file discovery
│   │   │   ├── graph_builder.py      # Findings → nodes + edges + risk score
│   │   │   └── analyzers/            # 8 specialized analyzers
│   │   │       ├── generic_analyzer.py       # Secrets, weak crypto, debug mode, etc.
│   │   │       ├── python_analyzer.py        # AST-based Python analysis
│   │   │       ├── javascript_analyzer.py    # JS/TS pattern analysis
│   │   │       ├── config_analyzer.py        # Docker, K8s, .env files
│   │   │       ├── dependency_analyzer.py    # Package manifest analysis
│   │   │       ├── terraform_analyzer.py     # IaC security analysis
│   │   │       └── git_history_analyzer.py   # Historical secret scanning
│   │   └── utils/
│   │       └── git_clone.py          # GitHub repo cloning
│   └── requirements.txt
├── frontend/                         # React + TypeScript + Vite
│   ├── src/
│   │   ├── App.tsx                   # Scan → Graph flow
│   │   ├── components/
│   │   │   ├── GraphView.tsx         # React Flow interactive canvas
│   │   │   ├── FindingsPanel.tsx     # Findings explorer with remediation
│   │   │   ├── DeepDivePanel.tsx     # Deep-dive analysis panel
│   │   │   ├── ScanForm.tsx          # Scan input (path / GitHub URL)
│   │   │   ├── StatsBar.tsx          # Risk score + statistics
│   │   │   ├── AISettingsModal.tsx   # Multi-provider AI configuration
│   │   │   ├── ContextMenu.tsx       # Right-click context menu
│   │   │   └── ...                   # FilterBar, Legend, NodeDetail, etc.
│   │   ├── hooks/
│   │   │   ├── useScan.ts           # Scan lifecycle + polling
│   │   │   └── useTheme.ts          # Dark/light mode
│   │   ├── api/client.ts            # Axios HTTP client
│   │   ├── types/graph.ts           # TypeScript type definitions
│   │   └── utils/                   # Layout, export, import utilities
│   └── package.json
└── docker-compose.yml
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Vite 6, React Flow, Dagre, Tailwind CSS |
| Backend | Python 3.11+, FastAPI, Pydantic v2, uvicorn |
| Analysis | Python AST, regex patterns, GitPython |
| CVE Lookup | OSV.dev API via httpx |
| AI | Anthropic, OpenAI, Google Generative AI (user-provided keys) |
| Containerization | Docker, Docker Compose |
| Storage | In-memory (no database required) |

## Contributing

Contributions welcome! Some ideas:

- **New language analyzers** — add deep analysis for Go, Java, Rust, etc.
- **New vulnerability patterns** — add detection for CSRF, race conditions, timing attacks
- **CI/CD integration** — GitHub Action to run scans on PRs
- **Persistence** — optional SQLite/Postgres for scan history
- **Diff view** — compare two scans to see what changed

```bash
# Run backend
cd backend && pip install -r requirements.txt && uvicorn app.main:app --reload

# Run frontend
cd frontend && npm install && npm run dev

# Both via Docker
docker compose up
```

## License

MIT

