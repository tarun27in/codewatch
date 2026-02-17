"""JavaScript/TypeScript regex-based analyzer for routes, API calls, and security patterns."""

import re
from ..analyzers.base import BaseAnalyzer
from ..analyzers.generic_analyzer import GenericAnalyzer
from ...models import Finding, NodeType, Severity


# Route patterns for Express, Koa, Fastify, Next.js
ROUTE_PATTERNS = [
    # Express: app.get('/path', handler) or router.post('/path', handler)
    (r'(?:app|router|server)\.(get|post|put|delete|patch|options|all)\s*\(\s*["\']([^"\']+)["\']', "express"),
    # Next.js API routes: export default/async function handler
    (r'export\s+(?:default\s+)?(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)\b', "nextjs"),
    # Fastify: fastify.get('/path', handler)
    (r'(?:fastify|server)\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', "fastify"),
    # NestJS: @Get('/path'), @Post('/path')
    (r'@(Get|Post|Put|Delete|Patch)\s*\(\s*["\']([^"\']*)["\']', "nestjs"),
]

# HTTP client patterns
HTTP_CALL_PATTERNS = [
    (r'fetch\s*\(\s*["\']([^"\']+)["\']', "fetch"),
    (r'fetch\s*\(\s*`([^`]+)`', "fetch"),
    (r'axios\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', "axios"),
    (r'axios\.(get|post|put|delete|patch)\s*\(\s*`([^`]+)`', "axios"),
    (r'\$\.ajax\s*\(', "jquery"),
]

# Database patterns
DB_PATTERNS = [
    (r'mongoose\.connect\s*\(', "MongoDB"),
    (r'new\s+MongoClient\s*\(', "MongoDB"),
    (r'createClient\s*\(\s*\{', "Redis"),
    (r'new\s+Pool\s*\(', "PostgreSQL"),
    (r'knex\s*\(', "SQL Database"),
    (r'prisma\.\$connect', "Prisma"),
    (r'sequelize', "Sequelize"),
    (r'typeorm', "TypeORM"),
    (r'createConnection\s*\(', "SQL Database"),
    (r'firebase\.initializeApp', "Firebase"),
    (r'initializeApp\s*\(', "Firebase"),
]


class JavaScriptAnalyzer(BaseAnalyzer):
    """Regex-based analyzer for JavaScript/TypeScript files."""

    @property
    def supported_languages(self) -> list[str]:
        return ["javascript", "typescript"]

    def analyze(self, file_path: str, content: str, metadata: dict) -> list[Finding]:
        findings: list[Finding] = []
        rel_path = metadata.get("rel_path", file_path)
        lines = content.split("\n")

        # Find routes
        findings.extend(self._find_routes(content, rel_path, lines))

        # Find HTTP client calls
        findings.extend(self._find_http_calls(content, rel_path, lines))

        # Find database connections
        findings.extend(self._find_db_connections(content, rel_path, lines))

        # Find Express/Fastify app creation
        findings.extend(self._find_services(content, rel_path, lines))

        # Find security vulnerabilities
        findings.extend(self._find_vulnerabilities(content, rel_path, lines))

        # JS-specific vulnerability patterns
        findings.extend(self._find_sql_injection(content, rel_path, lines))
        findings.extend(self._find_missing_security_headers(content, rel_path, lines))
        findings.extend(self._find_prototype_pollution(content, rel_path, lines))

        return findings

    def _find_routes(self, content: str, rel_path: str, lines: list[str]) -> list[Finding]:
        findings = []
        for pattern, framework in ROUTE_PATTERNS:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                if framework == "nextjs":
                    method = match.group(1).upper()
                    route_path = f"(Next.js API route)"
                else:
                    method = match.group(1).upper()
                    route_path = match.group(2)

                findings.append(Finding(
                    node_type=NodeType.ENTRY_POINT,
                    name=f"{method} {route_path}",
                    file_path=rel_path,
                    line_number=line_num,
                    description=f"{framework} route endpoint",
                    metadata={
                        "http_method": method,
                        "route_path": route_path,
                        "framework": framework,
                    },
                ))
        return findings

    def _find_http_calls(self, content: str, rel_path: str, lines: list[str]) -> list[Finding]:
        findings = []
        for pattern, client in HTTP_CALL_PATTERNS:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                if client == "axios":
                    url = match.group(2)
                elif client == "jquery":
                    url = "<jQuery AJAX>"
                else:
                    url = match.group(1)

                if url.startswith("/") or url.startswith("$") or url.startswith("`"):
                    continue  # Skip relative paths and template literals

                findings.append(Finding(
                    node_type=NodeType.EXTERNAL_API,
                    name=url[:80] if url else f"{client} API call",
                    file_path=rel_path,
                    line_number=line_num,
                    description=f"Outbound {client} HTTP call",
                    metadata={"library": client, "url": url},
                ))
        return findings

    def _find_db_connections(self, content: str, rel_path: str, lines: list[str]) -> list[Finding]:
        findings = []
        seen = set()
        for pattern, db_name in DB_PATTERNS:
            if re.search(pattern, content) and db_name not in seen:
                seen.add(db_name)
                match = re.search(pattern, content)
                line_num = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    node_type=NodeType.DATA_STORE,
                    name=db_name,
                    file_path=rel_path,
                    line_number=line_num,
                    description=f"{db_name} database connection",
                    metadata={"db_type": db_name},
                ))
        return findings

    def _find_services(self, content: str, rel_path: str, lines: list[str]) -> list[Finding]:
        findings = []
        patterns = [
            (r'express\s*\(\s*\)', "Express"),
            (r'new\s+Koa\s*\(\s*\)', "Koa"),
            (r'fastify\s*\(\s*\)', "Fastify"),
            (r'createServer\s*\(', "HTTP Server"),
            (r'new\s+Hono\s*\(', "Hono"),
        ]
        for pattern, framework in patterns:
            match = re.search(pattern, content)
            if match:
                line_num = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    node_type=NodeType.SERVICE,
                    name=framework,
                    file_path=rel_path,
                    line_number=line_num,
                    description=f"{framework} application",
                    metadata={"framework": framework},
                ))
        return findings

    @staticmethod
    def _is_inside_string_literal(line: str, match_start_in_line: int) -> bool:
        """Check if a regex match position falls inside a string literal on that line."""
        in_single = False
        in_double = False
        in_template = False
        i = 0
        while i < match_start_in_line and i < len(line):
            ch = line[i]
            if ch == '\\' and i + 1 < len(line):
                i += 2
                continue
            if ch == "'" and not in_double and not in_template:
                in_single = not in_single
            elif ch == '"' and not in_single and not in_template:
                in_double = not in_double
            elif ch == '`' and not in_single and not in_double:
                in_template = not in_template
            i += 1
        return in_single or in_double or in_template

    def _find_vulnerabilities(self, content: str, rel_path: str, lines: list[str]) -> list[Finding]:
        findings = []
        vuln_patterns = [
            (r'innerHTML\s*=', "XSS", Severity.HIGH, "Direct innerHTML assignment may allow XSS"),
            (r'dangerouslySetInnerHTML', "XSS", Severity.HIGH, "dangerouslySetInnerHTML may allow XSS"),
            (r'eval\s*\(', "Code Injection", Severity.HIGH, "eval() may allow code injection"),
            (r'new\s+Function\s*\(', "Code Injection", Severity.HIGH, "new Function() may allow code injection"),
            (r'document\.write\s*\(', "XSS", Severity.MEDIUM, "document.write() may allow XSS"),
            (r'rejectUnauthorized\s*:\s*false', "TLS Bypass", Severity.MEDIUM, "TLS certificate verification disabled"),
            (r'NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']0["\']', "TLS Bypass", Severity.MEDIUM, "TLS verification globally disabled"),
        ]
        for pattern, vuln_type, severity, description in vuln_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                line = lines[line_num - 1] if line_num <= len(lines) else ""
                line_offset = match.start() - content.rfind("\n", 0, match.start()) - 1

                # Skip matches inside string literals (e.g., remediation text mentioning "eval()")
                if self._is_inside_string_literal(line, line_offset):
                    continue

                # Skip matches in comments
                stripped = line.lstrip()
                if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
                    continue

                findings.append(Finding(
                    node_type=NodeType.VULNERABILITY,
                    name=f"{vuln_type} ({rel_path.split('/')[-1]}:{line_num})",
                    file_path=rel_path,
                    line_number=line_num,
                    severity=severity,
                    description=description,
                    metadata={"vuln_type": vuln_type.lower().replace(" ", "_")},
                ))
        return findings

    def _find_sql_injection(self, content: str, rel_path: str, lines: list[str]) -> list[Finding]:
        """Detect SQL injection via template literals or string concatenation."""
        findings = []
        sql_patterns = [
            # Template literal SQL: `SELECT ... ${variable}`
            (r'`(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b[^`]*\$\{', "SQL query with template literal interpolation — use parameterized queries"),
            # String concat SQL: "SELECT " + variable
            (r'["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*["\']\s*\+', "SQL query with string concatenation — use parameterized queries"),
            # .query() with template literal
            (r'\.query\s*\(\s*`[^`]*\$\{', "SQL query() with template literal — use parameterized queries"),
            # .raw() with interpolation
            (r'\.raw\s*\(\s*`[^`]*\$\{', "SQL raw() with template literal — use parameterized queries"),
            # sequelize.literal with user input
            (r'sequelize\.literal\s*\(.*(?:req\.|params|query|body)', "sequelize.literal with user input — vulnerable to SQL injection"),
        ]
        for pattern, desc in sql_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                line = lines[line_num - 1] if line_num <= len(lines) else ""
                stripped = line.lstrip()
                if stripped.startswith("//") or stripped.startswith("*"):
                    continue
                if GenericAnalyzer._is_string_literal_or_pattern(line):
                    continue
                findings.append(Finding(
                    node_type=NodeType.VULNERABILITY,
                    name=f"SQL Injection ({rel_path.split('/')[-1]}:{line_num})",
                    file_path=rel_path,
                    line_number=line_num,
                    severity=Severity.CRITICAL,
                    description=desc,
                    metadata={"vuln_type": "sql_injection"},
                ))
        return findings

    def _find_missing_security_headers(self, content: str, rel_path: str, lines: list[str]) -> list[Finding]:
        """Detect missing security headers in Express/Fastify apps."""
        findings = []
        # Only check files that create an Express/Fastify app
        has_express = bool(re.search(r'express\s*\(\s*\)', content))
        has_fastify = bool(re.search(r'fastify\s*\(\s*\)', content))
        if not has_express and not has_fastify:
            return findings

        # Check for helmet (comprehensive security headers)
        has_helmet = bool(re.search(r'helmet\s*\(', content) or re.search(r'require\s*\(\s*["\']helmet["\']', content) or re.search(r'from\s+["\']helmet["\']', content))
        if has_helmet:
            return findings  # Helmet handles most security headers

        # Check for individual security headers
        has_csp = bool(re.search(r'Content-Security-Policy', content, re.IGNORECASE))
        has_hsts = bool(re.search(r'Strict-Transport-Security', content, re.IGNORECASE))
        has_xframe = bool(re.search(r'X-Frame-Options', content, re.IGNORECASE))
        has_cors = bool(re.search(r'cors\s*\(', content))

        # Find the line where the app is created for the finding location
        app_line = 1
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:express|fastify)\s*\(\s*\)', line):
                app_line = i
                break

        if not has_csp:
            findings.append(Finding(
                node_type=NodeType.VULNERABILITY,
                name="Missing Content-Security-Policy header",
                file_path=rel_path, line_number=app_line,
                severity=Severity.MEDIUM,
                description="No Content-Security-Policy header configured — add helmet or set CSP manually to prevent XSS",
                metadata={"vuln_type": "missing_security_header", "header": "Content-Security-Policy"},
            ))
        if not has_hsts:
            findings.append(Finding(
                node_type=NodeType.VULNERABILITY,
                name="Missing Strict-Transport-Security header",
                file_path=rel_path, line_number=app_line,
                severity=Severity.MEDIUM,
                description="No HSTS header configured — add helmet or set Strict-Transport-Security to enforce HTTPS",
                metadata={"vuln_type": "missing_security_header", "header": "Strict-Transport-Security"},
            ))
        if not has_xframe:
            findings.append(Finding(
                node_type=NodeType.VULNERABILITY,
                name="Missing X-Frame-Options header",
                file_path=rel_path, line_number=app_line,
                severity=Severity.LOW,
                description="No X-Frame-Options header — add helmet or set header to prevent clickjacking",
                metadata={"vuln_type": "missing_security_header", "header": "X-Frame-Options"},
            ))

        return findings

    def _find_prototype_pollution(self, content: str, rel_path: str, lines: list[str]) -> list[Finding]:
        """Detect prototype pollution vectors in JS/TS."""
        findings = []
        pollution_patterns = [
            (r'Object\.assign\s*\(\s*\{\s*\}.*(?:req\.|params|query|body|input)', "Object.assign with user input — vulnerable to prototype pollution"),
            (r'_\.merge\s*\(.*(?:req\.|params|query|body)', "lodash merge with user input — vulnerable to prototype pollution"),
            (r'_\.defaultsDeep\s*\(.*(?:req\.|params|query|body)', "lodash defaultsDeep with user input — vulnerable to prototype pollution"),
            (r'\[.*(?:req\.|params|query|body).*\]\s*=', "Dynamic property assignment from user input — may allow prototype pollution"),
        ]
        for pattern, desc in pollution_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count("\n") + 1
                line = lines[line_num - 1] if line_num <= len(lines) else ""
                stripped = line.lstrip()
                if stripped.startswith("//") or stripped.startswith("*"):
                    continue
                if GenericAnalyzer._is_string_literal_or_pattern(line):
                    continue
                findings.append(Finding(
                    node_type=NodeType.VULNERABILITY,
                    name=f"Prototype Pollution ({rel_path.split('/')[-1]}:{line_num})",
                    file_path=rel_path,
                    line_number=line_num,
                    severity=Severity.HIGH,
                    description=desc,
                    metadata={"vuln_type": "prototype_pollution"},
                ))
        return findings
