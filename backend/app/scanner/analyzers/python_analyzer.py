"""Python AST-based analyzer for routes, imports, connections, and security patterns."""

import ast
import re
from ..analyzers.base import BaseAnalyzer
from ..analyzers.generic_analyzer import GenericAnalyzer
from ...models import Finding, NodeType, Severity, EdgeType


# HTTP client libraries
HTTP_CLIENTS = {"httpx", "requests", "aiohttp", "urllib3", "http.client"}

# Database/storage clients
DB_CLIENTS = {
    "opensearchpy": "OpenSearch",
    "opensearch": "OpenSearch",
    "pymongo": "MongoDB",
    "motor": "MongoDB",
    "psycopg2": "PostgreSQL",
    "asyncpg": "PostgreSQL",
    "sqlalchemy": "SQL Database",
    "redis": "Redis",
    "boto3": "AWS",
    "google.cloud": "Google Cloud",
    "firebase_admin": "Firebase",
    "elasticsearch": "Elasticsearch",
}

# Web framework route decorators
ROUTE_DECORATORS = {"get", "post", "put", "delete", "patch", "options", "head", "websocket"}


class PythonAnalyzer(BaseAnalyzer):
    """AST-based analyzer for Python files."""

    @property
    def supported_languages(self) -> list[str]:
        return ["python"]

    def analyze(self, file_path: str, content: str, metadata: dict) -> list[Finding]:
        findings: list[Finding] = []
        rel_path = metadata.get("rel_path", file_path)

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        # Collect imports first for context
        imports = self._collect_imports(tree)

        # Detect FastAPI/Flask route decorators
        findings.extend(self._find_routes(tree, rel_path, content))

        # Detect external API calls
        findings.extend(self._find_external_calls(tree, rel_path, imports, content))

        # Detect database connections
        findings.extend(self._find_db_connections(tree, rel_path, imports, content))

        # Detect FastAPI app or router creation (service nodes)
        findings.extend(self._find_services(tree, rel_path, content))

        # Detect auth patterns (or lack thereof)
        findings.extend(self._find_auth_patterns(tree, rel_path, content))

        # Python-specific vulnerability patterns
        findings.extend(self._find_sql_injection(content, rel_path))
        findings.extend(self._find_insecure_deserialization(content, rel_path))
        findings.extend(self._find_ssrf_patterns(tree, rel_path, content))

        return findings

    def _collect_imports(self, tree: ast.AST) -> set[str]:
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split(".")[0])
        return imports

    def _find_routes(self, tree: ast.AST, rel_path: str, content: str) -> list[Finding]:
        findings = []
        lines = content.split("\n")

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                route_path = None
                http_method = None

                # @app.get("/path") or @router.post("/path")
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                    method_name = decorator.func.attr.lower()
                    if method_name in ROUTE_DECORATORS:
                        http_method = method_name.upper()
                        if decorator.args and isinstance(decorator.args[0], ast.Constant):
                            route_path = decorator.args[0].value

                if route_path and http_method:
                    # Check if route has auth dependencies
                    has_auth = self._route_has_auth(node, decorator, lines)

                    finding = Finding(
                        node_type=NodeType.ENTRY_POINT,
                        name=f"{http_method} {route_path}",
                        file_path=rel_path,
                        line_number=node.lineno,
                        description=f"{'Authenticated' if has_auth else 'Unauthenticated'} {http_method} endpoint",
                        metadata={
                            "http_method": http_method,
                            "route_path": route_path,
                            "function_name": node.name,
                            "has_auth": has_auth,
                        },
                    )
                    if not has_auth:
                        finding.severity = Severity.MEDIUM
                        finding.connections.append({
                            "type": "has_vulnerability",
                            "target_name": f"No Auth: {http_method} {route_path}",
                            "target_type": "vulnerability",
                        })
                    findings.append(finding)

        return findings

    def _route_has_auth(self, func_node: ast.AST, decorator: ast.Call, lines: list[str]) -> bool:
        """Check if a route has authentication (Depends, Security, api_key, etc.)."""
        # Check decorator arguments for Depends()
        for kw in getattr(decorator, "keywords", []):
            if kw.arg == "dependencies":
                return True

        # Check function parameters for auth-related dependencies
        for arg in func_node.args.args:
            arg_name = arg.arg.lower()
            if any(w in arg_name for w in ["auth", "token", "user", "current_user", "api_key"]):
                return True

        # Check function parameter annotations for Depends()
        for default in func_node.args.defaults:
            if isinstance(default, ast.Call):
                func_name = ""
                if isinstance(default.func, ast.Name):
                    func_name = default.func.id
                elif isinstance(default.func, ast.Attribute):
                    func_name = default.func.attr
                if func_name.lower() in ("depends", "security"):
                    return True

        return False

    def _find_external_calls(self, tree: ast.AST, rel_path: str, imports: set, content: str) -> list[Finding]:
        findings = []

        # Check for HTTP client usage
        has_http_client = bool(imports & HTTP_CLIENTS)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # httpx.AsyncClient(), requests.get(), aiohttp.ClientSession()
            if isinstance(node.func, ast.Attribute):
                call_chain = self._get_call_chain(node.func)

                # Detect HTTP client method calls
                if any(client in call_chain for client in ["httpx", "requests", "aiohttp"]):
                    method = node.func.attr
                    if method in ("get", "post", "put", "delete", "patch", "request"):
                        url = self._extract_url_arg(node)
                        name = url[:80] if url else f"HTTP {method.upper()} call"
                        findings.append(Finding(
                            node_type=NodeType.EXTERNAL_API,
                            name=name,
                            file_path=rel_path,
                            line_number=node.lineno,
                            description=f"Outbound HTTP {method.upper()} request",
                            metadata={"method": method, "url": url, "library": call_chain},
                        ))

            # Detect URL constants that look like API endpoints
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value.startswith("https://") and "api" in node.value.lower():
                    findings.append(Finding(
                        node_type=NodeType.EXTERNAL_API,
                        name=node.value[:80],
                        file_path=rel_path,
                        line_number=node.lineno,
                        description="External API endpoint URL",
                        metadata={"url": node.value},
                    ))

        # Also scan string constants for API URLs
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                        val = node.value.value
                        if isinstance(val, str) and val.startswith("https://") and any(
                            w in target.id.lower() for w in ["url", "endpoint", "api", "base"]
                        ):
                            findings.append(Finding(
                                node_type=NodeType.EXTERNAL_API,
                                name=f"{target.id}: {val[:60]}",
                                file_path=rel_path,
                                line_number=node.lineno,
                                description=f"External API endpoint: {val}",
                                metadata={"var_name": target.id, "url": val},
                            ))

        return findings

    def _find_db_connections(self, tree: ast.AST, rel_path: str, imports: set, content: str) -> list[Finding]:
        findings = []

        for module, db_name in DB_CLIENTS.items():
            if module.split(".")[0] in imports:
                # Find where the client is instantiated
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        func_name = self._get_func_name(node)
                        if any(kw in func_name.lower() for kw in ["opensearch", "mongoclient", "create_engine", "redis", "client", "connection"]):
                            findings.append(Finding(
                                node_type=NodeType.DATA_STORE,
                                name=db_name,
                                file_path=rel_path,
                                line_number=node.lineno,
                                description=f"{db_name} connection",
                                metadata={"db_type": db_name, "library": module},
                            ))
                            break
                else:
                    # Import exists but no explicit instantiation found
                    findings.append(Finding(
                        node_type=NodeType.DATA_STORE,
                        name=db_name,
                        file_path=rel_path,
                        line_number=1,
                        description=f"{db_name} library imported",
                        metadata={"db_type": db_name, "library": module},
                    ))

        return findings

    def _find_services(self, tree: ast.AST, rel_path: str, content: str) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)
                if func_name in ("FastAPI", "Flask", "APIRouter", "Blueprint", "Sanic"):
                    name = func_name
                    # Try to get title/name from kwargs
                    for kw in getattr(node, "keywords", []):
                        if kw.arg in ("title", "name") and isinstance(kw.value, ast.Constant):
                            name = kw.value.value
                            break
                    findings.append(Finding(
                        node_type=NodeType.SERVICE,
                        name=name,
                        file_path=rel_path,
                        line_number=node.lineno,
                        description=f"{func_name} application/router",
                        metadata={"framework": func_name},
                    ))
        return findings

    def _find_auth_patterns(self, tree: ast.AST, rel_path: str, content: str) -> list[Finding]:
        findings = []

        # Check for common insecure patterns
        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            if line.lstrip().startswith("#"):
                continue
            if GenericAnalyzer._is_string_literal_or_pattern(line):
                continue

            # verify=False in requests/httpx
            if re.search(r'verify\s*=\s*False', line):
                findings.append(Finding(
                    node_type=NodeType.VULNERABILITY,
                    name="TLS verification disabled",
                    file_path=rel_path,
                    line_number=i,
                    severity=Severity.MEDIUM,
                    description="SSL/TLS certificate verification is disabled",
                    metadata={"vuln_type": "insecure_tls"},
                ))

            # eval(), exec() with potential user input
            eval_match = re.search(r'\b(eval|exec)\s*\(', line)
            if eval_match and "import" not in line.lower():
                # Skip if inside a string literal
                prefix = line[:eval_match.start()]
                in_string = (prefix.count("'") % 2 == 1) or (prefix.count('"') % 2 == 1)
                if not in_string:
                    findings.append(Finding(
                        node_type=NodeType.VULNERABILITY,
                        name="Dangerous function: eval/exec",
                        file_path=rel_path,
                        line_number=i,
                        severity=Severity.HIGH,
                        description="Use of eval()/exec() may allow code injection",
                        metadata={"vuln_type": "code_injection"},
                    ))

            # subprocess with shell=True
            if re.search(r'subprocess\.\w+\(.*shell\s*=\s*True', line):
                findings.append(Finding(
                    node_type=NodeType.VULNERABILITY,
                    name="subprocess with shell=True",
                    file_path=rel_path,
                    line_number=i,
                    severity=Severity.HIGH,
                    description="subprocess with shell=True is vulnerable to command injection",
                    metadata={"vuln_type": "command_injection"},
                ))

        return findings

    def _get_call_chain(self, node: ast.Attribute) -> str:
        parts = [node.attr]
        current = node.value
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))

    def _get_func_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    def _extract_url_arg(self, node: ast.Call) -> str | None:
        if node.args and isinstance(node.args[0], ast.Constant):
            return str(node.args[0].value)
        if node.args and isinstance(node.args[0], ast.JoinedStr):
            return "<f-string URL>"
        for kw in node.keywords:
            if kw.arg == "url" and isinstance(kw.value, ast.Constant):
                return str(kw.value.value)
        return None

    def _find_sql_injection(self, content: str, rel_path: str) -> list[Finding]:
        """Detect SQL injection via string interpolation in queries."""
        findings = []
        lines = content.split("\n")
        sql_patterns = [
            # f-string SQL: f"SELECT ... {variable}"
            (r'f["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b.*\{', "SQL query with f-string interpolation — use parameterized queries"),
            # %-format SQL: "SELECT ... %s" % variable
            (r'["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*%[sd].*["\']\s*%', "SQL query with % formatting — use parameterized queries"),
            # .format() SQL: "SELECT ...{}".format(variable)
            (r'["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\{\}.*["\']\.format', "SQL query with .format() — use parameterized queries"),
            # String concat SQL: "SELECT " + variable
            (r'["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*["\']\s*\+', "SQL query with string concatenation — use parameterized queries"),
            # execute() with string interpolation
            (r'\.execute\s*\(\s*f["\']', "execute() with f-string — use parameterized queries"),
            (r'\.execute\s*\(\s*["\'].*%[sd].*["\']\s*%', "execute() with % formatting — use parameterized queries"),
            # cursor.execute with string concat
            (r'cursor\.execute\s*\(.*\+', "cursor.execute with string concatenation — use parameterized queries"),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if GenericAnalyzer._is_string_literal_or_pattern(line):
                continue
            for pattern, desc in sql_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        node_type=NodeType.VULNERABILITY,
                        name=f"SQL Injection ({rel_path.split('/')[-1]}:{line_num})",
                        file_path=rel_path,
                        line_number=line_num,
                        severity=Severity.CRITICAL,
                        description=desc,
                        metadata={"vuln_type": "sql_injection"},
                    ))
                    break
        return findings

    def _find_insecure_deserialization(self, content: str, rel_path: str) -> list[Finding]:
        """Detect insecure deserialization patterns."""
        findings = []
        lines = content.split("\n")
        deser_patterns = [
            (r'pickle\.loads?\s*\(', "pickle.load()", "CRITICAL", "pickle deserialization can execute arbitrary code — use JSON or msgpack"),
            (r'pickle\.Unpickler\s*\(', "pickle.Unpickler()", "CRITICAL", "pickle deserialization can execute arbitrary code"),
            (r'yaml\.load\s*\((?!.*Loader\s*=\s*(?:yaml\.)?SafeLoader)', "yaml.load()", "HIGH", "yaml.load() without SafeLoader can execute arbitrary code — use yaml.safe_load()"),
            (r'yaml\.unsafe_load\s*\(', "yaml.unsafe_load()", "CRITICAL", "yaml.unsafe_load() can execute arbitrary code — use yaml.safe_load()"),
            (r'marshal\.loads?\s*\(', "marshal.load()", "HIGH", "marshal deserialization is not safe for untrusted data"),
            (r'shelve\.open\s*\(', "shelve.open()", "HIGH", "shelve uses pickle internally — unsafe for untrusted data"),
            (r'jsonpickle\.decode\s*\(', "jsonpickle.decode()", "HIGH", "jsonpickle can execute arbitrary code during deserialization"),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if GenericAnalyzer._is_string_literal_or_pattern(line):
                continue
            for pattern, name, sev, desc in deser_patterns:
                if re.search(pattern, line):
                    severity = Severity.CRITICAL if sev == "CRITICAL" else Severity.HIGH
                    findings.append(Finding(
                        node_type=NodeType.VULNERABILITY,
                        name=f"Insecure Deserialization: {name}",
                        file_path=rel_path,
                        line_number=line_num,
                        severity=severity,
                        description=desc,
                        metadata={"vuln_type": "insecure_deserialization", "function": name},
                    ))
                    break
        return findings

    def _find_ssrf_patterns(self, tree: ast.AST, rel_path: str, content: str) -> list[Finding]:
        """Detect potential SSRF: HTTP calls where URL comes from user input."""
        findings = []
        lines = content.split("\n")
        ssrf_patterns = [
            # requests/httpx with user-controlled URL
            (r'(?:requests|httpx)\.\w+\s*\(.*(?:request\.|params|args|query|form|data)\b', "HTTP request with user-controlled URL — validate against SSRF"),
            (r'(?:requests|httpx)\.\w+\s*\(\s*(?:url|target|endpoint)\s*[,)]', "HTTP request with variable URL — ensure SSRF protection"),
            # urllib
            (r'urllib\.request\.urlopen\s*\(.*(?:request|params|args)', "urlopen with user input — validate against SSRF"),
            # aiohttp
            (r'session\.\w+\s*\(.*(?:request\.|params|query)', "aiohttp request with user input — validate against SSRF"),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if GenericAnalyzer._is_string_literal_or_pattern(line):
                continue
            for pattern, desc in ssrf_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        node_type=NodeType.VULNERABILITY,
                        name=f"SSRF Risk ({rel_path.split('/')[-1]}:{line_num})",
                        file_path=rel_path,
                        line_number=line_num,
                        severity=Severity.HIGH,
                        description=desc,
                        metadata={"vuln_type": "ssrf"},
                    ))
                    break
        return findings
