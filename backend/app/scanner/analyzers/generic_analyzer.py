"""Generic analyzer: regex-based detection for secrets, URLs, auth patterns in any language."""

import re
from ..analyzers.base import BaseAnalyzer
from ...models import Finding, NodeType, Severity

# Patterns for secret/credential detection
SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']{8,})["\']', "API Key"),
    (r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', "Password/Secret"),
    (r'(?i)(token|auth_token|access_token|bearer)\s*[=:]\s*["\']([^"\']{8,})["\']', "Token"),
    (r'(?i)(private[_-]?key|priv[_-]?key)\s*[=:]\s*["\']([^"\']{8,})["\']', "Private Key"),
    (r'(?i)(database_url|db_url|connection_string)\s*[=:]\s*["\']([^"\']{8,})["\']', "Connection String"),
    (r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["\']([^"\']{8,})["\']', "AWS Credential"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
    (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', "Private Key File"),
    (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API Key"),
]

# Patterns for hardcoded URLs with potential security implications
URL_PATTERNS = [
    (r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s"\']*)?', "Non-HTTPS URL"),
]

# Patterns for security-related TODOs/FIXMEs
TODO_PATTERNS = [
    (r'(?i)#\s*TODO:?\s*(.*(?:security|auth|secret|password|token|credential|encrypt|vulnerab|hack|inject|xss|csrf|sql).*)', "Security TODO"),
    (r'(?i)#\s*FIXME:?\s*(.*(?:security|auth|secret|password|token|credential|encrypt|vulnerab).*)', "Security FIXME"),
    (r'(?i)//\s*TODO:?\s*(.*(?:security|auth|secret|password|token|credential|encrypt|vulnerab).*)', "Security TODO"),
    (r'(?i)//\s*FIXME:?\s*(.*(?:security|auth|secret|password|token|credential|encrypt|vulnerab).*)', "Security FIXME"),
]

# Environment variable patterns
ENV_VAR_PATTERNS = [
    (r'os\.environ(?:\.get)?\s*\(\s*["\']([^"\']+)["\']', "Python env var"),
    (r'process\.env\.([A-Z_][A-Z0-9_]*)', "JS env var"),
    (r'os\.Getenv\s*\(\s*["\']([^"\']+)["\']', "Go env var"),
    (r'System\.getenv\s*\(\s*["\']([^"\']+)["\']', "Java env var"),
    (r'\$\{([A-Z_][A-Z0-9_]*)\}', "Template env var"),
    (r'ENV\s+([A-Z_][A-Z0-9_]*)', "Docker ENV"),
]


class GenericAnalyzer(BaseAnalyzer):
    """Regex-based analyzer that works on any language."""

    @property
    def supported_languages(self) -> list[str]:
        return ["*"]

    @staticmethod
    def _is_string_literal_or_pattern(line: str) -> bool:
        """Check if a line is a regex pattern definition, tuple in a pattern list,
        or a description/remediation string — not actual executable code."""
        stripped = line.strip()
        # Python raw string regex pattern: (r'...' or r"...")
        if re.search(r"""\br['"]""", stripped):
            return True
        # Line is a tuple/list element that starts with ( and contains a regex-style string
        if stripped.startswith("(") and re.search(r"""r['"]""", stripped):
            return True
        # Line is purely a string literal (a description, remediation text, etc.)
        # Matches lines like: "Use SHA-256 instead of DES/RC4", 'pickle deserialization...'
        if re.match(r"""^\s*['"].*['"]\s*[,)}\]]?\s*$""", stripped):
            return True
        # Line is inside a data structure definition — starts with ( or [ and contains only strings
        if re.match(r"""^\s*[\[(]\s*r?['"]""", stripped):
            return True
        # Line contains .includes('...') or .includes("...") wrapping the suspicious text
        # e.g.: desc.includes('debug=true') or desc.includes('pickle.load')
        if re.search(r'\.includes\s*\(', stripped):
            return True
        # Line is a JS/TS conditional checking string values against known patterns
        # e.g.: if (meta.vuln_type === 'debug_enabled')
        if re.search(r"""===?\s*['"].*['"]""", stripped) and "if" in stripped[:20]:
            return True
        return False

    @staticmethod
    def _is_false_positive_secret(line: str, match: re.Match) -> bool:
        """Check if a secret match is actually a false positive."""
        lower = line.lower()

        # Skip placeholders, variable references, env lookups
        if any(p in lower for p in [
            "example", "placeholder", "your_", "xxx", "changeme",
            "${", "{{", "os.environ", "process.env", "getenv",
        ]):
            return True

        # Extract the captured value (last group is usually the value)
        groups = match.groups()
        value = groups[-1] if groups else ""
        if not value:
            return True  # No value captured

        value_lower = value.lower().strip()

        # Skip if value is obviously not a secret:
        # - Color codes: #EF4444, #3B82F6, etc.
        if re.match(r'^#[0-9a-fA-F]{3,8}$', value_lower):
            return True
        # - Unicode escapes or short symbol strings
        if re.match(r'^\\u[0-9a-fA-F]{4}', value):
            return True
        # - Very short enum/label values (e.g., "secret", "Secret", "Exposed Secrets")
        if len(value) < 30 and value_lower.replace("_", "").replace("-", "").replace(" ", "").isalpha():
            return True
        # - CSS class names, Tailwind values
        if re.match(r'^[a-z][a-z0-9_-]*$', value) and len(value) < 40:
            return True
        # - Common non-secret patterns: "true", "false", "null", "none", numbers
        if value_lower in ("true", "false", "null", "none", "yes", "no", "0", "1"):
            return True

        # Skip values that look like natural language sentences (contain spaces + common words)
        if " " in value and len(value) > 20:
            return True

        # Skip if the line looks like a type definition, enum, or object key mapping
        # e.g., "secret: '#EF4444'" or "SECRET = 'secret'" or "secret: 'Exposed Secrets'"
        stripped = line.strip()
        # Object/dict literal where key is a bare word mapping to a label/config
        if re.match(r'^["\']?(secret|password|passwd|pwd|token)["\']?\s*[:=]', stripped, re.IGNORECASE):
            # This looks like a key in a dict/object — only flag if value looks like an actual credential
            # Actual credentials are typically: long random strings, no spaces, contain mixed case + digits
            if not (
                len(value) >= 16 and " " not in value
                and re.search(r'[A-Z]', value) and re.search(r'[a-z0-9]', value)
            ) and not any(value.startswith(p) for p in ['sk-', 'pk-', 'ghp_', 'gho_', 'AKIA', 'eyJ']):
                return True

        return False

    def analyze(self, file_path: str, content: str, metadata: dict) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#!"):
                continue

            # Secret detection
            for pattern, secret_type in SECRET_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    if self._is_false_positive_secret(line, match):
                        continue
                    findings.append(Finding(
                        node_type=NodeType.SECRET,
                        name=f"{secret_type} ({file_path.split('/')[-1]}:{line_num})",
                        file_path=metadata.get("rel_path", file_path),
                        line_number=line_num,
                        severity=Severity.HIGH,
                        description=f"Potential hardcoded {secret_type.lower()} detected",
                        metadata={"secret_type": secret_type, "pattern_matched": True},
                    ))
                    break  # One finding per line

            # Non-HTTPS URL detection
            for pattern, url_type in URL_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    url = match.group(0)
                    # Skip if in a comment about URLs or obvious dev defaults
                    if "example.com" in url or "test" in url.lower():
                        continue
                    findings.append(Finding(
                        node_type=NodeType.VULNERABILITY,
                        name=f"Non-HTTPS URL: {url[:60]}",
                        file_path=metadata.get("rel_path", file_path),
                        line_number=line_num,
                        severity=Severity.MEDIUM,
                        description=f"Unencrypted HTTP connection: {url}",
                        metadata={"vuln_type": "insecure_transport", "url": url},
                    ))

            # Security TODOs
            for pattern, todo_type in TODO_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    findings.append(Finding(
                        node_type=NodeType.VULNERABILITY,
                        name=f"{todo_type}: {match.group(1)[:60].strip()}",
                        file_path=metadata.get("rel_path", file_path),
                        line_number=line_num,
                        severity=Severity.LOW,
                        description=f"Security-related {todo_type.lower()} found",
                        metadata={"vuln_type": "security_todo", "text": match.group(1).strip()},
                    ))

            # Environment variables (as secret references)
            for pattern, env_type in ENV_VAR_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    var_name = match.group(1)
                    # Only flag if the var name suggests a secret
                    secret_words = {"key", "secret", "password", "token", "credential", "auth", "private"}
                    if any(w in var_name.lower() for w in secret_words):
                        findings.append(Finding(
                            node_type=NodeType.SECRET,
                            name=var_name,
                            file_path=metadata.get("rel_path", file_path),
                            line_number=line_num,
                            severity=Severity.INFO,
                            description=f"Secret loaded from environment variable: {var_name}",
                            metadata={"secret_type": "env_var", "var_name": var_name, "env_type": env_type},
                        ))

        # Cross-language vulnerability patterns (run once on full content)
        rel_path = metadata.get("rel_path", file_path)
        findings.extend(self._detect_weak_crypto(lines, rel_path))
        findings.extend(self._detect_debug_mode(lines, rel_path))
        findings.extend(self._detect_path_traversal(lines, rel_path))
        findings.extend(self._detect_log_injection(lines, rel_path))
        findings.extend(self._detect_open_redirect(lines, rel_path))

        return findings

    def _detect_weak_crypto(self, lines: list[str], rel_path: str) -> list[Finding]:
        """Detect use of weak cryptographic functions."""
        findings = []
        weak_patterns = [
            (r'\bmd5\s*\(', "MD5", "MD5 is cryptographically broken — use SHA-256 or bcrypt"),
            (r'\bsha1\s*\(', "SHA-1", "SHA-1 is deprecated — use SHA-256 or stronger"),
            (r'hashlib\.md5\b', "MD5", "MD5 is cryptographically broken — use hashlib.sha256 or bcrypt"),
            (r'hashlib\.sha1\b', "SHA-1", "SHA-1 is deprecated — use hashlib.sha256 or stronger"),
            (r'createHash\s*\(\s*["\']md5["\']', "MD5", "MD5 is cryptographically broken — use sha256"),
            (r'createHash\s*\(\s*["\']sha1["\']', "SHA-1", "SHA-1 is deprecated — use sha256"),
            (r'DES\b|Blowfish|RC4|RC2', "Weak Cipher", "Weak cipher algorithm — use AES-256-GCM"),
            (r'\bMath\.random\s*\(', "Insecure Random", "Math.random() is not cryptographically secure — use crypto.getRandomValues()"),
            (r'\brandom\.random\s*\(', "Insecure Random", "random.random() is not cryptographically secure — use secrets module"),
            (r'\brandom\.randint\s*\(', "Insecure Random", "random.randint() is not cryptographically secure — use secrets.randbelow()"),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            if self._is_string_literal_or_pattern(line):
                continue
            for pattern, name, desc in weak_patterns:
                if re.search(pattern, line):
                    # Skip MD5/SHA1 used for non-cryptographic purposes (IDs, checksums, cache keys)
                    if name in ("MD5", "SHA-1"):
                        line_lower = line.lower()
                        if any(w in line_lower for w in ["hexdigest", "make_id", "cache_key", "checksum", "fingerprint", "etag"]):
                            continue
                    findings.append(Finding(
                        node_type=NodeType.VULNERABILITY,
                        name=f"Weak Crypto: {name}",
                        file_path=rel_path,
                        line_number=line_num,
                        severity=Severity.MEDIUM,
                        description=desc,
                        metadata={"vuln_type": "weak_cryptography", "algorithm": name},
                    ))
                    break
        return findings

    def _detect_debug_mode(self, lines: list[str], rel_path: str) -> list[Finding]:
        """Detect debug mode enabled in production configs."""
        findings = []
        debug_patterns = [
            (r'DEBUG\s*=\s*True\b', "DEBUG=True may expose sensitive data in production"),
            (r'app\.debug\s*=\s*True\b', "Flask debug mode leaks stack traces and allows code execution"),
            (r'debug\s*[:=]\s*true\b', "Debug mode should be disabled in production"),
            (r'FLASK_DEBUG\s*=\s*1\b', "Flask debug mode leaks stack traces"),
            (r'NODE_ENV\s*[=:]\s*["\']development["\']', "NODE_ENV set to development — should be production in deploy"),
            (r'stacktrace\s*[:=]\s*true\b', "Stack trace exposure leaks internal implementation details"),
            (r'verbose\s*[:=]\s*true\b.*error', "Verbose error output may leak sensitive details"),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            if self._is_string_literal_or_pattern(line):
                continue
            for pattern, desc in debug_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        node_type=NodeType.VULNERABILITY,
                        name=f"Debug Mode: {line.strip()[:50]}",
                        file_path=rel_path,
                        line_number=line_num,
                        severity=Severity.MEDIUM,
                        description=desc,
                        metadata={"vuln_type": "debug_enabled"},
                    ))
                    break
        return findings

    def _detect_path_traversal(self, lines: list[str], rel_path: str) -> list[Finding]:
        """Detect potential path traversal vulnerabilities."""
        findings = []
        # File operations with user-controllable paths
        traversal_patterns = [
            (r'open\s*\(.*\+.*\)', "File open with string concatenation — may allow path traversal"),
            (r'readFile(?:Sync)?\s*\(.*\+', "File read with string concatenation — may allow path traversal"),
            (r'writeFile(?:Sync)?\s*\(.*\+', "File write with string concatenation — may allow path traversal"),
            (r'send_file\s*\(.*request', "send_file with request data — validate path to prevent traversal"),
            (r'res\.sendFile\s*\(.*req\.', "sendFile with request data — validate path to prevent traversal"),
            (r'os\.path\.join\s*\(.*request', "os.path.join with request data — validate against directory traversal"),
            (r'Path\s*\(.*request', "Path construction with request data — validate against traversal"),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            if self._is_string_literal_or_pattern(line):
                continue
            for pattern, desc in traversal_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        node_type=NodeType.VULNERABILITY,
                        name=f"Path Traversal Risk ({rel_path.split('/')[-1]}:{line_num})",
                        file_path=rel_path,
                        line_number=line_num,
                        severity=Severity.HIGH,
                        description=desc,
                        metadata={"vuln_type": "path_traversal"},
                    ))
                    break
        return findings

    def _detect_log_injection(self, lines: list[str], rel_path: str) -> list[Finding]:
        """Detect sensitive data being logged."""
        findings = []
        log_patterns = [
            (r'(?:log(?:ger)?|console)\.\w+\s*\(.*(?:password|passwd|pwd|secret|token|api_key|apikey|credential|private_key)', "Sensitive data in log output — may leak credentials in log files"),
            (r'print\s*\(.*(?:password|passwd|secret|token|api_key|credential)', "Sensitive data in print statement — remove before production"),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            if self._is_string_literal_or_pattern(line):
                continue
            for pattern, desc in log_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Skip if the line is defining the variable, not logging it
                    if "=" in line and "log" not in line.split("=")[0].lower():
                        continue
                    # Skip if the sensitive keyword only appears as a count/label (not an actual value)
                    # e.g., "found 5 secrets" or "scanning for tokens" vs "token=sk-1234"
                    log_lower = line.lower()
                    is_count_or_label = any(p in log_lower for p in [
                        "found", "scanning", "detected", "count", "total",
                        "number of", "historical", "checking", "analyzed",
                    ])
                    has_value_pattern = bool(re.search(
                        r'(?:password|secret|token|api_key|credential)\s*[=:]\s*[{%f]',
                        line, re.IGNORECASE
                    ))
                    if is_count_or_label and not has_value_pattern:
                        continue
                    findings.append(Finding(
                        node_type=NodeType.VULNERABILITY,
                        name=f"Sensitive Data Logged ({rel_path.split('/')[-1]}:{line_num})",
                        file_path=rel_path,
                        line_number=line_num,
                        severity=Severity.HIGH,
                        description=desc,
                        metadata={"vuln_type": "sensitive_data_logged"},
                    ))
                    break
        return findings

    def _detect_open_redirect(self, lines: list[str], rel_path: str) -> list[Finding]:
        """Detect potential open redirect vulnerabilities."""
        findings = []
        redirect_patterns = [
            (r'redirect\s*\(.*(?:request|req|params|query|args)', "Redirect with user-controlled URL — validate against open redirect"),
            (r'res\.redirect\s*\(.*(?:req\.|params|query)', "Express redirect with user input — validate URL to prevent open redirect"),
            (r'RedirectResponse\s*\(.*(?:request|query)', "RedirectResponse with user input — validate URL to prevent open redirect"),
            (r'Location\s*[:=]\s*.*(?:request|req\.|params|query)', "Location header from user input — validate against open redirect"),
            (r'window\.location\s*=\s*.*(?:param|query|search|hash|input)', "Client-side redirect with user input — validate URL"),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            if self._is_string_literal_or_pattern(line):
                continue
            for pattern, desc in redirect_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        node_type=NodeType.VULNERABILITY,
                        name=f"Open Redirect ({rel_path.split('/')[-1]}:{line_num})",
                        file_path=rel_path,
                        line_number=line_num,
                        severity=Severity.MEDIUM,
                        description=desc,
                        metadata={"vuln_type": "open_redirect"},
                    ))
                    break
        return findings
