"""Dependency analyzer: parse package.json, requirements.txt, go.mod, etc.

Only creates individual nodes for risky/security-relevant packages.
Normal dependencies are grouped into a single summary node per manifest.
"""

import json
import re
from ..analyzers.base import BaseAnalyzer
from ...models import Finding, NodeType, Severity

# Known risky or security-sensitive packages
RISKY_PACKAGES = {
    # Python
    "pyyaml": ("MEDIUM", "YAML deserialization — use safe_load only"),
    "pickle": ("HIGH", "Python pickle is inherently unsafe for untrusted data"),
    "jinja2": ("LOW", "Template injection risk if user input is not escaped"),
    "paramiko": ("LOW", "SSH library — ensure key management is secure"),
    "cryptography": ("INFO", "Crypto library — review for correct usage"),
    "pycryptodome": ("INFO", "Crypto library — review for correct usage"),
    "requests": ("INFO", "HTTP client — verify TLS settings"),
    "httpx": ("INFO", "HTTP client — verify TLS settings"),
    "boto3": ("INFO", "AWS SDK — ensure IAM least privilege"),
    "google-cloud-storage": ("INFO", "GCP SDK — ensure IAM least privilege"),
    "django": ("INFO", "Web framework — keep updated"),
    "flask": ("INFO", "Web framework — keep updated"),
    "fastapi": ("INFO", "Web framework — keep updated"),
    "sqlalchemy": ("LOW", "ORM — review for raw SQL injection"),
    "psycopg2": ("INFO", "PostgreSQL driver"),
    "pymongo": ("LOW", "MongoDB driver — review for NoSQL injection"),
    # JavaScript
    "jsonwebtoken": ("INFO", "JWT library — ensure proper validation"),
    "bcrypt": ("INFO", "Password hashing — good practice"),
    "helmet": ("INFO", "Security headers — good practice"),
    "cors": ("LOW", "CORS configuration — review for overly permissive settings"),
    "express-validator": ("INFO", "Input validation — good practice"),
    "sequelize": ("LOW", "ORM — review for SQL injection in raw queries"),
    "mongoose": ("LOW", "ODM — review for NoSQL injection"),
    "child_process": ("HIGH", "Command execution risk"),
    "vm2": ("HIGH", "Sandbox escape vulnerabilities known"),
    "eval": ("HIGH", "Code execution risk"),
    "serialize-javascript": ("MEDIUM", "Serialization risk"),
}


class DependencyAnalyzer(BaseAnalyzer):
    """Analyze dependency manifests."""

    @property
    def supported_languages(self) -> list[str]:
        return ["json", "toml", "python"]

    def analyze(self, file_path: str, content: str, metadata: dict) -> list[Finding]:
        findings = []
        rel_path = metadata.get("rel_path", file_path)
        filename = metadata.get("filename", "").lower()

        if filename == "package.json":
            findings.extend(self._analyze_package_json(content, rel_path))
        elif filename == "requirements.txt":
            findings.extend(self._analyze_requirements_txt(content, rel_path))
        elif filename == "pyproject.toml":
            findings.extend(self._analyze_pyproject_toml(content, rel_path))
        elif filename == "go.mod":
            findings.extend(self._analyze_go_mod(content, rel_path))

        return findings

    def _analyze_package_json(self, content: str, rel_path: str) -> list[Finding]:
        try:
            pkg = json.loads(content)
        except json.JSONDecodeError:
            return []

        all_deps: dict[str, str] = {}
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            all_deps.update(pkg.get(section, {}))

        return self._group_deps(all_deps, rel_path, "npm")

    def _analyze_requirements_txt(self, content: str, rel_path: str) -> list[Finding]:
        deps: dict[str, str] = {}
        for line in content.split("\n"):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                continue
            match = re.match(r'([a-zA-Z0-9_-]+)\s*(?:[><=!~]+\s*(.+))?', stripped)
            if match:
                dep_name = match.group(1).lower()
                version = match.group(2) or "any"
                deps[dep_name] = version

        return self._group_deps(deps, rel_path, "pip")

    def _analyze_pyproject_toml(self, content: str, rel_path: str) -> list[Finding]:
        deps: dict[str, str] = {}
        in_deps = False
        for line in content.split("\n"):
            stripped = line.strip()
            if stripped.startswith("[") and "dependencies" in stripped.lower():
                in_deps = True
                continue
            elif stripped.startswith("["):
                in_deps = False
                continue
            if in_deps:
                match = re.match(r'["\']([a-zA-Z0-9_-]+)(?:\[.*?\])?', stripped)
                if match:
                    deps[match.group(1).lower()] = "any"
        return self._group_deps(deps, rel_path, "pip")

    def _analyze_go_mod(self, content: str, rel_path: str) -> list[Finding]:
        deps: dict[str, str] = {}
        for line in content.split("\n"):
            match = re.match(r'\s+(\S+)\s+v(\S+)', line)
            if match:
                full_name = match.group(1)
                short_name = full_name.split("/")[-1]
                deps[short_name] = match.group(2)
        return self._group_deps(deps, rel_path, "go")

    def _group_deps(self, deps: dict[str, str], rel_path: str, pkg_manager: str) -> list[Finding]:
        """Only create individual nodes for risky deps. Group the rest into one summary."""
        findings: list[Finding] = []
        normal_deps: list[str] = []

        for dep_name, version in deps.items():
            risk = RISKY_PACKAGES.get(dep_name)
            if risk:
                sev_str, reason = risk
                findings.append(Finding(
                    node_type=NodeType.DEPENDENCY,
                    name=dep_name,
                    file_path=rel_path,
                    line_number=1,
                    severity=Severity(sev_str.lower()),
                    description=f"{pkg_manager}: {dep_name}@{version} — {reason}",
                    metadata={"package_manager": pkg_manager, "version": version, "risk": reason},
                ))
            else:
                normal_deps.append(f"{dep_name}@{version}")

        # Create a single summary node for non-risky deps
        if normal_deps:
            findings.append(Finding(
                node_type=NodeType.DEPENDENCY,
                name=f"{pkg_manager} packages ({len(normal_deps)})",
                file_path=rel_path,
                line_number=1,
                description=f"{len(normal_deps)} {pkg_manager} packages (no known risks)",
                metadata={
                    "package_manager": pkg_manager,
                    "count": len(normal_deps),
                    "packages": ", ".join(sorted(normal_deps)[:20]),
                    "truncated": len(normal_deps) > 20,
                },
            ))

        return findings
