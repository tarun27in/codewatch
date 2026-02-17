"""Config file analyzer: Dockerfile, K8s YAML, .env, docker-compose."""

import re
from ..analyzers.base import BaseAnalyzer
from ...models import Finding, NodeType, Severity

try:
    import yaml
except ImportError:
    yaml = None


class ConfigAnalyzer(BaseAnalyzer):
    """Analyzer for configuration files."""

    @property
    def supported_languages(self) -> list[str]:
        return ["yaml", "dockerfile", "json", "toml"]

    def analyze(self, file_path: str, content: str, metadata: dict) -> list[Finding]:
        rel_path = metadata.get("rel_path", file_path)
        filename = metadata.get("filename", "").lower()

        if filename == "dockerfile" or filename.startswith("dockerfile."):
            return self._analyze_dockerfile(content, rel_path)
        elif filename.startswith(".env"):
            return self._analyze_env_file(content, rel_path)
        elif filename.endswith((".yaml", ".yml")):
            return self._analyze_yaml(content, rel_path, filename)
        return []

    def _analyze_dockerfile(self, content: str, rel_path: str) -> list[Finding]:
        findings = []
        lines = content.split("\n")

        has_user = False
        has_healthcheck = False
        exposed_ports = []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            if stripped.startswith("USER") and "root" not in stripped.lower():
                has_user = True

            if stripped.startswith("HEALTHCHECK"):
                has_healthcheck = True

            # EXPOSE ports
            match = re.match(r'EXPOSE\s+(\d+)', stripped)
            if match:
                port = match.group(1)
                exposed_ports.append(port)
                findings.append(Finding(
                    node_type=NodeType.ENTRY_POINT,
                    name=f"Container port :{port}",
                    file_path=rel_path,
                    line_number=i,
                    description=f"Docker container exposes port {port}",
                    metadata={"port": port, "source": "dockerfile"},
                ))

            # Running as root
            if re.match(r'USER\s+root', stripped):
                findings.append(Finding(
                    node_type=NodeType.VULNERABILITY,
                    name="Container runs as root",
                    file_path=rel_path,
                    line_number=i,
                    severity=Severity.HIGH,
                    description="Container explicitly runs as root user",
                    metadata={"vuln_type": "container_root"},
                ))

            # ADD instead of COPY
            if stripped.startswith("ADD ") and not stripped.startswith("ADD --from"):
                findings.append(Finding(
                    node_type=NodeType.VULNERABILITY,
                    name="ADD instead of COPY",
                    file_path=rel_path,
                    line_number=i,
                    severity=Severity.LOW,
                    description="ADD can auto-extract archives and fetch URLs; prefer COPY",
                    metadata={"vuln_type": "dockerfile_add"},
                ))

        # Missing USER directive
        if not has_user:
            findings.append(Finding(
                node_type=NodeType.VULNERABILITY,
                name="No USER directive",
                file_path=rel_path,
                line_number=1,
                severity=Severity.MEDIUM,
                description="Dockerfile has no USER directive — container may run as root",
                metadata={"vuln_type": "missing_user"},
            ))

        # Create a service node for the container
        if exposed_ports:
            findings.append(Finding(
                node_type=NodeType.SERVICE,
                name=f"Docker Container (:{', :'.join(exposed_ports)})",
                file_path=rel_path,
                line_number=1,
                description="Containerized service",
                metadata={"ports": exposed_ports, "has_user": has_user, "has_healthcheck": has_healthcheck},
            ))

        return findings

    def _analyze_env_file(self, content: str, rel_path: str) -> list[Finding]:
        findings = []
        lines = content.split("\n")
        secret_words = {"key", "secret", "password", "token", "credential", "auth", "private"}

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            match = re.match(r'([A-Z_][A-Z0-9_]*)=(.+)', stripped)
            if match:
                var_name = match.group(1)
                value = match.group(2).strip().strip("\"'")

                is_secret = any(w in var_name.lower() for w in secret_words)
                has_value = bool(value) and value not in ("", "changeme", "your_key_here", "xxx")

                if is_secret:
                    severity = Severity.CRITICAL if has_value else Severity.INFO
                    findings.append(Finding(
                        node_type=NodeType.SECRET,
                        name=var_name,
                        file_path=rel_path,
                        line_number=i,
                        severity=severity,
                        description=f"{'Hardcoded' if has_value else 'Empty'} secret in .env file",
                        metadata={"var_name": var_name, "has_value": has_value, "source": "env_file"},
                    ))
                else:
                    # Non-secret config vars that look like URLs (external services)
                    if re.match(r'https?://', value):
                        findings.append(Finding(
                            node_type=NodeType.EXTERNAL_API,
                            name=f"{var_name}: {value[:60]}",
                            file_path=rel_path,
                            line_number=i,
                            description=f"External service URL from .env",
                            metadata={"var_name": var_name, "url": value},
                        ))

        return findings

    def _analyze_yaml(self, content: str, rel_path: str, filename: str) -> list[Finding]:
        findings = []
        if yaml is None:
            return findings

        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            return findings

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            kind = doc.get("kind", "")

            # Kubernetes Deployment
            if kind == "Deployment":
                findings.extend(self._analyze_k8s_deployment(doc, rel_path))
            # NetworkPolicy
            elif kind == "NetworkPolicy":
                findings.extend(self._analyze_k8s_network_policy(doc, rel_path))
            # Service
            elif kind == "Service":
                findings.extend(self._analyze_k8s_service(doc, rel_path))
            # docker-compose
            elif "services" in doc:
                findings.extend(self._analyze_docker_compose(doc, rel_path))

        return findings

    def _analyze_k8s_deployment(self, doc: dict, rel_path: str) -> list[Finding]:
        findings = []
        name = doc.get("metadata", {}).get("name", "unknown")

        spec = doc.get("spec", {}).get("template", {}).get("spec", {})
        containers = spec.get("containers", [])

        for container in containers:
            sec_ctx = container.get("securityContext", {})

            if not sec_ctx.get("readOnlyRootFilesystem"):
                findings.append(Finding(
                    node_type=NodeType.VULNERABILITY,
                    name=f"Writable root filesystem: {name}",
                    file_path=rel_path,
                    line_number=1,
                    severity=Severity.LOW,
                    description="Container filesystem is writable",
                    metadata={"vuln_type": "writable_fs", "deployment": name},
                ))

            if sec_ctx.get("privileged"):
                findings.append(Finding(
                    node_type=NodeType.VULNERABILITY,
                    name=f"Privileged container: {name}",
                    file_path=rel_path,
                    line_number=1,
                    severity=Severity.CRITICAL,
                    description="Container runs in privileged mode",
                    metadata={"vuln_type": "privileged_container", "deployment": name},
                ))

            # Create trust boundary node
            findings.append(Finding(
                node_type=NodeType.AUTH_BOUNDARY,
                name=f"K8s: {name}",
                file_path=rel_path,
                line_number=1,
                description=f"Kubernetes deployment: {name}",
                metadata={"kind": "Deployment", "name": name},
            ))

        return findings

    def _analyze_k8s_network_policy(self, doc: dict, rel_path: str) -> list[Finding]:
        findings = []
        name = doc.get("metadata", {}).get("name", "unknown")
        findings.append(Finding(
            node_type=NodeType.AUTH_BOUNDARY,
            name=f"NetworkPolicy: {name}",
            file_path=rel_path,
            line_number=1,
            description="Kubernetes network policy",
            metadata={"kind": "NetworkPolicy", "name": name},
        ))
        return findings

    def _analyze_k8s_service(self, doc: dict, rel_path: str) -> list[Finding]:
        findings = []
        name = doc.get("metadata", {}).get("name", "unknown")
        svc_type = doc.get("spec", {}).get("type", "ClusterIP")
        ports = doc.get("spec", {}).get("ports", [])

        for port in ports:
            findings.append(Finding(
                node_type=NodeType.ENTRY_POINT,
                name=f"K8s Service {name}:{port.get('port')}",
                file_path=rel_path,
                line_number=1,
                description=f"{svc_type} service exposing port {port.get('port')}",
                metadata={"kind": "Service", "name": name, "type": svc_type},
            ))

        return findings

    def _analyze_docker_compose(self, doc: dict, rel_path: str) -> list[Finding]:
        findings = []
        services = doc.get("services", {})

        for svc_name, svc_config in services.items():
            if not isinstance(svc_config, dict):
                continue

            ports = svc_config.get("ports", [])
            for port in ports:
                findings.append(Finding(
                    node_type=NodeType.ENTRY_POINT,
                    name=f"Compose {svc_name}:{port}",
                    file_path=rel_path,
                    line_number=1,
                    description=f"Docker Compose service port mapping",
                    metadata={"service": svc_name, "port": str(port)},
                ))

            findings.append(Finding(
                node_type=NodeType.SERVICE,
                name=f"Compose: {svc_name}",
                file_path=rel_path,
                line_number=1,
                description=f"Docker Compose service",
                metadata={"service": svc_name, "image": svc_config.get("image", "")},
            ))

        return findings
