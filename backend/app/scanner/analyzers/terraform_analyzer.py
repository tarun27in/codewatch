"""Terraform (.tf) analyzer: parses HCL resources, detects security misconfigs, maps infra topology."""

import re
from .base import BaseAnalyzer
from ...models import Finding, NodeType, Severity, EdgeType


# Patterns for extracting Terraform blocks
BLOCK_RE = re.compile(
    r'^(resource|data|module|provider|variable|output|locals)\s+'
    r'"([^"]+)"(?:\s+"([^"]+)")?\s*\{',
    re.MULTILINE,
)

# Security misconfigurations to detect
SECURITY_CHECKS = {
    # S3 / storage buckets
    "aws_s3_bucket": [
        {
            "field": "acl",
            "bad_values": {"public-read", "public-read-write", "authenticated-read"},
            "severity": Severity.CRITICAL,
            "name": "Public S3 bucket",
            "description": "S3 bucket has a public ACL — data may be exposed to the internet",
            "vuln_type": "public_storage",
        },
    ],
    "aws_s3_bucket_versioning": [
        {
            "field_absent": "versioning_configuration",
            "severity": Severity.LOW,
            "name": "S3 bucket without versioning",
            "description": "S3 bucket does not have versioning enabled — data loss risk",
            "vuln_type": "no_versioning",
        },
    ],
    # Security groups
    "aws_security_group": [
        {
            "pattern": r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
            "severity": Severity.HIGH,
            "name": "Security group open to 0.0.0.0/0",
            "description": "Security group allows traffic from all IP addresses",
            "vuln_type": "open_security_group",
        },
    ],
    "aws_security_group_rule": [
        {
            "pattern": r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
            "severity": Severity.HIGH,
            "name": "Security group rule open to 0.0.0.0/0",
            "description": "Security group rule allows traffic from all IP addresses",
            "vuln_type": "open_security_group",
        },
    ],
    # RDS / databases
    "aws_db_instance": [
        {
            "field": "publicly_accessible",
            "bad_values": {"true"},
            "severity": Severity.CRITICAL,
            "name": "Public RDS instance",
            "description": "RDS database instance is publicly accessible",
            "vuln_type": "public_database",
        },
        {
            "field": "storage_encrypted",
            "bad_values": {"false"},
            "severity": Severity.HIGH,
            "name": "Unencrypted RDS storage",
            "description": "RDS instance storage is not encrypted",
            "vuln_type": "unencrypted_storage",
        },
    ],
    # IAM
    "aws_iam_policy": [
        {
            "pattern": r'"Action"\s*:\s*"\*"',
            "severity": Severity.CRITICAL,
            "name": "IAM policy with wildcard action",
            "description": "IAM policy grants all actions (*) — violates least privilege",
            "vuln_type": "iam_wildcard",
        },
        {
            "pattern": r'"Resource"\s*:\s*"\*"',
            "severity": Severity.HIGH,
            "name": "IAM policy with wildcard resource",
            "description": "IAM policy applies to all resources (*)",
            "vuln_type": "iam_wildcard_resource",
        },
    ],
    # EC2
    "aws_instance": [
        {
            "field_absent": "metadata_options",
            "severity": Severity.MEDIUM,
            "name": "EC2 missing IMDSv2",
            "description": "EC2 instance does not enforce IMDSv2 — vulnerable to SSRF credential theft",
            "vuln_type": "no_imdsv2",
        },
    ],
    # ELB / ALB
    "aws_lb": [
        {
            "field": "internal",
            "bad_values": {"false"},
            "severity": Severity.MEDIUM,
            "name": "Internet-facing load balancer",
            "description": "Load balancer is internet-facing",
            "vuln_type": "public_lb",
        },
    ],
    # GCP
    "google_compute_firewall": [
        {
            "pattern": r'source_ranges\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
            "severity": Severity.HIGH,
            "name": "GCP firewall open to 0.0.0.0/0",
            "description": "GCP firewall rule allows all source IPs",
            "vuln_type": "open_firewall",
        },
    ],
    "google_storage_bucket": [
        {
            "field_absent": "uniform_bucket_level_access",
            "severity": Severity.MEDIUM,
            "name": "GCS bucket without uniform access",
            "description": "GCS bucket does not enforce uniform bucket-level access",
            "vuln_type": "no_uniform_access",
        },
    ],
    # Azure
    "azurerm_network_security_rule": [
        {
            "pattern": r'source_address_prefix\s*=\s*"\*"',
            "severity": Severity.HIGH,
            "name": "Azure NSG rule open to all",
            "description": "Azure network security rule allows traffic from any source",
            "vuln_type": "open_nsg",
        },
    ],
    "azurerm_storage_account": [
        {
            "field": "allow_blob_public_access",
            "bad_values": {"true"},
            "severity": Severity.CRITICAL,
            "name": "Azure storage with public blob access",
            "description": "Azure storage account allows public blob access",
            "vuln_type": "public_storage",
        },
    ],
}

# Resource types that represent infra topology nodes
RESOURCE_NODE_MAP = {
    # Compute
    "aws_instance": ("service", "EC2 Instance"),
    "aws_ecs_service": ("service", "ECS Service"),
    "aws_ecs_task_definition": ("service", "ECS Task"),
    "aws_lambda_function": ("service", "Lambda Function"),
    "google_compute_instance": ("service", "GCE Instance"),
    "google_cloud_run_service": ("service", "Cloud Run Service"),
    "google_cloudfunctions_function": ("service", "Cloud Function"),
    "azurerm_function_app": ("service", "Azure Function"),
    "azurerm_linux_web_app": ("service", "Azure Web App"),
    "azurerm_virtual_machine": ("service", "Azure VM"),
    # Databases
    "aws_db_instance": ("data_store", "RDS Database"),
    "aws_dynamodb_table": ("data_store", "DynamoDB Table"),
    "aws_elasticache_cluster": ("data_store", "ElastiCache"),
    "google_sql_database_instance": ("data_store", "Cloud SQL"),
    "google_bigtable_instance": ("data_store", "Bigtable"),
    "azurerm_cosmosdb_account": ("data_store", "CosmosDB"),
    "azurerm_mssql_database": ("data_store", "Azure SQL"),
    # Storage
    "aws_s3_bucket": ("data_store", "S3 Bucket"),
    "google_storage_bucket": ("data_store", "GCS Bucket"),
    "azurerm_storage_account": ("data_store", "Azure Storage"),
    # Networking / Entry points
    "aws_lb": ("entry_point", "Load Balancer"),
    "aws_alb": ("entry_point", "Application LB"),
    "aws_api_gateway_rest_api": ("entry_point", "API Gateway"),
    "aws_apigatewayv2_api": ("entry_point", "API Gateway v2"),
    "aws_cloudfront_distribution": ("entry_point", "CloudFront CDN"),
    "google_compute_global_forwarding_rule": ("entry_point", "GCP LB"),
    "azurerm_application_gateway": ("entry_point", "Azure App GW"),
    "azurerm_frontdoor": ("entry_point", "Azure Front Door"),
    # Security boundaries
    "aws_security_group": ("auth_boundary", "Security Group"),
    "aws_vpc": ("auth_boundary", "VPC"),
    "google_compute_network": ("auth_boundary", "VPC Network"),
    "google_compute_firewall": ("auth_boundary", "Firewall Rule"),
    "azurerm_network_security_group": ("auth_boundary", "NSG"),
    "azurerm_virtual_network": ("auth_boundary", "VNet"),
    # External / SaaS
    "aws_sns_topic": ("external_api", "SNS Topic"),
    "aws_sqs_queue": ("external_api", "SQS Queue"),
    "google_pubsub_topic": ("external_api", "Pub/Sub Topic"),
}

# Secret patterns in Terraform files
SECRET_PATTERNS = [
    (re.compile(r'(password|secret_key|access_key|api_key|token|private_key)\s*=\s*"([^"]{8,})"', re.IGNORECASE), "Hardcoded secret"),
    (re.compile(r'(AKIA[0-9A-Z]{16})', re.IGNORECASE), "AWS Access Key"),
]


class TerraformAnalyzer(BaseAnalyzer):
    """Analyzer for Terraform (.tf) infrastructure-as-code files."""

    @property
    def supported_languages(self) -> list[str]:
        return ["terraform"]

    def analyze(self, file_path: str, content: str, metadata: dict) -> list[Finding]:
        rel_path = metadata.get("rel_path", file_path)
        findings: list[Finding] = []

        # Extract all resource blocks
        blocks = self._extract_blocks(content)

        for block in blocks:
            block_type = block["block_type"]
            resource_type = block["resource_type"]
            name = block["name"]
            body = block["body"]
            line = block["line"]

            if block_type == "resource":
                # Map to graph nodes
                findings.extend(self._map_resource_node(resource_type, name, body, rel_path, line))

                # Check security misconfigurations
                findings.extend(self._check_security(resource_type, name, body, rel_path, line))

                # Build connections between resources
                findings.extend(self._find_connections(resource_type, name, body, rel_path, line, blocks))

            elif block_type == "module":
                findings.append(Finding(
                    node_type=NodeType.SERVICE,
                    name=f"Module: {resource_type}",
                    file_path=rel_path,
                    line_number=line,
                    description=f"Terraform module: {resource_type}",
                    metadata={"tf_type": "module", "module_name": resource_type, "source": self._extract_field(body, "source")},
                ))

            elif block_type == "provider":
                findings.append(Finding(
                    node_type=NodeType.EXTERNAL_API,
                    name=f"Provider: {resource_type}",
                    file_path=rel_path,
                    line_number=line,
                    description=f"Terraform provider: {resource_type}",
                    metadata={"tf_type": "provider", "provider": resource_type, "region": self._extract_field(body, "region")},
                ))

        # Check for hardcoded secrets
        findings.extend(self._check_secrets(content, rel_path))

        return findings

    def _extract_blocks(self, content: str) -> list[dict]:
        """Extract all top-level blocks from Terraform content."""
        blocks = []
        lines = content.split("\n")

        for match in BLOCK_RE.finditer(content):
            block_type = match.group(1)
            resource_type = match.group(2)
            name = match.group(3) or resource_type

            # Find the line number
            line_num = content[:match.start()].count("\n") + 1

            # Extract block body by counting braces
            start = match.end()
            depth = 1
            pos = start
            while pos < len(content) and depth > 0:
                if content[pos] == "{":
                    depth += 1
                elif content[pos] == "}":
                    depth -= 1
                pos += 1

            body = content[start:pos - 1] if pos <= len(content) else ""

            blocks.append({
                "block_type": block_type,
                "resource_type": resource_type,
                "name": name,
                "body": body,
                "line": line_num,
            })

        return blocks

    def _map_resource_node(self, resource_type: str, name: str, body: str, rel_path: str, line: int) -> list[Finding]:
        """Map a Terraform resource to a graph node."""
        mapping = RESOURCE_NODE_MAP.get(resource_type)
        if not mapping:
            return []

        node_type_str, label_prefix = mapping
        node_type = NodeType(node_type_str)

        # Try to extract a friendly name from tags or name field
        display_name = self._extract_field(body, "name") or name
        tags_name = self._extract_tag(body, "Name")
        if tags_name:
            display_name = tags_name

        return [Finding(
            node_type=node_type,
            name=f"{label_prefix}: {display_name}",
            file_path=rel_path,
            line_number=line,
            description=f"Terraform {resource_type}.{name}",
            metadata={
                "tf_type": "resource",
                "resource_type": resource_type,
                "resource_name": name,
                "source": "terraform",
            },
        )]

    def _check_security(self, resource_type: str, name: str, body: str, rel_path: str, line: int) -> list[Finding]:
        """Check a resource block for security misconfigurations."""
        findings = []
        checks = SECURITY_CHECKS.get(resource_type, [])

        for check in checks:
            triggered = False

            if "field" in check:
                value = self._extract_field(body, check["field"])
                if value and value.lower() in check["bad_values"]:
                    triggered = True

            if "pattern" in check:
                if re.search(check["pattern"], body):
                    triggered = True

            if "field_absent" in check:
                if check["field_absent"] not in body:
                    triggered = True

            if triggered:
                findings.append(Finding(
                    node_type=NodeType.VULNERABILITY,
                    name=f"{check['name']}: {name}",
                    file_path=rel_path,
                    line_number=line,
                    severity=check["severity"],
                    description=check["description"],
                    metadata={
                        "vuln_type": check["vuln_type"],
                        "resource_type": resource_type,
                        "resource_name": name,
                        "source": "terraform",
                    },
                ))

        return findings

    def _find_connections(self, resource_type: str, name: str, body: str, rel_path: str, line: int, all_blocks: list[dict]) -> list[Finding]:
        """Find references to other resources in a block body."""
        findings = []

        # Look for references like: aws_security_group.my_sg.id, module.xxx.output
        ref_pattern = re.compile(r'(?:aws|google|azurerm)_\w+\.(\w+)\.\w+')
        refs = set(ref_pattern.findall(body))

        # Also look for security_group_ids, subnet_ids, etc.
        id_refs = re.findall(r'(\w+)\.(\w+)\.id', body)
        for ref_type, ref_name in id_refs:
            refs.add(ref_name)

        # Create connection findings for cross-references
        for ref_name in refs:
            # Find the target block
            for block in all_blocks:
                if block["name"] == ref_name and block["block_type"] == "resource":
                    target_type = RESOURCE_NODE_MAP.get(block["resource_type"])
                    if target_type:
                        target_node_type = target_type[0]
                        target_label = f"{target_type[1]}: {ref_name}"

                        # Determine edge type
                        if target_node_type == "auth_boundary":
                            edge_type = "belongs_to"
                        elif target_node_type == "data_store":
                            edge_type = "connects_to"
                        elif target_node_type == "external_api":
                            edge_type = "data_flow"
                        else:
                            edge_type = "data_flow"

                        source_mapping = RESOURCE_NODE_MAP.get(resource_type)
                        if source_mapping:
                            source_label = f"{source_mapping[1]}: {name}"
                            # Add connection metadata to the source finding
                            findings.append(Finding(
                                node_type=NodeType(source_mapping[0]),
                                name=source_label,
                                file_path=rel_path,
                                line_number=line,
                                description=f"Terraform {resource_type}.{name}",
                                metadata={
                                    "tf_type": "resource",
                                    "resource_type": resource_type,
                                    "resource_name": name,
                                    "source": "terraform",
                                },
                                connections=[{
                                    "target_name": target_label,
                                    "target_type": target_node_type,
                                    "type": edge_type,
                                }],
                            ))
                    break

        return findings

    def _check_secrets(self, content: str, rel_path: str) -> list[Finding]:
        """Check for hardcoded secrets in Terraform files."""
        findings = []
        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            for pattern, secret_type in SECRET_PATTERNS:
                match = pattern.search(line)
                if match:
                    # Skip if it's a variable reference
                    if "var." in line or "data." in line or "local." in line:
                        continue
                    findings.append(Finding(
                        node_type=NodeType.SECRET,
                        name=f"{secret_type} in Terraform",
                        file_path=rel_path,
                        line_number=i,
                        severity=Severity.CRITICAL,
                        description=f"Hardcoded {secret_type.lower()} found in Terraform configuration",
                        metadata={"secret_type": secret_type, "source": "terraform"},
                    ))
                    break  # One finding per line

        return findings

    @staticmethod
    def _extract_field(body: str, field: str) -> str:
        """Extract a simple field value from HCL body."""
        match = re.search(rf'{field}\s*=\s*"([^"]*)"', body)
        if match:
            return match.group(1)
        match = re.search(rf'{field}\s*=\s*(true|false|\d+)', body)
        if match:
            return match.group(1)
        return ""

    @staticmethod
    def _extract_tag(body: str, tag_name: str) -> str:
        """Extract a value from a tags block."""
        tags_match = re.search(r'tags\s*=?\s*\{([^}]*)\}', body, re.DOTALL)
        if tags_match:
            tag_match = re.search(rf'{tag_name}\s*=\s*"([^"]*)"', tags_match.group(1))
            if tag_match:
                return tag_match.group(1)
        return ""
