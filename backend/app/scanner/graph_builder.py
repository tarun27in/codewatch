"""Build the security knowledge graph from analyzer findings."""

import hashlib
from collections import defaultdict

from ..models import (
    Finding, GraphNode, GraphEdge, GraphStats,
    SecurityGraph, NodeType, EdgeType, Severity,
)


def _make_id(prefix: str, name: str) -> str:
    """Create a deterministic node ID."""
    h = hashlib.md5(f"{prefix}:{name}".encode()).hexdigest()[:8]
    return f"{prefix}-{h}"


def build_graph(findings: list[Finding], files_scanned: int, languages: list[str]) -> SecurityGraph:
    """Build the security knowledge graph from raw findings."""
    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []
    edge_set: set[tuple[str, str, str]] = set()

    # Group findings by type for relationship building
    by_type: dict[NodeType, list[Finding]] = defaultdict(list)
    for f in findings:
        by_type[f.node_type].append(f)

    # Phase 1: Create nodes (deduplicate by name+type)
    seen_keys: dict[str, str] = {}  # (type, canonical_name) → node_id
    for finding in findings:
        canonical = _canonical_name(finding)
        key = f"{finding.node_type.value}:{canonical}"

        if key in seen_keys:
            node_id = seen_keys[key]
            # Merge metadata: keep the more detailed one
            existing = nodes[node_id]
            if finding.line_number > 0 and existing.line_number == 0:
                existing.line_number = finding.line_number
                existing.file_path = finding.file_path
            if finding.severity and (not existing.severity or _severity_rank(finding.severity) > _severity_rank(existing.severity)):
                existing.severity = finding.severity
            if finding.source_snippet and not existing.source_snippet:
                existing.source_snippet = finding.source_snippet
            continue

        node_id = _make_id(finding.node_type.value[:3], canonical)
        seen_keys[key] = node_id

        nodes[node_id] = GraphNode(
            id=node_id,
            label=finding.name,
            node_type=finding.node_type,
            severity=finding.severity,
            file_path=finding.file_path,
            line_number=finding.line_number,
            description=finding.description,
            metadata=finding.metadata,
            source_snippet=finding.source_snippet,
        )

    # Phase 2: Build edges

    # Get service nodes
    service_nodes = [nid for nid, n in nodes.items() if n.node_type == NodeType.SERVICE]
    primary_service = service_nodes[0] if service_nodes else None

    # If no explicit service node, create one from the project
    if not primary_service:
        primary_service = _make_id("svc", "application")
        nodes[primary_service] = GraphNode(
            id=primary_service,
            label="Application",
            node_type=NodeType.SERVICE,
            description="Main application",
            metadata={},
        )

    for node_id, node in list(nodes.items()):
        # entry_point → service
        if node.node_type == NodeType.ENTRY_POINT:
            _add_edge(edges, edge_set, node_id, primary_service, EdgeType.BELONGS_TO, "serves")

        # service → external_api
        elif node.node_type == NodeType.EXTERNAL_API:
            _add_edge(edges, edge_set, primary_service, node_id, EdgeType.DATA_FLOW, "calls")

        # service → data_store
        elif node.node_type == NodeType.DATA_STORE:
            _add_edge(edges, edge_set, primary_service, node_id, EdgeType.CONNECTS_TO, "connects")

        # secret → service (service uses secret)
        elif node.node_type == NodeType.SECRET:
            _add_edge(edges, edge_set, primary_service, node_id, EdgeType.USES_SECRET, "uses")

        # dependency → service
        elif node.node_type == NodeType.DEPENDENCY:
            _add_edge(edges, edge_set, primary_service, node_id, EdgeType.DEPENDS_ON, "depends on")

    # Link vulnerabilities to the closest related node
    for finding in findings:
        if finding.node_type != NodeType.VULNERABILITY:
            continue

        vuln_key = f"{finding.node_type.value}:{_canonical_name(finding)}"
        vuln_id = seen_keys.get(vuln_key)
        if not vuln_id:
            continue

        # Try to link to a node in the same file
        linked = False
        for other_id, other_node in nodes.items():
            if other_id == vuln_id:
                continue
            if other_node.file_path == finding.file_path and other_node.node_type in (
                NodeType.ENTRY_POINT, NodeType.SERVICE
            ):
                _add_edge(edges, edge_set, other_id, vuln_id, EdgeType.HAS_VULNERABILITY, "vulnerability")
                linked = True
                break

        if not linked and primary_service:
            _add_edge(edges, edge_set, primary_service, vuln_id, EdgeType.HAS_VULNERABILITY, "vulnerability")

    # Handle explicit connections from findings
    for finding in findings:
        if not finding.connections:
            continue
        source_key = f"{finding.node_type.value}:{_canonical_name(finding)}"
        source_id = seen_keys.get(source_key)
        if not source_id:
            continue

        for conn in finding.connections:
            target_name = conn.get("target_name", "")
            target_type = conn.get("target_type", "vulnerability")
            target_key = f"{target_type}:{target_name}"
            target_id = seen_keys.get(target_key)

            if not target_id:
                # Create the target node if it doesn't exist
                target_id = _make_id(target_type[:3], target_name)
                node_type_enum = NodeType(target_type) if target_type in NodeType.__members__.values() else NodeType.VULNERABILITY
                nodes[target_id] = GraphNode(
                    id=target_id,
                    label=target_name,
                    node_type=node_type_enum,
                    severity=Severity.MEDIUM,
                    file_path=finding.file_path,
                    line_number=finding.line_number,
                    description=f"Auto-detected: {target_name}",
                    metadata={},
                )
                seen_keys[target_key] = target_id

            edge_type = EdgeType(conn.get("type", "has_vulnerability"))
            _add_edge(edges, edge_set, source_id, target_id, edge_type)

    # Phase 3: Compute stats
    stats = _compute_stats(nodes, edges, files_scanned, languages)

    return SecurityGraph(
        nodes=list(nodes.values()),
        edges=edges,
        stats=stats,
    )


def _add_edge(
    edges: list[GraphEdge],
    edge_set: set[tuple[str, str, str]],
    source: str,
    target: str,
    edge_type: EdgeType,
    label: str | None = None,
):
    key = (source, target, edge_type.value)
    if key in edge_set:
        return
    edge_set.add(key)
    edge_id = f"e-{hashlib.md5(f'{source}-{target}-{edge_type.value}'.encode()).hexdigest()[:8]}"
    edges.append(GraphEdge(
        id=edge_id,
        source=source,
        target=target,
        edge_type=edge_type,
        label=label,
    ))


def _canonical_name(finding: Finding) -> str:
    """Get a canonical name for deduplication."""
    name = finding.name
    # For secrets loaded from env vars, use the var name
    if finding.metadata.get("var_name"):
        return finding.metadata["var_name"]
    # For external APIs, use the URL
    if finding.metadata.get("url"):
        url = finding.metadata["url"]
        # Strip query params for dedup
        return url.split("?")[0]
    # For DB connections, use the DB type
    if finding.metadata.get("db_type"):
        return finding.metadata["db_type"]
    return name


def _severity_rank(severity: Severity) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity.value, 0)


def _compute_stats(
    nodes: dict[str, GraphNode],
    edges: list[GraphEdge],
    files_scanned: int,
    languages: list[str],
) -> GraphStats:
    severity_counts: dict[str, int] = defaultdict(int)
    type_counts: dict[str, int] = defaultdict(int)

    for node in nodes.values():
        type_counts[node.node_type.value] += 1
        if node.severity:
            severity_counts[node.severity.value] += 1

    # Risk score: weighted sum normalized by total nodes
    total = max(len(nodes), 1)
    weighted = (
        severity_counts.get("critical", 0) * 10
        + severity_counts.get("high", 0) * 5
        + severity_counts.get("medium", 0) * 2
        + severity_counts.get("low", 0) * 1
    )
    risk_score = min(round(weighted / total, 2), 10.0)

    return GraphStats(
        total_files_scanned=files_scanned,
        total_nodes=len(nodes),
        total_edges=len(edges),
        entry_points=type_counts.get("entry_point", 0),
        external_apis=type_counts.get("external_api", 0),
        data_stores=type_counts.get("data_store", 0),
        secrets=type_counts.get("secret", 0),
        vulnerabilities=type_counts.get("vulnerability", 0),
        dependencies=type_counts.get("dependency", 0),
        risk_score=risk_score,
        severity_counts=dict(severity_counts),
        languages_detected=languages,
    )
