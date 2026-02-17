"""Data models for the security knowledge graph."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class NodeType(str, Enum):
    ENTRY_POINT = "entry_point"
    SERVICE = "service"
    EXTERNAL_API = "external_api"
    DATA_STORE = "data_store"
    SECRET = "secret"
    VULNERABILITY = "vulnerability"
    AUTH_BOUNDARY = "auth_boundary"
    DEPENDENCY = "dependency"
    FILE = "file"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EdgeType(str, Enum):
    DATA_FLOW = "data_flow"
    AUTHENTICATION = "authentication"
    USES_SECRET = "uses_secret"
    CONNECTS_TO = "connects_to"
    BELONGS_TO = "belongs_to"
    HAS_VULNERABILITY = "has_vulnerability"
    DEPENDS_ON = "depends_on"
    IMPORTS = "imports"


class Finding(BaseModel):
    """Raw finding from an analyzer."""
    node_type: NodeType
    name: str
    file_path: str
    line_number: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)
    severity: Optional[Severity] = None
    description: Optional[str] = None
    connections: list[dict[str, Any]] = Field(default_factory=list)
    source_snippet: Optional[str] = None


class GraphNode(BaseModel):
    """A node in the security knowledge graph."""
    id: str
    label: str
    node_type: NodeType
    severity: Optional[Severity] = None
    file_path: Optional[str] = None
    line_number: int = 0
    description: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    parent_id: Optional[str] = None
    source_snippet: Optional[str] = None


class GraphEdge(BaseModel):
    """An edge in the security knowledge graph."""
    id: str
    source: str
    target: str
    edge_type: EdgeType
    label: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphStats(BaseModel):
    """Summary statistics for a scan."""
    total_files_scanned: int = 0
    total_nodes: int = 0
    total_edges: int = 0
    entry_points: int = 0
    external_apis: int = 0
    data_stores: int = 0
    secrets: int = 0
    vulnerabilities: int = 0
    dependencies: int = 0
    risk_score: float = 0.0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    languages_detected: list[str] = Field(default_factory=list)


class SecurityGraph(BaseModel):
    """Complete security knowledge graph."""
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    stats: GraphStats = Field(default_factory=GraphStats)


class ScanStatus(str, Enum):
    PENDING = "pending"
    SCANNING = "scanning"
    BUILDING_GRAPH = "building_graph"
    COMPLETE = "complete"
    ERROR = "error"


class ScanRequest(BaseModel):
    """Request to start a scan."""
    path: Optional[str] = None
    github_url: Optional[str] = None


class ScanResult(BaseModel):
    """Status of a scan."""
    scan_id: str
    status: ScanStatus
    progress: float = 0.0
    message: str = ""
    scan_path: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    graph: Optional[SecurityGraph] = None
    error: Optional[str] = None
