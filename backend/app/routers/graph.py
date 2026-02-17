"""Graph data API routes."""

from fastapi import APIRouter, HTTPException

from ..models import SecurityGraph, ScanStatus
from ..scanner.orchestrator import get_scan

router = APIRouter(prefix="/api", tags=["Graph"])


@router.get("/graph/{scan_id}", response_model=SecurityGraph)
async def get_graph(scan_id: str):
    """Get the security knowledge graph for a completed scan."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(404, f"Scan not found: {scan_id}")

    if scan.status != ScanStatus.COMPLETE:
        raise HTTPException(
            409,
            f"Scan is not complete yet. Current status: {scan.status.value}"
        )

    if not scan.graph:
        raise HTTPException(500, "Scan completed but no graph data available")

    return scan.graph
