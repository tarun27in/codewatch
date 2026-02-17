"""Scan API routes."""

import os
from fastapi import APIRouter, HTTPException

from ..models import ScanRequest, ScanResult, ScanStatus
from ..scanner.orchestrator import start_scan, get_scan, get_all_scans, delete_scan
from ..utils.git_clone import clone_repo, cleanup_clone

router = APIRouter(prefix="/api", tags=["Scan"])


@router.post("/scan", response_model=ScanResult)
async def create_scan(request: ScanRequest):
    """Start a new security scan."""
    if not request.path and not request.github_url:
        raise HTTPException(400, "Either 'path' or 'github_url' is required")

    scan_path = request.path

    # Handle GitHub URL
    if request.github_url:
        try:
            scan_path = clone_repo(request.github_url)
        except Exception as e:
            raise HTTPException(400, f"Failed to clone repository: {e}")

    # Validate path
    if not scan_path or not os.path.isdir(scan_path):
        raise HTTPException(400, f"Path not found or not a directory: {scan_path}")

    result = await start_scan(scan_path)
    return result


@router.get("/scan/{scan_id}", response_model=ScanResult)
async def get_scan_status(scan_id: str):
    """Get scan status and progress."""
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(404, f"Scan not found: {scan_id}")

    # Don't include full graph in status endpoint (use /graph/{id} for that)
    result = scan.model_copy()
    result.graph = None
    return result


@router.get("/scans", response_model=list[ScanResult])
async def list_scans():
    """List all scans."""
    scans = get_all_scans()
    results = []
    for s in scans:
        r = s.model_copy()
        r.graph = None
        results.append(r)
    return results


@router.delete("/scan/{scan_id}")
async def remove_scan(scan_id: str):
    """Delete scan data from server memory."""
    found = delete_scan(scan_id)
    if not found:
        raise HTTPException(404, f"Scan not found: {scan_id}")
    return {"deleted": True, "scan_id": scan_id}
