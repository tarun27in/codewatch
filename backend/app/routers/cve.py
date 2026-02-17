"""CVE lookup via OSV.dev API."""

import logging
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["CVE"])

OSV_API = "https://api.osv.dev/v1/query"


class CVELookupRequest(BaseModel):
    package_name: str
    version: Optional[str] = None
    ecosystem: str = "npm"  # npm, PyPI, Go, etc.


class CVEEntry(BaseModel):
    id: str
    summary: str
    severity: Optional[str] = None
    affected_versions: Optional[str] = None
    fixed_version: Optional[str] = None
    url: Optional[str] = None


class CVELookupResponse(BaseModel):
    package_name: str
    version: Optional[str] = None
    vulns: list[CVEEntry]


@router.post("/cve-lookup")
async def cve_lookup(req: CVELookupRequest) -> CVELookupResponse:
    payload: dict = {
        "package": {
            "name": req.package_name,
            "ecosystem": req.ecosystem,
        }
    }
    if req.version:
        payload["version"] = req.version

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(OSV_API, json=payload)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as exc:
        logger.error("OSV API error: %s", exc)
        raise HTTPException(status_code=502, detail=f"OSV API returned {exc.response.status_code}")
    except httpx.RequestError as exc:
        logger.error("OSV API connection error: %s", exc)
        raise HTTPException(status_code=502, detail="Failed to connect to OSV.dev API")

    vulns: list[CVEEntry] = []
    for v in data.get("vulns", []):
        # Extract severity from CVSS or database_specific
        severity = None
        for sev_entry in v.get("severity", []):
            if sev_entry.get("type") == "CVSS_V3":
                score_str = sev_entry.get("score", "")
                # Parse CVSS score if available
                try:
                    # CVSS vector string — extract base score from database_specific instead
                    pass
                except Exception:
                    pass

        # Try database_specific severity
        db_specific = v.get("database_specific", {})
        if db_specific.get("severity"):
            severity = db_specific["severity"].upper()

        # If still no severity, try to extract from CVSS
        if not severity:
            for sev_entry in v.get("severity", []):
                score_str = sev_entry.get("score", "")
                if "/" in score_str:
                    # CVSS vector — rough mapping
                    # Try to find AV:N or similar indicators
                    severity = "MEDIUM"  # default for CVSS vectors

        # Collect affected/fixed versions
        affected_str = None
        fixed_str = None
        for affected in v.get("affected", []):
            pkg = affected.get("package", {})
            if pkg.get("name", "").lower() == req.package_name.lower():
                ranges = affected.get("ranges", [])
                for r in ranges:
                    for event in r.get("events", []):
                        if "fixed" in event:
                            fixed_str = event["fixed"]

                versions = affected.get("versions", [])
                if versions:
                    affected_str = f"{versions[0]} - {versions[-1]}" if len(versions) > 1 else versions[0]

        # Build URL
        vuln_id = v.get("id", "")
        url = f"https://osv.dev/vulnerability/{vuln_id}" if vuln_id else None

        vulns.append(CVEEntry(
            id=vuln_id,
            summary=v.get("summary") or v.get("details", "")[:200] or "No description available",
            severity=severity,
            affected_versions=affected_str,
            fixed_version=fixed_str,
            url=url,
        ))

    return CVELookupResponse(
        package_name=req.package_name,
        version=req.version,
        vulns=vulns,
    )
