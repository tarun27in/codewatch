"""Source context API — returns lines of code around a given line number."""

import os
from fastapi import APIRouter, HTTPException, Query

router = APIRouter(prefix="/api", tags=["Source"])


@router.get("/source")
async def get_source_context(
    path: str = Query(..., description="Absolute file path"),
    line: int = Query(..., ge=1, description="Line number"),
    context: int = Query(5, ge=0, le=50, description="Lines of context above/below"),
):
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="File not found")

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not read file: {exc}")

    start = max(0, line - 1 - context)
    end = min(len(all_lines), line + context)
    selected = [l.rstrip("\n\r") for l in all_lines[start:end]]

    return {
        "file_path": path,
        "start_line": start + 1,
        "lines": selected,
    }
