"""Browse local filesystem directories."""

from pathlib import Path
from fastapi import APIRouter, Query
from pydantic import BaseModel

router = APIRouter(prefix="/api", tags=["browse"])


class DirEntry(BaseModel):
    name: str
    path: str
    is_dir: bool


class BrowseResponse(BaseModel):
    current: str
    parent: str | None
    entries: list[DirEntry]


@router.get("/browse", response_model=BrowseResponse)
async def browse_directory(path: str = Query(default="~", description="Directory path to browse")):
    """List subdirectories of the given path for folder selection."""
    target = Path(path).expanduser().resolve()

    if not target.exists() or not target.is_dir():
        return BrowseResponse(current=str(target), parent=str(target.parent), entries=[])

    entries: list[DirEntry] = []
    try:
        for item in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            # Skip hidden files/dirs and common non-project dirs
            if item.name.startswith('.'):
                continue
            if item.name in ('node_modules', '__pycache__', '.git', 'venv', '.venv'):
                continue
            entries.append(DirEntry(
                name=item.name,
                path=str(item),
                is_dir=item.is_dir(),
            ))
    except PermissionError:
        pass

    parent = str(target.parent) if target.parent != target else None

    return BrowseResponse(current=str(target), parent=parent, entries=entries)
