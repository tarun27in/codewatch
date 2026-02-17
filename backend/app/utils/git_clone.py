"""Clone GitHub repos to temp directory for scanning."""

import logging
import shutil
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


def clone_repo(github_url: str, timeout: int = 120) -> str:
    """Clone a GitHub repo to a temp directory and return the path."""
    try:
        import git
    except ImportError:
        raise RuntimeError("gitpython is required for GitHub URL scanning. Install with: pip install gitpython")

    # Normalize URL
    url = github_url.strip()
    if url.endswith("/"):
        url = url[:-1]
    if not url.endswith(".git"):
        url = url + ".git"

    # Create temp directory
    temp_dir = tempfile.mkdtemp(prefix="skg-clone-")
    logger.info(f"Cloning {url} to {temp_dir}")

    try:
        git.Repo.clone_from(
            url,
            temp_dir,
            depth=1,  # Shallow clone for speed
            no_checkout=False,
        )
        logger.info(f"Clone complete: {temp_dir}")
        return temp_dir
    except Exception as e:
        # Clean up on failure
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise RuntimeError(f"Failed to clone {url}: {e}") from e


def cleanup_clone(path: str):
    """Remove a cloned repo temp directory."""
    try:
        if path and Path(path).exists() and "skg-clone-" in path:
            shutil.rmtree(path, ignore_errors=True)
            logger.info(f"Cleaned up clone: {path}")
    except Exception as e:
        logger.warning(f"Failed to clean up {path}: {e}")
