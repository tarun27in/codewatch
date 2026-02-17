"""Git history analyzer: scans git commit diffs for secrets that were committed then removed."""

import logging
import os
import re
from typing import Optional

from ...models import Finding, NodeType, Severity
from .generic_analyzer import SECRET_PATTERNS

logger = logging.getLogger(__name__)

MAX_COMMITS = 100
MAX_FINDINGS = 50


def analyze_git_history(scan_path: str) -> list[Finding]:
    """Scan git history for secrets in deleted/modified lines."""
    git_dir = os.path.join(scan_path, ".git")
    if not os.path.isdir(git_dir):
        return []

    try:
        import git
    except ImportError:
        logger.warning("GitPython not installed, skipping git history scan")
        return []

    try:
        repo = git.Repo(scan_path)
    except Exception as e:
        logger.warning("Failed to open git repo at %s: %s", scan_path, e)
        return []

    findings: list[Finding] = []
    seen_secrets: set[str] = set()

    try:
        commits = list(repo.iter_commits(max_count=MAX_COMMITS, no_merges=True))
    except Exception as e:
        logger.warning("Failed to iterate commits: %s", e)
        return []

    for commit in commits:
        if len(findings) >= MAX_FINDINGS:
            break

        try:
            # Get diff against parent
            if not commit.parents:
                continue
            parent = commit.parents[0]
            diffs = parent.diff(commit, create_patch=True)
        except Exception:
            continue

        for diff in diffs:
            if len(findings) >= MAX_FINDINGS:
                break

            try:
                diff_text = diff.diff
                if isinstance(diff_text, bytes):
                    diff_text = diff_text.decode("utf-8", errors="replace")
            except Exception:
                continue

            # Look at removed lines (lines starting with -)
            for line in diff_text.split("\n"):
                if not line.startswith("-") or line.startswith("---"):
                    continue

                removed_line = line[1:]  # Strip the leading -

                for pattern, secret_type in SECRET_PATTERNS:
                    if re.search(pattern, removed_line):
                        # Skip placeholders
                        if any(p in removed_line.lower() for p in [
                            "example", "placeholder", "your_", "xxx", "changeme",
                            "${", "{{", "os.environ", "process.env", "getenv"
                        ]):
                            continue

                        # Deduplicate by pattern + file
                        file_path = diff.b_path or diff.a_path or "unknown"
                        dedup_key = f"{secret_type}:{file_path}"
                        if dedup_key in seen_secrets:
                            continue
                        seen_secrets.add(dedup_key)

                        commit_date = commit.committed_datetime.strftime("%Y-%m-%d")
                        author = str(commit.author)
                        short_hash = commit.hexsha[:8]

                        findings.append(Finding(
                            node_type=NodeType.VULNERABILITY,
                            name=f"Historical {secret_type} in {file_path}",
                            file_path=file_path,
                            line_number=0,
                            severity=Severity.HIGH,
                            description=(
                                f"{secret_type} was committed in {short_hash} by {author} "
                                f"on {commit_date} and later removed — the secret is still in git history"
                            ),
                            metadata={
                                "vuln_type": "historical_secret",
                                "secret_type": secret_type,
                                "commit_hash": commit.hexsha,
                                "commit_short": short_hash,
                                "author": author,
                                "date": commit_date,
                            },
                        ))
                        break  # One finding per diff hunk

    logger.info("Git history scan found %d historical secrets", len(findings))
    return findings
