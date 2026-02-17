"""Scan orchestrator: walks files, dispatches analyzers, builds graph."""

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from ..config import settings
from ..models import Finding, ScanResult, ScanStatus, SecurityGraph
from .file_walker import walk_files
from .analyzers.generic_analyzer import GenericAnalyzer
from .analyzers.python_analyzer import PythonAnalyzer
from .analyzers.javascript_analyzer import JavaScriptAnalyzer
from .analyzers.config_analyzer import ConfigAnalyzer
from .analyzers.dependency_analyzer import DependencyAnalyzer
from .analyzers.terraform_analyzer import TerraformAnalyzer
from .graph_builder import build_graph
from .analyzers.git_history_analyzer import analyze_git_history

logger = logging.getLogger(__name__)

# Analyzer registry
ANALYZERS = {
    "generic": GenericAnalyzer(),
    "python": PythonAnalyzer(),
    "javascript": JavaScriptAnalyzer(),
    "config": ConfigAnalyzer(),
    "dependency": DependencyAnalyzer(),
    "terraform": TerraformAnalyzer(),
}

# Map file metadata to which analyzers to run
LANGUAGE_ANALYZER_MAP = {
    "python": ["python", "generic"],
    "javascript": ["javascript", "generic"],
    "typescript": ["javascript", "generic"],
    "go": ["generic"],
    "java": ["generic"],
    "rust": ["generic"],
    "ruby": ["generic"],
    "php": ["generic"],
    "csharp": ["generic"],
    "c": ["generic"],
    "cpp": ["generic"],
    "shell": ["generic"],
    "yaml": ["config"],
    "dockerfile": ["config"],
    "json": ["dependency", "generic"],
    "toml": ["dependency", "generic"],
    "terraform": ["terraform", "generic"],
}

# Files that should go through the dependency analyzer
DEPENDENCY_FILENAMES = {
    "package.json", "requirements.txt", "pyproject.toml", "go.mod",
    "go.sum", "Cargo.toml", "build.gradle", "pom.xml",
}

# In-memory scan storage (no persistence, no auto-expiry — user controls cleanup)
_scans: dict[str, ScanResult] = {}


def get_scan(scan_id: str) -> ScanResult | None:
    return _scans.get(scan_id)


def get_all_scans() -> list[ScanResult]:
    return list(_scans.values())


def delete_scan(scan_id: str) -> bool:
    """Delete a scan and its data from memory. Returns True if found."""
    if scan_id in _scans:
        del _scans[scan_id]
        return True
    return False


async def start_scan(path: str) -> ScanResult:
    """Start an async scan of the given path."""
    scan_id = str(uuid.uuid4())[:8]
    scan = ScanResult(
        scan_id=scan_id,
        status=ScanStatus.SCANNING,
        progress=0.0,
        message="Starting scan...",
        scan_path=path,
        started_at=datetime.now(timezone.utc),
    )
    _scans[scan_id] = scan

    # Run scan in background
    asyncio.create_task(_run_scan(scan_id, path))

    return scan


async def _run_scan(scan_id: str, path: str):
    """Execute the full scan pipeline."""
    scan = _scans[scan_id]

    try:
        # Step 1: Walk files
        scan.message = "Discovering files..."
        scan.progress = 0.05

        files = walk_files(path, max_files=settings.max_files)
        total_files = len(files)

        if total_files == 0:
            scan.status = ScanStatus.ERROR
            scan.error = "No source files found in the specified path"
            return

        scan.message = f"Found {total_files} files to analyze"
        scan.progress = 0.1

        # Step 2: Analyze files
        all_findings: list[Finding] = []
        languages_seen: set[str] = set()

        for i, file_meta in enumerate(files):
            progress = 0.1 + (0.7 * (i / total_files))
            scan.progress = round(progress, 2)
            scan.message = f"Analyzing {file_meta['rel_path']} ({i+1}/{total_files})"

            try:
                with open(file_meta["path"], "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, UnicodeDecodeError):
                continue

            language = file_meta["language"]
            filename = file_meta["filename"]

            if language != "unknown":
                languages_seen.add(language)

            # Determine which analyzers to run
            analyzer_names = set()

            # Language-specific analyzers
            if language in LANGUAGE_ANALYZER_MAP:
                analyzer_names.update(LANGUAGE_ANALYZER_MAP[language])

            # Dependency files
            if filename.lower() in DEPENDENCY_FILENAMES:
                analyzer_names.add("dependency")

            # .env files
            if filename.startswith(".env"):
                analyzer_names.add("config")

            # Config files
            if file_meta["category"] == "config":
                analyzer_names.add("config")
                analyzer_names.add("generic")

            # Run analyzers
            content_lines = content.splitlines()
            for analyzer_name in analyzer_names:
                analyzer = ANALYZERS.get(analyzer_name)
                if not analyzer:
                    continue

                try:
                    findings = analyzer.analyze(file_meta["path"], content, file_meta)
                    # Attach source snippets to findings that have line numbers
                    for finding in findings:
                        if finding.line_number > 0 and not finding.source_snippet:
                            finding.source_snippet = _extract_snippet(
                                content_lines, finding.line_number
                            )
                    all_findings.extend(findings)
                except Exception as e:
                    logger.warning(f"Analyzer {analyzer_name} failed on {file_meta['rel_path']}: {e}")

            # Yield control to event loop periodically
            if i % 50 == 0:
                await asyncio.sleep(0)

        # Step 2.5: Scan git history for historical secrets
        scan.message = "Scanning git history..."
        scan.progress = 0.82
        git_findings = analyze_git_history(path)
        all_findings.extend(git_findings)
        if git_findings:
            logger.info(f"Scan {scan_id}: found {len(git_findings)} historical secrets in git history")

        # Step 3: Build graph
        scan.status = ScanStatus.BUILDING_GRAPH
        scan.progress = 0.85
        scan.message = f"Building knowledge graph from {len(all_findings)} findings..."

        graph = build_graph(all_findings, total_files, sorted(languages_seen))

        # Step 4: Done
        scan.status = ScanStatus.COMPLETE
        scan.progress = 1.0
        scan.message = f"Complete: {graph.stats.total_nodes} nodes, {graph.stats.total_edges} edges"
        scan.graph = graph
        scan.completed_at = datetime.now(timezone.utc)

        logger.info(
            f"Scan {scan_id} complete: {total_files} files, "
            f"{len(all_findings)} findings, {graph.stats.total_nodes} nodes"
        )

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
        scan.status = ScanStatus.ERROR
        scan.error = str(e)
        scan.message = f"Scan failed: {e}"


def _extract_snippet(lines: list[str], line_number: int, context: int = 8) -> str:
    """Extract a source code snippet around the given line number.

    Returns a formatted string with line numbers, e.g.:
        10| def foo():
        11|     bar()    ← target line
        12|     return
    """
    start = max(0, line_number - 1 - context)
    end = min(len(lines), line_number + context)
    snippet_lines = []
    for i in range(start, end):
        num = i + 1
        marker = " >>>" if num == line_number else "    "
        snippet_lines.append(f"{num:>5}{marker} {lines[i]}")
    return "\n".join(snippet_lines)
