"""Recursive file discovery with gitignore-like filtering."""

import os
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", ".next", ".nuxt", "out", "coverage",
    ".terraform", ".serverless", "vendor", "target",
    ".idea", ".vscode", ".DS_Store", "eggs", "*.egg-info",
}

SKIP_EXTENSIONS = {
    ".pyc", ".pyo", ".so", ".o", ".a", ".dylib", ".dll",
    ".exe", ".bin", ".dat", ".db", ".sqlite", ".sqlite3",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".rar", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv",
    ".lock", ".min.js", ".min.css", ".map",
}

# Skip test files and templates to reduce false positives
SKIP_FILE_PATTERNS = [
    ".test.", ".spec.", "_test.", "_spec.",
    ".template", ".example", ".sample", ".tmpl",
]

SKIP_PATH_PATTERNS = [
    "/test/", "/tests/", "/__test__/", "/__tests__/",
    "/examples/", "/samples/", "/demo/", "/demos/",
    "/mock/", "/mocks/", "/fixture/", "/fixtures/", "/stub/", "/stubs/",
]

SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rs",
    ".rb", ".php", ".cs", ".cpp", ".c", ".h", ".hpp",
    ".swift", ".kt", ".scala", ".sh", ".bash",
    ".tf", ".tfvars",
}

CONFIG_EXTENSIONS = {
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".env.example", ".env.local", ".env.production",
}

CONFIG_FILENAMES = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Makefile", "Procfile", "Vagrantfile",
    "requirements.txt", "setup.py", "setup.cfg", "pyproject.toml",
    "package.json", "tsconfig.json", "vite.config.ts", "vite.config.js",
    "go.mod", "go.sum", "Cargo.toml", "build.gradle", "pom.xml",
    ".gitignore", ".dockerignore", ".helmignore",
}


def walk_files(root_path: str, max_files: int = 5000) -> list[dict]:
    """Walk directory and return list of files with metadata."""
    root = Path(root_path).resolve()
    if not root.is_dir():
        raise ValueError(f"Not a directory: {root_path}")

    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip ignored directories (modify in-place to prevent descent)
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not d.startswith(".")
        ]

        for filename in filenames:
            if len(files) >= max_files:
                return files

            filepath = Path(dirpath) / filename
            ext = filepath.suffix.lower()

            # Skip binary/large files
            if ext in SKIP_EXTENSIONS:
                continue

            # Determine file category
            rel_path = str(filepath.relative_to(root))

            # Skip test files and templates to reduce false positives
            if any(pattern in filename.lower() for pattern in SKIP_FILE_PATTERNS):
                continue
            if any(pattern in f"/{rel_path}" for pattern in SKIP_PATH_PATTERNS):
                continue
            category = "other"

            if ext in SOURCE_EXTENSIONS:
                category = "source"
            elif ext in CONFIG_EXTENSIONS or filename in CONFIG_FILENAMES:
                category = "config"
            elif filename.startswith(".env"):
                category = "config"

            if category == "other":
                continue

            # Detect language
            language = _detect_language(ext, filename)

            try:
                size = filepath.stat().st_size
                if size > 500 * 1024:  # Skip files > 500KB
                    continue
            except OSError:
                continue

            files.append({
                "path": str(filepath),
                "rel_path": rel_path,
                "filename": filename,
                "extension": ext,
                "category": category,
                "language": language,
                "size": size,
            })

    return files


def _detect_language(ext: str, filename: str) -> str:
    lang_map = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".jsx": "javascript", ".tsx": "typescript",
        ".go": "go", ".java": "java", ".rs": "rust",
        ".rb": "ruby", ".php": "php", ".cs": "csharp",
        ".cpp": "cpp", ".c": "c", ".h": "c",
        ".swift": "swift", ".kt": "kotlin", ".scala": "scala",
        ".sh": "shell", ".bash": "shell",
        ".yaml": "yaml", ".yml": "yaml",
        ".json": "json", ".toml": "toml",
    }
    if filename == "Dockerfile":
        return "dockerfile"
    if filename == "Makefile":
        return "makefile"
    if ext in (".tf", ".tfvars"):
        return "terraform"
    return lang_map.get(ext, "unknown")
