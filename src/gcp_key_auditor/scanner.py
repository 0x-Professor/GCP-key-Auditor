from __future__ import annotations

import re
import os
from pathlib import Path

GOOGLE_API_KEY_PATTERN = re.compile(r"AIza[0-9A-Za-z\-_]{35}")

_TEXT_EXT_ALLOWLIST = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".kt",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".cpp",
    ".c",
    ".h",
    ".hpp",
    ".rs",
    ".swift",
    ".m",
    ".mm",
    ".dart",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".xml",
    ".html",
    ".md",
    ".txt",
    ".env",
    ".properties",
    ".sql",
    ".tf",
    ".sh",
    ".ps1",
    ".bat",
}

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
}


def extract_keys_from_text(text: str) -> list[str]:
    return list(dict.fromkeys(GOOGLE_API_KEY_PATTERN.findall(text)))


def looks_text_file(path: Path) -> bool:
    if path.suffix.lower() in _TEXT_EXT_ALLOWLIST:
        return True
    # Handle extensionless config and dotfiles frequently used for secrets.
    return path.name in {".env", "Dockerfile", "Makefile"}


def scan_path_for_keys(base_path: Path) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}

    for root, dirs, files in os.walk(base_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]

        root_path = Path(root)
        for file_name in files:
            path = root_path / file_name
            if not looks_text_file(path):
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            keys = extract_keys_from_text(content)
            if not keys:
                continue

            rel = str(path.relative_to(base_path))
            for key in keys:
                found.setdefault(key, []).append(rel)

    return found
