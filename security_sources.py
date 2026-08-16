"""Local signature-source preparation for future Atlhas1x integrations.

This module deliberately does not run ClamAV, freshclam, YARA, or scans.  It
only resolves local paths, reports optional-tool availability, and exposes a
small SQLite store for manually managed SHA-256 reference hashes.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = PROJECT_DIR / "config" / "security_sources.json"


def load_security_source_config(config_path=CONFIG_PATH):
    """Load local source paths without contacting a network service."""
    with Path(config_path).open("r", encoding="utf-8") as source:
        return json.load(source)


def resolve_project_path(value, project_dir=PROJECT_DIR):
    """Resolve a configured relative path inside the Atlhas1x directory."""
    path = Path(value)
    return path if path.is_absolute() else Path(project_dir) / path


def optional_tool_status(config=None):
    """Return presence only; missing optional tools never raise an exception."""
    config = config or load_security_source_config()
    clamav = config.get("clamav", {})
    try:
        import yara  # noqa: F401 - availability is the result being queried.
        yara_status = "AVAILABLE"
    except ImportError:
        yara_status = "NOT AVAILABLE"
    return {
        "yara-python": yara_status,
        "clamscan": "AVAILABLE" if shutil.which(clamav.get("clamscan_command", "clamscan.exe")) else "NOT AVAILABLE",
        "freshclam": "AVAILABLE" if shutil.which(clamav.get("freshclam_command", "freshclam.exe")) else "NOT AVAILABLE",
    }


class LocalHashStore:
    """SQLite-backed, local-only SHA-256 reference-hash storage.

    No file is hashed here and no record is uploaded. Callers add hashes only
    after they have obtained them through their own read-only workflow.
    """
    def __init__(self, database_path):
        self.database_path = Path(database_path)

    def initialize(self):
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS sha256_hashes ("
                "sha256 TEXT PRIMARY KEY, label TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '', "
                "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
            )
            connection.commit()
        finally:
            connection.close()

    def add(self, sha256, label="", source="local"):
        value = str(sha256).strip().lower()
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("SHA-256 values must contain exactly 64 hexadecimal characters")
        self.initialize()
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                "INSERT OR REPLACE INTO sha256_hashes (sha256, label, source) VALUES (?, ?, ?)",
                (value, str(label), str(source)),
            )
            connection.commit()
        finally:
            connection.close()

    def lookup(self, sha256):
        if not self.database_path.exists():
            return None
        connection = sqlite3.connect(self.database_path)
        try:
            row = connection.execute(
                "SELECT sha256, label, source, created_at FROM sha256_hashes WHERE sha256 = ?",
                (str(sha256).strip().lower(),),
            ).fetchone()
        finally:
            connection.close()
        if not row:
            return None
        return dict(zip(("sha256", "label", "source", "created_at"), row))
