"""Optional, local-only YARA rule loading and scanning for Atlhas1x.

This module never downloads rules, sends files anywhere, or invokes yara.exe.
When yara-python or local rules are unavailable, callers receive a clean status
object and can continue with the rest of their defensive audit.
"""
from pathlib import Path


ANALYZABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".js"}
DEFAULT_TIMEOUT_SECONDS = 12
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024


class YaraEngine:
    def __init__(self, rules_root, max_file_size=DEFAULT_MAX_FILE_SIZE, timeout=DEFAULT_TIMEOUT_SECONDS):
        self.rules_root = Path(rules_root)
        self.max_file_size = max_file_size
        self.timeout = timeout
        self._compiled = []
        self._scanned = {}
        self._failed_rules = []
        self._yara = None
        self.available = False
        self.reason = None
        self._load()

    def _load(self):
        try:
            import yara  # Imported only when this optional dependency exists.
        except ImportError as exc:
            self.reason = "yara-python is not installed: " + str(exc)
            return
        self._yara = yara
        self.available = True
        for path in self.discover_rules():
            try:
                self._compiled.append((path, yara.compile(filepath=str(path))))
            except Exception as exc:  # Invalid third-party rule stays isolated.
                self._failed_rules.append({"path": str(path), "reason": str(exc)})

    def discover_rules(self):
        if not self.rules_root.is_dir():
            return []
        return sorted(path for path in self.rules_root.rglob("*") if path.is_file() and path.suffix.lower() in (".yar", ".yara"))

    @property
    def summary(self):
        return {
            "engine": "AVAILABLE" if self.available else "NOT AVAILABLE",
            "reason": self.reason,
            "rules_discovered": len(self.discover_rules()),
            "rules_loaded": len(self._compiled),
            "rules_failed": len(self._failed_rules),
            "files_scanned": sum(1 for result in self._scanned.values() if result["status"] == "SCANNED"),
            "files_skipped": sum(1 for result in self._scanned.values() if result["status"] == "SKIPPED"),
            "files_timed_out": sum(1 for result in self._scanned.values() if result["status"] == "TIMEOUT"),
            "matches": sum(len(result.get("matches", [])) for result in self._scanned.values()),
            "failed_rules": list(self._failed_rules),
        }

    def scan(self, path):
        path = Path(path)
        cache_key = str(path).lower()
        if cache_key in self._scanned:
            return self._scanned[cache_key]
        result = {"path": str(path), "status": "NOT AVAILABLE", "matches": [], "reason": None}
        if not self.available:
            result["reason"] = "yara-python is not installed"
        elif not self._compiled:
            result["reason"] = "No local YARA rules are available"
        elif path.suffix.lower() not in ANALYZABLE_EXTENSIONS:
            result.update(status="SKIPPED", reason="File extension is not in the focused scan list")
        else:
            try:
                if not path.is_file():
                    result.update(status="SKIPPED", reason="File is not available")
                elif path.stat().st_size > self.max_file_size:
                    result.update(status="SKIPPED", reason="File exceeds configured scan size limit")
                else:
                    matches = []
                    for rule_path, rules in self._compiled:
                        for match in rules.match(str(path), timeout=self.timeout):
                            matches.append({
                                "rule": getattr(match, "rule", "UNKNOWN"),
                                "namespace": getattr(match, "namespace", rule_path.stem),
                                "tags": list(getattr(match, "tags", []) or []),
                                "meta": dict(getattr(match, "meta", {}) or {}),
                                "source": str(rule_path),
                            })
                    result.update(status="SCANNED", matches=matches)
            except getattr(self._yara, "TimeoutError", RuntimeError):
                result.update(status="TIMEOUT", reason="YARA scan timed out")
            except OSError as exc:
                result.update(status="SKIPPED", reason=str(exc))
            except Exception as exc:
                result.update(status="ERROR", reason=str(exc))
        self._scanned[cache_key] = result
        return result
