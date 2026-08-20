"""Platform-independent checks for Atlhas1x result processing."""
import datetime as dt
import tempfile
import unittest
from pathlib import Path

import atlhas1x as app
import threat_analysis
from yara_engine import YaraEngine
from security_sources import LocalHashStore, load_security_source_config, optional_tool_status


def make_finding(identifier, severity="INFO", result="INFO", confidence="HIGH", score_key=None):
    return app.finding(identifier, identifier, "Test", "Status", result, severity,
                       "Description", "Recommendation", "Evidence", confidence=confidence,
                       score_key=score_key)


class ResultProcessingTests(unittest.TestCase):
    def test_unknown_does_not_reduce_score_or_raise_risk(self):
        unknown = make_finding("ATL-TEST-UNKNOWN", "LOW", "UNKNOWN", "LOW")
        self.assertEqual(app.security_score([unknown]), 100)
        self.assertEqual(app.overall([unknown]), "INFO")

    def test_score_is_limited_and_shared_score_key_is_deduplicated(self):
        findings = [
            make_finding("one", "HIGH", "WARNING", score_key="shared"),
            make_finding("two", "MEDIUM", "WARNING", score_key="shared"),
            make_finding("three", "CRITICAL", "FAIL"),
        ]
        self.assertEqual(app.security_score(findings), 70)
        self.assertEqual(app.overall(findings), "CRITICAL")

    def test_low_confidence_cannot_remain_high_severity(self):
        item = make_finding("uncertain", "HIGH", "WARNING", "LOW")
        result = app.finalize_findings([item])
        self.assertEqual(result[0]["severity"], "MEDIUM")
        self.assertEqual(result[0]["score_impact"], 5)

    def test_scan_health_separates_unavailable_and_failed(self):
        available = make_finding("available")
        unavailable = make_finding("unavailable", "INFO", "INFO")
        unavailable["status"] = "NOT AVAILABLE"
        failed = make_finding("failed", "LOW", "UNKNOWN", "LOW")
        failed["error"] = "Access denied"
        failed["error_type"] = app.classify_error(failed["error"])
        health = app.scan_health([available, unavailable, failed])
        self.assertEqual(health, {"requested": 3, "completed": 1, "unavailable": 1, "failed": 1, "completeness": 33})

    def test_html_escapes_collected_values(self):
        item = make_finding("html")
        item["name"] = "<unsafe>"
        page = app.report_html("advanced", [item], {"hostname": "<host>", "user": "user", "operating_system": "Windows"}, dt.datetime.now(), dt.datetime.now(), [])
        self.assertIn("&lt;unsafe&gt;", page)
        self.assertIn("&lt;host&gt;", page)
        self.assertNotIn("<unsafe>", page)
        self.assertIn("section-help", page)
        self.assertIn("What is this analysis?", page)

    def test_html_uses_unknown_for_missing_inventory_values(self):
        page = app.inventory_html(app.inventory("Inventory", ("Name", "Path"), [{"Name": "item", "Path": None}]))
        self.assertIn("UNKNOWN", page)
        self.assertNotIn(">None<", page)

    def test_unexpected_module_error_becomes_a_clean_unknown_finding(self):
        diagnostics = []
        result = app.run_module("Example Check", lambda: (_ for _ in ()).throw(RuntimeError("unavailable")), diagnostics)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual(result["result"], "UNKNOWN")
        self.assertEqual(len(diagnostics), 1)

    def test_oem_mojibake_is_repaired_without_changing_utf8(self):
        self.assertEqual(app.normalize_windows_text("Configura‡Æo"), "Configuração")
        self.assertEqual(app.normalize_windows_text("Configuração"), "Configuração")

    def test_port_exposure(self):
        self.assertEqual(app.port_exposure("127.0.0.1"), "Local only")
        self.assertEqual(app.port_exposure("0.0.0.0"), "All IPv4 interfaces")
        self.assertEqual(app.port_exposure("::"), "All IPv6 interfaces")
        self.assertEqual(app.port_exposure("192.168.1.50"), "LAN-bound")

    def test_threat_helpers_are_conservative_for_expected_windows_path(self):
        self.assertTrue(threat_analysis.expected_system_path("svchost.exe", r"C:\Windows\System32\svchost.exe"))
        self.assertTrue(threat_analysis.expected_system_path("svchost", r"C:\Windows\System32\svchost.exe"))
        self.assertFalse(threat_analysis.expected_system_path("svchost.exe", r"C:\Users\Test\svchost.exe"))
        self.assertFalse(threat_analysis.is_unusual_path(r"C:\Windows\System32\svchost.exe"))
        self.assertTrue(threat_analysis.is_unusual_path(r"C:\Users\Test\AppData\Local\Temp\item.exe"))

    def test_command_path_extraction_does_not_execute_or_open_files(self):
        self.assertEqual(threat_analysis.extract_executable('"C:\\Program Files\\Example\\app.exe" --silent'), r"C:\Program Files\Example\app.exe")
        self.assertEqual(threat_analysis.extract_executable(r"C:\Temp\job.ps1 -Mode Test"), r"C:\Temp\job.ps1")
        self.assertEqual(threat_analysis.extract_executable("Access restricted"), "")

    def test_normal_windows_scheduled_task_is_not_a_threat_candidate(self):
        self.assertFalse(threat_analysis.persistence_path_worth_review(r"%windir%\system32\defrag.exe"))
        self.assertTrue(threat_analysis.persistence_path_worth_review(r"C:\Users\Test\AppData\Local\Temp\update.exe"))

    def test_local_yara_test_rule_matches_and_uses_cache_when_available(self):
        rules = Path(app.__file__).parent / "rules"
        engine = YaraEngine(rules)
        if not engine.available:
            self.skipTest("yara-python is optional and unavailable")
        with tempfile.NamedTemporaryFile(suffix=".exe") as sample:
            sample.write(b"ATLHAS1X_YARA_TEST_MARKER")
            sample.flush()
            first = engine.scan(sample.name)
            second = engine.scan(sample.name)
        self.assertEqual(first["status"], "SCANNED")
        self.assertTrue(first["matches"])
        self.assertIs(first, second)
        self.assertEqual(engine.summary["files_scanned"], 1)

    def test_yara_unavailable_footer_has_local_explanation_and_rule_link(self):
        page = app.report_html("basic", [], {"hostname": "test", "user": "test", "operating_system": "Windows"}, dt.datetime.now(), dt.datetime.now(), [], yara_summary={"engine": "NOT AVAILABLE"})
        self.assertIn("YARA: unavailable", page)
        self.assertIn("What is YARA?", page)
        self.assertIn("YARA Analysis", page)
        self.assertIn("Files scanned", page)
        self.assertIn("https://github.com/Yara-Rules/rules", page)

    def test_local_security_source_configuration_is_offline_and_complete(self):
        config = load_security_source_config()
        self.assertIn("clamav", config)
        self.assertIn("yara", config)
        self.assertIn("hashes", config)
        self.assertIn("signatures/yara", config["yara"]["rule_directories"])
        status = optional_tool_status(config)
        self.assertIn(status["yara-python"], ("AVAILABLE", "NOT AVAILABLE"))

    def test_local_hash_store_uses_sqlite_and_validates_sha256(self):
        with tempfile.TemporaryDirectory() as directory:
            store = LocalHashStore(Path(directory) / "hashes.sqlite3")
            digest = "a" * 64
            store.add(digest, "benign test", "unit-test")
            record = store.lookup(digest)
            self.assertEqual(record["label"], "benign test")
            self.assertEqual(record["source"], "unit-test")
            with self.assertRaises(ValueError):
                store.add("not-a-sha256")


if __name__ == "__main__":
    unittest.main()
