import datetime as dt
import unittest

import atlhas1x as app


class OfflineReportTests(unittest.TestCase):
    def setUp(self):
        self.finding = app.finding("ATL-TEST", "Example <check>", "Test", "Enabled", "PASS", "INFO", "Safe & local", "No action required.", "value=<safe>")
        self.info = {"hostname": "host<one>", "user": "user", "operating_system": "Windows"}

    def test_all_report_levels_are_self_contained_and_escaped(self):
        for level in ("basic", "intermediate", "advanced"):
            page = app.report_html(level, [self.finding], self.info, dt.datetime.now(), dt.datetime.now(), [])
            self.assertIn("<meta charset='utf-8'>", page)
            self.assertIn("section-help", page)
            self.assertNotIn("https://fonts", page)
            if level != "basic":
                self.assertIn("&lt;check&gt;", page)

    def test_advanced_report_explains_false_positive_context(self):
        record = {
            "classification": "OBSERVE", "severity": "LOW", "path": "C:\\Windows\\System32\\test.exe",
            "suspicion_score": 0, "indicators": ["YARA_LOW_CONFIDENCE"],
            "positive_indicators": ["VALID_MICROSOFT_SIGNATURE", "EXPECTED_WINDOWS_PATH"],
            "possible_false_positive": True, "potential_backdoor": False,
            "reasoning": [{"indicator": "YARA_LOW_CONFIDENCE", "impact": 15}, {"indicator": "VALID_MICROSOFT_SIGNATURE", "impact": -20}],
            "metadata": {"recent": False, "sha256": "a" * 64, "signature": {"status": "VALID_MICROSOFT"}, "related_to": []},
            "yara": {"status": "SCANNED", "matches": []}, "relations": set(), "listeners": [], "processes": [],
        }
        page = app.report_html("advanced", [], self.info, dt.datetime.now(), dt.datetime.now(), [], threats=[record], yara_summary={"engine": "AVAILABLE"})
        self.assertIn("False Positive Considerations", page)
        self.assertIn("Possible False Positive", page)
        self.assertIn("Why this item was flagged", page)
