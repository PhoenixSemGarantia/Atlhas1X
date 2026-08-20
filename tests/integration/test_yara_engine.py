import tempfile
import unittest
from pathlib import Path

import threat_analysis as threat
from yara_engine import YaraEngine


class YaraEngineValidationTests(unittest.TestCase):
    def setUp(self):
        self.rules = Path(__file__).parents[2] / "rules"
        self.engine = YaraEngine(self.rules)
        if not self.engine.available:
            self.skipTest("yara-python is optional and unavailable")

    def test_benign_generic_and_high_confidence_metadata(self):
        with tempfile.NamedTemporaryFile(suffix=".exe") as sample:
            sample.write(b"ATLHAS1X_YARA_GENERIC_MARKER ATLHAS1X_YARA_HIGHCONF_MARKER")
            sample.flush()
            result = self.engine.scan(sample.name)
        self.assertEqual(result["status"], "SCANNED")
        self.assertGreaterEqual(len(result["matches"]), 2)
        self.assertEqual(threat.yara_confidence(result["matches"]), "HIGH")

    def test_benign_file_without_marker_has_no_match(self):
        with tempfile.NamedTemporaryFile(suffix=".exe") as sample:
            sample.write(b"ordinary benign test content")
            sample.flush()
            result = self.engine.scan(sample.name)
        self.assertEqual(result["status"], "SCANNED")
        self.assertEqual(result["matches"], [])

    def test_large_file_is_skipped_without_reading_it(self):
        with tempfile.NamedTemporaryFile(suffix=".exe") as sample:
            sample.write(b"12")
            sample.flush()
            result = YaraEngine(self.rules, max_file_size=1).scan(sample.name)
        self.assertEqual(result["status"], "SKIPPED")
        self.assertIn("size limit", result["reason"])

    def test_invalid_rule_is_isolated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "invalid.yar").write_text("rule broken { condition: this is invalid }", encoding="utf-8")
            engine = YaraEngine(root)
            self.assertEqual(engine.summary["rules_discovered"], 1)
            self.assertEqual(engine.summary["rules_failed"], 1)

    def test_timeout_is_returned_as_a_clean_result(self):
        class FakeYara:
            class TimeoutError(Exception):
                pass

        class SlowRules:
            def match(self, *_args, **_kwargs):
                raise FakeYara.TimeoutError()

        engine = YaraEngine.__new__(YaraEngine)
        engine.rules_root = self.rules
        engine.max_file_size = 1024
        engine.timeout = 1
        engine._compiled = [(self.rules / "local" / "test.yar", SlowRules())]
        engine._scanned = {}
        engine._failed_rules = []
        engine._yara = FakeYara
        engine.available = True
        engine.reason = None
        with tempfile.NamedTemporaryFile(suffix=".exe") as sample:
            sample.write(b"safe")
            sample.flush()
            result = engine.scan(sample.name)
        self.assertEqual(result["status"], "TIMEOUT")
