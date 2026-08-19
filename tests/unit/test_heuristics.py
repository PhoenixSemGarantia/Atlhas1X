import tempfile
import unittest
from pathlib import Path

import threat_analysis as threat


class HeuristicAccuracyTests(unittest.TestCase):
    def test_indicator_weights_are_centralized_and_recent_file_is_weak(self):
        self.assertEqual(threat.INDICATOR_WEIGHTS["RECENT_FILE"], 5)
        score, _ = threat._suspicion(["RECENT_FILE"])
        self.assertEqual(score, 5)
        self.assertEqual(threat._classification(score), ("NORMAL", "INFO"))

    def test_benign_system_context_reduces_suspicion(self):
        score, reasoning = threat._suspicion(
            ["RECENT_FILE", "YARA_LOW_CONFIDENCE"],
            ["VALID_MICROSOFT_SIGNATURE", "EXPECTED_WINDOWS_PATH", "KNOWN_WINDOWS_COMPONENT"],
        )
        self.assertEqual(score, 0)
        self.assertTrue(any(item["impact"] < 0 for item in reasoning))

    def test_temp_unsigned_recent_requires_review_not_high(self):
        indicators = ["TEMP_LOCATION", "UNSIGNED", "RECENT_FILE", "CORRELATED_WEAK_INDICATORS"]
        score, _ = threat._suspicion(indicators)
        self.assertEqual(score, 32)
        self.assertEqual(threat._classification(score), ("NEEDS REVIEW", "MEDIUM"))

    def test_strong_correlated_case_is_high_priority(self):
        indicators = ["TEMP_LOCATION", "UNSIGNED", "SCHEDULED_TASK_PERSISTENCE", "PUBLIC_NETWORK_LISTENER", "YARA_HIGH_CONFIDENCE"]
        score, _ = threat._suspicion(indicators)
        self.assertGreaterEqual(score, 70)
        self.assertEqual(threat._classification(score), ("HIGH PRIORITY REVIEW", "HIGH"))

    def test_normalizes_path_and_parses_command_without_executing(self):
        self.assertEqual(threat.normalized_path('"C:/Windows//System32/SVCHOST.EXE"'), r"c:\windows\system32\svchost.exe")
        self.assertEqual(threat.extract_executable('"C:\\Program Files\\Example\\agent.exe" --service'), r"C:\Program Files\Example\agent.exe")
        self.assertEqual(threat.extract_executable("PROCESS_EXITED"), "")

    def test_loopback_is_not_public_network_exposure(self):
        self.assertFalse(threat.listener_is_public({"Local Address": "127.0.0.1"}))
        self.assertFalse(threat.listener_is_public({"Local Address": "::1"}))
        self.assertTrue(threat.listener_is_public({"Local Address": "0.0.0.0"}))

    def test_yara_confidence_uses_metadata_before_generic_name(self):
        self.assertEqual(threat.yara_confidence([{"rule": "Generic_Packer", "meta": {}}]), "LOW")
        self.assertEqual(threat.yara_confidence([{"rule": "ATL_Test_Generic", "meta": {"confidence": "high"}}]), "HIGH")

    def test_same_path_is_one_correlated_record(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / "Temp"
            folder.mkdir()
            sample = folder / "agent.exe"
            sample.write_bytes(b"benign fixture")
            process = {"PID": "42", "Process": "agent.exe", "Path": str(sample)}
            records, _ = threat.analyze(
                [process, dict(process)], [], {"STARTUP": [{"Path": str(sample)}], "SCHEDULED_TASK": [], "SERVICE": []}, [], Path(directory),
                signature_lookup=lambda _: {"status": "UNSIGNED"},
            )
        self.assertEqual(len(records), 1)
        self.assertIn("PROCESS", records[0]["relations"])
        self.assertIn("STARTUP", records[0]["relations"])

