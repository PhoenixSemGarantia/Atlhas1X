import unittest
import os
import json
import shutil
import tempfile
from unittest.mock import patch, MagicMock
from io import BytesIO

# Import repair module assuming we are running from project root
import repair

class TestRepair(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        
        # Setup dummy environment
        self.manifest_path = "app_manifest.json"
        self.manifest_data = {
            "version": "1.4.0",
            "files": {
                "test_file.py": "dummyhash"
            }
        }
        with open(self.manifest_path, "w") as f:
            json.dump(self.manifest_data, f)
            
        with open("test_file.py", "w") as f:
            f.write("content")
            
        # Update hash to match
        self.manifest_data["files"]["test_file.py"] = repair.get_file_hash("test_file.py")
        with open(self.manifest_path, "w") as f:
            json.dump(self.manifest_data, f)

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def test_healthy_installation(self):
        res = repair.verify_integrity()
        self.assertIsNone(res["error"])
        self.assertEqual(len(res["problems"]), 0)

    def test_missing_file(self):
        os.remove("test_file.py")
        res = repair.verify_integrity()
        self.assertEqual(res["problems"].get("test_file.py"), "MISSING")

    def test_modified_file(self):
        with open("test_file.py", "w") as f:
            f.write("modified content")
        res = repair.verify_integrity()
        self.assertEqual(res["problems"].get("test_file.py"), "HASH_MISMATCH")

    def test_missing_manifest(self):
        os.remove(self.manifest_path)
        res = repair.verify_integrity()
        self.assertEqual(res["error"], "Missing manifest")

    def test_invalid_manifest(self):
        with open(self.manifest_path, "w") as f:
            f.write("invalid json")
        res = repair.verify_integrity()
        self.assertEqual(res["error"], "Invalid manifest")

    @patch('urllib.request.urlopen')
    def test_network_unavailable(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Network unavailable")
        res = repair.download_and_validate_release("1.4.0")
        self.assertIsNone(res)

    @patch('urllib.request.urlopen')
    def test_download_timeout(self, mock_urlopen):
        import socket
        mock_urlopen.side_effect = socket.timeout("Timeout")
        res = repair.download_and_validate_release("1.4.0")
        self.assertIsNone(res)
        
    @patch('urllib.request.urlopen')
    def test_wrong_version(self, mock_urlopen):
        # Mocks HTTPError 404
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError("url", 404, "Not Found", {}, None)
        res = repair.download_and_validate_release("99.99.99")
        self.assertIsNone(res)

    def test_invalid_package_structure(self):
        import zipfile
        zip_path = "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("root1/test.txt", "content")
            zf.writestr("root2/test.txt", "content")
            
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_response = MagicMock()
            with open(zip_path, "rb") as f:
                mock_response.read = f.read
                
            mock_urlopen.return_value.__enter__.return_value = mock_response
            res = repair.download_and_validate_release("1.4.0")
            self.assertIsNone(res)

    def test_path_traversal_attempt(self):
        import zipfile
        zip_path = "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("root/../malicious.txt", "content")
            
        extract_dir = "ext"
        os.makedirs(extract_dir, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as zf:
            repair.safe_extract(zf, extract_dir, "root/")
            
        self.assertFalse(os.path.exists(os.path.join(extract_dir, "../malicious.txt")))

    def test_backup_creation_and_rollback(self):
        # Setup corrupted file
        with open("test_file.py", "w") as f:
            f.write("corrupted")
            
        # Mock successful download package with original file
        extract_dir = "mock_ext"
        os.makedirs(extract_dir, exist_ok=True)
        with open(os.path.join(extract_dir, "test_file.py"), "w") as f:
            f.write("content") # valid content
            
        mock_manifest = self.manifest_data
        
        with patch('repair.download_and_validate_release', return_value=(extract_dir, mock_manifest)):
            # Introduce a failure during replace
            with patch('shutil.copy2', side_effect=Exception("Simulated failure")):
                success = repair.do_repair(full=False)
                
                self.assertFalse(success)
                # Ensure rollback happened
                with open("test_file.py", "r") as f:
                    self.assertEqual(f.read(), "corrupted")

    def test_successful_quick_repair(self):
        # Corrupt file
        with open("test_file.py", "w") as f:
            f.write("corrupted")
            
        extract_dir = "mock_ext"
        os.makedirs(extract_dir, exist_ok=True)
        with open(os.path.join(extract_dir, "test_file.py"), "w") as f:
            f.write("content") # valid content
            
        with patch('repair.download_and_validate_release', return_value=(extract_dir, self.manifest_data)):
            success = repair.do_repair(full=False)
            self.assertTrue(success)
            with open("test_file.py", "r") as f:
                self.assertEqual(f.read(), "content")

    def test_successful_full_repair(self):
        extract_dir = "mock_ext"
        os.makedirs(extract_dir, exist_ok=True)
        with open(os.path.join(extract_dir, "test_file.py"), "w") as f:
            f.write("content") # valid content
            
        with patch('repair.download_and_validate_release', return_value=(extract_dir, self.manifest_data)):
            success = repair.do_repair(full=True)
            self.assertTrue(success)

    def test_verify_only_mode(self):
        # Should not raise exception
        res = repair.verify_integrity()
        self.assertIsNone(res["error"])

if __name__ == "__main__":
    unittest.main()
