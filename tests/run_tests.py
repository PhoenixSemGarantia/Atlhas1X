"""Run the Atlhas1x offline validation suite with a compact final summary."""
from pathlib import Path
import sys
import unittest


def main():
    root = Path(__file__).resolve().parent
    project_root = str(root.parent)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    suite = unittest.defaultTestLoader.discover(str(root))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print("\nAtlhas1x Test Suite")
    print("Unit / heuristic / YARA / report integration tests: " + ("PASS" if result.wasSuccessful() else "FAIL"))
    print(f"Total: {result.testsRun - len(result.skipped)} passed, {len(result.skipped)} skipped, {len(result.failures) + len(result.errors)} failed")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
