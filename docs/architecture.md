# Architecture

Atlhas1x intentionally keeps its architecture small and local.

| Component | Responsibility |
| --- | --- |
| `atlhas1x.py` | Collects local Windows information, normalizes findings, calculates score and writes reports |
| `threat_analysis.py` | Correlates focused file, path, persistence, signature, and listener indicators |
| `yara_engine.py` | Discovers, validates, compiles, and applies local YARA rules to focused files |
| `security_sources.py` | Handles configured local signature and source locations |
| `updater.py` | Checks and applies a newer official package while preserving local data |
| `repair.py` | Validates application files and restores project files when necessary |
| `scripts/` | Windows launcher and progress user-interface helpers |

The scanner is designed so that individual Windows queries fail in isolation. A missing interface, unsupported Windows feature, or permission restriction should be shown as a clean status rather than terminating the whole scan.
