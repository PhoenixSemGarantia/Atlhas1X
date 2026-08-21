# Changelog

## v1.2

### Improved

- Centralized heuristic indicator weights and trusted-context reductions.
- Context-aware YARA confidence handling and listener correlation.
- Windows process path validation, command parsing and file deduplication.
- Advanced-report explanation of score reasoning and false-positive context.

### Fixed

- False positives from normal Windows scheduled tasks and environment-variable paths.
- Access-restricted process values being interpreted as executable paths.
- Duplicate threat findings for the same correlated file.
- Loopback or listener-only context escalating suspicious activity by itself.

### Added

- False-positive regression, heuristic, YARA and offline-report validation tests.
- `TESTING.md` with safe local and Windows VM validation guidance.

## v1.1

### Added

- Focused suspicious-process, persistence and listener correlation.
- Recently modified relevant-file metadata and local SHA-256 identification.
- Optional `yara-python` engine with rule isolation, per-run scan cache and
  bounded local file scanning.
- Offline YARA match and threat-analysis sections in HTML reports.

### Improved

- Startup, scheduled-task, service and Defender-exclusion context for manual
  review.
- Conservative Windows system-process path validation and signature metadata.

YARA matches and heuristic indicators require manual verification; they are not
confirmation that a file is malicious.

## v1.0

### Added

- Stable CLI with `--help` and `--version`.
- Scan health, completeness and module-duration diagnostics.
- Platform-independent validation tests for score, risk, escaping and status handling.

### Improved

- Security score calculation only uses confirmed findings and avoids repeated score keys.
- HTML reports group findings, show confidence and remain self-contained for offline use.
- Windows command output handling and localized text normalization.

### Fixed

- Unknown and unavailable checks no longer affect the security score or overall risk.
- Common localized OEM text corruption in collected Windows names.
- Device Guard query syntax and reporting of unavailable hardening features.
