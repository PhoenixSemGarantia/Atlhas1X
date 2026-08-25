# Changelog

## v1.4.2

### Fixed
- Automatic updates now download, validate and apply the official package instead of only reporting availability.
- Startup no longer waits for a hidden terminal response before applying a newer release.

### Improved
- Updates preserve local reports, the embedded Python runtime and local preferences.

## v1.4

### Added
- Atlhas1x application integrity verification
- GitHub-based self repair
- Quick Repair
- Full Repair
- Verify Only mode
- Repair rollback
- Application manifest validation

### Improved
- Update and recovery reliability
- Protection of local reports and preferences

## v1.2

### Added
- Optional automatic update system
- Persistent update preference
- Manual updater for users who disable automatic updates
- Single Windows launcher
- Repository version checking

### Improved
- README documentation
- Distribution workflow
- Detection accuracy
- False-positive handling
- Test coverage

### Fixed
- Remaining scanner and report issues discovered during validation

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
