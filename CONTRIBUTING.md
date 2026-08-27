# Contributing to Atlhas1x

Thank you for helping improve Atlhas1x.

## Before opening a pull request

1. Keep the scanner local and read-only. Do not add automatic remediation, file execution, destructive actions, or cloud upload.
2. Describe the Windows versions and permissions used to validate a change.
3. Keep changes focused. Update documentation when user-facing behavior changes.
4. Do not commit reports, personal paths, credentials, tokens, captured output, or machine-specific data.

## Development checks

Run the following lightweight checks before opening a pull request:

```powershell
python -m py_compile atlhas1x.py updater.py repair.py yara_engine.py threat_analysis.py
python atlhas1x.py --help
python atlhas1x.py --version
```

Do not run a full Windows audit on a development host merely to validate a documentation change. Validate Windows-specific behavior in an environment you are authorized to audit.

## Pull requests

- Explain the problem, the approach, and how it was checked.
- Avoid unrelated formatting or refactoring.
- Use clear commit messages such as `feat:`, `fix:`, `docs:`, or `chore:` when practical.
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

For vulnerabilities in Atlhas1x, use the process in [SECURITY.md](SECURITY.md) instead of a public issue.
