<p align="center">
  <img src="assets/banner.png" alt="Atlhas1x — Windows Security Audit" width="860">
</p>

<h1 align="center">Atlhas1x</h1>

<p align="center">
  A local, read-only <strong>Windows security audit</strong> tool for reviewing security controls, identifying findings, and generating offline HTML reports.
</p>

<p align="center">
  <a href="https://github.com/PhoenixSemGarantia/Atlhas1X/actions/workflows/ci.yml"><img src="https://github.com/PhoenixSemGarantia/Atlhas1X/actions/workflows/ci.yml/badge.svg" alt="Windows CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-BSD--3--Clause-5d7fb9.svg" alt="BSD 3-Clause License"></a>
  <img src="https://img.shields.io/badge/platform-Windows-0078D4.svg" alt="Windows">
  <img src="https://img.shields.io/badge/Python-3.x-3776AB.svg" alt="Python 3">
</p>

<p align="center"><strong>English</strong> · <a href="README.pt-BR.md">Português</a></p>

> **Current version:** v1.4.2 &nbsp;|&nbsp; **Status:** Active &nbsp;|&nbsp; **License:** BSD 3-Clause

## What is Atlhas1x?

Atlhas1x is a local Windows security scanner for administrators, home-lab users, and defenders who need a clear baseline of a machine's security configuration. It collects local security metadata, classifies findings, calculates an internal Security Score, and writes self-contained HTML reports.

It is designed for **audit and review**, not remediation. Atlhas1x does not change Windows settings, execute discovered files, stop processes, modify the firewall, or upload scan data.

## Why use it?

- Review a broad set of Windows security controls from one local tool.
- Generate Basic, Intermediate, or Advanced reports that work offline.
- Keep the audit read-only and inspect findings in the context of the machine.
- Use Terminal Mode when a graphical report is not practical.

## Quick Start

On a Windows machine with Git and Python 3 installed:

```powershell
git clone https://github.com/PhoenixSemGarantia/Atlhas1X.git
cd Atlhas1X
python -m pip install -r requirements.txt
python atlhas1x.py --report intermediate
```

Or launch `Atlhas1x.bat` from File Explorer for the Windows guided launcher. The scanner is usable without administrator privileges; some checks may be unavailable depending on permissions and the Windows edition.

## Features

- Windows Defender, firewall, update, account, SMB, RDP, and hardening checks.
- BitLocker, Secure Boot, VBS, Credential Guard, SmartScreen, and related Windows protection visibility when available.
- Startup programs, scheduled tasks, services, shares, processes, listeners, and active connection inventories.
- Focused suspicious-activity analysis with path, persistence, signature, and listener context.
- Optional offline YARA matching for focused, locally discovered files.
- Basic, Intermediate, and Advanced offline HTML reports.
- Terminal Mode, integrity verification, guided launcher, and update support.

## Security Checks

| Area | Examples of collected information |
| --- | --- |
| Endpoint protection | Defender state, real-time protection, signatures, exclusions, ASR, Controlled Folder Access |
| Firewall and remote access | Domain/Private/Public profiles, rules summary, RDP and NLA context |
| Accounts and policy | UAC, local users, administrators, Guest, password and lockout policy |
| System hardening | BitLocker, Secure Boot, SmartScreen, VBS, Memory Integrity, Credential Guard, LSASS protection |
| Network | SMBv1, proxy, DNS, interfaces, shares, listening ports, active connections |
| Persistence and activity | Startup entries, scheduled tasks, automatic services, processes and focused threat indicators |

Availability depends on Windows edition, local policy, running security products, and permissions. `UNKNOWN`, `NOT AVAILABLE`, and `ACCESS DENIED` are reported distinctly and are not automatically treated as security failures.

## Security Score

The **Atlhas1x Security Score** starts at 100 and is reduced by confirmed findings according to their severity. It is an internal project metric intended to make a scan easier to review.

It is **not** a Microsoft, NIST, CIS, or industry-standard score, and it is not a certification of system security. Read [the score documentation](docs/security-score.md) before relying on it for decisions.

## Audit Modes

| Mode | Best for | Output |
| --- | --- | --- |
| Basic | Quick review | Score, overall risk, scan health, and important findings |
| Intermediate | Everyday auditing | Context, descriptions, and recommendations |
| Advanced | Technical review | Technical evidence, inventories, module timings, and report navigation |

Run a chosen report level directly:

```powershell
python atlhas1x.py --report basic
python atlhas1x.py --report intermediate
python atlhas1x.py --report advanced
```

Read more in [Audit Modes](docs/audit-modes.md).

## Terminal Mode

For a text-only workflow, open `Atlhas1x_Terminal.bat` or run:

```powershell
python atlhas1x.py --terminal --report intermediate
```

The terminal mode remains read-only. See [Terminal Mode](docs/terminal-mode.md).

## Reports and Screenshots

Reports are written locally to `reports/` and open offline in the default browser. They contain information from the audited machine, so generated reports are intentionally ignored by Git.

The repository includes the project banner above. Redacted screenshots and demonstration assets belong in [`docs/images/`](docs/images/README.md); no machine-specific reports or screenshots are published by default.

## Installation

See the complete [installation guide](docs/installation.md) for the guided launcher, Python installation, optional YARA support, and troubleshooting.

### Requirements

- Windows 10 or Windows 11. Windows Server equivalents may work where the underlying Windows interfaces are available.
- Python 3.x for direct command-line execution.
- Optional: `yara-python` for local YARA matching. The scanner continues with heuristics when it is unavailable.

## How It Works

```text
Collect local Windows metadata
        ↓
Analyze and normalize results
        ↓
Classify findings and calculate the internal score
        ↓
Generate an offline HTML report
```

Atlhas1x focuses file-related analysis on files already linked to local processes, startup entries, scheduled tasks, services, or other relevant persistence locations. It does not scan the whole disk, execute files, or use cloud scanning.

## Project Structure

```text
Atlhas1x/
├── atlhas1x.py              # scanner and report generation
├── Atlhas1x.bat             # guided Windows launcher
├── Atlhas1x_Terminal.bat    # terminal launcher
├── scripts/                 # PowerShell and VBS launcher helpers
├── rules/                   # local and third-party YARA rule locations
├── signatures/              # local signature database locations
├── docs/                    # user and technical documentation
├── config/                  # non-sensitive project configuration
└── reports/                 # local, ignored report output
```

For implementation notes, see [Architecture](docs/architecture.md).

## Privacy and Security Model

- All audit collection and reports stay on the audited machine.
- Atlhas1x does not upload files, hashes, credentials, clipboard data, browser data, or report contents.
- YARA matching is local and optional. Rules are not automatically downloaded during a scan.
- The normal external operation is an optional check for application updates against the official repository.
- Findings require human review. A suspicious indicator or a YARA match is not proof of malware.

## Limitations

- Some checks require permissions that are not available to a standard user.
- Windows security APIs differ by edition, build, policy, and installed security product.
- Dynamic inventories such as processes, PIDs, and connections can legitimately change between scans.
- Atlhas1x is an auditing tool, not an antivirus, EDR, SIEM, vulnerability scanner, or remediation system.

## Roadmap

**Completed**

- Offline HTML reports and Terminal Mode
- Windows hardening, account, network, persistence, and activity checks
- Focused heuristic analysis and optional local YARA support
- Integrity verification and update workflow

**In progress**

- Improving report clarity and Windows compatibility
- Reducing false positives through better context

**Planned**

- Additional Windows hardening checks
- Optional machine-readable report export
- Expanded regression coverage

**Ideas**

- User-requested audit profiles that remain local and read-only

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md), follow the [Code of Conduct](CODE_OF_CONDUCT.md), and keep changes aligned with the project's local, read-only security model.

## Reporting Bugs and Security Issues

- For reproducible defects, use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md).
- For security vulnerabilities in Atlhas1x itself, follow [SECURITY.md](SECURITY.md) and do **not** open a public issue first.

## License

Atlhas1x is licensed under the [BSD 3-Clause License](LICENSE). Third-party YARA rules and signature sources retain their own licenses; see [RULE_SOURCES.md](RULE_SOURCES.md).

## Disclaimer

Atlhas1x is an auditing tool and does not automatically modify or remediate Windows security settings. Review findings in the context of the audited system before making changes.
