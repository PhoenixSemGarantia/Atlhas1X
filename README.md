![Atlhas1x Banner](assets/banner.png)

# Atlhas1x
Windows Security Scanner

## About
Atlhas1x is a local Windows security scanner designed to audit security configurations, identify suspicious indicators, analyze persistence mechanisms, perform YARA-based file analysis and generate offline HTML security reports.

## Features
- Defender, Firewall, account, update, network and Windows hardening checks.
- Basic, Intermediate and Advanced offline HTML reports.
- **Terminal Mode (v1.3)**: Execute the scanner and view the full report entirely in the command line.
- Security Score, finding confidence and Scan Completeness metrics.
- Read-only local collection with isolated check failures.
- Focused suspicious-activity heuristics for persistence, process paths, recent files and process/listener relationships.
- Optional local YARA matching and Authenticode metadata for files.

## How It Works
Atlhas1x correlates local indicators like temporary locations, startup persistence, scheduled tasks, services, network listeners, recent modifications, digital signatures, and optional YARA matches. It only examines files related to these items; it never scans the entire disk, executes files, or sends data over the internet.

Suspicious findings and YARA matches require manual review and are not definitive proof that a file is malicious.

## Installation
Clone or download this repository.
Ensure you have Python 3.x installed on your system.

## Running Atlhas1x
To start the application, simply run:
```text
Atlhas1x.bat
```
This will automatically launch the internal scanner menu. You can choose to generate an HTML report (which automatically opens in your browser) or use the new **Terminal Mode** (Option 4) to view the results directly in the prompt.

### Command Line Arguments
For automation and advanced users, you can bypass the interactive menu by providing arguments directly to the batch file:
```text
Atlhas1x.bat --terminal --report basic
Atlhas1x.bat --report advanced
```

## Report Levels
- **Basic**: System overview, Security Score, Risk, Scan Completeness, and high-priority findings.
- **Intermediate**: All findings with descriptions and recommended actions.
- **Advanced**: Detailed evidence, module timings, and technical inventories.

## Threat Analysis
Atlhas1x uses heuristic indicators to identify items that may require manual review. Context such as valid digital signatures or expected Windows paths reduces the relevance of a finding, limiting false positives.

## YARA
YARA engine support (`yara-python`) is optional. If available, the scanner will use rules located in `rules/local/` and `rules/third_party/`. The scanner never downloads or updates rules automatically. If YARA is not installed, the tool gracefully continues with heuristic checks.

## Security Score
The Atlhas1x Security Score is an internal project metric designed to provide a simple overview of confirmed findings. It is not an official Microsoft, CIS, NIST, or industry-standard security score.

## Suspicion Score
An internal measure of the relevance of correlated indicators, ranging from 0 to 100. It is not a probability of malware. Advanced reports detail the positive and negative weights applied.

## Screenshots
Offline HTML reports are generated locally and work entirely without an internet connection.

## Requirements
- Windows OS (Windows 10/11 or Server equivalents).
- Python 3.x.
- Optional: `yara-python` for YARA matching.

## Updating Atlhas1x
Atlhas1x can check its official GitHub repository for newer releases. Automatic updates are optional and require user consent.

If you choose not to allow automatic updates, a manual `Update_Atlhas1x.bat` will be created for you to trigger updates whenever you prefer.

## Privacy
The scan:
- runs locally
- does not upload scanned files
- does not upload hashes
- does not send security reports
- does not send credentials
- does not use cloud malware scanning

The only normal external communication allowed is the update check against the official Atlhas1x repository.

## Limitations
Some hardening features depend on Windows editions, virtualization, and active antivirus. The scanner continues without administrative privileges, though some checks may be unavailable.

## Testing
To run the offline validation suite:
```powershell
python -m unittest discover -s tests -v
```
See `TESTING.md` for detailed instructions on validating the tool safely.

## License
This project is licensed under the [BSD 3-Clause License](LICENSE).

## Acknowledgements
This project utilizes the [YARA](https://github.com/VirusTotal/yara) pattern matching swiss knife, created and maintained by Victor M. Alvarez and the VirusTotal team. YARA is licensed under the BSD 3-Clause License. We express our gratitude for their incredible work in the cybersecurity community.

## Disclaimer
Atlhas1x is designed as an auditing and baseline analysis tool. It **does not** replace a dedicated EDR/Antivirus solution. Always verify findings manually before making critical system changes.
