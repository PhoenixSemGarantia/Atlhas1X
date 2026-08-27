# Troubleshooting

## A check says `UNKNOWN`, `NOT AVAILABLE`, or `ACCESS DENIED`

These states have different meanings:

- **UNKNOWN** — the scanner could not determine a reliable value.
- **NOT AVAILABLE** — the feature is not supported or exposed by this Windows environment.
- **ACCESS DENIED** — the current account cannot query the required information.

The scan continues and these statuses do not automatically lower the Security Score.

## YARA is unavailable

Install the Python dependency when compatible with your Python environment:

```powershell
python -m pip install -r requirements.txt
```

YARA remains optional. Atlhas1x continues with its local heuristic checks if it is unavailable. Do not download unknown rule collections during a scan.

## A report does not open

Check the local `reports/` directory. Reports are generated on the audited machine and require a browser capable of opening a local HTML file.

## No administrator privileges

Atlhas1x is designed to continue without elevation. Some Windows interfaces may provide less information. Run it only with permissions appropriate for the machine you are auditing.
