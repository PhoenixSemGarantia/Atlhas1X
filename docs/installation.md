# Installation

## Guided launcher

1. Download or clone the repository to a writable local folder.
2. Open `Atlhas1x.bat`.
3. If no compatible Python runtime is found, the launcher explains the available setup path.
4. Choose the audit mode when prompted.

The launcher may use a local embedded Python runtime. It never changes Windows security settings.

## Command line

Install the optional Python dependency and run a report level:

```powershell
python -m pip install -r requirements.txt
python atlhas1x.py --report intermediate
```

Other supported choices are `basic` and `advanced`:

```powershell
python atlhas1x.py --report basic
python atlhas1x.py --report advanced
```

Use `python atlhas1x.py --help` for the command reference and `python atlhas1x.py --version` to show the installed version.

## Optional YARA support

`yara-python` is listed in `requirements.txt` and is optional at runtime. If it cannot be imported, Atlhas1x continues with its non-YARA local checks and reports that the engine is unavailable. Rules must be present locally; the scanner does not download them during an audit.

## Troubleshooting

See [Troubleshooting](troubleshooting.md) for common setup and permission issues.
