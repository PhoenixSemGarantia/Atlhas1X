# Atlhas1x testing

## Automated suite

Run the platform-independent suite from the project directory:

```powershell
python -m unittest discover -s tests -v
```

Or use `python tests/run_tests.py` to print a compact final summary.

The suite is split into `tests/unit/`, `tests/integration/` and
`tests/fixtures/`. It uses only benign temporary files and `TEST ONLY` YARA
markers. No malware, payload, backdoor, executable launch, cloud lookup or file
upload is required.

It validates score limits, severity and confidence handling, path and command
normalization, HTML escaping, report levels, optional YARA behavior, local hash
storage, duplicate-file correlation and false-positive regressions.

## YARA validation

`rules/local/atlhas_test_only.yar` contains harmless markers for a no-match,
generic-match and high-confidence-classification test. Rules are compiled
locally. Invalid rules, unavailable `yara-python`, large files and timeouts are
handled as isolated outcomes; they do not stop the scanner.

## Windows environment validation

Run complete audits only inside the Windows environment:

```powershell
python atlhas1x.py --report basic
python atlhas1x.py --report intermediate
python atlhas1x.py --report advanced
```

Repeat the scan three times. Static findings, Security Score and Overall Risk
should remain consistent; processes, connections and PIDs can naturally vary.
Test once without administrator rights and once as an administrator when
available. Do not change environment security settings or create malicious samples to
produce findings.

## Known limits

The scanner is read-only and uses local metadata. A YARA match or heuristic
finding is an indicator for manual review, never proof that a file is malicious.
Some Windows information can be unavailable due to edition, permissions or
virtualization features.
