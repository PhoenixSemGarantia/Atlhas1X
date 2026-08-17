# Rule sources

## Local Atlhas1x rule

- Location: `rules/local/atlhas_test_only.yar`
- Purpose: a benign, clearly marked test fixture for validating the optional
  YARA engine. It is not a malware-detection rule.

## Third-party YARA rules

- Source: [Yara-Rules/rules](https://github.com/Yara-Rules/rules)
- Type: third-party YARA rules
- License: GPL-2.0
- Purpose: local defensive pattern matching

Third-party files are **not bundled** in this checkout. If they are added under
`rules/third_party/yara-rules/`, their license, copyright notices, authors and
rule metadata must remain intact. Atlhas1x keeps third-party rules separate
from its own rules and never downloads, uploads or updates them during a scan.
