# Audit Modes

Atlhas1x supports three report levels. All are local and read-only.

## Basic

Use for a fast overview. It highlights the Security Score, overall risk, scan completeness, and important findings without large technical inventories.

## Intermediate

Use for routine reviews. It includes finding status, severity, descriptions, and recommendations with enough context for follow-up.

## Advanced

Use for technical investigation. It includes normalized evidence and inventories such as applicable services, processes, network information, and module diagnostics. The report remains a self-contained offline HTML file.

Run a mode directly:

```powershell
python atlhas1x.py --report advanced
```

The guided launcher exposes the same report levels.
