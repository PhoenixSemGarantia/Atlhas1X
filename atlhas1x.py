"""Atlhas1x v0.2 - read-only Windows security audit and HTML reports."""
import argparse
import datetime as dt
import getpass
import html
import json
import os
import platform
import socket
import subprocess
import time
from pathlib import Path

APP_NAME = "Atlhas1x"
VERSION = "v0.2"
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def powershell(command):
    if os.name != "nt": return None, "This check requires Windows"
    try:
        result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, text=True, timeout=20)
        if result.returncode: return None, result.stderr.strip() or f"PowerShell exited with {result.returncode}"
        return result.stdout.strip(), None
    except (OSError, subprocess.TimeoutExpired) as exc: return None, str(exc)


def finding(fid, name, category, status, result, severity, description, recommendation, evidence, error=None):
    return {"id": fid, "name": name, "category": category, "status": status, "result": result,
            "severity": severity, "description": description, "recommendation": recommendation,
            "evidence": evidence, "error": error, "timestamp": dt.datetime.now().isoformat(timespec="seconds")}


def defender():
    raw, error = powershell("Get-MpComputerStatus | Select AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json -Compress")
    if not raw: return finding("ATL-0001", "Windows Defender", "Antivirus", "UNKNOWN", "UNKNOWN", "LOW", "Defender status could not be collected.", "Review Defender status manually.", "No data returned", error)
    try:
        data = json.loads(raw); enabled = data.get("AntivirusEnabled") and data.get("RealTimeProtectionEnabled")
        return finding("ATL-0001", "Windows Defender", "Antivirus", "Enabled" if enabled else "Disabled", "PASS" if enabled else "FAIL", "INFO" if enabled else "HIGH", "Microsoft Defender real-time protection appears to be enabled." if enabled else "Microsoft Defender or real-time protection appears to be disabled.", "No action required." if enabled else "Enable and review Microsoft Defender real-time protection.", f"AntivirusEnabled={data.get('AntivirusEnabled')}; RealTimeProtectionEnabled={data.get('RealTimeProtectionEnabled')}")
    except (ValueError, AttributeError) as exc: return finding("ATL-0001", "Windows Defender", "Antivirus", "UNKNOWN", "UNKNOWN", "LOW", "Defender status could not be parsed.", "Review Defender status manually.", "Invalid PowerShell response", str(exc))


def firewall():
    raw, error = powershell("Get-NetFirewallProfile | Select Name,Enabled | ConvertTo-Json -Compress")
    if not raw: return finding("ATL-0002", "Windows Firewall", "Network Security", "UNKNOWN", "UNKNOWN", "LOW", "Firewall status could not be collected.", "Review Firewall status manually.", "No data returned", error)
    try:
        profiles = json.loads(raw); profiles = profiles if isinstance(profiles, list) else [profiles]
        enabled = [p.get("Enabled") for p in profiles]; evidence = "; ".join(f"{p.get('Name')}={p.get('Enabled')}" for p in profiles)
        ok = bool(enabled) and all(enabled)
        return finding("ATL-0002", "Windows Firewall", "Network Security", "Enabled" if ok else "Disabled or partial", "PASS" if ok else "FAIL", "INFO" if ok else "HIGH", "Windows Firewall is enabled for all profiles." if ok else "Windows Firewall is disabled for one or more profiles.", "No action required." if ok else "Enable and review Windows Firewall profiles.", evidence)
    except (ValueError, AttributeError) as exc: return finding("ATL-0002", "Windows Firewall", "Network Security", "UNKNOWN", "UNKNOWN", "LOW", "Firewall status could not be parsed.", "Review Firewall status manually.", "Invalid PowerShell response", str(exc))


def registry_check(fid, name, category, command, enabled_value, safe_status, unsafe_status, safe_description, unsafe_description, recommendation, evidence_name, severity):
    raw, error = powershell(command)
    if raw is None: return finding(fid, name, category, "UNKNOWN", "UNKNOWN", "LOW", f"{name} status could not be collected.", "Review this setting manually.", "No data returned", error)
    safe = raw == enabled_value
    return finding(fid, name, category, safe_status if safe else unsafe_status, "PASS" if safe else "WARNING", "INFO" if safe else severity, safe_description if safe else unsafe_description, "No action required." if safe else recommendation, f"{evidence_name}={raw}")


def uac():
    return registry_check("ATL-0003", "User Account Control", "System Security", "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA).EnableLUA", "1", "Enabled", "Disabled", "User Account Control is enabled.", "User Account Control appears to be disabled.", "Review the current UAC configuration.", "EnableLUA", "HIGH")


def rdp():
    return registry_check("ATL-0004", "Remote Desktop", "Remote Access", "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections", "1", "Disabled", "Enabled", "Remote Desktop is disabled.", "Remote Desktop is enabled on this Windows installation.", "Verify whether Remote Desktop is required for this machine.", "fDenyTSConnections", "MEDIUM")


def administrators():
    raw, error = powershell("Get-LocalGroupMember -SID S-1-5-32-544 | Select -Expand Name")
    if raw is None: return finding("ATL-0005", "Local Administrators", "Accounts", "UNKNOWN", "UNKNOWN", "LOW", "Local administrator membership could not be collected.", "Review local administrator accounts manually.", "No data returned", error)
    members = raw.splitlines(); return finding("ATL-0005", "Local Administrators", "Accounts", f"{len(members)} account(s)", "INFO", "INFO", "Local administrator accounts were collected for review.", "Review whether every listed account requires administrator privileges.", "; ".join(members) or "No members returned")


def system_info():
    return {"hostname": socket.gethostname(), "operating_system": platform.platform(), "os_build": platform.version(), "architecture": platform.machine(), "user": getpass.getuser(), "administrator_privileges": "Not evaluated", "python": platform.python_version()}


def overall(findings):
    present = {f["severity"] for f in findings}
    return next(level for level in reversed(SEVERITIES) if level in present)


def esc(value): return html.escape(str(value))
def card(f, advanced=False):
    extra = "" if not advanced else f"<p><b>Finding ID:</b> {esc(f['id'])}<br><b>Category:</b> {esc(f['category'])}<br><b>Result:</b> {esc(f['result'])}<br><b>Evidence:</b> {esc(f['evidence'])}<br><b>Timestamp:</b> {esc(f['timestamp'])}</p>"
    if f["error"] and advanced: extra += f"<p><b>Technical error:</b> {esc(f['error'])}</p>"
    return f"<article class='card {f['severity'].lower()}'><span class='badge'>{esc(f['severity'])}</span><h3>{esc(f['name'])}</h3><p><b>Status:</b> {esc(f['status'])}</p><p>{esc(f['description'])}</p><p><b>Recommendation:</b> {esc(f['recommendation'])}</p>{extra}</article>"


def report_html(level, findings, info, started, ended):
    risk = overall(findings); counts = {s: sum(f["severity"] == s for f in findings) for s in SEVERITIES}
    head = f"<header><h1>{APP_NAME} Security Audit</h1><p>{VERSION} · {esc(level.title())} report</p><div class='risk {risk.lower()}'>Overall Risk: {risk}</div></header>"
    system = "".join(f"<tr><th>{esc(k.replace('_',' ').title())}</th><td>{esc(v)}</td></tr>" for k,v in info.items() if level != "basic" or k in ("hostname","user","operating_system"))
    summary = "" if level == "basic" else "<section><h2>Summary</h2><p>Passed: %d · Alerts: %d · Total checks: %d</p><div class='counts'>%s</div></section>" % (sum(f['result']=='PASS' for f in findings), sum(f['result'] in ('WARNING','FAIL','UNKNOWN') for f in findings), len(findings), " ".join(f"<span class='{s.lower()}'>{s}: {counts[s]}</span>" for s in SEVERITIES))
    technical = "" if level != "advanced" else f"<section><h2>Scan Information</h2><p><b>Report ID:</b> ATL-{started.strftime('%Y%m%d-%H%M%S')}<br><b>Scan Start:</b> {started.isoformat(timespec='seconds')}<br><b>Scan End:</b> {ended.isoformat(timespec='seconds')}<br><b>Duration:</b> {(ended-started).total_seconds():.2f} seconds<br><b>Scope:</b> Read-only Windows Defender, Firewall, UAC, RDP and local administrator queries.</p></section>"
    cards = "".join(card(f, level == "advanced") for f in findings)
    css = "body{font:15px Segoe UI,Arial;background:#f4f6f8;color:#1d2733;margin:0}main{max-width:1000px;margin:auto;padding:28px}header,section,.card{background:#fff;border:1px solid #dce2e8;border-radius:8px;padding:20px;margin:16px 0}h1,h2{margin-top:0}.risk,.badge{display:inline-block;padding:7px 12px;border-radius:4px;font-weight:bold}.card{border-left:6px solid #718096}.card.info{border-color:#4a7fa7}.card.low{border-color:#3b9b70}.card.medium{border-color:#c69b20}.card.high{border-color:#d77a24}.card.critical{border-color:#c53030}.info{background:#e7f0f8}.low{background:#e5f5ed}.medium{background:#fff6d8}.high{background:#fff0df}.critical{background:#ffe4e4}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;border-bottom:1px solid #e4e8ec}.counts span{margin-right:12px;font-weight:bold}.badge{float:right}"
    return f"<!doctype html><html><head><meta charset='utf-8'><title>Atlhas1x {esc(level.title())} Report</title><style>{css}</style></head><body><main>{head}<section><h2>System Information</h2><table>{system}</table></section>{summary}{technical}<section><h2>Findings</h2>{cards}</section><footer>Generated locally by {APP_NAME} {VERSION}. No settings were modified.</footer></main></body></html>"


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--report", choices=("basic","intermediate","advanced")); parser.add_argument("--mode", choices=("basic","intermediate","advanced"))
    args = parser.parse_args(); level = args.report or args.mode or "basic"; started = dt.datetime.now(); findings = [defender(), firewall(), uac(), rdp(), administrators()]; ended = dt.datetime.now()
    reports = Path("reports"); reports.mkdir(exist_ok=True); stamp = started.strftime("%Y-%m-%d_%H%M%S"); path = reports / f"atlhas1x_{level}_{stamp}.html"; path.write_text(report_html(level, findings, system_info(), started, ended), encoding="utf-8")
    print(f"Atlhas1x {VERSION}\nReport generated: {path}\nOverall Risk: {overall(findings)}")

if __name__ == "__main__": main()
