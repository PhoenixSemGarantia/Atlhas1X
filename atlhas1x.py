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
VERSION = "v0.5"
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SCORE_IMPACTS = {"INFO": 0, "LOW": 2, "MEDIUM": 5, "HIGH": 10, "CRITICAL": 20}


def powershell(command):
    if os.name != "nt": return None, "This check requires Windows"
    try:
        result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, text=True, timeout=20)
        if result.returncode: return None, result.stderr.strip() or f"PowerShell exited with {result.returncode}"
        return result.stdout.strip(), None
    except (OSError, subprocess.TimeoutExpired) as exc: return None, str(exc)

def command(command_line):
    """Run a built-in Windows command as a read-only fallback."""
    if os.name != "nt": return None, "This check requires Windows"
    try:
        result = subprocess.run(["cmd", "/c", command_line], capture_output=True, text=True, timeout=20)
        return (result.stdout.strip(), None) if result.returncode == 0 else (None, result.stderr.strip() or f"Command exited with {result.returncode}")
    except (OSError, subprocess.TimeoutExpired) as exc: return None, str(exc)


def finding(fid, name, category, status, result, severity, description, recommendation, evidence, error=None):
    return {"id": fid, "name": name, "category": category, "status": status, "result": result,
            "severity": severity, "description": description, "recommendation": recommendation,
            "evidence": evidence, "error": error, "score_impact": SCORE_IMPACTS[severity], "timestamp": dt.datetime.now().isoformat(timespec="seconds")}


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
    if not raw: return finding(fid, name, category, "UNKNOWN", "UNKNOWN", "LOW", f"{name} status could not be collected.", "Review this setting manually.", "No data returned", error)
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

def bitlocker():
    raw, error = powershell("Get-BitLockerVolume -MountPoint $env:SystemDrive | Select -Expand ProtectionStatus")
    if not raw:
        fallback, fallback_error = command("manage-bde -status %SystemDrive%")
        if fallback:
            enabled = "Protection Status:" in fallback and "On" in fallback
            return finding("ATL-0007", "BitLocker", "Disk Encryption", "Enabled" if enabled else "Disabled", "PASS" if enabled else "WARNING", "INFO" if enabled else "MEDIUM", "System drive BitLocker protection was read through manage-bde.", "No action required." if enabled else "Review whether disk encryption should be enabled.", fallback[:1200])
        return finding("ATL-0007", "BitLocker", "Disk Encryption", "UNKNOWN", "UNKNOWN", "LOW", "BitLocker status could not be collected.", "Review system drive encryption manually.", "No data returned", fallback_error or error)
    enabled = raw in ("1", "On"); return finding("ATL-0007", "BitLocker", "Disk Encryption", "Enabled" if enabled else "Disabled", "PASS" if enabled else "WARNING", "INFO" if enabled else "MEDIUM", "System drive BitLocker protection is enabled." if enabled else "BitLocker protection is not enabled on the system drive.", "Review whether disk encryption should be enabled.", f"ProtectionStatus={raw}")

def secure_boot():
    raw, error = powershell("try { Confirm-SecureBootUEFI } catch { 'NOT AVAILABLE' }")
    if not raw: return finding("ATL-0008", "Secure Boot", "Boot Security", "UNKNOWN", "UNKNOWN", "LOW", "Secure Boot status could not be determined.", "Review Secure Boot manually.", "No data returned", error)
    if raw == "NOT AVAILABLE": return finding("ATL-0008", "Secure Boot", "Boot Security", "NOT AVAILABLE", "INFO", "INFO", "Secure Boot is not available on this system.", "No action required.", raw)
    enabled = raw.lower() == "true"; return finding("ATL-0008", "Secure Boot", "Boot Security", "Enabled" if enabled else "Disabled", "PASS" if enabled else "WARNING", "INFO" if enabled else "MEDIUM", "Secure Boot is enabled." if enabled else "Secure Boot is disabled.", "Review whether Secure Boot should be enabled.", f"Confirm-SecureBootUEFI={raw}")

def windows_update():
    raw, error = powershell("Get-Service wuauserv | Select Status,StartType | ConvertTo-Json -Compress")
    if not raw: return finding("ATL-0009", "Windows Update", "Updates", "UNKNOWN", "UNKNOWN", "LOW", "Windows Update service status could not be determined.", "Review Windows Update manually.", "No data returned", error)
    try:
        data=json.loads(raw); return finding("ATL-0009", "Windows Update", "Updates", "Available", "INFO", "INFO", "Windows Update service is available.", "Review updates through Windows Update.", f"Status={data.get('Status')}; StartType={data.get('StartType')}")
    except ValueError as exc: return finding("ATL-0009", "Windows Update", "Updates", "UNKNOWN", "UNKNOWN", "LOW", "Windows Update service status could not be parsed.", "Review Windows Update manually.", "Invalid response", str(exc))

def automatic_updates():
    raw,error=powershell("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoUpdate -ErrorAction SilentlyContinue).NoAutoUpdate")
    if not raw: return finding("ATL-0010", "Automatic Updates", "Updates", "UNKNOWN", "UNKNOWN", "LOW", "Automatic Updates policy could not be determined.", "Review Automatic Updates settings manually.", "No policy value returned", error)
    enabled=raw != "1"; return finding("ATL-0010", "Automatic Updates", "Updates", "Enabled" if enabled else "Disabled", "PASS" if enabled else "WARNING", "INFO" if enabled else "MEDIUM", "Automatic Updates appear to be enabled." if enabled else "Automatic Updates appear to be disabled.", "Review Automatic Updates configuration.", f"NoAutoUpdate={raw or 'Not configured'}")

def smbv1():
    raw,error=powershell("Get-SmbServerConfiguration | Select -Expand EnableSMB1Protocol")
    if not raw: return finding("ATL-0011","SMBv1","Network Security","UNKNOWN","UNKNOWN","LOW","SMB configuration could not be determined.","Review SMB configuration manually.","No data returned",error)
    enabled=raw.lower()=="true"; return finding("ATL-0011","SMBv1","Network Security","Enabled" if enabled else "Disabled","WARNING" if enabled else "PASS","HIGH" if enabled else "INFO","SMBv1 is enabled on this system." if enabled else "SMBv1 is disabled on this system.","Review whether the legacy SMB protocol is required." if enabled else "No action required.",f"EnableSMB1Protocol={raw}")

def password_policy():
    raw,error=powershell("net accounts")
    if not raw: return finding("ATL-0012","Local Password Policy","Authentication","UNKNOWN","UNKNOWN","LOW","Local password policy could not be collected.","Review the local password policy manually.","No data returned",error)
    import re
    match=re.search(r"Minimum password length.*?:\s*(\d+)",raw,re.I); length=int(match.group(1)) if match else None
    severity="MEDIUM" if length is not None and length < 8 else "INFO" if length is not None else "LOW"
    status=f"{length} characters" if length is not None else "Available for review"
    return finding("ATL-0012","Local Password Policy","Authentication",status,"WARNING" if severity=="MEDIUM" else "INFO",severity,"The configured minimum password length is relatively low." if severity=="MEDIUM" else "Local password policy data was collected.","Review the local password policy." if severity=="MEDIUM" else "No action required.",raw[:1200])

def guest_account():
    raw,error=powershell("Get-LocalUser | Where-Object {$_.SID.Value -match '-501$'} | Select Name,Enabled | ConvertTo-Json -Compress")
    if not raw: return finding("ATL-0013","Guest Account","Account Security","UNKNOWN","UNKNOWN","LOW","Guest account status could not be determined.","Review the Guest account manually.","No data returned",error)
    try:
        data=json.loads(raw); enabled=data.get("Enabled"); return finding("ATL-0013","Guest Account","Account Security","Enabled" if enabled else "Disabled","WARNING" if enabled else "PASS","MEDIUM" if enabled else "INFO","The Guest account is enabled." if enabled else "The Guest account is disabled.","Review whether the Guest account is required." if enabled else "No action required.",f"Name={data.get('Name')}; Enabled={enabled}")
    except ValueError as exc: return finding("ATL-0013","Guest Account","Account Security","UNKNOWN","UNKNOWN","LOW","Guest account status could not be parsed.","Review the Guest account manually.","Invalid response",str(exc))

def passwordless_accounts():
    raw,error=powershell("Get-LocalUser | Where-Object {$_.PasswordRequired -eq $false} | Select -Expand Name")
    if raw is None: return finding("ATL-0014","Local Account Password Check","Account Security","UNKNOWN","UNKNOWN","LOW","Local account password configuration could not be determined.","Review local account settings manually.","No data returned",error)
    accounts=[x for x in raw.splitlines() if x]; count=len(accounts); return finding("ATL-0014","Local Account Password Check","Account Security",f"{count} account(s) require review","WARNING" if count else "PASS","HIGH" if count else "INFO","Accounts configured without a required password were found." if count else "No local accounts with PasswordRequired=False were returned.","Review listed accounts and their password configuration." if count else "No action required.","; ".join(accounts) or "PasswordRequired=False accounts: none")

def security_service(fid,name,service):
    raw,error=powershell(f"Get-Service -Name '{service}' | Select Status,StartType | ConvertTo-Json -Compress")
    if not raw:
        fallback, fallback_error = command(f"sc query {service}")
        if fallback:
            running = "RUNNING" in fallback.upper()
            state = "Running" if running else "Not Running"
            return finding(fid,name,"System Services",state,"PASS" if running else "WARNING","INFO" if running else "LOW",f"{name} service is running." if running else f"{name} service is not running.","No action required." if running else "Review whether this service is expected to run.",fallback[:500])
        return finding(fid,name,"System Services","UNKNOWN","UNKNOWN","LOW",f"{name} service could not be determined.","Review the service manually.","No data returned",fallback_error or error)
    try:
        data=json.loads(raw); running=data.get("Status")=="Running"; return finding(fid,name,"System Services","Running" if running else str(data.get("Status")),"PASS" if running else "WARNING","INFO" if running else "LOW",f"{name} service is running." if running else f"{name} service is not running.","No action required." if running else "Review whether this service is expected to run.",f"Status={data.get('Status')}; StartType={data.get('StartType')}")
    except ValueError as exc: return finding(fid,name,"System Services","UNKNOWN","UNKNOWN","LOW",f"{name} service could not be parsed.","Review the service manually.","Invalid response",str(exc))

def unusual_path(value):
    text=(value or "").lower().replace("/","\\")
    return any(part in text for part in ("\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\", "\\desktop\\"))

def startup_programs():
    raw,error=powershell("Get-CimInstance Win32_StartupCommand | Select Name,Command,Location,User | ConvertTo-Json -Compress")
    if not raw: return finding("ATL-0019","Startup Programs","Startup","UNKNOWN","UNKNOWN","LOW","Startup programs could not be collected.","Review startup items manually.","No data returned",error)
    try:
        items=json.loads(raw); items=items if isinstance(items,list) else [items]; risky=[x for x in items if unusual_path(x.get('Command'))]
        sev="MEDIUM" if risky else "INFO"; return finding("ATL-0019","Startup Programs","Startup",f"{len(items)} detected; {len(risky)} require review","WARNING" if risky else "INFO",sev,"Startup items were collected. Items from temporary or user download locations require review." if risky else "Startup items were collected without unusual path indicators.","Review listed startup items." if risky else "No action required.",json.dumps(risky[:10]) if risky else f"Total={len(items)}")
    except ValueError as exc: return finding("ATL-0019","Startup Programs","Startup","UNKNOWN","UNKNOWN","LOW","Startup programs could not be parsed.","Review startup items manually.","Invalid response",str(exc))

def scheduled_tasks():
    raw,error=powershell("Get-ScheduledTask | Select TaskName,TaskPath,State,@{N='Action';E={$_.Actions.Execute}},@{N='RunAs';E={$_.Principal.UserId}} | ConvertTo-Json -Compress")
    if not raw: return finding("ATL-0020","Scheduled Tasks","Scheduled Tasks","UNKNOWN","UNKNOWN","LOW","Scheduled tasks could not be collected.","Review scheduled tasks manually.","No data returned",error)
    try:
        items=json.loads(raw); items=items if isinstance(items,list) else [items]; risky=[x for x in items if unusual_path(x.get('Action'))]
        return finding("ATL-0020","Scheduled Tasks","Scheduled Tasks",f"{len(items)} detected; {len(risky)} require review","WARNING" if risky else "INFO","MEDIUM" if risky else "INFO","Tasks executing from potentially risky locations require review." if risky else "Scheduled tasks were collected without unusual path indicators.","Review listed scheduled tasks." if risky else "No action required.",json.dumps(risky[:10]) if risky else f"Total={len(items)}")
    except ValueError as exc: return finding("ATL-0020","Scheduled Tasks","Scheduled Tasks","UNKNOWN","UNKNOWN","LOW","Scheduled tasks could not be parsed.","Review scheduled tasks manually.","Invalid response",str(exc))

def network_shares():
    raw,error=powershell("Get-SmbShare | Select Name,Path,Special | ConvertTo-Json -Compress")
    if not raw: return finding("ATL-0021","Network Shares","Network Sharing","UNKNOWN","UNKNOWN","LOW","Network shares could not be collected.","Review network shares manually.","No data returned",error)
    try:
        items=json.loads(raw); items=items if isinstance(items,list) else [items]; user=[x for x in items if not x.get('Special')]
        return finding("ATL-0021","Network Shares","Network Sharing",f"{len(items)} detected; {len(user)} user-created","INFO","INFO","Local SMB shares were collected. Administrative shares are not treated as vulnerabilities.","Review user-created shares and their access requirements.",json.dumps(items[:30]))
    except ValueError as exc: return finding("ATL-0021","Network Shares","Network Sharing","UNKNOWN","UNKNOWN","LOW","Network shares could not be parsed.","Review network shares manually.","Invalid response",str(exc))

def automatic_services():
    raw,error=powershell("Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq 'Auto'} | Select Name,State,PathName | ConvertTo-Json -Compress")
    if not raw: return finding("ATL-0022","Automatic Services","System Services","UNKNOWN","UNKNOWN","LOW","Automatic services could not be collected.","Review automatic services manually.","No data returned",error)
    try:
        items=json.loads(raw); items=items if isinstance(items,list) else [items]; risky=[x for x in items if x.get('State')!='Running' or unusual_path(x.get('PathName'))]
        return finding("ATL-0022","Automatic Services","System Services",f"{len(items)} detected; {len(risky)} require review","WARNING" if risky else "INFO","LOW" if risky else "INFO","Automatic services that are stopped or use unusual paths require review." if risky else "Automatic services were collected without basic review indicators.","Review listed automatic services." if risky else "No action required.",json.dumps(risky[:10]) if risky else f"Total={len(items)}")
    except ValueError as exc: return finding("ATL-0022","Automatic Services","System Services","UNKNOWN","UNKNOWN","LOW","Automatic services could not be parsed.","Review automatic services manually.","Invalid response",str(exc))


def system_info():
    return {"hostname": socket.gethostname(), "operating_system": platform.platform(), "os_build": platform.version(), "architecture": platform.machine(), "user": getpass.getuser(), "administrator_privileges": "Not evaluated", "python": platform.python_version()}


def overall(findings):
    present = {f["severity"] for f in findings}
    return next(level for level in reversed(SEVERITIES) if level in present)

def security_score(findings): return max(0, 100 - sum(f["score_impact"] for f in findings))
def score_classification(score): return "Good" if score >= 90 else "Attention" if score >= 75 else "Risk" if score >= 50 else "High Risk" if score >= 25 else "Critical"


def esc(value): return html.escape(str(value))
def card(f, advanced=False):
    extra = "" if not advanced else f"<p><b>Finding ID:</b> {esc(f['id'])}<br><b>Category:</b> {esc(f['category'])}<br><b>Result:</b> {esc(f['result'])}<br><b>Score Impact:</b> -{f['score_impact']}<br><b>Evidence:</b> {esc(f['evidence'])}<br><b>Timestamp:</b> {esc(f['timestamp'])}</p>"
    if f["error"] and advanced: extra += f"<p><b>Technical error:</b> {esc(f['error'])}</p>"
    return f"<article class='card {f['severity'].lower()}'><span class='badge'>{esc(f['severity'])}</span><h3>{esc(f['name'])}</h3><p><b>Status:</b> {esc(f['status'])}</p><p>{esc(f['description'])}</p><p><b>Recommendation:</b> {esc(f['recommendation'])}</p>{extra}</article>"


def report_html(level, findings, info, started, ended):
    risk = overall(findings); score=security_score(findings); counts = {s: sum(f["severity"] == s for f in findings) for s in SEVERITIES}
    head = f"<header><h1>{APP_NAME} Security Audit</h1><p>{VERSION} · {esc(level.title())} report</p><div class='risk {risk.lower()}'>Security Score: {score}/100 · {score_classification(score)} · Overall Risk: {risk}</div></header>"
    system = "".join(f"<tr><th>{esc(k.replace('_',' ').title())}</th><td>{esc(v)}</td></tr>" for k,v in info.items() if level != "basic" or k in ("hostname","user","operating_system"))
    summary = "" if level == "basic" else "<section><h2>Summary</h2><p>Passed: %d · Alerts: %d · Total checks: %d</p><div class='counts'>%s</div></section>" % (sum(f['result']=='PASS' for f in findings), sum(f['result'] in ('WARNING','FAIL','UNKNOWN') for f in findings), len(findings), " ".join(f"<span class='{s.lower()}'>{s}: {counts[s]}</span>" for s in SEVERITIES))
    technical = "" if level != "advanced" else f"<section><h2>Security Assessment</h2><p><b>Security Score:</b> {score}/100<br><b>Score Classification:</b> {score_classification(score)}<br><b>Overall Risk:</b> {risk}<br><b>Total Checks:</b> {len(findings)}</p></section><section><h2>Scan Information</h2><p><b>Report ID:</b> ATL-{started.strftime('%Y%m%d-%H%M%S')}<br><b>Duration:</b> {(ended-started).total_seconds():.2f} seconds<br><b>Scope:</b> Read-only security queries; no settings were changed.</p></section>"
    cards = "".join(card(f, level == "advanced") for f in findings)
    css = "body{font:15px Segoe UI,Arial;background:#f4f6f8;color:#1d2733;margin:0}main{max-width:1000px;margin:auto;padding:28px}header,section,.card{background:#fff;border:1px solid #dce2e8;border-radius:8px;padding:20px;margin:16px 0}h1,h2{margin-top:0}.risk,.badge{display:inline-block;padding:7px 12px;border-radius:4px;font-weight:bold}.card{border-left:6px solid #718096}.card.info{border-color:#4a7fa7}.card.low{border-color:#3b9b70}.card.medium{border-color:#c69b20}.card.high{border-color:#d77a24}.card.critical{border-color:#c53030}.info{background:#e7f0f8}.low{background:#e5f5ed}.medium{background:#fff6d8}.high{background:#fff0df}.critical{background:#ffe4e4}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;border-bottom:1px solid #e4e8ec}.counts span{margin-right:12px;font-weight:bold}.badge{float:right}"
    return f"<!doctype html><html><head><meta charset='utf-8'><title>Atlhas1x {esc(level.title())} Report</title><style>{css}</style></head><body><main>{head}<section><h2>System Information</h2><table>{system}</table></section>{summary}{technical}<section><h2>Findings</h2>{cards}</section><footer>Generated locally by {APP_NAME} {VERSION}. No settings were modified.</footer></main></body></html>"


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--report", choices=("basic","intermediate","advanced")); parser.add_argument("--mode", choices=("basic","intermediate","advanced"))
    args = parser.parse_args(); level = args.report or args.mode or "basic"; started = dt.datetime.now(); findings = [defender(), firewall(), uac(), rdp(), administrators(), bitlocker(), secure_boot(), windows_update(), automatic_updates(), smbv1(), password_policy(), guest_account(), passwordless_accounts(), security_service("ATL-0015","Windows Defender Service","WinDefend"), security_service("ATL-0016","Windows Firewall Service","MpsSvc"), security_service("ATL-0017","Windows Update Service","wuauserv"), security_service("ATL-0018","Security Center Service","wscsvc"), startup_programs(), scheduled_tasks(), network_shares(), automatic_services()]; ended = dt.datetime.now()
    path = None
    try:
        reports = Path("reports"); reports.mkdir(exist_ok=True); stamp = started.strftime("%Y-%m-%d_%H%M%S"); path = reports / f"atlhas1x_{level}_{stamp}.html"; path.write_text(report_html(level, findings, system_info(), started, ended), encoding="utf-8")
    except OSError as exc:
        report_error = str(exc)
    print(f"Atlhas1x {VERSION}\nWindows Security Auditor\n\nScanning...")
    for f in findings: print(f"[{'OK' if f['result'] in ('PASS','INFO') else 'WARN'}] {f['name']}: {f['status']}")
    print(f"\nSecurity Score\n{security_score(findings)} / 100\n\nOverall Risk\n{overall(findings)}\n\nScan completed.")
    print(f"\nReport:\n{path}" if path else f"\n[WARN] Report could not be saved: {report_error}")

if __name__ == "__main__": main()
