"""Atlhas1x v1.3 - read-only Windows detection-accuracy scanner."""
import sys
import argparse
import base64
import ctypes
import datetime as dt
import html
import getpass
import json
import logging
import os
import platform
import socket
import subprocess
import time
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Iterable

# The official embeddable Python runtime used by the Windows installer runs in
# isolated mode. In that mode the directory of this script is not guaranteed
# to be in sys.path, so explicitly expose only this local application folder.
APP_DIRECTORY = str(Path(__file__).resolve().parent)
if APP_DIRECTORY not in sys.path:
    sys.path.insert(0, APP_DIRECTORY)

try:
    from threat_analysis import analyze as analyze_threats
    THREAT_ENGINE_IMPORT_ERROR = None
except (ImportError, OSError) as exc:
    # The base scanner must remain usable if a partially copied v1.2 install
    # is missing its optional threat-analysis modules.
    analyze_threats = None
    THREAT_ENGINE_IMPORT_ERROR = str(exc)

APP_NAME = "Atlhas1x"
VERSION = "v1.2"
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SCORE_IMPACTS = {"INFO": 0, "LOW": 2, "MEDIUM": 5, "HIGH": 10, "CRITICAL": 20}
LIVE_DETAILS = False
LIVE_LOG_PATH = None
SCAN_TOTAL_MODULES = 46
SCAN_COMPLETED_MODULES = 0


def normalize_windows_text(value):
    """Repair common CP850-to-Windows-1252 mojibake from legacy utilities."""
    text = str(value or "")
    if not any(marker in text for marker in ("†", "‡", "ˆ", "Æ", "ƒ")):
        return text
    try:
        repaired = text.encode("cp1252").decode("cp850")
        return repaired if "�" not in repaired else text
    except (UnicodeError, LookupError):
        return text


def live_detail(kind, value):
    """Send bounded, local audit telemetry to the optional graphical launcher."""
    if not LIVE_DETAILS:
        return
    text = str(value or "No response returned").strip()
    limit = 700
    if len(text) > limit:
        text = text[:limit] + " ... [response truncated]"
    line = f"[{kind}] {text}"
    print(line, flush=True)
    if LIVE_LOG_PATH:
        try:
            with open(LIVE_LOG_PATH, "a", encoding="utf-8") as live_log:
                live_log.write(line + "\n")
        except OSError:
            pass


def powershell(command, timeout=20):
    if os.name != "nt": return None, "This check requires Windows"
    live_detail("COMMAND", "PowerShell: " + command)
    try:
        # PowerShell 5 may otherwise serialize localized output using the
        # active console code page. Force UTF-8 before Python reads stdout so
        # names such as "Configuração" remain correct in offline HTML.
        utf8_command = "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); " + command
        result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", utf8_command], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        if result.returncode:
            error = normalize_windows_text(result.stderr.strip()) or f"PowerShell exited with {result.returncode}"
            live_detail("RESPONSE", error)
            return None, error
        output = normalize_windows_text(result.stdout.strip())
        live_detail("RESPONSE", output)
        return output, None
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        live_detail("RESPONSE", str(exc))
        return None, str(exc)

def command(command_line, timeout=20):
    """Run a built-in Windows command as a read-only fallback."""
    if os.name != "nt": return None, "This check requires Windows"
    live_detail("COMMAND", "CMD: " + command_line)
    try:
        # Native Windows utilities commonly use the OEM code page, unlike
        # PowerShell above. Python's Windows "oem" codec keeps their localized
        # output readable without changing the console or system locale.
        result = subprocess.run(["cmd", "/c", command_line], capture_output=True, text=True, encoding="oem", errors="replace", timeout=timeout)
        if result.returncode == 0:
            output = normalize_windows_text(result.stdout.strip())
            live_detail("RESPONSE", output)
            return output, None
        error = normalize_windows_text(result.stderr.strip()) or f"Command exited with {result.returncode}"
        live_detail("RESPONSE", error)
        return None, error
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        live_detail("RESPONSE", str(exc))
        return None, str(exc)


def classify_error(error):
    text = str(error or "").lower()
    if not text:
        return None
    if any(word in text for word in ("access denied", "acesso negado", "access restricted", "acesso restrito", "requires elevation", "privilege")):
        return "ACCESS_DENIED"
    if any(word in text for word in ("not available", "not supported", "not recognized", "not found", "requires windows")):
        return "NOT_AVAILABLE"
    if "timed out" in text or "timeout" in text:
        return "TIMEOUT"
    return "QUERY_FAILED"


def finding(fid, name, category, status, result, severity, description, recommendation, evidence, error=None, confidence=None, score_key=None):
    error_type = classify_error(error)
    if confidence is None:
        confidence = "LOW" if result == "UNKNOWN" else "MEDIUM" if error_type else "HIGH"
    return {"id": fid, "name": name, "category": category, "status": status, "result": result,
            "severity": severity, "description": description, "recommendation": recommendation,
            "evidence": evidence, "error": error, "error_type": error_type, "confidence": confidence,
            "score_key": score_key or fid, "score_impact": SCORE_IMPACTS[severity], "timestamp": dt.datetime.now().isoformat(timespec="seconds"), "duration_seconds": None}


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
        # Only classify the fallback when its known output marker is present.
        # manage-bde output is localized, so an unrecognised response is UNKNOWN,
        # rather than incorrectly reported as disabled.
        if fallback and "Protection Status:" in fallback:
            enabled = "On" in fallback
            return finding("ATL-0007", "BitLocker", "Disk Encryption", "Enabled" if enabled else "Disabled", "PASS" if enabled else "WARNING", "INFO" if enabled else "MEDIUM", "System drive BitLocker protection was read through manage-bde.", "No action required." if enabled else "Review whether disk encryption should be enabled.", fallback[:1200])
        if fallback:
            return finding("ATL-0007", "BitLocker", "Disk Encryption", "UNKNOWN", "UNKNOWN", "LOW", "BitLocker command output could not be interpreted.", "Review system drive encryption manually.", fallback[:1200])
        return finding("ATL-0007", "BitLocker", "Disk Encryption", "UNKNOWN", "UNKNOWN", "LOW", "BitLocker status could not be collected.", "Review system drive encryption manually.", "No data returned", fallback_error or error)
    enabled = raw in ("1", "On"); return finding("ATL-0007", "BitLocker", "Disk Encryption", "Enabled" if enabled else "Disabled", "PASS" if enabled else "WARNING", "INFO" if enabled else "MEDIUM", "System drive BitLocker protection is enabled." if enabled else "BitLocker protection is not enabled on the system drive.", "Review whether disk encryption should be enabled.", f"ProtectionStatus={raw}")

def secure_boot():
    raw, error = powershell("try { Confirm-SecureBootUEFI } catch { 'NOT AVAILABLE' }")
    if not raw: return finding("ATL-0008", "Secure Boot", "Boot Security", "UNKNOWN", "UNKNOWN", "LOW", "Secure Boot status could not be determined.", "Review Secure Boot manually.", "No data returned", error)
    if raw == "NOT AVAILABLE": return finding("ATL-0008", "Secure Boot", "Boot Security", "NOT AVAILABLE", "INFO", "INFO", "Secure Boot is not available on this system.", "No action required.", raw)
    enabled = raw.lower() == "true"; return finding("ATL-0008", "Secure Boot", "Boot Security", "Enabled" if enabled else "Disabled", "PASS" if enabled else "WARNING", "INFO" if enabled else "MEDIUM", "Secure Boot is enabled." if enabled else "Secure Boot is disabled.", "Review whether Secure Boot should be enabled.", f"Confirm-SecureBootUEFI={raw}")

def windows_update():
    query = "$s=Get-Service wuauserv -ErrorAction Stop; $h=Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1; [PSCustomObject]@{ServiceStatus=$s.Status;StartType=$s.StartType;LastInstalledOn=$h.InstalledOn;HotFix=$h.HotFixID} | ConvertTo-Json -Compress"
    raw, error = powershell(query)
    if not raw: return finding("ATL-0009", "Windows Update", "Updates", "UNKNOWN", "UNKNOWN", "LOW", "Windows Update service status could not be determined.", "Review Windows Update manually.", "No data returned", error)
    try:
        data=json.loads(raw); last_update = clean_value(data.get("LastInstalledOn")); return finding("ATL-0009", "Windows Update", "Updates", "Available", "INFO", "INFO", "Windows Update service and last installed update metadata were collected.", "Review updates through Windows Update.", json.dumps({"Service Status": data.get("ServiceStatus"), "Start Type": data.get("StartType"), "Last Successful Update": last_update, "HotFix": data.get("HotFix")}))
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
    # PowerShell can serialise a multi-action task as a list. Converting it to
    # text keeps this review-only heuristic from aborting an entire scan.
    text=str(value or "").lower().replace("/","\\")
    return any(part in text for part in ("\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\", "\\desktop\\"))


def startup_programs():
    raw,error=powershell("Get-CimInstance Win32_StartupCommand | Select Name,Command,Location,User | ConvertTo-Json -Compress")
    if not raw: return finding("ATL-0019","Startup Programs","Startup","UNKNOWN","UNKNOWN","LOW","Startup programs could not be collected.","Review startup items manually.","No data returned",error)
    try:
        items=json.loads(raw); items=items if isinstance(items,list) else [items]; risky=[x for x in items if unusual_path(x.get('Command'))]
        sev="MEDIUM" if risky else "INFO"; return finding("ATL-0019","Startup Programs","Startup",f"{len(items)} detected; {len(risky)} require review","WARNING" if risky else "INFO",sev,"Startup items were collected. Items from temporary or user download locations require review." if risky else "Startup items were collected without unusual path indicators.","Review listed startup items." if risky else "No action required.",json.dumps(risky[:10]) if risky else f"Total={len(items)}")
    except (ValueError, TypeError, AttributeError) as exc: return finding("ATL-0019","Startup Programs","Startup","UNKNOWN","UNKNOWN","LOW","Startup programs could not be parsed.","Review startup items manually.","Invalid response",str(exc))

def scheduled_tasks():
    raw,error=powershell("Get-ScheduledTask | Select TaskName,TaskPath,State,@{N='Action';E={$_.Actions.Execute}},@{N='RunAs';E={$_.Principal.UserId}} | ConvertTo-Json -Compress")
    if not raw: return finding("ATL-0020","Scheduled Tasks","Scheduled Tasks","UNKNOWN","UNKNOWN","LOW","Scheduled tasks could not be collected.","Review scheduled tasks manually.","No data returned",error)
    try:
        items=json.loads(raw); items=items if isinstance(items,list) else [items]; risky=[x for x in items if unusual_path(x.get('Action'))]
        return finding("ATL-0020","Scheduled Tasks","Scheduled Tasks",f"{len(items)} detected; {len(risky)} require review","WARNING" if risky else "INFO","MEDIUM" if risky else "INFO","Tasks executing from potentially risky locations require review." if risky else "Scheduled tasks were collected without unusual path indicators.","Review listed scheduled tasks." if risky else "No action required.",json.dumps(risky[:10]) if risky else f"Total={len(items)}")
    except (ValueError, TypeError, AttributeError) as exc: return finding("ATL-0020","Scheduled Tasks","Scheduled Tasks","UNKNOWN","UNKNOWN","LOW","Scheduled tasks could not be parsed.","Review scheduled tasks manually.","Invalid response",str(exc))

def network_shares():
    raw,error=powershell("Get-SmbShare | Select Name,Path,Special | ConvertTo-Json -Compress")
    if not raw: return finding("ATL-0021","Network Shares","Network Sharing","UNKNOWN","UNKNOWN","LOW","Network shares could not be collected.","Review network shares manually.","No data returned",error)
    try:
        items=json.loads(raw); items=items if isinstance(items,list) else [items]; user=[x for x in items if not x.get('Special')]
        return finding("ATL-0021","Network Shares","Network Sharing",f"{len(items)} detected; {len(user)} user-created","INFO","INFO","Local SMB shares were collected. Administrative shares are not treated as vulnerabilities.","Review user-created shares and their access requirements.",json.dumps(items[:30]))
    except (ValueError, TypeError, AttributeError) as exc: return finding("ATL-0021","Network Shares","Network Sharing","UNKNOWN","UNKNOWN","LOW","Network shares could not be parsed.","Review network shares manually.","Invalid response",str(exc))

def automatic_services():
    raw,error=powershell("Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq 'Auto'} | Select Name,State,PathName | ConvertTo-Json -Compress")
    if not raw: return finding("ATL-0022","Automatic Services","System Services","UNKNOWN","UNKNOWN","LOW","Automatic services could not be collected.","Review automatic services manually.","No data returned",error)
    try:
        items=json.loads(raw); items=items if isinstance(items,list) else [items]; risky=[x for x in items if unusual_path(x.get('PathName'))]
        return finding("ATL-0022","Automatic Services","System Services",f"{len(items)} detected; {len(risky)} require review","WARNING" if risky else "INFO","LOW" if risky else "INFO","Automatic services using unusual paths require review. A stopped automatic service alone is not treated as a security finding." if risky else "Automatic services were collected without unusual path indicators.","Review the service path and expected startup configuration." if risky else "No action required.",json.dumps(risky[:10]) if risky else f"Total={len(items)}")
    except (ValueError, TypeError, AttributeError) as exc: return finding("ATL-0022","Automatic Services","System Services","UNKNOWN","UNKNOWN","LOW","Automatic services could not be parsed.","Review automatic services manually.","Invalid response",str(exc))


def defender_extended():
    """Collect Defender protection properties without changing Defender state."""
    fields = "AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,CloudBlockLevel,IsTamperProtected,AntivirusSignatureLastUpdated,AntivirusSignatureAge"
    raw, error = powershell(f"Get-MpComputerStatus | Select {fields} | ConvertTo-Json -Compress")
    if not raw:
        return finding("ATL-0025", "Windows Defender Protection Details", "Endpoint Protection", "UNKNOWN", "UNKNOWN", "LOW", "Expanded Defender protection information could not be collected.", "Review Microsoft Defender protection settings manually.", "No data returned", error)
    try:
        data = json.loads(raw)
        antivirus_value = data.get("AntivirusEnabled")
        realtime_value = data.get("RealTimeProtectionEnabled")
        # A missing property can mean that Defender is not the active provider
        # or that this Windows release does not expose it. It must never be
        # presented as a confirmed disabled protection.
        if antivirus_value is None or realtime_value is None:
            return finding("ATL-0025", "Windows Defender Protection Details", "Endpoint Protection", "UNKNOWN", "UNKNOWN", "LOW", "Core Defender protection properties were not exposed by this Windows installation.", "Review the active antivirus product and Defender status manually.", json.dumps(data), "One or more Defender properties were unavailable", confidence="LOW")
        antivirus = antivirus_value is True
        realtime = realtime_value is True
        severity = "INFO" if antivirus and realtime else "HIGH"
        result = "PASS" if severity == "INFO" else "FAIL"
        status = "Enabled" if antivirus and realtime else "Protection requires review"
        details = {
            "Antivirus": "Enabled" if antivirus else "Disabled",
            "Real-time Protection": "Enabled" if realtime else "Disabled",
            "Behavior Monitoring": clean_value(data.get("BehaviorMonitorEnabled")),
            "Cloud-delivered Protection": clean_value(data.get("CloudBlockLevel")),
            "Tamper Protection": clean_value(data.get("IsTamperProtected")),
            "Last Signature Update": clean_value(data.get("AntivirusSignatureLastUpdated")),
            "Signature Age (days)": clean_value(data.get("AntivirusSignatureAge")),
        }
        return finding("ATL-0025", "Windows Defender Protection Details", "Endpoint Protection", status, result, severity, "Microsoft Defender protection settings were collected." if severity == "INFO" else "One or more core Microsoft Defender protections appear to be disabled.", "No action required." if severity == "INFO" else "Review Microsoft Defender and real-time protection.", json.dumps(details))
    except (ValueError, TypeError, AttributeError) as exc:
        return finding("ATL-0025", "Windows Defender Protection Details", "Endpoint Protection", "UNKNOWN", "UNKNOWN", "LOW", "Expanded Defender protection information could not be parsed.", "Review Microsoft Defender protection settings manually.", "Invalid response", str(exc))


def firewall_profiles():
    raw, error = powershell("Get-NetFirewallProfile | Select Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress")
    if not raw:
        return [finding("ATL-0026", "Windows Firewall Profiles", "Firewall", "UNKNOWN", "UNKNOWN", "LOW", "Firewall profiles could not be collected.", "Review Windows Firewall profiles manually.", "No data returned", error)], []
    try:
        profiles = json_records(raw)
        findings = []
        for index, profile in enumerate(profiles):
            name = clean_value(profile.get("Name"))
            enabled = profile.get("Enabled") is True
            severity = "INFO" if enabled else "HIGH"
            findings.append(finding(f"ATL-002{6 + index}", f"{name} Firewall Profile", "Firewall", "Enabled" if enabled else "Disabled", "PASS" if enabled else "WARNING", severity, f"The Windows Firewall {name} profile is {'enabled' if enabled else 'disabled'}.", "No action required." if enabled else f"Review whether the {name} firewall profile should be enabled.", json.dumps(profile)))
        return findings, profiles
    except (ValueError, TypeError, AttributeError) as exc:
        return [finding("ATL-0026", "Windows Firewall Profiles", "Firewall", "UNKNOWN", "UNKNOWN", "LOW", "Firewall profiles could not be parsed.", "Review Windows Firewall profiles manually.", "Invalid response", str(exc))], []


def firewall_rules_summary():
    raw, error = powershell("Get-NetFirewallRule | Select Enabled,DisplayName,Direction,Action | ConvertTo-Json -Compress", timeout=45)
    if not raw:
        return finding("ATL-0029", "Firewall Rules Summary", "Firewall", "UNKNOWN", "UNKNOWN", "LOW", "Firewall rules could not be summarized.", "Review Windows Firewall rules manually.", "No data returned", error), []
    try:
        rules = json_records(raw)
        enabled = sum(1 for rule in rules if rule.get("Enabled") is True)
        details = {"Total": len(rules), "Enabled": enabled, "Disabled": len(rules) - enabled}
        return finding("ATL-0029", "Firewall Rules Summary", "Firewall", f"{len(rules)} total; {enabled} enabled", "INFO", "INFO", "Firewall rules were summarized. Individual rules are not automatically classified as vulnerabilities.", "Review rules when a specific policy requires it.", json.dumps(details)), rules[:100]
    except (ValueError, TypeError, AttributeError) as exc:
        return finding("ATL-0029", "Firewall Rules Summary", "Firewall", "UNKNOWN", "UNKNOWN", "LOW", "Firewall rules could not be parsed.", "Review Windows Firewall rules manually.", "Invalid response", str(exc)), []


def powershell_security():
    raw, error = powershell("$v=$PSVersionTable.PSVersion.ToString(); $p=Get-ExecutionPolicy -List | Select Scope,ExecutionPolicy; [PSCustomObject]@{Version=$v;Policies=$p} | ConvertTo-Json -Depth 3 -Compress")
    if not raw:
        return finding("ATL-0030", "PowerShell Security Configuration", "PowerShell", "UNKNOWN", "UNKNOWN", "LOW", "PowerShell version or execution policy could not be collected.", "Review PowerShell execution policy manually.", "No data returned", error)
    try:
        data = json.loads(raw)
        policies = data.get("Policies", [])
        policies = policies if isinstance(policies, list) else [policies]
        policy_text = {clean_value(item.get("Scope")): clean_value(item.get("ExecutionPolicy")) for item in policies if isinstance(item, dict)}
        return finding("ATL-0030", "PowerShell Security Configuration", "PowerShell", f"PowerShell {clean_value(data.get('Version'))}", "INFO", "INFO", "PowerShell version and execution policy were collected for review.", "No action required.", json.dumps({"Version": data.get("Version"), "Execution Policies": policy_text}))
    except (ValueError, TypeError, AttributeError) as exc:
        return finding("ATL-0030", "PowerShell Security Configuration", "PowerShell", "UNKNOWN", "UNKNOWN", "LOW", "PowerShell configuration could not be parsed.", "Review PowerShell execution policy manually.", "Invalid response", str(exc))


def proxy_configuration():
    raw, error = powershell("$p=Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | Select ProxyEnable,ProxyServer,AutoConfigURL; $p | ConvertTo-Json -Compress")
    if not raw:
        return finding("ATL-0031", "System Proxy", "Network Configuration", "UNKNOWN", "UNKNOWN", "LOW", "System proxy configuration could not be collected.", "Review proxy settings manually.", "No data returned", error)
    try:
        data = json.loads(raw)
        configured = data.get("ProxyEnable") is True or bool(data.get("ProxyServer")) or bool(data.get("AutoConfigURL"))
        status = "Configured" if configured else "Not configured"
        return finding("ATL-0031", "System Proxy", "Network Configuration", status, "INFO", "INFO", "A system proxy is configured." if configured else "No system proxy was reported.", "Review proxy configuration if it is unexpected." if configured else "No action required.", json.dumps({"Proxy Server": data.get("ProxyServer"), "Auto Config URL": data.get("AutoConfigURL")}))
    except (ValueError, TypeError, AttributeError) as exc:
        return finding("ATL-0031", "System Proxy", "Network Configuration", "UNKNOWN", "UNKNOWN", "LOW", "System proxy configuration could not be parsed.", "Review proxy settings manually.", "Invalid response", str(exc))


def network_interfaces():
    query = "Get-NetIPConfiguration | Where-Object {$_.NetAdapter.Status -eq 'Up'} | ForEach-Object {[PSCustomObject]@{Adapter=$_.InterfaceAlias;Status=$_.NetAdapter.Status;IPv4=($_.IPv4Address.IPAddress -join ', ');IPv6=($_.IPv6Address.IPAddress -join ', ');MAC=$_.NetAdapter.MacAddress;DNS=($_.DNSServer.ServerAddresses -join ', ')}} | ConvertTo-Json -Compress"
    raw, error = powershell(query, timeout=35)
    if not raw:
        return finding("ATL-0032", "Network Interfaces and DNS", "Network Configuration", "UNKNOWN", "UNKNOWN", "LOW", "Active network interfaces or DNS servers could not be collected.", "Review network configuration manually.", "No data returned", error), [], error
    try:
        items = json_records(raw)
        return finding("ATL-0032", "Network Interfaces and DNS", "Network Configuration", f"{len(items)} active interface(s)", "INFO", "INFO", "Active network interfaces and their configured DNS servers were collected.", "No action required.", json.dumps(items[:20])), items, None
    except (ValueError, TypeError, AttributeError) as exc:
        return finding("ATL-0032", "Network Interfaces and DNS", "Network Configuration", "UNKNOWN", "UNKNOWN", "LOW", "Active network interfaces could not be parsed.", "Review network configuration manually.", "Invalid response", str(exc)), [], str(exc)


def account_lockout_policy():
    raw, error = command("net accounts")
    if not raw:
        return finding("ATL-0033", "Account Lockout Policy", "Authentication", "UNKNOWN", "UNKNOWN", "LOW", "Account lockout policy could not be collected.", "Review local account policy manually.", "No data returned", error)
    import re
    values = {}
    patterns = {"Lockout Threshold": r"Lockout threshold.*?:\\s*(.+)", "Lockout Duration": r"Lockout duration.*?:\\s*(.+)", "Reset Lockout Counter": r"Lockout observation window.*?:\\s*(.+)"}
    for label, pattern in patterns.items():
        match = re.search(pattern, raw, re.I)
        values[label] = match.group(1).strip() if match else "UNKNOWN"
    return finding("ATL-0033", "Account Lockout Policy", "Authentication", "Available for review", "INFO", "INFO", "Account lockout settings were collected when present in the local policy output.", "Review the local account lockout policy.", json.dumps(values))


def local_users_summary():
    raw, error = powershell("Get-LocalUser | Select Name,Enabled,PrincipalSource | ConvertTo-Json -Compress")
    if not raw:
        return finding("ATL-0034", "Local Users Summary", "Account Security", "UNKNOWN", "UNKNOWN", "LOW", "Local user accounts could not be collected.", "Review local user accounts manually.", "No data returned", error), [], error
    try:
        users = json_records(raw)
        enabled = sum(1 for user in users if user.get("Enabled") is True)
        return finding("ATL-0034", "Local Users Summary", "Account Security", f"{len(users)} total; {enabled} enabled", "INFO", "INFO", "Local user account metadata was collected.", "Review local accounts when necessary.", json.dumps({"Total": len(users), "Enabled": enabled, "Disabled": len(users) - enabled})), users, None
    except (ValueError, TypeError, AttributeError) as exc:
        return finding("ATL-0034", "Local Users Summary", "Account Security", "UNKNOWN", "UNKNOWN", "LOW", "Local user accounts could not be parsed.", "Review local user accounts manually.", "Invalid response", str(exc)), [], str(exc)


def rdp_extended():
    query = "$rdp=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server'; [PSCustomObject]@{Enabled=($rdp.fDenyTSConnections -eq 0);NLA=($rdp.UserAuthentication -eq 1)} | ConvertTo-Json -Compress"
    raw, error = powershell(query)
    if not raw:
        return finding("ATL-0035", "Remote Desktop Security Details", "Remote Access", "UNKNOWN", "UNKNOWN", "LOW", "Remote Desktop security details could not be collected.", "Review Remote Desktop configuration manually.", "No data returned", error)
    try:
        data = json.loads(raw)
        enabled = data.get("Enabled") is True
        nla = data.get("NLA") is True
        severity = "HIGH" if enabled and not nla else "MEDIUM" if enabled else "INFO"
        return finding("ATL-0035", "Remote Desktop Security Details", "Remote Access", "Enabled" if enabled else "Disabled", "WARNING" if enabled else "PASS", severity, "Remote Desktop is enabled with Network Level Authentication." if enabled and nla else "Remote Desktop is enabled without Network Level Authentication." if enabled else "Remote Desktop is disabled.", "Verify whether Remote Desktop is required and review Network Level Authentication." if enabled else "No action required.", json.dumps({"RDP Enabled": enabled, "Network Level Authentication": nla}))
    except (ValueError, TypeError, AttributeError) as exc:
        return finding("ATL-0035", "Remote Desktop Security Details", "Remote Access", "UNKNOWN", "UNKNOWN", "LOW", "Remote Desktop security details could not be parsed.", "Review Remote Desktop configuration manually.", "Invalid response", str(exc))


def smartscreen():
    query = "$e=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -ErrorAction SilentlyContinue; $p=Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -ErrorAction SilentlyContinue; $m=Get-MpPreference -ErrorAction SilentlyContinue; [PSCustomObject]@{ExplorerSmartScreen=$e.SmartScreenEnabled;PolicySmartScreen=$p.EnableSmartScreen;PUAProtection=$m.PUAProtection} | ConvertTo-Json -Compress"
    raw, error = powershell(query)
    if not raw:
        return finding("ATL-0036", "Microsoft Defender SmartScreen", "Application Protection", "UNKNOWN", "UNKNOWN", "LOW", "SmartScreen configuration could not be collected.", "Review SmartScreen and app protection settings manually.", "No data returned", error)
    try:
        data = json.loads(raw)
        values = [data.get("ExplorerSmartScreen"), data.get("PolicySmartScreen")]
        known = [str(value).lower() for value in values if value not in (None, "")]
        disabled = any(value in ("off", "0", "false", "disabled") for value in known)
        status = "Disabled" if disabled else "Enabled" if known else "UNKNOWN"
        severity = "MEDIUM" if disabled else "INFO" if known else "LOW"
        result = "WARNING" if disabled else "INFO" if known else "UNKNOWN"
        return finding("ATL-0036", "Microsoft Defender SmartScreen", "Application Protection", status, result, severity, "Microsoft Defender SmartScreen and app/file checking settings were collected." if known else "SmartScreen configuration was not exposed by this Windows installation.", "Review SmartScreen settings when application protection is required." if disabled else "No action required.", json.dumps({"SmartScreen": data.get("ExplorerSmartScreen"), "Policy": data.get("PolicySmartScreen"), "Potentially Unwanted App Protection": data.get("PUAProtection")}))
    except (ValueError, TypeError, AttributeError) as exc:
        return finding("ATL-0036", "Microsoft Defender SmartScreen", "Application Protection", "UNKNOWN", "UNKNOWN", "LOW", "SmartScreen configuration could not be parsed.", "Review SmartScreen settings manually.", "Invalid response", str(exc))


def device_guard_state():
    query = "$data=try {$d=Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction Stop; [PSCustomObject]@{VBS=$d.VirtualizationBasedSecurityStatus;Running=($d.SecurityServicesRunning -join ',');Configured=($d.SecurityServicesConfigured -join ',')}} catch {[PSCustomObject]@{VBS=$null;Running=$null;Configured=$null}}; $data | ConvertTo-Json -Compress"
    raw, error = powershell(query)
    if not raw:
        return None, error
    try:
        return json.loads(raw), None
    except (ValueError, TypeError, AttributeError) as exc:
        return None, str(exc)


def device_guard_available(device_guard):
    return bool(device_guard) and any(device_guard.get(key) not in (None, "") for key in ("VBS", "Running", "Configured"))


def memory_integrity():
    raw, error = powershell("$v=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' -Name Enabled -ErrorAction SilentlyContinue).Enabled; [PSCustomObject]@{Enabled=$v} | ConvertTo-Json -Compress")
    if not raw:
        return finding("ATL-0037", "Memory Integrity", "System Hardening", "UNKNOWN", "UNKNOWN", "LOW", "Memory Integrity configuration could not be collected.", "Review whether Memory Integrity is supported and appropriate for this system.", "No data returned", error)
    try:
        value = json.loads(raw).get("Enabled")
        if value is None:
            return finding("ATL-0037", "Memory Integrity", "System Hardening", "NOT AVAILABLE", "INFO", "INFO", "Memory Integrity is not exposed as an available feature on this system.", "No action required.", "HypervisorEnforcedCodeIntegrity value not present")
        enabled = str(value).lower() in ("1", "true")
        return finding("ATL-0037", "Memory Integrity", "System Hardening", "Enabled" if enabled else "Disabled", "PASS" if enabled else "WARNING", "INFO" if enabled else "MEDIUM", "Windows Memory Integrity is enabled." if enabled else "Windows Memory Integrity is not enabled.", "No action required." if enabled else "Review whether this protection is supported and appropriate for this system.", f"MemoryIntegrity={value}")
    except (ValueError, TypeError, AttributeError) as exc:
        return finding("ATL-0037", "Memory Integrity", "System Hardening", "UNKNOWN", "UNKNOWN", "LOW", "Memory Integrity configuration could not be parsed.", "Review Memory Integrity manually.", "Invalid response", str(exc))


def virtualization_security(device_guard):
    if not device_guard_available(device_guard):
        return finding("ATL-0038", "Virtualization-Based Security", "Virtualization Security", "NOT AVAILABLE", "INFO", "INFO", "Virtualization-Based Security information is not available on this system.", "No action required.", "Win32_DeviceGuard not available")
    value = clean_value(device_guard.get("VBS"), "")
    mapping = {"0": "Disabled", "1": "Configured but not running", "2": "Running"}
    status = mapping.get(value, "NOT AVAILABLE" if not value else "UNKNOWN")
    severity = "INFO" if status in ("Running", "NOT AVAILABLE") else "LOW" if status == "Configured but not running" else "INFO"
    result = "PASS" if status == "Running" else "INFO" if status in ("Disabled", "NOT AVAILABLE") else "WARNING" if status == "Configured but not running" else "UNKNOWN"
    return finding("ATL-0038", "Virtualization-Based Security", "Virtualization Security", status, result, severity, "Virtualization-Based Security state was collected from Windows Device Guard data.", "Review virtualization security settings if this feature is required.", f"VBSStatus={value}; SecurityServicesRunning={device_guard.get('Running')}")


def credential_guard(device_guard):
    if not device_guard_available(device_guard):
        return finding("ATL-0039", "Credential Guard", "Credential Protection", "NOT AVAILABLE", "INFO", "INFO", "Credential Guard is not available through Windows Device Guard data on this system.", "No action required.", "Win32_DeviceGuard not available")
    running = [part.strip() for part in clean_value(device_guard.get("Running"), "").split(",") if part.strip()]
    configured = [part.strip() for part in clean_value(device_guard.get("Configured"), "").split(",") if part.strip()]
    if "1" in running:
        status, result, severity = "Running", "PASS", "INFO"
    elif "1" in configured:
        status, result, severity = "Configured but not running", "WARNING", "MEDIUM"
    else:
        status, result, severity = "Disabled", "INFO", "INFO"
    return finding("ATL-0039", "Credential Guard", "Credential Protection", status, result, severity, "Credential Guard state was derived from Windows Device Guard security-service data.", "Review Credential Guard support and configuration when appropriate." if status != "Running" else "No action required.", f"SecurityServicesRunning={device_guard.get('Running')}; SecurityServicesConfigured={device_guard.get('Configured')}")


def lsass_protection():
    raw, error = powershell("$v=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -ErrorAction SilentlyContinue; [PSCustomObject]@{RunAsPPL=$v.RunAsPPL;RunAsPPLBoot=$v.RunAsPPLBoot} | ConvertTo-Json -Compress")
    if not raw:
        return finding("ATL-0040", "LSASS Protection", "Credential Protection", "UNKNOWN", "UNKNOWN", "LOW", "LSASS protection configuration could not be collected.", "Review LSASS protection manually.", "No data returned", error)
    try:
        data = json.loads(raw); value = data.get("RunAsPPL")
        if value is None:
            return finding("ATL-0040", "LSASS Protection", "Credential Protection", "Not configured", "INFO", "INFO", "LSASS protection is not explicitly configured in the available registry value.", "Review LSASS protection support and policy when appropriate.", json.dumps(data))
        enabled = str(value).lower() in ("1", "2", "true")
        return finding("ATL-0040", "LSASS Protection", "Credential Protection", "Enabled" if enabled else "Disabled", "PASS" if enabled else "WARNING", "INFO" if enabled else "MEDIUM", "LSASS additional protection is enabled." if enabled else "LSASS additional protection is disabled.", "Review whether LSASS protection is appropriate for this system." if not enabled else "No action required.", json.dumps(data))
    except (ValueError, TypeError, AttributeError) as exc:
        return finding("ATL-0040", "LSASS Protection", "Credential Protection", "UNKNOWN", "UNKNOWN", "LOW", "LSASS protection configuration could not be parsed.", "Review LSASS protection manually.", "Invalid response", str(exc))


def defender_cloud_protection():
    raw, error = powershell("Get-MpPreference | Select MAPSReporting,SubmitSamplesConsent,CloudBlockLevel | ConvertTo-Json -Compress")
    if not raw:
        return finding("ATL-0041", "Cloud-delivered Protection", "Defender Hardening", "UNKNOWN", "UNKNOWN", "LOW", "Defender cloud-delivered protection could not be collected.", "Review Defender cloud protection manually.", "No data returned", error)
    try:
        data = json.loads(raw); maps = data.get("MAPSReporting")
        if maps is None:
            return finding("ATL-0041", "Cloud-delivered Protection", "Defender Hardening", "UNKNOWN", "UNKNOWN", "LOW", "Defender cloud-delivered protection was not exposed by this Windows installation.", "Review Defender cloud protection manually.", json.dumps(data))
        enabled = str(maps).lower() not in ("0", "false", "disabled")
        return finding("ATL-0041", "Cloud-delivered Protection", "Defender Hardening", "Enabled" if enabled else "Disabled", "PASS" if enabled else "WARNING", "INFO" if enabled else "LOW", "Microsoft Defender cloud-delivered protection appears to be enabled." if enabled else "Microsoft Defender cloud-delivered protection appears to be disabled.", "No action required." if enabled else "Review whether Defender cloud-delivered protection should be enabled.", json.dumps(data))
    except (ValueError, TypeError, AttributeError) as exc:
        return finding("ATL-0041", "Cloud-delivered Protection", "Defender Hardening", "UNKNOWN", "UNKNOWN", "LOW", "Defender cloud protection could not be parsed.", "Review Defender cloud protection manually.", "Invalid response", str(exc))


def defender_tamper_protection():
    raw, error = powershell("Get-MpComputerStatus | Select IsTamperProtected | ConvertTo-Json -Compress")
    if not raw:
        return finding("ATL-0042", "Tamper Protection", "Defender Hardening", "UNKNOWN", "UNKNOWN", "LOW", "Defender Tamper Protection could not be collected.", "Review Tamper Protection manually.", "No data returned", error)
    try:
        value = json.loads(raw).get("IsTamperProtected")
        if value is None:
            return finding("ATL-0042", "Tamper Protection", "Defender Hardening", "UNKNOWN", "UNKNOWN", "LOW", "The Windows Defender API did not expose a Tamper Protection state.", "Review Tamper Protection manually.", "IsTamperProtected not present")
        enabled = value is True or str(value).lower() == "true"
        return finding("ATL-0042", "Tamper Protection", "Defender Hardening", "Enabled" if enabled else "Disabled", "PASS" if enabled else "WARNING", "INFO" if enabled else "MEDIUM", "Microsoft Defender Tamper Protection is enabled." if enabled else "Microsoft Defender Tamper Protection appears to be disabled.", "No action required." if enabled else "Review Tamper Protection configuration.", f"IsTamperProtected={value}")
    except (ValueError, TypeError, AttributeError) as exc:
        return finding("ATL-0042", "Tamper Protection", "Defender Hardening", "UNKNOWN", "UNKNOWN", "LOW", "Tamper Protection could not be parsed.", "Review Tamper Protection manually.", "Invalid response", str(exc))


def defender_signature_age():
    # Internal Atlhas1x rule: signatures older than seven days need review.
    # This threshold is a project heuristic, not a Microsoft requirement.
    raw, error = powershell("Get-MpComputerStatus | Select AntivirusSignatureLastUpdated,AntivirusSignatureAge | ConvertTo-Json -Compress")
    if not raw:
        return finding("ATL-0043", "Defender Signatures", "Defender Hardening", "UNKNOWN", "UNKNOWN", "LOW", "Defender signature age could not be collected.", "Review Defender signature status manually.", "No data returned", error)
    try:
        data = json.loads(raw); age = data.get("AntivirusSignatureAge")
        if age is None:
            return finding("ATL-0043", "Defender Signatures", "Defender Hardening", "UNKNOWN", "UNKNOWN", "LOW", "Defender signature age was not provided by Windows.", "Review Defender signature status manually.", json.dumps(data))
        age_days = float(age); outdated = age_days > 7
        return finding("ATL-0043", "Defender Signatures", "Defender Hardening", "Outdated" if outdated else "Current", "WARNING" if outdated else "PASS", "MEDIUM" if outdated else "INFO", "Defender signatures are older than the internal seven-day review threshold." if outdated else "Defender signatures are within the internal seven-day review threshold.", "Update and review Microsoft Defender signatures." if outdated else "No action required.", json.dumps({"Last Update": data.get("AntivirusSignatureLastUpdated"), "Age Days": age_days, "Internal Review Threshold Days": 7}))
    except (ValueError, TypeError, AttributeError) as exc:
        return finding("ATL-0043", "Defender Signatures", "Defender Hardening", "UNKNOWN", "UNKNOWN", "LOW", "Defender signature age could not be parsed.", "Review Defender signature status manually.", "Invalid response", str(exc))


def defender_exclusions():
    raw, error = powershell("Get-MpPreference | Select ExclusionPath,ExclusionProcess,ExclusionExtension | ConvertTo-Json -Compress")
    if not raw:
        return finding("ATL-0044", "Microsoft Defender Exclusions", "Defender Hardening", "UNKNOWN", "UNKNOWN", "LOW", "Defender exclusions could not be collected.", "Review Defender exclusions manually.", "No data returned", error)
    try:
        data = json.loads(raw)
        paths = data.get("ExclusionPath") or []; processes = data.get("ExclusionProcess") or []; extensions = data.get("ExclusionExtension") or []
        paths = paths if isinstance(paths, list) else [paths]; processes = processes if isinstance(processes, list) else [processes]; extensions = extensions if isinstance(extensions, list) else [extensions]
        broad = [str(path) for path in paths if str(path).strip().rstrip("\\/").endswith(":")]
        status = "Needs review" if broad else f"{len(paths)} path; {len(processes)} process; {len(extensions)} extension"
        return finding("ATL-0044", "Microsoft Defender Exclusions", "Defender Hardening", status, "WARNING" if broad else "INFO", "MEDIUM" if broad else "INFO", "A broad Defender path exclusion was found." if broad else "Defender exclusion counts were collected; exclusions are not automatically considered unsafe.", "Review broad path exclusions." if broad else "Review exclusions only when unexpected.", json.dumps({"Path Exclusions": paths, "Process Exclusions": processes, "Extension Exclusions": extensions}))
    except (ValueError, TypeError, AttributeError) as exc:
        return finding("ATL-0044", "Microsoft Defender Exclusions", "Defender Hardening", "UNKNOWN", "UNKNOWN", "LOW", "Defender exclusions could not be parsed.", "Review Defender exclusions manually.", "Invalid response", str(exc))


def attack_surface_reduction():
    raw, error = powershell("Get-MpPreference | Select AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions | ConvertTo-Json -Compress")
    if not raw:
        return finding("ATL-0045", "Attack Surface Reduction", "Defender Hardening", "UNKNOWN", "UNKNOWN", "LOW", "Attack Surface Reduction configuration could not be collected.", "Review ASR configuration manually.", "No data returned", error)
    try:
        data = json.loads(raw); ids = data.get("AttackSurfaceReductionRules_Ids") or []; actions = data.get("AttackSurfaceReductionRules_Actions") or []
        ids = ids if isinstance(ids, list) else [ids]; actions = actions if isinstance(actions, list) else [actions]
        action_names = {"1": "Enabled", "2": "Audit", "0": "Disabled", "6": "Warn"}
        details = [{"Rule": str(rule), "State": action_names.get(str(actions[index]), str(actions[index])) if index < len(actions) else "UNKNOWN"} for index, rule in enumerate(ids)]
        counts = {"Enabled": sum(item["State"] == "Enabled" for item in details), "Audit": sum(item["State"] == "Audit" for item in details), "Disabled": sum(item["State"] == "Disabled" for item in details)}
        return finding("ATL-0045", "Attack Surface Reduction", "Defender Hardening", f"{len(details)} rules configured", "INFO", "INFO", "Attack Surface Reduction rules were summarized; an absent rule set is not automatically a vulnerability.", "Review ASR configuration when it is part of the local hardening policy.", json.dumps({"Summary": counts, "Rules": details}))
    except (ValueError, TypeError, AttributeError) as exc:
        return finding("ATL-0045", "Attack Surface Reduction", "Defender Hardening", "UNKNOWN", "UNKNOWN", "LOW", "Attack Surface Reduction configuration could not be parsed.", "Review ASR configuration manually.", "Invalid response", str(exc))


def controlled_folder_access():
    raw, error = powershell("Get-MpPreference | Select EnableControlledFolderAccess | ConvertTo-Json -Compress")
    if not raw:
        return finding("ATL-0046", "Controlled Folder Access", "Application Protection", "UNKNOWN", "UNKNOWN", "LOW", "Controlled Folder Access state could not be collected.", "Review Controlled Folder Access manually.", "No data returned", error)
    try:
        value = json.loads(raw).get("EnableControlledFolderAccess")
        states = {"0": "Disabled", "1": "Enabled", "2": "Audit Mode"}
        status = states.get(str(value), "UNKNOWN" if value is None else str(value))
        return finding("ATL-0046", "Controlled Folder Access", "Application Protection", status, "PASS" if status == "Enabled" else "INFO" if status in ("Disabled", "Audit Mode") else "UNKNOWN", "INFO" if status in ("Enabled", "Disabled", "Audit Mode") else "LOW", "Controlled Folder Access is reported as " + status.lower() + "." if status != "UNKNOWN" else "Controlled Folder Access state was not exposed by Windows.", "Review Controlled Folder Access support and policy when appropriate." if status != "Enabled" else "No action required.", f"EnableControlledFolderAccess={value}")
    except (ValueError, TypeError, AttributeError) as exc:
        return finding("ATL-0046", "Controlled Folder Access", "Application Protection", "UNKNOWN", "UNKNOWN", "LOW", "Controlled Folder Access could not be parsed.", "Review Controlled Folder Access manually.", "Invalid response", str(exc))


def security_center_overview():
    query = "$s=Get-Service wscsvc -ErrorAction SilentlyContinue; try {$a=(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop | Measure-Object).Count} catch {$a=$null}; try {$f=(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction Stop | Measure-Object).Count} catch {$f=$null}; [PSCustomObject]@{Service=$s.Status;AntivirusProducts=$a;FirewallProducts=$f} | ConvertTo-Json -Compress"
    raw, error = powershell(query)
    if not raw:
        return finding("ATL-0047", "Windows Security Center Overview", "System Services", "UNKNOWN", "UNKNOWN", "LOW", "Windows Security Center overview could not be collected.", "Review Windows Security Center manually.", "No data returned", error)
    try:
        data = json.loads(raw); running = data.get("Service") == "Running"
        return finding("ATL-0047", "Windows Security Center Overview", "System Services", "Running" if running else clean_value(data.get("Service")), "PASS" if running else "WARNING", "INFO" if running else "LOW", "Windows Security Center service and available security product counts were collected.", "Review Windows Security Center service status." if not running else "No action required.", json.dumps(data))
    except (ValueError, TypeError, AttributeError) as exc:
        return finding("ATL-0047", "Windows Security Center Overview", "System Services", "UNKNOWN", "UNKNOWN", "LOW", "Windows Security Center overview could not be parsed.", "Review Windows Security Center manually.", "Invalid response", str(exc))


def json_records(raw):
    """Return only JSON objects, so an unusual command response stays isolated."""
    data = json.loads(raw)
    records = data if isinstance(data, list) else [data]
    if not all(isinstance(record, dict) for record in records):
        raise ValueError("Expected JSON objects")
    return records


def clean_value(value, unknown="UNKNOWN"):
    if value is None or value == "":
        return unknown
    return str(value)


def process_value(value):
    """Use an honest label when Windows withholds protected-process metadata."""
    text = clean_value(value, "Access restricted")
    return "Access restricted" if text.upper() in ("UNKNOWN", "N/A", "") else text


def value_available(value):
    return str(value).lower() not in ("unknown", "access restricted", "not collected", "n/a", "")


def tasklist_processes():
    """Read process owners from the native command, including on older Windows."""
    raw, error = command("tasklist /FO CSV /NH /V", timeout=35)
    if not raw:
        return [], error
    try:
        items = []
        for row in csv.reader(raw.splitlines()):
            if len(row) >= 2 and row[1].strip().isdigit():
                items.append({"PID": row[1].strip(), "Process": process_value(row[0]), "Path": "Access restricted", "User": process_value(row[6] if len(row) > 6 else None)})
        return items, None if items else "No process rows returned"
    except (csv.Error, IndexError) as exc:
        return [], str(exc)


def running_processes():
    """Collect process metadata only; this does not inspect process memory or files."""
    # -IncludeUserName requires elevation on many Windows installations. The
    # base inventory is useful without it, so do not force the whole check into
    # a fallback just to obtain usernames that may be unavailable.
    query = "Get-Process | Select @{N='PID';E={$_.Id}},@{N='Process';E={$_.ProcessName}},@{N='Path';E={$_.Path}},@{N='User';E={'UNKNOWN'}} | ConvertTo-Json -Compress"
    raw, error = powershell(query, timeout=35)
    task_items, task_error = tasklist_processes()
    task_by_pid = {item["PID"]: item for item in task_items}
    if raw:
        try:
            items = [{"PID": clean_value(row.get("PID")), "Process": process_value(row.get("Process")), "Path": process_value(row.get("Path")), "User": task_by_pid.get(clean_value(row.get("PID")), {}).get("User", "Access restricted")} for row in json_records(raw)]
            # WMI supplies another read-only source for protected service paths
            # and, in an elevated session, their actual process owners.
            wmi_raw, _ = powershell("Get-WmiObject Win32_Process | ForEach-Object {$owner=$null; try {$result=$_.GetOwner(); if($result.ReturnValue -eq 0){$owner=$result.Domain+'\\'+$result.User}} catch {}; New-Object PSObject -Property @{PID=$_.ProcessId;Path=$_.ExecutablePath;User=$owner}} | ConvertTo-Json -Compress", timeout=45)
            if wmi_raw:
                try:
                    wmi_items = {clean_value(row.get("PID")): row for row in json_records(wmi_raw)}
                    for item in items:
                        wmi_item = wmi_items.get(item["PID"], {})
                        wmi_path = process_value(wmi_item.get("Path"))
                        wmi_user = process_value(wmi_item.get("User"))
                        if not value_available(item["Path"]) and value_available(wmi_path):
                            item["Path"] = wmi_path
                        if not value_available(item["User"]) and value_available(wmi_user):
                            item["User"] = wmi_user
                except (ValueError, TypeError, AttributeError):
                    pass
            return items, None
        except (ValueError, TypeError, AttributeError) as exc:
            error = str(exc)

    # tasklist is available on older Windows versions and still gives process
    # names and owners even when PowerShell process metadata is unavailable.
    if task_items:
        return task_items, None
    return [], task_error or error or "Process inventory was not available"


def process_location_review(processes, error=None):
    if error and not processes:
        return finding("ATL-0023", "Processes Requiring Review", "Process Activity", "UNKNOWN", "UNKNOWN", "LOW", "Running process metadata could not be collected.", "Review running processes manually.", "No data returned", error)
    risky = [item for item in processes if value_available(item["Path"]) and unusual_path(item["Path"])]
    return finding("ATL-0023", "Processes Requiring Review", "Process Activity", f"{len(risky)} require review", "WARNING" if risky else "INFO", "MEDIUM" if risky else "INFO", "One or more running processes use a temporary, Downloads, or Desktop location." if risky else "Running processes were collected without basic unusual-path indicators.", "Review whether the listed processes are expected." if risky else "No action required.", json.dumps(risky[:15]) if risky else f"Total processes={len(processes)}")


def endpoint(value):
    text = clean_value(value, "")
    if not text:
        return "UNKNOWN", "UNKNOWN"
    address, separator, port = text.rpartition(":")
    if not separator:
        return text, "UNKNOWN"
    return address.strip("[]"), port


def tcp_state(value):
    """Get-NetTCPConnection serialises its enum as a number on some systems."""
    states = {"2": "Listen", "5": "Established"}
    text = clean_value(value)
    return states.get(text, text)


def port_exposure(address):
    text = clean_value(address).lower()
    if text in ("127.0.0.1", "::1"):
        return "Local only"
    if text == "0.0.0.0":
        return "All IPv4 interfaces"
    if text in ("::", "*"):
        return "All IPv6 interfaces"
    return "LAN-bound"


def network_inventory(processes):
    """Collect local TCP metadata without connecting to, scanning, or reading traffic."""
    names = {item["PID"]: item["Process"] for item in processes}
    query = "Get-NetTCPConnection -State Listen,Established | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Json -Compress"
    raw, error = powershell(query, timeout=35)
    records = []
    if raw:
        try:
            for row in json_records(raw):
                pid = clean_value(row.get("OwningProcess"))
                address = clean_value(row.get("LocalAddress"))
                records.append({"Protocol": "TCP", "Local Address": address, "Local Port": clean_value(row.get("LocalPort")), "Remote Address": clean_value(row.get("RemoteAddress")), "Remote Port": clean_value(row.get("RemotePort")), "State": tcp_state(row.get("State")), "PID": pid, "Process": names.get(pid, "UNKNOWN"), "Exposure": port_exposure(address)})
        except (ValueError, TypeError, AttributeError) as exc:
            error = str(exc)

    if not records:
        fallback, fallback_error = command("netstat -ano -p tcp", timeout=35)
        if fallback:
            for line in fallback.splitlines():
                parts = line.split()
                if len(parts) < 5 or parts[0].upper() != "TCP" or not parts[-1].isdigit():
                    continue
                local_address, local_port = endpoint(parts[1])
                remote_address, remote_port = endpoint(parts[2])
                state, pid = parts[3], parts[4]
                records.append({"Protocol": "TCP", "Local Address": local_address, "Local Port": local_port, "Remote Address": remote_address, "Remote Port": remote_port, "State": state, "PID": pid, "Process": names.get(pid, "UNKNOWN"), "Exposure": port_exposure(local_address)})
        if not records and fallback_error:
            error = fallback_error

    listening_words = ("listen", "escut")
    listening = [row for row in records if row["State"].lower().startswith(listening_words)]
    active = [row for row in records if not row["State"].lower().startswith(listening_words)]
    return listening, active, error


def rdp_listener(listening, error=None):
    if error and not listening:
        return finding("ATL-0024", "Remote Desktop Port", "Listening Ports", "UNKNOWN", "UNKNOWN", "LOW", "Listening TCP ports could not be collected.", "Review the Remote Desktop listener manually.", "No data returned", error)
    rdp_ports = [item for item in listening if item["Local Port"] == "3389"]
    if rdp_ports:
        return finding("ATL-0024", "Remote Desktop Port", "Listening Ports", "Listening on port 3389", "INFO", "INFO", "A service is listening on the default Remote Desktop port. The Remote Desktop configuration finding provides the security classification.", "Verify whether Remote Desktop access is required.", json.dumps(rdp_ports[:5]))
    return finding("ATL-0024", "Remote Desktop Port", "Listening Ports", "Not listening on port 3389", "PASS", "INFO", "No TCP listener was found on the default Remote Desktop port.", "No action required.", "Port 3389 not present in collected listeners")


def threat_persistence_inventory():
    """Collect only persistence paths already in scope for threat correlation."""
    query = "$startup=Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | Select Name,Command; $startupFolders=@((Join-Path $env:APPDATA 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),(Join-Path $env:ProgramData 'Microsoft\\Windows\\Start Menu\\Programs\\StartUp')) | Where-Object {Test-Path $_}; $startupFiles=$startupFolders | ForEach-Object {Get-ChildItem -LiteralPath $_ -File -ErrorAction SilentlyContinue} | Select @{N='Name';E={$_.Name}},@{N='Path';E={$_.FullName}}; $tasks=Get-ScheduledTask -ErrorAction SilentlyContinue | Select TaskName,TaskPath,@{N='Action';E={$_.Actions.Execute}}; $services=Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {$_.StartMode -eq 'Auto'} | Select Name,PathName; [PSCustomObject]@{Startup=$startup;StartupFiles=$startupFiles;Tasks=$tasks;Services=$services} | ConvertTo-Json -Depth 4 -Compress"
    raw, error = powershell(query, timeout=45)
    empty = {"STARTUP": [], "SCHEDULED_TASK": [], "SERVICE": []}
    if not raw:
        return empty, error
    try:
        data = json.loads(raw)
        startup = json_records(json.dumps(data.get("Startup") or []))
        startup.extend(json_records(json.dumps(data.get("StartupFiles") or [])))
        return {
            "STARTUP": startup,
            "SCHEDULED_TASK": json_records(json.dumps(data.get("Tasks") or [])),
            "SERVICE": json_records(json.dumps(data.get("Services") or [])),
        }, None
    except (ValueError, TypeError, AttributeError) as exc:
        return empty, str(exc)


def defender_exclusion_paths_for_threats():
    raw, error = powershell("Get-MpPreference | Select -Expand ExclusionPath | ConvertTo-Json -Compress")
    if not raw:
        return [], error
    try:
        value = json.loads(raw)
        return value if isinstance(value, list) else [value], None
    except (ValueError, TypeError, AttributeError) as exc:
        return [], str(exc)


def file_signature(path):
    """Read Authenticode metadata without opening or executing the file."""
    escaped = str(path).replace("'", "''")
    raw, _ = powershell("$s=Get-AuthenticodeSignature -LiteralPath '" + escaped + "' -ErrorAction SilentlyContinue; [PSCustomObject]@{Status=$s.Status;Publisher=$s.SignerCertificate.Subject} | ConvertTo-Json -Compress", timeout=20)
    if not raw:
        return {"status": "UNKNOWN"}
    try:
        data = json.loads(raw)
        status = clean_value(data.get("Status"), "UNKNOWN")
        publisher = clean_value(data.get("Publisher"), "UNKNOWN")
        if status.lower() == "valid":
            return {"status": "VALID_MICROSOFT" if "microsoft" in publisher.lower() else "VALID", "publisher": publisher}
        if status.lower() in ("notsigned", "unknownerror"):
            return {"status": "UNSIGNED", "publisher": publisher}
        return {"status": status.upper(), "publisher": publisher}
    except (ValueError, TypeError, AttributeError):
        return {"status": "UNKNOWN"}


def hosts_file_check():
    if os.name != "nt":
        return finding("ATL-0048", "Hosts File", "Network Security", "NOT AVAILABLE", "INFO", "INFO", "Hosts file review is available only on Windows.", "No action required.", "This check requires Windows")
    path = Path(os.environ.get("SystemRoot", r"C:\\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        entries = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
        non_default = [line for line in entries if not line.split()[0] in ("127.0.0.1", "::1") or len(line.split()) > 2]
        if non_default:
            return finding("ATL-0048", "Hosts File", "Network Security", f"{len(non_default)} custom entr{'y' if len(non_default) == 1 else 'ies'}", "WARNING", "LOW", "The hosts file contains non-default entries that may require review.", "Review recent hosts entries if they were not expected.", json.dumps({"Path": str(path), "Entries": non_default[:50], "Modified": dt.datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")}))
        return finding("ATL-0048", "Hosts File", "Network Security", "No custom entries", "PASS", "INFO", "No non-default hosts entries were found.", "No action required.", f"Path={path}")
    except OSError as exc:
        return finding("ATL-0048", "Hosts File", "Network Security", "UNKNOWN", "UNKNOWN", "LOW", "Hosts file could not be read.", "Review the hosts file manually.", f"Path={path}", str(exc))


def threat_findings(records, yara_summary):
    findings = []
    for index, record in enumerate(records, 1):
        if record["classification"] == "NORMAL":
            continue
        fid = f"ATL-THREAT-{index:04d}"
        metadata = record["metadata"]
        evidence = {
            "Path": record["path"], "SHA-256": metadata.get("sha256", "UNKNOWN"),
            "Created": metadata.get("created", "UNKNOWN"), "Modified": metadata.get("modified", "UNKNOWN"),
            "Signature": metadata.get("signature", {}), "Relations": metadata.get("related_to", []),
            "Listeners": record.get("listeners", []), "Indicators": record["indicators"],
            "Positive Context": record.get("positive_indicators", []), "Reasoning": record.get("reasoning", []),
            "Possible False Positive": record.get("possible_false_positive", False),
            "Suspicion Score": record["suspicion_score"], "YARA": record["yara"],
        }
        result = "WARNING" if record["classification"] in ("NEEDS REVIEW", "SUSPICIOUS", "HIGH PRIORITY REVIEW") else "INFO"
        name = "Potential Backdoor Indicator" if record.get("potential_backdoor") else "Suspicious Activity Item"
        description = ("A listener and at least two independent indicators were correlated for this file. This is not confirmation of a backdoor."
                       if record.get("potential_backdoor") else
                       "Local indicators were correlated for this file. This is not a confirmation of malware.")
        confidence = "HIGH" if record["suspicion_score"] >= 70 and not record.get("possible_false_positive") else "MEDIUM" if record["suspicion_score"] >= 30 else "LOW"
        findings.append(finding(fid, name, "Potential Backdoor Indicators" if record.get("potential_backdoor") else "Threat Detection", record["classification"], result, record["severity"], description, "Review the file, its persistence relationship, signature context and related network activity before taking any action.", json.dumps(evidence), confidence=confidence, score_key="THREAT:" + record["path"].lower()))
    if yara_summary["engine"] == "NOT AVAILABLE":
        findings.append(finding("ATL-YARA-ENGINE", "YARA Engine", "Threat Detection", "NOT AVAILABLE", "INFO", "INFO", "YARA support is unavailable. Threat analysis continued with local heuristics.", "Install yara-python and add local rules to enable optional YARA matching.", "yara-python not installed"))
    return findings


def inventory(title, columns, items, review_count=0, error=None):
    return {"title": title, "columns": columns, "items": items, "review_count": review_count, "error": error}


def attach_duration(value, duration):
    if isinstance(value, dict) and "id" in value:
        value["duration_seconds"] = round(duration, 3)
    elif isinstance(value, (list, tuple)):
        for item in value:
            attach_duration(item, duration)


def run_module(label, callback, diagnostics):
    global SCAN_COMPLETED_MODULES
    started = time.perf_counter()
    try:
        value = callback()
    except Exception as exc:  # A module failure must never terminate the scan.
        error = f"{type(exc).__name__}: {exc}"
        live_detail("RESPONSE", f"{label} could not be completed: {error}")
        # A few collection modules return an inventory together with a finding.
        # Preserve their documented shape so the rest of the scan can continue.
        if label == "Firewall Profiles":
            value = ([module_error_finding(label, error)], [])
        elif label == "Firewall Rules":
            value = (module_error_finding(label, error), [])
        elif label in {"Network Interfaces", "Local Users"}:
            value = (module_error_finding(label, error), [], error)
        elif label == "Device Guard":
            value = (None, error)
        elif label == "Running Processes":
            value = ([], error)
        elif label == "Network Activity":
            value = ([], [], error)
        else:
            value = module_error_finding(label, error)
    duration = time.perf_counter() - started
    attach_duration(value, duration)
    diagnostics.append({"Module": label, "Duration": f"{duration:.3f}s"})
    SCAN_COMPLETED_MODULES += 1
    live_detail("PROGRESS", f"{SCAN_COMPLETED_MODULES}/{SCAN_TOTAL_MODULES}|{label}")
    return value


def module_error_finding(label, error):
    """Return a clean UNKNOWN result if an unexpected module error occurs."""
    safe_id = "ATL-ERROR-" + "".join(character for character in label.upper() if character.isalnum())[:16]
    return finding(safe_id, label, "Scan Diagnostics", "UNKNOWN", "UNKNOWN", "LOW", f"{label} could not be completed.", "Review this setting manually or run the scan again.", "No result returned", error, confidence="LOW", score_key=safe_id)


def system_info():
    fallback = {"hostname": socket.gethostname(), "operating_system": platform.platform(), "edition": "UNKNOWN", "version": "UNKNOWN", "os_build": platform.version(), "architecture": platform.machine(), "user": getpass.getuser(), "administrator_privileges": "Not evaluated", "python": platform.python_version()}
    raw, _ = powershell("$os=Get-CimInstance Win32_OperatingSystem; $identity=[Security.Principal.WindowsIdentity]::GetCurrent(); $principal=New-Object Security.Principal.WindowsPrincipal($identity); [PSCustomObject]@{Caption=$os.Caption;Version=$os.Version;BuildNumber=$os.BuildNumber;OSArchitecture=$os.OSArchitecture;Administrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)} | ConvertTo-Json -Compress")
    if not raw:
        return fallback
    try:
        data = json.loads(raw)
        fallback.update({"operating_system": clean_value(data.get("Caption"), fallback["operating_system"]), "edition": clean_value(data.get("Caption"), "UNKNOWN"), "version": clean_value(data.get("Version"), "UNKNOWN"), "os_build": clean_value(data.get("BuildNumber"), fallback["os_build"]), "architecture": clean_value(data.get("OSArchitecture"), fallback["architecture"]), "administrator_privileges": "Yes" if data.get("Administrator") is True else "No" if data.get("Administrator") is False else "Not evaluated"})
    except (ValueError, TypeError, AttributeError):
        pass
    return fallback


def overall(findings):
    # Unknown, unavailable and informational checks are coverage signals, not
    # security findings. They must not raise the machine risk level.
    present = {f["severity"] for f in findings if f["result"] in ("WARNING", "FAIL")}
    if not present:
        return "INFO"
    return next(level for level in reversed(SEVERITIES) if level in present)


def finalize_findings(findings):
    """Normalize confidence and remove exact duplicate score contributions."""
    unique, seen = [], set()
    for item in findings:
        if item["confidence"] == "LOW" and item["severity"] in ("HIGH", "CRITICAL"):
            item["severity"] = "MEDIUM"
            item["score_impact"] = SCORE_IMPACTS["MEDIUM"]
        identity = (item["name"], item["category"], item["status"], item["result"])
        if identity not in seen:
            unique.append(item)
            seen.add(identity)
    return unique


def scored_findings(findings):
    # Only confirmed warnings/failures affect the internal score. When two
    # findings intentionally share a score key, retain only the larger impact.
    selected = {}
    for item in findings:
        if item["result"] not in ("WARNING", "FAIL") or item["score_impact"] <= 0:
            continue
        current = selected.get(item["score_key"])
        if current is None or item["score_impact"] > current["score_impact"]:
            selected[item["score_key"]] = item
    return list(selected.values())


def security_score(findings):
    return max(0, 100 - sum(item["score_impact"] for item in scored_findings(findings)))


def score_classification(score): return "Good" if score >= 90 else "Attention" if score >= 75 else "Risk" if score >= 50 else "High Risk" if score >= 25 else "Critical"


def scan_health(findings):
    requested = len(findings)
    unavailable = sum(item["status"] in ("NOT AVAILABLE", "NOT APPLICABLE") or item.get("error_type") == "NOT_AVAILABLE" for item in findings)
    failed = sum(item["result"] == "UNKNOWN" and item.get("error_type") not in ("NOT_AVAILABLE", None) for item in findings)
    completed = requested - unavailable - failed
    completeness = round((completed / requested) * 100) if requested else 0
    return {"requested": requested, "completed": completed, "unavailable": unavailable, "failed": failed, "completeness": completeness}


def esc(value):
    """Escape collected text and avoid leaking Python None into HTML."""
    return html.escape(clean_value(value))


# Short, local explanations shown beside report sections. They describe the
# purpose of a check without changing its collection, severity, or score.
SECTION_HELP = {
    "findings": "Each line is one security check. Click it to read the evidence, why it matters, and a suggested manual review step. Severity is an internal Atlhas1x classification, not a certification.",
    "summary": "A quick overview of completed checks, alerts, score and coverage. It is intended to help prioritize where to look first.",
    "hardening": "Windows hardening features add layers of protection against unwanted application, credential, and system changes. Some features depend on Windows edition, hardware, or virtualization support.",
    "activity": "Inventories summarize local startup items, services, tasks, processes, and network information. A detected item is not automatically a security problem.",
    "threat": "This is a cautious heuristic review of files already related to running processes, persistence, or network listeners. It does not confirm malware.",
    "yara": "YARA compares selected local files with local rules. A match requires manual verification; no files are sent to the internet or executed.",
    "system": "Basic information identifies the computer and Windows installation that produced this report.",
    "health": "Scan completeness measures audit coverage, not security. Unavailable or access-restricted checks do not reduce the Security Score.",
    "score": "The Security Score is an Atlhas1x internal metric. It starts at 100 and deducts points only for confirmed warnings or failures, without double-counting the same issue.",
    "diagnostics": "Check duration is included to help identify slow or unavailable local queries. Technical command output is not included here.",
    "inventory": "Technical inventory collected locally for review. Long lists are informational unless a separate finding explains a reason for attention.",
}


def help_icon(topic):
    text = SECTION_HELP.get(topic, "This section contains locally collected information for manual review.")
    return f"<details class='section-help'><summary aria-label='What does this analysis mean?' title='What is this analysis?'>?</summary><div>{esc(text)}</div></details>"


def section_title(title, topic="inventory"):
    return f"<h2>{esc(title)}{help_icon(topic)}</h2>"


def findings_table(findings, advanced=False):
    rows = []
    category_order = ("Endpoint Protection", "Firewall", "System Hardening", "Credential Protection", "Defender Hardening", "Application Protection", "Account Security", "Authentication", "Remote Access", "Network Security", "Network Configuration", "Listening Ports", "Startup", "Scheduled Tasks", "Persistence", "Process Activity", "System Services", "Updates", "Operating System", "PowerShell", "Accounts")
    categories = [category for category in category_order if any(item["category"] == category for item in findings)]
    categories += sorted({item["category"] for item in findings if item["category"] not in categories})
    for category in categories:
        rows.append(f"<tr class='category-row'><td colspan='6'>{esc(category)}</td></tr>")
        for item in [entry for entry in findings if entry["category"] == category]:
            details = f"<div class='finding-details'><div><b>Description</b><p>{esc(item['description'])}</p></div><div><b>Recommendation</b><p>{esc(item['recommendation'])}</p></div>"
            if advanced:
                details += f"<div class='technical-details'><b>Technical details</b><p><b>Finding ID:</b> {esc(item['id'])}<br><b>Category:</b> {esc(item['category'])}<br><b>Result:</b> {esc(item['result'])}<br><b>Confidence:</b> {esc(item['confidence'])}<br><b>Score impact:</b> -{item['score_impact']}<br><b>Check duration:</b> {item['duration_seconds'] if item['duration_seconds'] is not None else 'UNKNOWN'}s<br><b>Evidence:</b> {esc(item['evidence'])}<br><b>Timestamp:</b> {esc(item['timestamp'])}</p>"
                if item["error"]:
                    details += f"<p><b>Status reason:</b> {esc(item.get('error_type') or 'QUERY_FAILED')}<br><b>Details:</b> {esc(item['error'])}</p>"
                details += "</div>"
            details += "</div>"
            rows.append(f"<tr class='finding-row' data-severity='{item['severity']}' tabindex='0' role='button' aria-expanded='false' onclick='toggleFinding(this)' onkeydown='toggleOnEnter(event,this)'><td><span class='badge {item['severity'].lower()}'>{esc(item['severity'])}</span></td><td>{esc(item['name'])}</td><td>{esc(item['category'])}</td><td>{esc(item['status'])}</td><td>{esc(item['confidence'])}</td><td class='expand-icon'>+</td></tr><tr class='finding-detail-row' hidden><td colspan='6'>{details}</td></tr>")
    return "<section class='findings-section' id='findings'><div class='section-heading'><div>" + section_title("Findings", "findings") + "<p>Click a line to open the explanation, evidence and recommendation.</p></div><div class='filters' aria-label='Severity filters'><button class='filter active' data-filter='ALL' onclick='filterFindings(this)'>All</button>" + "".join(f"<button class='filter {severity.lower()}' data-filter='{severity}' onclick='filterFindings(this)'>{severity}</button>" for severity in SEVERITIES) + "</div></div><div class='table-wrap'><table class='findings-table'><thead><tr><th>Severity</th><th>Check</th><th>Category</th><th>Status</th><th>Confidence</th><th></th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></div></section>"


def activity_overview(inventories):
    return "".join(f"<tr><th>{esc(data['title'])}</th><td>{len(data['items'])} detected" + (f" · {data['review_count']} require review" if data["review_count"] else "") + (" · collection unavailable" if data["error"] and not data["items"] else "") + "</td></tr>" for data in inventories)


def hardening_section(findings, level):
    categories = {"System Hardening", "Credential Protection", "Defender Hardening", "Application Protection", "Virtualization Security"}
    items = [item for item in findings if item["category"] in categories]
    if level == "basic":
        preferred = {"Microsoft Defender SmartScreen", "Memory Integrity", "Credential Guard", "LSASS Protection"}
        items = [item for item in items if item["name"] in preferred or item["result"] in ("WARNING", "FAIL")]
    if not items:
        return ""
    rows = "".join(f"<tr><td>{esc(item['name'])}</td><td>{esc(item['status'])}</td><td><span class='badge {item['severity'].lower()}'>{esc(item['severity'])}</span></td>" + (f"<td>{esc(item['description'])}<br><b>Recommendation:</b> {esc(item['recommendation'])}</td>" if level != "basic" else "") + "</tr>" for item in items)
    details = "<th>Description</th>" if level != "basic" else ""
    return f"<section>{section_title('Windows Hardening', 'hardening')}<div class='table-wrap'><table><thead><tr><th>Feature</th><th>Status</th><th>Severity</th>{details}</tr></thead><tbody>{rows}</tbody></table></div></section>"


def threat_analysis_html(records, yara_summary, level):
    flagged = [item for item in records if item["classification"] != "NORMAL"]
    high = sum(item["classification"] == "HIGH PRIORITY REVIEW" for item in flagged)
    recent = sum(bool(item["metadata"].get("recent")) for item in flagged)
    overview = f"<section id='threat-analysis'>{section_title('Threat Analysis', 'threat')}<table><tbody><tr><th>Potentially suspicious items</th><td>{len(flagged)}</td></tr><tr><th>High priority review</th><td>{high}</td></tr><tr><th>Recent security-relevant files</th><td>{recent}</td></tr><tr><th>YARA engine</th><td>{esc(yara_summary.get('engine'))}</td></tr><tr><th>YARA files scanned</th><td>{yara_summary.get('files_scanned', 0)}</td></tr><tr><th>YARA matches</th><td>{yara_summary.get('matches', 0)}</td></tr></tbody></table><p>Suspicion Score orders local heuristic indicators. It is not a malware probability score.</p></section>"
    yara_status = yara_analysis_html(records, yara_summary, level)
    if level == "basic":
        return overview + yara_status
    rows = []
    for item in flagged:
        metadata = item["metadata"]
        rows.append(f"<tr><td><span class='badge {item['severity'].lower()}'>{esc(item['severity'])}</span></td><td>{esc(item['classification'])}</td><td>{esc(item['path'])}</td><td>{item['suspicion_score']} / 100</td><td>{esc(', '.join(item['indicators']) or 'None')}</td><td>{len(item['yara'].get('matches', []))}</td></tr>")
    detailed = "<section>" + section_title("Suspicious Activity", "threat") + "<div class='table-wrap'><table><thead><tr><th>Severity</th><th>Classification</th><th>File</th><th>Suspicion Score</th><th>Indicators</th><th>YARA Matches</th></tr></thead><tbody>" + ("".join(rows) or "<tr><td colspan='6'>No suspicious file correlations were identified.</td></tr>") + "</tbody></table></div></section>"
    if level != "advanced":
        return overview + yara_status + detailed
    metadata_rows = []
    for item in records:
        meta = item["metadata"]
        reasoning = ", ".join(f"{entry['impact']:+d} {entry['indicator']}" for entry in item.get("reasoning", [])) or "No score-impacting indicators"
        context = ", ".join(item.get("positive_indicators", [])) or "None"
        metadata_rows.append(f"<tr><td>{esc(item['path'])}</td><td>{esc(meta.get('sha256'))}</td><td>{esc(meta.get('signature'))}</td><td>{esc(', '.join(meta.get('related_to', [])))}</td><td>{esc(reasoning)}</td><td>{esc(context)}</td><td>{'Yes' if item.get('possible_false_positive') else 'No'}</td></tr>")
    technical = "<section>" + section_title("Threat Analysis Technical Details", "threat") + "<p><b>False Positive Considerations:</b> valid signatures and expected Windows or Program Files paths reduce suspicion. A YARA match remains an indicator for manual review, not a malware verdict.</p><div class='table-wrap'><table><thead><tr><th>File</th><th>SHA-256</th><th>Signature</th><th>Observed As</th><th>Why this item was flagged</th><th>Trusted Context</th><th>Possible False Positive</th></tr></thead><tbody>" + ("".join(metadata_rows) or "<tr><td colspan='7'>No file metadata available.</td></tr>") + "</tbody></table></div><p>Rules discovered: %s · Rules loaded: %s · Rules failed: %s · Files skipped: %s · Files timed out: %s.</p></section>" % (yara_summary.get("rules_discovered", 0), yara_summary.get("rules_loaded", 0), yara_summary.get("rules_failed", 0), yara_summary.get("files_skipped", 0), yara_summary.get("files_timed_out", 0))
    return overview + yara_status + detailed + technical


def yara_analysis_html(records, summary, level):
    """Always show the YARA state so zero matches are not ambiguous."""
    engine = summary.get("engine", "NOT AVAILABLE")
    if engine == "NOT AVAILABLE":
        reason = summary.get("reason") or "yara-python is not installed or the optional engine could not be loaded. Heuristic threat analysis remains active."
    elif not summary.get("rules_loaded", 0):
        reason = "The YARA engine is available, but no local rules were loaded."
    else:
        reason = "Local YARA rules were loaded and matched only focused files already selected by the scanner."
    rows = "".join(
        f"<tr><td>{esc(record['path'])}</td><td>{esc(record['yara'].get('status'))}</td><td>{len(record['yara'].get('matches', []))}</td><td>{esc(', '.join(match.get('rule', 'UNKNOWN') for match in record['yara'].get('matches', [])) or 'No matches')}</td></tr>"
        for record in records if record["yara"].get("status") not in ("NOT AVAILABLE", None)
    )
    details = "" if level == "basic" else "<div class='table-wrap'><table><thead><tr><th>File</th><th>Scan Status</th><th>Matches</th><th>Rules</th></tr></thead><tbody>" + (rows or "<tr><td colspan='4'>No focused files were scanned by YARA in this run.</td></tr>") + "</tbody></table></div>"
    return "<section id='yara-analysis'>" + section_title("YARA Analysis", "yara") + "<table><tbody><tr><th>Engine</th><td>%s</td></tr><tr><th>Rules discovered</th><td>%s</td></tr><tr><th>Rules loaded</th><td>%s</td></tr><tr><th>Rules failed</th><td>%s</td></tr><tr><th>Files scanned</th><td>%s</td></tr><tr><th>Files skipped</th><td>%s</td></tr><tr><th>Files timed out</th><td>%s</td></tr><tr><th>Total matches</th><td>%s</td></tr></tbody></table><p>%s</p>%s</section>" % (esc(engine), summary.get("rules_discovered", 0), summary.get("rules_loaded", 0), summary.get("rules_failed", 0), summary.get("files_scanned", 0), summary.get("files_skipped", 0), summary.get("files_timed_out", 0), summary.get("matches", 0), esc(reason), details)


def inventory_html(data):
    columns = data["columns"]
    head = "".join(f"<th>{esc(column)}</th>" for column in columns)
    rows = "".join("<tr>" + "".join(f"<td>{esc(clean_value(item.get(column), 'UNKNOWN'))}</td>" for column in columns) + "</tr>" for item in data["items"])
    note = f"<p>{len(data['items'])} detected" + (f" · {data['review_count']} require review" if data["review_count"] else "") + ".</p>"
    if data["error"] and not data["items"]:
        note += f"<p><b>Status:</b> UNKNOWN<br><b>Reason:</b> {esc(data['error'])}</p>"
    return f"<section>{section_title(data['title'], 'inventory')}{note}<div class='table-wrap'><table><thead><tr>{head}</tr></thead><tbody>{rows or '<tr><td colspan=\'' + str(len(columns)) + '\'>No items available.</td></tr>'}</tbody></table></div></section>"


def report_html(level, findings, info, started, ended, inventories, health=None, diagnostics=None, threats=None, yara_summary=None):
    risk = overall(findings); score=security_score(findings); counts = {s: sum(f["severity"] == s for f in findings) for s in SEVERITIES}
    health = health or scan_health(findings)
    diagnostics = diagnostics or []
    threats = threats or []
    yara_summary = yara_summary or {"engine": "NOT AVAILABLE"}
    yara_footer = ""
    if yara_summary.get("engine") == "NOT AVAILABLE":
        yara_footer = "<span class='yara-unavailable'>YARA: unavailable. Heuristic analysis remains active.</span><details class='yara-help'><summary title='What is YARA and how can I enable it?'>?</summary><div><b>What is YARA?</b><br>YARA is a local rule-matching engine used to identify files that may require review. Atlhas1x does not upload files or execute them.<br><br><b>Install manually in PowerShell:</b><br><code>python -m ensurepip --upgrade</code><br><code>python -m pip install --upgrade pip</code><br><code>python -m pip install yara-python</code><br><br>Then run a new Atlhas1x scan. Keep rules locally in <code>rules</code>.<br><a href='https://github.com/Yara-Rules/rules' target='_blank' rel='noopener noreferrer'>Open the Yara-Rules repository</a></div></details>"
    duration = (ended - started).total_seconds()
    head = f"<header id='overview'><div class='report-brand'><div><span class='eyebrow'>LOCAL WINDOWS SECURITY AUDIT</span><h1>{APP_NAME} Report</h1><p>{VERSION} · {esc(level.title())} detail · Generated {started.strftime('%Y-%m-%d %H:%M:%S')}</p></div><div class='report-scope'>Read-only scan<br>No settings changed</div></div><div class='metrics'><div class='metric'><span>Security score</span><strong>{score}<small>/100</small></strong></div><div class='metric'><span>Overall risk</span><strong class='risk-text {risk.lower()}'>{risk}</strong></div><div class='metric'><span>Scan completeness</span><strong>{health['completeness']}<small>%</small></strong></div></div></header>"
    system = "".join(f"<tr><th>{esc(k.replace('_',' ').title())}</th><td>{esc(v)}</td></tr>" for k,v in info.items() if level != "basic" or k in ("hostname","user","operating_system"))
    activity = "<section>" + section_title("Activity Overview", "activity") + "<table>" + activity_overview(inventories) + "</table></section>"
    hardening = hardening_section(findings, level)
    threats_html = threat_analysis_html(threats, yara_summary, level)
    health_html = f"<section id='scan-health'>{section_title('Scan Health', 'health')}<table><tbody><tr><th>Checks requested</th><td>{health['requested']}</td></tr><tr><th>Checks completed</th><td>{health['completed']}</td></tr><tr><th>Checks unavailable</th><td>{health['unavailable']}</td></tr><tr><th>Checks failed</th><td>{health['failed']}</td></tr><tr><th>Scan completeness</th><td>{health['completeness']}%</td></tr><tr><th>Scan duration</th><td>{duration:.2f}s</td></tr></tbody></table>" + ("<p>Scan results may be incomplete because one or more checks could not be executed.</p>" if health['unavailable'] or health['failed'] else "") + "</section>"
    summary = health_html + activity if level == "basic" else "<section>" + section_title("Executive Summary", "summary") + "<p>Passed: %d · Alerts: %d · Total checks: %d</p><div class='counts'>%s</div></section>%s%s" % (sum(f['result'] in ('PASS','INFO') for f in findings), sum(f['result'] in ('WARNING','FAIL') for f in findings), len(findings), " ".join(f"<span class='{s.lower()}'>{s}: {counts[s]}</span>" for s in SEVERITIES), health_html, activity)
    score_rows = "".join(f"<tr><td>{esc(item['name'])}</td><td>{esc(item['severity'])}</td><td>-{item['score_impact']}</td></tr>" for item in scored_findings(findings)) or "<tr><td colspan='3'>No confirmed findings reduced the score.</td></tr>"
    diagnostics_rows = "".join(f"<tr><td>{esc(item['Module'])}</td><td>{esc(item['Duration'])}</td></tr>" for item in diagnostics)
    technical = "" if level != "advanced" else f"<section id='score'>{section_title('Security Score', 'score')}<p><b>Initial Score:</b> 100<br><b>Final Score:</b> {score}/100<br><b>Score Classification:</b> {score_classification(score)}<br><b>Overall Risk:</b> {risk}</p><div class='table-wrap'><table><thead><tr><th>Finding</th><th>Severity</th><th>Impact</th></tr></thead><tbody>{score_rows}</tbody></table></div><p>The Atlhas1x Security Score is an internal project metric and is not an official Microsoft, CIS, NIST or industry-standard security score.</p></section><section id='scan-information'>{section_title('Scan Information', 'summary')}<p><b>Report ID:</b> ATL-{started.strftime('%Y%m%d-%H%M%S')}<br><b>Scan Start:</b> {started.strftime('%Y-%m-%d %H:%M:%S')}<br><b>Scan End:</b> {ended.strftime('%Y-%m-%d %H:%M:%S')}<br><b>Duration:</b> {duration:.2f} seconds<br><b>Scope:</b> Read-only security queries; no settings were changed.</p></section><section id='diagnostics'>{section_title('Scan Diagnostics', 'diagnostics')}<div class='table-wrap'><table><thead><tr><th>Module</th><th>Duration</th></tr></thead><tbody>{diagnostics_rows or '<tr><td colspan=\'2\'>No module timing data available.</td></tr>'}</tbody></table></div></section>"
    detailed_inventories = "" if level != "advanced" else "".join(inventory_html(data) for data in inventories)
    displayed_findings = findings if level != "basic" else [item for item in findings if item["result"] in ("WARNING", "FAIL")]
    finding_list = findings_table(displayed_findings, level == "advanced")
    navigation = "" if level != "advanced" else "<nav><a href='#overview'>Overview</a><a href='#score'>Score</a><a href='#findings'>Findings</a><a href='#threat-analysis'>Threat Analysis</a><a href='#yara-analysis'>YARA</a><a href='#scan-health'>Scan Health</a><a href='#scan-information'>Scan Information</a><a href='#diagnostics'>Diagnostics</a></nav>"
    css = "body{font:13px Arial,Helvetica,sans-serif;background:#d7d7d7;color:#111;margin:0}main{margin:7px;padding:0;background:#efefef;border:1px solid #888}header{padding:12px 14px 0;background:#f5f5f5;border-bottom:1px solid #888}header h1{font:normal 22px Georgia,serif;color:#1b5ea6;margin:0 0 8px}header p{margin:0 0 10px;color:#333}nav{padding:8px 14px;background:#d0d0d0;border-bottom:1px solid #999}nav a{display:inline-block;margin-right:12px;color:#124f87;font-weight:bold;text-decoration:none}nav a:hover{text-decoration:underline}.risk{display:block;background:#8a8a8a;color:#fff;padding:8px 10px;font-weight:bold;border-top:1px solid #727272}section{margin:14px 10px;border:1px solid #9a9a9a;background:#e5e5e5;padding:0}section>h2{font-size:15px;margin:0;padding:7px 10px;color:#fff;background:#2c5d96;border-bottom:1px solid #1d416c}section>p{padding:0 10px}.badge{display:inline-block;padding:2px 6px;font-size:11px;font-weight:bold;color:#111;border:1px solid #777;background:#ddd;white-space:nowrap}.badge.info,.info{background:#d7e4f5;color:#174f83}.badge.low,.low{background:#d8eadc;color:#245a32}.badge.medium,.medium{background:#fff0b8;color:#735600}.badge.high,.high{background:#ffd7af;color:#8a3d00}.badge.critical,.critical{background:#f3b7b7;color:#7f1111}table{width:100%;border-collapse:collapse;background:#f8f8f8}th{background:#2c5d96;color:#fff;font-size:12px;font-weight:bold;border:1px solid #7e9ab9;padding:6px 7px;text-align:left}td{padding:6px 7px;border:1px solid #b0b0b0;vertical-align:top}tbody tr:nth-child(even){background:#e3e3e3}.category-row td{background:#d2d2d2!important;color:#174f83;font-weight:bold;border-top:2px solid #888}.table-wrap{overflow-x:auto}.counts{padding:0 10px 10px}.counts span{display:inline-block;margin:2px 8px 2px 0;padding:3px 6px;border:1px solid #999}.section-heading{display:flex;gap:10px;align-items:flex-start;justify-content:space-between;background:#e5e5e5;padding:0}.section-heading>div:first-child{flex:1}.section-heading h2{margin:0;padding:7px 10px;color:#fff;background:#2c5d96;border-bottom:1px solid #1d416c}.section-heading p{margin:7px 10px;color:#333}.filters{display:flex;gap:4px;flex-wrap:wrap;justify-content:flex-end;padding:7px}.filter{border:1px solid #666;background:#d2d2d2;color:#111;padding:4px 8px;cursor:pointer;font:12px Arial}.filter.active,.filter:hover{background:#2c5d96;color:#fff;border-color:#1d416c}.finding-row{cursor:pointer}.finding-row:hover,.finding-row:focus{background:#cbdced!important;outline:2px solid #2c5d96;outline-offset:-2px}.finding-row[aria-expanded='true']{background:#bfd3e6!important}.finding-detail-row td{background:#f4f4f4;padding:0}.finding-details{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:13px 16px}.finding-details p{margin:5px 0 0}.technical-details{grid-column:1/-1;border-top:1px solid #aaa;padding-top:11px;word-break:break-word}.expand-icon{text-align:center;font-size:17px;font-weight:bold}.findings-table th:last-child{width:28px}footer{display:block;padding:12px;color:#444;font-size:11px}@media(max-width:700px){main{margin:0;border:0}.section-heading{display:block}.filters{justify-content:flex-start}.finding-details{grid-template-columns:1fr}}"
    # System and activity tables use neutral labels; blue remains reserved for
    # section and column headers, keeping the lower part of the report calmer.
    css += "section:not(.findings-section) tbody th{background:#d0d0d0;color:#111;font-size:12px;border:1px solid #aaa;padding:6px 7px;font-weight:bold}section:not(.findings-section) tbody td{background:#f4f4f4}section:not(.findings-section) tbody tr:nth-child(even) th,section:not(.findings-section) tbody tr:nth-child(even) td{background:#e1e1e1}footer{background:#c6c6c6;border-top:1px solid #888;padding:9px 10px;color:#333;font-size:11px}.yara-unavailable{margin-left:14px;color:#765700}.yara-help{display:inline-block;margin-left:5px;vertical-align:middle;position:relative}.yara-help summary{display:inline-block;width:16px;height:16px;line-height:16px;text-align:center;border:1px solid #555;border-radius:50%;background:#f5f5f5;color:#174f83;font-weight:bold;cursor:pointer;list-style:none}.yara-help summary::-webkit-details-marker{display:none}.yara-help div{position:absolute;z-index:2;bottom:23px;right:0;width:310px;padding:9px;background:#fff;border:1px solid #777;box-shadow:0 2px 5px #777;color:#222;line-height:1.35}.yara-help a{color:#124f87;font-weight:bold}"
    # Final offline visual layer: compact cards, calmer contrast and useful
    # section help without changing report data or requiring an external CDN.
    css += "body{font:14px 'Segoe UI',Arial,sans-serif;background:#eef3f8;color:#172033;line-height:1.45}main{max-width:1400px;margin:24px auto;background:transparent;border:0;padding:0 18px 24px}header{padding:28px;border:0;border-radius:14px;background:linear-gradient(135deg,#102a43,#1f5f98);box-shadow:0 8px 24px #102a4330;color:#fff}header h1{font:700 27px 'Segoe UI',Arial,sans-serif;color:#fff;margin:0 0 6px}header p{color:#d9e9f7;margin:0 0 16px}.risk{display:inline-block;border:1px solid #ffffff45;border-radius:9px;background:#ffffff17;color:#fff;padding:9px 12px}nav{position:sticky;top:0;z-index:3;margin-top:14px;padding:10px 14px;border:1px solid #dbe5ef;border-radius:10px;background:#ffffffed;box-shadow:0 4px 12px #102a4312}nav a{color:#285f91;margin:3px 13px 3px 0}section{margin:16px 0;border:1px solid #dbe4ee;border-radius:12px;background:#fff;box-shadow:0 4px 14px #102a430c;overflow:visible}section>h2,.section-heading h2{display:flex;align-items:center;gap:8px;font:700 16px 'Segoe UI',Arial,sans-serif;color:#173f67;background:#f7fbff;border-bottom:1px solid #e5edf5;padding:12px 16px;margin:0}.section-heading{background:#fff;border-radius:12px 12px 0 0}.section-heading p{color:#526477;margin:8px 16px 12px}.section-heading h2{border-radius:12px 12px 0 0}.section-help{display:inline-block;position:relative}.section-help summary{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border:1px solid #7290aa;border-radius:50%;background:#fff;color:#285f91;font:700 12px Arial;cursor:pointer;list-style:none}.section-help summary::-webkit-details-marker{display:none}.section-help div{position:absolute;z-index:8;top:25px;left:0;width:min(340px,70vw);padding:11px 12px;border:1px solid #bfd0df;border-radius:8px;background:#fff;color:#33475b;font:13px 'Segoe UI',Arial,sans-serif;line-height:1.45;box-shadow:0 8px 24px #102a4330}section>p{color:#526477;padding:0 16px}table{background:#fff}th{background:#f0f6fb;color:#254f78;border-color:#dce7f0;padding:8px 10px}td{border-color:#e5edf4;padding:8px 10px;word-break:break-word}tbody tr:nth-child(even),section:not(.findings-section) tbody tr:nth-child(even) td{background:#f8fbfd}section:not(.findings-section) tbody th,section:not(.findings-section) tbody tr:nth-child(even) th{background:#f0f6fb;color:#254f78;border-color:#dce7f0}.category-row td{background:#eaf3fb!important;color:#285f91;border-top:1px solid #c6dceb}.badge{border:0;border-radius:999px;padding:4px 8px;font-size:11px}.counts{padding:0 16px 14px}.counts span{border:0;border-radius:999px;padding:5px 9px}.filters{padding:10px 16px}.filter{border:1px solid #ccd8e4;border-radius:7px;background:#fff;color:#38546d;padding:5px 9px}.filter.active,.filter:hover{background:#285f91;color:#fff;border-color:#285f91}.finding-row:hover,.finding-row:focus,.finding-row[aria-expanded='true']{background:#edf6ff!important;outline-color:#72a7d3}.finding-detail-row td{background:#f8fbfd}.finding-details{gap:18px;padding:16px 18px}.technical-details{border-color:#dce7f0}.table-wrap{border-radius:0 0 12px 12px}.yara-unavailable{color:#8a6200;font-weight:600}footer{border:1px solid #dbe4ee;border-radius:10px;background:#fff;color:#64748b;padding:12px 16px;margin-top:16px}.yara-help summary{border-color:#7290aa;color:#285f91}.yara-help div{border-color:#bfd0df}@media(max-width:700px){main{margin:0;padding:12px}header{border-radius:10px;padding:20px}header h1{font-size:22px}nav{position:static}.section-help div{left:auto;right:0}.finding-details{grid-template-columns:1fr}}"
    # Deliberately restrained audit-report presentation: square edges, clear
    # lines and dense data tables rather than dashboard-like visual effects.
    css += "body{background:#f3f5f7;color:#202a34;font:13px Arial,Helvetica,sans-serif}main{max-width:1540px;margin:18px auto;padding:0 12px 22px}header{padding:0;border:1px solid #234a70;border-radius:0;background:#173b5e;box-shadow:none}.report-brand{display:flex;justify-content:space-between;gap:20px;padding:20px 22px 16px}.eyebrow{display:block;color:#b8d5ef;font-size:10px;font-weight:bold;letter-spacing:.09em;margin-bottom:5px}header h1{font:700 25px Arial,Helvetica,sans-serif;margin:0 0 5px;color:#fff}header p{font-size:12px;color:#d6e5f1;margin:0}.report-scope{align-self:flex-start;border-left:1px solid #5b7792;color:#d6e5f1;font-size:11px;line-height:1.5;padding:2px 0 2px 14px;text-align:right}.metrics{display:grid;grid-template-columns:repeat(3,1fr);border-top:1px solid #4e6b85;background:#fff}.metric{padding:10px 15px;border-right:1px solid #d9e0e6}.metric:last-child{border-right:0}.metric span{display:block;color:#617181;font-size:11px;text-transform:uppercase;letter-spacing:.04em}.metric strong{display:block;color:#183c60;font-size:20px;margin-top:2px}.metric small{font-size:12px;font-weight:normal}.risk-text.info{color:#2a5a87}.risk-text.low{color:#28713d}.risk-text.medium{color:#946b00}.risk-text.high{color:#a64a00}.risk-text.critical{color:#a51f1f}nav{position:static;margin:10px 0 0;padding:8px 11px;border:1px solid #c9d3dc;border-radius:0;background:#fff;box-shadow:none}nav a{font-size:12px;margin:2px 14px 2px 0;color:#1f5d92}section{margin:12px 0;border:1px solid #c9d3dc;border-radius:0;box-shadow:none;background:#fff}section>h2,.section-heading h2{font:700 14px Arial,Helvetica,sans-serif;color:#fff;background:#2f6699;border:0;padding:8px 11px}.section-heading{border-radius:0;background:#fff}.section-heading h2{border-radius:0}.section-heading p{font-size:12px;color:#586775;margin:7px 11px}.section-help summary{width:16px;height:16px;border-color:#b8d2e8;border-radius:50%;color:#2f6699}.section-help div{width:min(310px,70vw);border-radius:0;box-shadow:0 3px 10px #0003;font:12px Arial,Helvetica,sans-serif}section>p{font-size:12px;color:#4d5e6c;padding:0 11px}th{background:#e8f0f6;color:#244a6c;border-color:#cad7e2;padding:6px 8px;font-size:11px}td{border-color:#d8e1e8;padding:6px 8px}tbody tr:nth-child(even),section:not(.findings-section) tbody tr:nth-child(even) td{background:#f6f8fa}section:not(.findings-section) tbody th,section:not(.findings-section) tbody tr:nth-child(even) th{background:#eef4f8;color:#244a6c;border-color:#cad7e2}.category-row td{background:#dcebf7!important;color:#244a6c;border-top:1px solid #a9c5da}.badge{border-radius:0;padding:3px 6px;font-size:10px}.counts{padding:0 11px 10px}.counts span{border-radius:0;padding:3px 6px}.filters{padding:8px 11px}.filter{border-radius:0;font-size:11px;padding:4px 7px}.filter.active,.filter:hover{background:#2f6699;border-color:#2f6699}.finding-row:hover,.finding-row:focus,.finding-row[aria-expanded='true']{background:#e4f1fb!important;outline:1px solid #5d9ac6;outline-offset:-1px}.finding-detail-row td{background:#f7fafc}.finding-details{gap:14px;padding:12px 14px}.technical-details{border-color:#cedae3}.table-wrap{border-radius:0}footer{border:1px solid #c9d3dc;border-radius:0;box-shadow:none;margin-top:12px;padding:9px 11px}.yara-help div{border-radius:0}@media(max-width:700px){main{padding:0}.report-brand{display:block}.report-scope{border-left:0;border-top:1px solid #5b7792;margin-top:12px;padding:8px 0 0;text-align:left}.metrics{grid-template-columns:1fr}.metric{border-right:0;border-bottom:1px solid #d9e0e6}.metric:last-child{border-bottom:0}}"
    script = "function closeDetail(row){var detail=row.nextElementSibling;if(detail){detail.hidden=true;}row.setAttribute('aria-expanded','false');row.querySelector('.expand-icon').textContent='+';}function toggleFinding(row){var detail=row.nextElementSibling;var open=row.getAttribute('aria-expanded')==='true';if(open){closeDetail(row);}else{detail.hidden=false;row.setAttribute('aria-expanded','true');row.querySelector('.expand-icon').textContent='−';}}function toggleOnEnter(event,row){if(event.key==='Enter'||event.key===' '){event.preventDefault();toggleFinding(row);}}function filterFindings(button){var filter=button.dataset.filter;document.querySelectorAll('.filter').forEach(function(item){item.classList.remove('active');});button.classList.add('active');document.querySelectorAll('.finding-row').forEach(function(row){var show=filter==='ALL'||row.dataset.severity===filter;row.hidden=!show;if(!show){closeDetail(row);}});}"
    return f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>Atlhas1x {esc(level.title())} Report</title><style>{css}</style></head><body><main>{head}{navigation}{summary}{hardening}{threats_html}{finding_list}<section id='system'>{section_title('System Information', 'system')}<table>{system}</table></section>{technical}{detailed_inventories}<footer>Generated locally by {APP_NAME} {VERSION}. No settings were modified.{yara_footer}</footer></main><script>{script}</script></body></html>"


def interactive_menu():
    while True:
        print("\nAtlhas1x v1.3\nWindows Security Scanner\n")
        print("Como deseja executar o Atlhas1x?\n")
        print("[1] Básico")
        print("[2] Intermediário")
        print("[3] Avançado")
        print("[4] Usar Atlhas por Terminal\n")
        print("[?] Qual a diferença entre os modos?")
        print("[0] Sair\n")
        try:
            choice = input("Escolha: ").strip()
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)
            
        if choice == "1": return "basic", "html"
        elif choice == "2": return "intermediate", "html"
        elif choice == "3": return "advanced", "html"
        elif choice == "4":
            res = terminal_menu()
            if res: return res
        elif choice == "?":
            print("\n================ DÚVIDAS ================\n")
            print("1, 2 e 3 (Básico, Intermediário, Avançado):")
            print("  O sistema fará um escaneamento silencioso")
            print("  e ao final abrirá um relatório HTML no")
            print("  seu navegador padrão.")
            print("\n4 (Modo Terminal):")
            print("  Para usuários que preferem não abrir")
            print("  o navegador. Tudo é exibido aqui no prompt,")
            print("  incluindo o progresso e o relatório final.")
            print("  Ao terminar, será sugerido salvar um .TXT.\n")
            print("=========================================\n")
            input("Pressione ENTER para voltar.")
        elif choice == "0":
            sys.exit(0)
        else:
            print("\nOpção inválida. Escolha uma opção entre 0 e 4.")

def terminal_menu():
    while True:
        print("\nAtlhas1x Terminal\n------------------------------------------------\n")
        print("Escolha o nível do scan:\n")
        print("[1] Básico")
        print("[2] Intermediário")
        print("[3] Avançado\n")
        print("[?] Explicar os níveis")
        print("[0] Voltar\n")
        try:
            choice = input("Escolha: ").strip()
        except (KeyboardInterrupt, EOFError):
            return None
            
        if choice == "1": return "basic", "terminal"
        elif choice == "2": return "intermediate", "terminal"
        elif choice == "3": return "advanced", "terminal"
        elif choice == "?":
            print("\n[Básico]: Foca em métricas essenciais. (Mais Rápido)")
            print("[Intermediário]: Padrão. Analisa processos, serviços e arquivos.")
            print("[Avançado]: Análise profunda. Lista tudo e checa TUDO. (Mais Demorado)\n")
            input("Pressione ENTER para voltar.")
        elif choice == "0":
            return None
        else:
            print("\nOpção inválida. Escolha uma opção entre 0 e 3.")

class Renderer:
    def __init__(self, level: str, findings: List[dict], info: dict, started: dt.datetime, ended: dt.datetime, inventories: List[dict], health: dict, diagnostics: List[dict], threats: List[dict], yara_summary: dict):
        self.level = level
        self.findings = findings
        self.info = info
        self.started = started
        self.ended = ended
        self.inventories = inventories
        self.health = health
        self.diagnostics = diagnostics
        self.threats = threats
        self.yara_summary = yara_summary
        
    def render(self):
        pass

class HTMLRenderer(Renderer):
    def render(self):
        reports = Path("reports")
        reports.mkdir(exist_ok=True)
        stamp = self.started.strftime("%Y-%m-%d_%H%M%S")
        path = reports / f"atlhas1x_{self.level}_{stamp}.html"
        path.write_text(report_html(self.level, self.findings, self.info, self.started, self.ended, self.inventories, self.health, self.diagnostics, self.threats, self.yara_summary), encoding="utf-8")
        print(f"\nRelatório salvo em:\n{path}")
        webbrowser.open(path.as_uri())
        return 0

class TerminalRenderer(Renderer):
    def render(self):
        reports = Path("reports")
        reports.mkdir(exist_ok=True)
        stamp = self.started.strftime("%Y-%m-%d_%H%M%S")
        
        print("\n" + "=" * 50)
        print(f" ATLHAS1X v1.3 - Relatório {self.level.upper()}")
        print("=" * 50)
        print(f"Sistema: {self.info['hostname']} | {self.info['operating_system']}")
        print(f"Privilégios Administrativos: {self.info['administrator_privileges']}")
        print(f"Início: {self.started.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 50)
        
        category_sets = (
            ("Endpoint Protection", {"Endpoint Protection", "Defender Hardening", "Application Protection"}),
            ("Firewall", {"Firewall"}),
            ("Account Security", {"Account Security", "Authentication", "Accounts"}),
            ("Windows Hardening", {"System Hardening", "Credential Protection", "Virtualization Security"}),
            ("Persistence", {"Startup", "Scheduled Tasks", "System Services"}),
            ("Processes", {"Process Activity"}),
            ("Network", {"Network Security", "Network Configuration", "Listening Ports", "Remote Access"})
        )
        for label, categories in category_sets:
            relevant = [item for item in self.findings if item["category"] in categories]
            if not relevant: continue
            mark = "[WARN]" if any(item["result"] in ("WARNING", "FAIL") for item in relevant) else "[INFO]" if any(item["result"] == "UNKNOWN" for item in relevant) else "[ OK ]"
            print(f"{mark} {label}")
            if self.level in ("intermediate", "advanced"):
                for item in relevant:
                    if item["result"] in ("WARNING", "FAIL"):
                        print(f"    - {item['name']}: {item['severity']} ({item['result']})")
        
        high_priority = sum(item["classification"] == "HIGH PRIORITY REVIEW" for item in self.threats)
        print("-" * 50)
        print(" THREAT ANALYSIS (YARA)")
        print("-" * 50)
        print(f"Arquivos revisados: {len(self.threats)}")
        print(f"Scans YARA: {self.yara_summary.get('files_scanned', 0)}")
        print(f"Matches YARA: {self.yara_summary.get('matches', 0)}")
        print(f"Suspeitos / High Priority: {sum(item['classification'] in ('SUSPICIOUS', 'HIGH PRIORITY REVIEW') for item in self.threats)} / {high_priority}")
        
        print("-" * 50)
        print(" ESTATÍSTICAS")
        print("-" * 50)
        severity_counts = {severity: sum(item["severity"] == severity and item["result"] in ("WARNING", "FAIL") for item in self.findings) for severity in SEVERITIES}
        print(f"INFO: {sum(item['severity'] == 'INFO' for item in self.findings)} | LOW: {severity_counts['LOW']} | MEDIUM: {severity_counts['MEDIUM']} | HIGH: {severity_counts['HIGH']} | CRITICAL: {severity_counts['CRITICAL']}")
        print(f"Completo: {self.health['completeness']}% ({self.health['completed']} completados, {self.health['unavailable']} indisponíveis, {self.health['failed']} falharam)")
        print(f"\nSECURITY SCORE: {security_score(self.findings)} / 100")
        print(f"RISCO GERAL: {overall(self.findings)}")
        print("=" * 50 + "\n")
        
        try:
            save_txt = input("Deseja salvar os resultados acima em um arquivo .TXT? (s/N): ").strip().lower()
            if save_txt == "s":
                path = reports / f"atlhas1x_terminal_{self.level}_{stamp}.txt"
                path.write_text("Atlhas1x Terminal Report\n\nSee console output.", encoding="utf-8") # A simplified version for now since it's just the console output.
                print(f"Salvo em: {path}")
        except (KeyboardInterrupt, EOFError):
            pass
        return 0

def main():
    global LIVE_DETAILS, LIVE_LOG_PATH, SCAN_COMPLETED_MODULES
    parser = argparse.ArgumentParser(description="Run a local, read-only Windows security scan and generate an offline HTML report.")
    parser.add_argument("--report", choices=("basic", "intermediate", "advanced"), help="report detail level (default: intermediate)")
    parser.add_argument("--mode", choices=("basic", "intermediate", "advanced"), help=argparse.SUPPRESS)
    parser.add_argument("--terminal", action="store_true", help="run in terminal mode instead of HTML")
    parser.add_argument("--version", action="version", version=f"Atlhas1x {VERSION}")
    parser.add_argument("--live-details", action="store_true", help="show bounded command and response details for the local launcher")
    parser.add_argument("--live-log", help="local path used by the graphical launcher for live audit details")
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        # No arguments passed, show interactive menu
        level, output_mode = interactive_menu()
        LIVE_DETAILS = True
        LIVE_LOG_PATH = None
    else:
        level = args.report or args.mode or "intermediate"
        output_mode = "terminal" if args.terminal else "html"
        LIVE_DETAILS = args.live_details and level != "basic"
        LIVE_LOG_PATH = args.live_log if LIVE_DETAILS else None

    SCAN_COMPLETED_MODULES = 0
    started = dt.datetime.now()
    diagnostics = []
    profile_findings, profiles = run_module("Firewall Profiles", firewall_profiles, diagnostics)
    rule_finding, firewall_rules = run_module("Firewall Rules", firewall_rules_summary, diagnostics)
    interface_finding, interfaces, interface_error = run_module("Network Interfaces", network_interfaces, diagnostics)
    users_finding, local_users, users_error = run_module("Local Users", local_users_summary, diagnostics)
    device_guard, _ = run_module("Device Guard", device_guard_state, diagnostics)
    findings = [
        run_module("Windows Defender", defender_extended, diagnostics), *profile_findings, rule_finding,
        run_module("User Account Control", uac, diagnostics), run_module("Remote Desktop", rdp_extended, diagnostics),
        run_module("Local Administrators", administrators, diagnostics), run_module("BitLocker", bitlocker, diagnostics),
        run_module("Secure Boot", secure_boot, diagnostics), run_module("Windows Update", windows_update, diagnostics),
        run_module("Automatic Updates", automatic_updates, diagnostics), run_module("SMBv1", smbv1, diagnostics),
        run_module("Password Policy", password_policy, diagnostics), run_module("Account Lockout", account_lockout_policy, diagnostics),
        run_module("Guest Account", guest_account, diagnostics), run_module("Passwordless Accounts", passwordless_accounts, diagnostics),
        users_finding, run_module("PowerShell", powershell_security, diagnostics), run_module("System Proxy", proxy_configuration, diagnostics), interface_finding,
        run_module("Windows Defender Service", lambda: security_service("ATL-0015", "Windows Defender Service", "WinDefend"), diagnostics),
        run_module("Windows Firewall Service", lambda: security_service("ATL-0016", "Windows Firewall Service", "MpsSvc"), diagnostics),
        run_module("Windows Update Service", lambda: security_service("ATL-0017", "Windows Update Service", "wuauserv"), diagnostics),
        run_module("Security Center Service", lambda: security_service("ATL-0018", "Security Center Service", "wscsvc"), diagnostics),
        run_module("Startup Programs", startup_programs, diagnostics), run_module("Scheduled Tasks", scheduled_tasks, diagnostics),
        run_module("Network Shares", network_shares, diagnostics), run_module("Automatic Services", automatic_services, diagnostics),
        run_module("SmartScreen", smartscreen, diagnostics), run_module("Memory Integrity", memory_integrity, diagnostics),
        run_module("Virtualization-Based Security", lambda: virtualization_security(device_guard), diagnostics),
        run_module("Credential Guard", lambda: credential_guard(device_guard), diagnostics), run_module("LSASS Protection", lsass_protection, diagnostics),
        run_module("Cloud Protection", defender_cloud_protection, diagnostics), run_module("Tamper Protection", defender_tamper_protection, diagnostics),
        run_module("Defender Signatures", defender_signature_age, diagnostics), run_module("Defender Exclusions", defender_exclusions, diagnostics),
        run_module("Attack Surface Reduction", attack_surface_reduction, diagnostics), run_module("Controlled Folder Access", controlled_folder_access, diagnostics),
        run_module("Security Center Overview", security_center_overview, diagnostics),
    ]

    processes, process_error = run_module("Running Processes", running_processes, diagnostics)
    findings.append(run_module("Process Location Review", lambda: process_location_review(processes, process_error), diagnostics))
    listening, active_connections, network_error = run_module("Network Activity", lambda: network_inventory(processes), diagnostics)
    findings.append(run_module("Remote Desktop Port", lambda: rdp_listener(listening, network_error), diagnostics))
    findings.append(run_module("Hosts File", hosts_file_check, diagnostics))
    persistence, persistence_error = threat_persistence_inventory()
    exclusions, exclusions_error = defender_exclusion_paths_for_threats()
    threat_started = time.perf_counter()
    try:
        if analyze_threats is None:
            raise RuntimeError("Threat-analysis module is unavailable: " + (THREAT_ENGINE_IMPORT_ERROR or "unknown import error"))
        threats, yara_summary = analyze_threats(processes, listening, persistence, exclusions, Path("rules"), file_signature)
        findings.extend(threat_findings(threats, yara_summary))
    except Exception as exc:
        threats, yara_summary = [], {"engine": "NOT AVAILABLE", "reason": str(exc), "rules_discovered": 0, "rules_loaded": 0, "rules_failed": 0, "files_scanned": 0, "files_skipped": 0, "files_timed_out": 0, "matches": 0}
        findings.append(module_error_finding("Threat Analysis", str(exc)))
    threat_duration = time.perf_counter() - threat_started
    diagnostics.append({"Module": "Threat Analysis", "Duration": f"{threat_duration:.3f}s"})
    SCAN_COMPLETED_MODULES += 1
    live_detail("PROGRESS", f"{SCAN_COMPLETED_MODULES}/{SCAN_TOTAL_MODULES}|Threat Analysis")
    findings = finalize_findings(findings)
    process_reviews = sum(value_available(item["Path"]) and unusual_path(item["Path"]) for item in processes)
    network_reviews = sum(item["Local Port"] == "3389" for item in listening)
    inventories = [
        inventory("Firewall Profiles", ("Name", "Enabled", "DefaultInboundAction", "DefaultOutboundAction"), profiles),
        inventory("Firewall Rules (first 100)", ("DisplayName", "Enabled", "Direction", "Action"), firewall_rules),
        inventory("Network Interfaces", ("Adapter", "Status", "IPv4", "IPv6", "MAC", "DNS"), interfaces, error=interface_error),
        inventory("Local Users", ("Name", "Enabled", "PrincipalSource"), local_users, error=users_error),
        inventory("Process Inventory", ("PID", "Process", "User", "Path"), processes, process_reviews, process_error),
        inventory("Listening Port Inventory", ("Protocol", "Local Address", "Local Port", "Exposure", "PID", "Process"), listening, network_reviews, network_error),
        inventory("Active Connection Inventory", ("Process", "PID", "Local Address", "Local Port", "Remote Address", "Remote Port", "State"), active_connections, 0, network_error),
        inventory("Threat Analysis Inventory", ("path", "classification", "suspicion_score", "indicators"), threats, error=persistence_error or exclusions_error),
    ]
    info = system_info()
    ended = dt.datetime.now()
    health = scan_health(findings)
    
    if output_mode == "terminal":
        renderer = TerminalRenderer(level, findings, info, started, ended, inventories, health, diagnostics, threats, yara_summary)
    else:
        renderer = HTMLRenderer(level, findings, info, started, ended, inventories, health, diagnostics, threats, yara_summary)
    
    return renderer.render()

if __name__ == "__main__": raise SystemExit(main())
