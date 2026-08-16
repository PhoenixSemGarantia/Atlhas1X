"""Focused, read-only heuristics for Atlhas1x suspicious-activity analysis."""
import datetime as dt
import hashlib
import os
import re
from pathlib import Path

from yara_engine import YaraEngine


RECENT_FILE_HOURS = 24
MAX_RECENT_FILES = 250
SYSTEM_PROCESS_NAMES = {"svchost.exe", "lsass.exe", "services.exe", "winlogon.exe", "explorer.exe"}

# v1.2: all heuristic scoring lives here. These are relevance weights, not a
# malware probability or a replacement for an analyst's judgement.
INDICATOR_WEIGHTS = {
    "RECENT_FILE": 5,
    "DOWNLOAD_LOCATION": 8,
    "TEMP_LOCATION": 12,
    "UNSIGNED": 10,
    "UNKNOWN_PUBLISHER": 5,
    "INVALID_SIGNATURE": 20,
    "STARTUP_PERSISTENCE": 15,
    "SCHEDULED_TASK_PERSISTENCE": 15,
    "SERVICE_PERSISTENCE": 18,
    "NETWORK_LISTENER": 12,
    "PUBLIC_NETWORK_LISTENER": 18,
    "UNEXPECTED_SYSTEM_PROCESS_PATH": 30,
    "DEFENDER_EXCLUSION": 20,
    "MISSING_EXECUTABLE": 30,
    "YARA_LOW_CONFIDENCE": 15,
    "YARA_MEDIUM_CONFIDENCE": 30,
    "YARA_HIGH_CONFIDENCE": 45,
    "CORRELATED_WEAK_INDICATORS": 5,
}
POSITIVE_INDICATOR_CREDITS = {
    "VALID_MICROSOFT_SIGNATURE": 20,
    "VALID_TRUSTED_SIGNATURE": 12,
    "EXPECTED_WINDOWS_PATH": 10,
    "EXPECTED_PROGRAM_FILES_PATH": 8,
    "KNOWN_WINDOWS_COMPONENT": 10,
}


def normalized_process_name(name):
    name = str(name or "").lower()
    return name if not name or name.endswith(".exe") else name + ".exe"


def normalized_path(path):
    """Normalise quoted Windows paths for deduplication and comparisons."""
    text = expand_windows_environment(path).strip().strip('"').replace("/", "\\")
    text = re.sub(r"\\+", r"\\", text)
    return text.lower()


def is_unusual_path(path):
    text = str(path or "").lower().replace("/", "\\")
    return "\\temp\\" in text or "\\downloads\\" in text or "\\desktop\\" in text


def expand_windows_environment(path):
    """Expand %VAR% paths returned by Windows task/service APIs safely."""
    text = str(path or "").strip()
    return re.sub(r"%([^%]+)%", lambda match: os.environ.get(match.group(1), os.environ.get(match.group(1).upper(), match.group(0))), text)


def expected_windows_location(path):
    """Recognise normal Windows/Program Files executables before correlating."""
    text = expand_windows_environment(path).lower().replace("/", "\\")
    return (bool(re.match(r"^[a-z]:\\windows\\", text)) or bool(re.match(r"^[a-z]:\\program files(?: \(x86\))?\\", text))
            or text.startswith("%windir%\\") or text.startswith("%systemroot%\\"))


def expected_program_files_location(path):
    return bool(re.match(r"^[a-z]:\\program files(?: \(x86\))?\\", normalized_path(path)))


def persistence_path_worth_review(path):
    """Limit persistence candidates; Windows scheduled tasks are normal by default."""
    text = expand_windows_environment(path).lower().replace("/", "\\")
    if not text or expected_windows_location(text):
        return False
    return (is_unusual_path(text) or "\\appdata\\" in text or "\\users\\public\\" in text)


def expected_system_path(name, path):
    """Conservative check: only flag system names when a real path is known."""
    name = normalized_process_name(name)
    path = str(path or "").lower().replace("/", "\\")
    if name not in SYSTEM_PROCESS_NAMES or not path:
        return False
    if name == "explorer.exe":
        return path.endswith("\\windows\\explorer.exe")
    return "\\windows\\system32\\" in path or "\\windows\\syswow64\\" in path


def listener_is_public(listener):
    address = str(listener.get("Local Address") or listener.get("local_address") or "").strip().lower()
    return address in ("0.0.0.0", "::") or (address not in ("", "127.0.0.1", "::1", "localhost") and not address.startswith("127."))


def yara_confidence(matches):
    """Classify a group of YARA matches conservatively from local metadata."""
    if not matches:
        return None
    declared = {str(match.get("meta", {}).get("confidence", "")).upper() for match in matches}
    if "HIGH" in declared:
        return "HIGH"
    if "LOW" in declared:
        return "LOW"
    high_words = {"malware", "trojan", "ransom", "backdoor", "credential", "stealer"}
    low_words = {"generic", "packer", "packed", "string", "test", "benign", "encoded", "pe_"}
    evidence = " ".join(
        " ".join([str(match.get("rule", "")), str(match.get("namespace", "")), " ".join(map(str, match.get("tags", []))), " ".join(f"{key}={value}" for key, value in match.get("meta", {}).items())])
        for match in matches
    ).lower()
    if any(word in evidence for word in high_words):
        return "HIGH"
    if any(word in evidence for word in low_words):
        return "LOW"
    return "MEDIUM"


def extract_executable(value):
    """Extract a likely executable from a startup/task/service command safely."""
    if isinstance(value, dict):
        value = value.get("Path") or value.get("Action") or value.get("Execute") or value.get("Value") or ""
    if isinstance(value, (list, tuple)):
        value = next((item for item in value if item), "")
    text = expand_windows_environment(value)
    if not text:
        return ""
    if text.startswith('"') and '"' in text[1:]:
        return text.split('"', 2)[1]
    lower = text.lower()
    for extension in (".exe", ".dll", ".sys", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".js"):
        index = lower.find(extension)
        if index >= 0:
            return text[:index + len(extension)]
    # Do not turn "Access restricted" or another status message into a file.
    return ""


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def age_hours(timestamp, now=None):
    now = now or dt.datetime.now().timestamp()
    return max(0, (now - timestamp) / 3600)


def file_metadata(path, related_to, signature_lookup=None, now=None):
    path = Path(path)
    try:
        data = path.stat()
    except OSError as exc:
        return {"path": str(path), "available": False, "reason": str(exc), "related_to": sorted(related_to)}
    modified_age = age_hours(data.st_mtime, now)
    created_age = age_hours(data.st_ctime, now)
    metadata = {
        "path": str(path), "available": True, "size": data.st_size,
        "created": dt.datetime.fromtimestamp(data.st_ctime).isoformat(timespec="seconds"),
        "modified": dt.datetime.fromtimestamp(data.st_mtime).isoformat(timespec="seconds"),
        "recent": modified_age <= RECENT_FILE_HOURS or created_age <= RECENT_FILE_HOURS,
        "age_hours": round(min(modified_age, created_age), 2),
        "related_to": sorted(related_to), "sha256": None, "signature": {"status": "UNKNOWN"},
    }
    try:
        metadata["sha256"] = sha256(path)
    except OSError as exc:
        metadata["hash_error"] = str(exc)
    if signature_lookup:
        try:
            metadata["signature"] = signature_lookup(str(path)) or {"status": "UNKNOWN"}
        except Exception:
            metadata["signature"] = {"status": "UNKNOWN"}
    return metadata


def _classification(score):
    if score >= 70:
        return "HIGH PRIORITY REVIEW", "HIGH"
    if score >= 50:
        return "SUSPICIOUS", "MEDIUM"
    if score >= 30:
        return "NEEDS REVIEW", "MEDIUM"
    if score >= 15:
        return "OBSERVE", "LOW"
    return "NORMAL", "INFO"


def _suspicion(indicators, positive_indicators=()):
    """Return a bounded score plus an auditable calculation breakdown."""
    indicator_set = list(dict.fromkeys(indicators))
    positive_set = list(dict.fromkeys(positive_indicators))
    additions = [(name, INDICATOR_WEIGHTS[name]) for name in indicator_set if name in INDICATOR_WEIGHTS]
    reductions = [(name, POSITIVE_INDICATOR_CREDITS[name]) for name in positive_set if name in POSITIVE_INDICATOR_CREDITS]
    raw_score = sum(value for _, value in additions) - sum(value for _, value in reductions)
    reasoning = ([{"indicator": name, "impact": value} for name, value in additions] +
                 [{"indicator": name, "impact": -value} for name, value in reductions])
    return max(0, min(100, raw_score)), reasoning


def analyze(processes, listening, persistence, exclusions, rules_root, signature_lookup=None):
    """Build correlated records only for paths already found by the scanner."""
    candidates = {}
    def add(path, relation, process=None, listener=None):
        raw_path = str(path or "").strip()
        if raw_path.upper() in ("", "UNKNOWN", "ACCESS RESTRICTED", "N/A", "NOT AVAILABLE"):
            return
        path = extract_executable(path)
        if not path:
            return
        item = candidates.setdefault(normalized_path(path), {"path": path, "relations": set(), "processes": [], "listeners": []})
        item["relations"].add(relation)
        if process and process not in item["processes"]: item["processes"].append(process)
        if listener and listener not in item["listeners"]: item["listeners"].append(listener)

    listeners_by_pid = {}
    for listener in listening:
        listeners_by_pid.setdefault(str(listener.get("PID")), []).append(listener)
    for process in processes:
        for listener in listeners_by_pid.get(str(process.get("PID")), []):
            add(process.get("Path"), "PROCESS", process, listener)
        path = process.get("Path")
        process_name = normalized_process_name(process.get("Process"))
        if is_unusual_path(path) or (process_name in SYSTEM_PROCESS_NAMES and not expected_system_path(process_name, path)):
            add(path, "PROCESS", process)
    for relation, entries in persistence.items():
        for entry in entries:
            path = entry.get("Path") or entry.get("Action") or entry.get("Command") or entry.get("PathName")
            # A task/service/startup entry is not suspicious by itself. Avoid
            # feeding the hundreds of normal Windows tasks into the engine.
            if persistence_path_worth_review(path):
                add(path, relation, None)

    engine = YaraEngine(rules_root)
    records = []
    # Bound expensive metadata, hash, signature and YARA reads. The scanner
    # never walks the full disk; it only examines this focused candidate set.
    for item in list(candidates.values())[:MAX_RECENT_FILES]:
        metadata = file_metadata(item["path"], item["relations"], signature_lookup)
        indicators = []
        positive_indicators = []
        path = item["path"]
        lowered = normalized_path(path)
        if "\\temp\\" in lowered: indicators.append("TEMP_LOCATION")
        if "\\downloads\\" in lowered: indicators.append("DOWNLOAD_LOCATION")
        if metadata.get("recent"): indicators.append("RECENT_FILE")
        if item["listeners"]:
            indicators.append("NETWORK_LISTENER")
            if any(listener_is_public(listener) for listener in item["listeners"]):
                indicators.append("PUBLIC_NETWORK_LISTENER")
        if any(not expected_system_path(p.get("Process"), path) and normalized_process_name(p.get("Process")) in SYSTEM_PROCESS_NAMES for p in item["processes"]):
            indicators.append("UNEXPECTED_SYSTEM_PROCESS_PATH")
        if any(path.lower().startswith(str(value).lower().rstrip("\\/") + "\\") for value in exclusions if value):
            indicators.append("DEFENDER_EXCLUSION")
        if not metadata.get("available") and item["relations"].intersection({"STARTUP", "SCHEDULED_TASK", "SERVICE"}):
            indicators.append("MISSING_EXECUTABLE")
        yara = engine.scan(path)
        if yara["matches"]:
            level = yara_confidence(yara["matches"])
            indicators.append("YARA_" + level + "_CONFIDENCE")
        signature = metadata.get("signature", {})
        signature_status = str(signature.get("status", "UNKNOWN")).upper()
        if signature_status == "VALID_MICROSOFT":
            positive_indicators.append("VALID_MICROSOFT_SIGNATURE")
        elif signature_status == "VALID":
            positive_indicators.append("VALID_TRUSTED_SIGNATURE")
        elif signature_status == "UNSIGNED":
            indicators.append("UNSIGNED")
        elif signature_status == "INVALID":
            indicators.append("INVALID_SIGNATURE")
        elif signature_status == "UNKNOWN":
            indicators.append("UNKNOWN_PUBLISHER")
        if expected_windows_location(path):
            positive_indicators.append("EXPECTED_WINDOWS_PATH")
        if expected_program_files_location(path):
            positive_indicators.append("EXPECTED_PROGRAM_FILES_PATH")
        if any(expected_system_path(process.get("Process"), path) for process in item["processes"]):
            positive_indicators.append("KNOWN_WINDOWS_COMPONENT")
        # Persistence contributes only when paired with another signal. This
        # keeps normal Windows and signed vendor tasks out of the findings.
        supporting_indicators = set(indicators) - {"NETWORK_LISTENER", "PUBLIC_NETWORK_LISTENER", "UNKNOWN_PUBLISHER"}
        if supporting_indicators:
            for relation, indicator in (("STARTUP", "STARTUP_PERSISTENCE"), ("SCHEDULED_TASK", "SCHEDULED_TASK_PERSISTENCE"), ("SERVICE", "SERVICE_PERSISTENCE")):
                if relation in item["relations"]:
                    indicators.append(indicator)
        weak_signals = {"RECENT_FILE", "TEMP_LOCATION", "DOWNLOAD_LOCATION", "UNSIGNED"}.intersection(indicators)
        if len(weak_signals) >= 3:
            indicators.append("CORRELATED_WEAK_INDICATORS")
        # A listening port (including a public listener) is context, not a
        # threat by itself. Unknown publisher is also deliberately neutral.
        independent_risk = set(indicators) - {"NETWORK_LISTENER", "PUBLIC_NETWORK_LISTENER", "UNKNOWN_PUBLISHER"}
        scoring_indicators = indicators if independent_risk else []
        score, reasoning = _suspicion(scoring_indicators, positive_indicators)
        classification, severity = _classification(score)
        support_for_backdoor = {"TEMP_LOCATION", "DOWNLOAD_LOCATION", "UNSIGNED", "INVALID_SIGNATURE", "STARTUP_PERSISTENCE", "SCHEDULED_TASK_PERSISTENCE", "SERVICE_PERSISTENCE", "YARA_HIGH_CONFIDENCE", "YARA_MEDIUM_CONFIDENCE", "RECENT_FILE", "UNEXPECTED_SYSTEM_PROCESS_PATH"}
        potential_backdoor = bool(item["listeners"] and len(support_for_backdoor.intersection(indicators)) >= 2)
        possible_false_positive = bool(positive_indicators and (yara["matches"] or indicators))
        if score or yara["matches"]:
            records.append({**item, "metadata": metadata, "yara": yara, "indicators": list(dict.fromkeys(indicators)), "positive_indicators": list(dict.fromkeys(positive_indicators)), "reasoning": reasoning, "potential_backdoor": potential_backdoor, "possible_false_positive": possible_false_positive, "suspicion_score": score, "classification": classification, "severity": severity})
    records.sort(key=lambda item: item["suspicion_score"], reverse=True)
    return records[:MAX_RECENT_FILES], engine.summary
