import csv
import ipaddress
import os
import re
from typing import Dict, List, Tuple, Optional

DEFAULT_FEATURE_COLUMNS = [
    "num_commands",
    "duration_sec",
    "command_density",
    "num_downloads",
    "has_downloads",
    "src_ip_internal",
    "short_session",
    "low_noise_session",
    "privileged_command_count",
    "persistence_command_count",
    "credential_command_count",
    "suspicious_command_count",
    "triage_priority",
    "triage_is_go",
    "triage_is_packed",
    "triage_is_stripped",
    "triage_is_dll",
    "triage_is_static",
    "triage_score_mining",
    "triage_score_botnet",
    "triage_score_recon",
    "triage_score_destructive",
    "mitre_severity_max",
    "mitre_severity_weighted",
    "mitre_kill_chain_score",
    "mitre_matched_commands",
    "has_ghidra_results",
    "has_angr_results",
    "has_script_results",
]

DEFAULT_LABEL_CONFIG = {
    "short_duration_sec": 5.0,
    "short_commands": 2,
    "low_activity_duration_sec": 8.0,
    "low_activity_commands": 3,
    "require_attack_label": False,
}

PRIVILEGED_PATTERNS = [
    "sudo",
    "passwd",
    "chattr",
    "chmod",
    "useradd",
    "usermod",
    "userdel",
    "chown",
    "chgrp",
    "sudo su",
    "su -",
    "systemctl",
    "service",
    "iptables",
    "mount",
    "umount",
]

PERSISTENCE_PATTERNS = [
    ".ssh/authorized_keys",
    ".ssh",
    "crontab",
    "cron",
    "rc.local",
    "bashrc",
    "profile",
    "systemd",
    "init.d",
    "rc.d",
    "at ",
    "anacron",
]

CREDENTIAL_PATTERNS = [
    "cat /etc/shadow",
    "cat /etc/passwd",
    "ssh-keygen",
    "ssh-rsa",
    "id_rsa",
    "id_dsa",
    "openssl genrsa",
    "gpg",
    "passwd",
    "token",
    "api_key",
]

SUSPICIOUS_PATTERNS = [
    "wget http",
    "curl http",
    "bash -i",
    "nc -e",
    "python -c",
    "perl -e",
    "base64 -d",
    "sh -i",
    "sudo chmod 777",
    "rm -rf",
    "history | tail",
    "netstat -tulpn",
    "ps aux",
    "uname -a",
    "whoami",
    "hostname",
    "id",
    "ifconfig",
    "ip a",
    "scp ",
    "rsync ",
]


def _is_private_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip.strip())
        return address.is_private or address.is_loopback
    except ValueError:
        return False


def _normalize_commands(value: Optional[str]) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        value = " ".join(value)
    text = str(value).lower()
    text = re.sub(r"[\r\n]+", " ", text)
    return text


def _count_patterns(text: str, patterns: List[str]) -> int:
    return sum(1 for pattern in patterns if pattern in text)


def count_internal_sessions(rows: List[Dict[str, str]]) -> int:
    return sum(1 for row in rows if _is_private_ip(row.get("src_ip")))


def _safe_int(value: Optional[str]) -> int:
    try:
        return int(float(value))
    except Exception:
        return 0


def _safe_float(value: Optional[str]) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0


def _parse_list(value: Optional[str]) -> List[str]:
    if value is None:
        return []
    text = str(value).strip()
    if not text or text.lower() in {"none", "nan", "null"}:
        return []
    if "|" in text:
        return [item.strip() for item in text.split("|") if item.strip()]
    return [item.strip() for item in text.split(",") if item.strip()]


def load_export_dataset(csv_path: str, max_rows: Optional[int] = None) -> List[Dict[str, str]]:
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Export dataset not found: {csv_path}")

    rows = []
    with open(csv_path, "r", newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for index, row in enumerate(reader):
            rows.append(row)
            if max_rows is not None and index + 1 >= max_rows:
                break
    return rows


def _build_feature_row(row: Dict[str, str]) -> Dict[str, float]:
    num_commands = _safe_int(row.get("num_commands"))
    duration_sec = _safe_float(row.get("duration_sec"))
    num_downloads = _safe_int(row.get("num_downloads"))
    command_density = num_commands / max(duration_sec, 1.0)
    has_downloads = 1 if num_downloads > 0 else 0
    src_ip_internal = float(1 if _is_private_ip(row.get("src_ip")) else 0)
    normalized_commands = _normalize_commands(row.get("commands"))
    privileged_count = _count_patterns(normalized_commands, PRIVILEGED_PATTERNS)
    persistence_count = _count_patterns(normalized_commands, PERSISTENCE_PATTERNS)
    credential_count = _count_patterns(normalized_commands, CREDENTIAL_PATTERNS)
    suspicious_count = _count_patterns(normalized_commands, SUSPICIOUS_PATTERNS)
    short_session = float(1 if duration_sec <= DEFAULT_LABEL_CONFIG["short_duration_sec"] else 0)
    low_noise_session = float(1 if num_downloads == 0 and num_commands <= DEFAULT_LABEL_CONFIG["low_activity_commands"] else 0)

    feature_values = {
        "num_commands": float(num_commands),
        "duration_sec": float(duration_sec),
        "command_density": float(command_density),
        "num_downloads": float(num_downloads),
        "has_downloads": float(has_downloads),
        "src_ip_internal": src_ip_internal,
        "short_session": short_session,
        "low_noise_session": low_noise_session,
        "privileged_command_count": float(privileged_count),
        "persistence_command_count": float(persistence_count),
        "credential_command_count": float(credential_count),
        "suspicious_command_count": float(suspicious_count),
        "triage_priority": _safe_float(row.get("triage_priority")),
        "triage_is_go": float(1 if _safe_float(row.get("triage_is_go")) else 0),
        "triage_is_packed": float(1 if _safe_float(row.get("triage_is_packed")) else 0),
        "triage_is_stripped": float(1 if _safe_float(row.get("triage_is_stripped")) else 0),
        "triage_is_dll": float(1 if _safe_float(row.get("triage_is_dll")) else 0),
        "triage_is_static": float(1 if _safe_float(row.get("triage_is_static")) else 0),
        "triage_score_mining": _safe_float(row.get("triage_score_mining")),
        "triage_score_botnet": _safe_float(row.get("triage_score_botnet")),
        "triage_score_recon": _safe_float(row.get("triage_score_recon")),
        "triage_score_destructive": _safe_float(row.get("triage_score_destructive")),
        "mitre_severity_max": _safe_float(row.get("mitre_severity_max")),
        "mitre_severity_weighted": _safe_float(row.get("mitre_severity_weighted")),
        "mitre_kill_chain_score": _safe_float(row.get("mitre_kill_chain_score")),
        "mitre_matched_commands": float(_safe_int(row.get("mitre_matched_commands"))),
        "has_ghidra_results": float(1 if _safe_int(row.get("has_ghidra_results")) else 0),
        "has_angr_results": float(1 if _safe_int(row.get("has_angr_results")) else 0),
        "has_script_results": float(1 if _safe_int(row.get("has_script_results")) else 0),
    }
    return feature_values


def build_insider_label(row: Dict[str, str], thresholds: Optional[Dict[str, float]] = None) -> Tuple[int, str]:
    if thresholds is None:
        thresholds = DEFAULT_LABEL_CONFIG

    label_name = str(row.get("label_name", "Safe")).strip()
    num_commands = _safe_int(row.get("num_commands"))
    duration_sec = _safe_float(row.get("duration_sec"))
    num_downloads = _safe_int(row.get("num_downloads"))
    commands_text = _normalize_commands(row.get("commands"))
    is_attack = label_name.lower() != "safe"

    privileged_attack = _count_patterns(commands_text, PRIVILEGED_PATTERNS) > 0
    persistence_attack = _count_patterns(commands_text, PERSISTENCE_PATTERNS) > 0
    credential_attack = _count_patterns(commands_text, CREDENTIAL_PATTERNS) > 0
    suspicious_attack = _count_patterns(commands_text, SUSPICIOUS_PATTERNS) > 0
    internal_source = _is_private_ip(row.get("src_ip"))
    mitre_severity_max = _safe_float(row.get("mitre_severity_max"))

    if thresholds["require_attack_label"] and not is_attack:
        return 0, "Not an attacker-labeled session"

    if internal_source and (privileged_attack or persistence_attack or credential_attack or suspicious_attack):
        return 1, "Internal source with suspicious or privileged commands"

    if privileged_attack and suspicious_attack:
        return 1, "Privileged command combined with suspicious behavior"

    if persistence_attack and suspicious_attack:
        return 1, "Persistence command combined with suspicious behavior"

    if label_name.lower() != "safe" and (privileged_attack or persistence_attack or credential_attack or suspicious_attack):
        return 1, "Confirmed attacker-like session with insider-like tactics"

    if num_downloads > 0 and (mitre_severity_max >= 5 or suspicious_attack):
        return 1, "Download activity with high severity or suspicious command patterns"

    return 0, "Normal session behavior"


def build_insider_dataset(
    rows: List[Dict[str, str]],
    thresholds: Optional[Dict[str, float]] = None,
) -> Tuple[List[List[float]], List[int], List[str], List[Dict[str, str]]]:
    X = []
    y = []
    reasons = []
    output_rows = []

    for row in rows:
        features = _build_feature_row(row)
        label, reason = build_insider_label(row, thresholds)

        X.append([features[col] for col in DEFAULT_FEATURE_COLUMNS])
        y.append(label)
        reasons.append(reason)

        output_row = {
            "session_id": row.get("session_id", ""),
            **{col: features[col] for col in DEFAULT_FEATURE_COLUMNS},
            "label": label,
            "label_reason": reason,
            "label_name": row.get("label_name", ""),
        }
        output_rows.append(output_row)

    return X, y, DEFAULT_FEATURE_COLUMNS, output_rows


def save_insider_dataset(rows: List[Dict[str, str]], output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    if not rows:
        raise ValueError("No rows available to save for insider dataset.")

    fieldnames = list(rows[0].keys())
    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
