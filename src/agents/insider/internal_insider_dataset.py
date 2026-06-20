import re
from typing import Any, Dict, List, Tuple

# 35 feature names
FEATURE_COLUMNS = [
    "role_admin", "role_finance", "role_developer", "role_hr", "role_normal",
    "work_after_hours", "work_weekends", "unusual_login_time", "unusual_pc_login",
    "access_unauthorized_scope", "access_sensitive_dirs", "access_intellectual_property",
    "access_hr_db", "access_finance_system", "high_volume_download",
    "download_count", "usb_write_count", "usb_mount_attempt", "cloud_upload_count",
    "printing_sensitive_files", "log_deletion_attempt", "sudoers_modification",
    "cron_tampering", "syslog_stop_attempt", "credential_sharing_indicators",
    "switch_user_count", "command_count", "duration_sec", "command_density",
    "failed_sudo_count", "obfuscated_command_count", "network_connection_count",
    "suspicious_process_spawned", "calculated_risk_score", "behavior_deviation_score"
]

def extract_features(session: Dict[str, Any]) -> Dict[str, float]:
    """
    Extracts 35 organizational-context features from a session dictionary.
    """
    # Extract roles (default to normal if not specified)
    role = str(session.get("role", "normal")).lower()
    features = {
        "role_admin": float(1 if role == "admin" else 0),
        "role_finance": float(1 if role == "finance" else 0),
        "role_developer": float(1 if role == "developer" else 0),
        "role_hr": float(1 if role == "hr" else 0),
        "role_normal": float(1 if role in {"normal", "employee", "staff"} else 0),
    }

    # Temporal access features
    features["work_after_hours"] = float(session.get("work_after_hours", 0))
    features["work_weekends"] = float(session.get("work_weekends", 0))
    features["unusual_login_time"] = float(session.get("unusual_login_time", 0))
    features["unusual_pc_login"] = float(session.get("unusual_pc_login", 0))

    # Unauthorized access features
    features["access_unauthorized_scope"] = float(session.get("access_unauthorized_scope", 0))
    features["access_sensitive_dirs"] = float(session.get("access_sensitive_dirs", 0))
    features["access_intellectual_property"] = float(session.get("access_intellectual_property", 0))
    features["access_hr_db"] = float(session.get("access_hr_db", 0))
    features["access_finance_system"] = float(session.get("access_finance_system", 0))

    # Exfiltration features
    features["high_volume_download"] = float(session.get("high_volume_download", 0))
    features["download_count"] = float(session.get("download_count", 0))
    features["usb_write_count"] = float(session.get("usb_write_count", 0))
    features["usb_mount_attempt"] = float(session.get("usb_mount_attempt", 0))
    features["cloud_upload_count"] = float(session.get("cloud_upload_count", 0))
    features["printing_sensitive_files"] = float(session.get("printing_sensitive_files", 0))

    # Cover-up / Persistence
    features["log_deletion_attempt"] = float(session.get("log_deletion_attempt", 0))
    features["sudoers_modification"] = float(session.get("sudoers_modification", 0))
    features["cron_tampering"] = float(session.get("cron_tampering", 0))
    features["syslog_stop_attempt"] = float(session.get("syslog_stop_attempt", 0))

    # Contextual and numeric
    features["credential_sharing_indicators"] = float(session.get("credential_sharing_indicators", 0))
    features["switch_user_count"] = float(session.get("switch_user_count", 0))
    features["command_count"] = float(session.get("command_count", len(session.get("commands", []))))
    features["duration_sec"] = float(session.get("duration_sec", 0))
    if features["duration_sec"] > 0:
        features["command_density"] = features["command_count"] / features["duration_sec"]
    else:
        features["command_density"] = 0.0

    features["failed_sudo_count"] = float(session.get("failed_sudo_count", 0))
    features["obfuscated_command_count"] = float(session.get("obfuscated_command_count", 0))
    features["network_connection_count"] = float(session.get("network_connection_count", 0))
    features["suspicious_process_spawned"] = float(session.get("suspicious_process_spawned", 0))

    # Dynamic risk calculations
    risk_score = 0.0
    # Weights for risk scoring
    weights = {
        "access_unauthorized_scope": 15,
        "access_sensitive_dirs": 10,
        "usb_write_count": 10,
        "cloud_upload_count": 10,
        "log_deletion_attempt": 15,
        "syslog_stop_attempt": 15,
        "sudoers_modification": 15,
        "failed_sudo_count": 5,
        "suspicious_process_spawned": 15,
        "work_after_hours": 5,
        "unusual_login_time": 5,
    }
    for key, weight in weights.items():
        if features.get(key, 0) > 0:
            risk_score += weight
    features["calculated_risk_score"] = min(risk_score, 100.0)

    # Behavior deviation
    features["behavior_deviation_score"] = float(session.get("behavior_deviation_score", features["calculated_risk_score"] / 100.0))

    return features

def determine_label(features: Dict[str, float], explicit_label: int = 0) -> Tuple[int, str]:
    """
    Applies the 7 decision paths to decide if the session is a Malicious Insider (1) or Normal (0).
    """
    if explicit_label == 1:
        return 1, "Path 1: Explicit malicious label"

    # Exfiltration + Cover-Up
    if (features["high_volume_download"] > 0 or features["usb_write_count"] > 0 or features["cloud_upload_count"] > 0) and \
       (features["log_deletion_attempt"] > 0 or features["syslog_stop_attempt"] > 0):
        return 1, "Path 2: Exfiltration combined with audit log tampering cover-up"

    # Log Tampering + Privilege Abuse
    if (features["log_deletion_attempt"] > 0 or features["syslog_stop_attempt"] > 0) and \
       (features["failed_sudo_count"] > 2 or features["sudoers_modification"] > 0):
        return 1, "Path 3: Log tampering combined with privilege abuse attempts"

    # Privilege Escalation + Unauthorized Access
    if (features["sudoers_modification"] > 0 or features["cron_tampering"] > 0 or features["suspicious_process_spawned"] > 0) and \
       (features["access_unauthorized_scope"] > 0 or features["access_sensitive_dirs"] > 0):
        return 1, "Path 4: Privilege escalation/persistence combined with unauthorized access"

    # Credential Abuse + Timing Anomalies
    if (features["credential_sharing_indicators"] > 0 or features["unusual_pc_login"] > 0) and \
       (features["work_after_hours"] > 0 or features["work_weekends"] > 0):
        return 1, "Path 5: Credential/PC login anomaly during non-working hours"

    # Unauthorized Exfiltration
    if features["access_unauthorized_scope"] > 0 and \
       (features["usb_write_count"] > 0 or features["cloud_upload_count"] > 0 or features["printing_sensitive_files"] > 0):
        return 1, "Path 6: Exfiltration of files accessed outside authorization scope"

    # High Overall Risk Score
    if features["calculated_risk_score"] >= 60.0:
        return 1, f"Path 7: High calculated risk score ({features['calculated_risk_score']})"

    return 0, "Normal session behavior"
