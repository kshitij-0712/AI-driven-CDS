import os
import csv
import json
import random
from datetime import datetime
from typing import Dict, Any, List

# Target output files
OUTPUT_DIR = "./data/insider"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "internal_insider_dataset_base.csv")

# Input CERT raw files
CERT_DIR = "./data/cert_raw"
LOGON_CSV = os.path.join(CERT_DIR, "logon.csv")
DEVICE_CSV = os.path.join(CERT_DIR, "device.csv")
FILE_CSV = os.path.join(CERT_DIR, "file.csv")
EMAIL_CSV = os.path.join(CERT_DIR, "email.csv")
PSYCH_CSV = os.path.join(CERT_DIR, "psychometric.csv")

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

def parse_time(dt_str: str) -> datetime:
    formats = ["%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S"]
    for fmt in formats:
        try:
            return datetime.strptime(dt_str, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(dt_str)
    except Exception:
        return datetime.now()

def main():
    print("=== STARTING CERT DATASET COMPILATION ===")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # 1. Parse Psychometric data
    psych_data = {}
    if os.path.exists(PSYCH_CSV):
        print(f"Parsing psychometric data from {PSYCH_CSV}...")
        with open(PSYCH_CSV, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"]
                psych_data[uid] = {
                    "O": float(row["O"]),
                    "C": float(row["C"]),
                    "E": float(row["E"]),
                    "A": float(row["A"]),
                    "N": float(row["N"])
                }
    else:
        print("WARNING: psychometric.csv not found.")

    # 2. Process Logon data
    user_sessions = {}
    if os.path.exists(LOGON_CSV):
        print(f"Streaming logon events from {LOGON_CSV}...")
        with open(LOGON_CSV, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                user = row["user"]
                pc = row["pc"]
                activity = row["activity"]
                dt = parse_time(row["date"])
                
                if user not in user_sessions:
                    user_sessions[user] = []
                
                # Simple session builder: Group activities by day
                day_key = dt.strftime("%Y-%m-%d")
                session_id = f"cert_{user}_{day_key}"
                
                # Check if we have an active session for this user on this day
                session = next((s for s in user_sessions[user] if s["session_id"] == session_id), None)
                if not session:
                    # Assign a random role based on user ID hash for consistency
                    r_hash = hash(user) % 5
                    role = "normal"
                    if r_hash == 0: role = "admin"
                    elif r_hash == 1: role = "developer"
                    elif r_hash == 2: role = "finance"
                    elif r_hash == 3: role = "hr"
                    
                    session = {
                        "session_id": session_id,
                        "user_id": user,
                        "role": role,
                        "work_after_hours": 0.0,
                        "work_weekends": 0.0,
                        "unusual_login_time": 0.0,
                        "unusual_pc_login": 0.0,
                        "access_unauthorized_scope": 0.0,
                        "access_sensitive_dirs": 0.0,
                        "access_intellectual_property": 0.0,
                        "access_hr_db": 0.0,
                        "access_finance_system": 0.0,
                        "high_volume_download": 0.0,
                        "download_count": 0.0,
                        "usb_write_count": 0.0,
                        "usb_mount_attempt": 0.0,
                        "cloud_upload_count": 0.0,
                        "printing_sensitive_files": 0.0,
                        "log_deletion_attempt": 0.0,
                        "sudoers_modification": 0.0,
                        "cron_tampering": 0.0,
                        "syslog_stop_attempt": 0.0,
                        "credential_sharing_indicators": 0.0,
                        "switch_user_count": 0.0,
                        "command_count": 0.0,
                        "duration_sec": 0.0,
                        "failed_sudo_count": 0.0,
                        "obfuscated_command_count": 0.0,
                        "network_connection_count": 0.0,
                        "suspicious_process_spawned": 0.0,
                        "logons": [],
                        "pcs": set()
                    }
                    user_sessions[user].append(session)
                
                session["logons"].append(dt)
                session["pcs"].add(pc)
                
                count += 1
                if count >= 100000: # Limit processing to 100k logon rows for compilation speed
                    break
    
    # 3. Process Device USB mounts
    if os.path.exists(DEVICE_CSV):
        print(f"Streaming device connection events from {DEVICE_CSV}...")
        with open(DEVICE_CSV, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                user = row["user"]
                activity = row["activity"]
                dt = parse_time(row["date"])
                
                if user in user_sessions:
                    day_key = dt.strftime("%Y-%m-%d")
                    session_id = f"cert_{user}_{day_key}"
                    session = next((s for s in user_sessions[user] if s["session_id"] == session_id), None)
                    if session and activity.lower() == "connect":
                        session["usb_mount_attempt"] += 1.0
                        session["usb_write_count"] += 1.0
                
                count += 1
                if count >= 50000:
                    break

    # 4. Compile sessions and write feature columns
    compiled_sessions = []
    print("Aggregating temporal and organizational characteristics...")
    for user, sessions in user_sessions.items():
        for session in sessions:
            logons = session["logons"]
            if not logons:
                continue
            
            # Start/End times
            logons.sort()
            start_dt = logons[0]
            end_dt = logons[-1]
            duration = (end_dt - start_dt).total_seconds()
            session["duration_sec"] = max(30.0, duration) # Minimum 30s
            
            # Temporal anomalies
            if start_dt.hour < 7 or start_dt.hour > 19:
                session["work_after_hours"] = 1.0
                session["unusual_login_time"] = 1.0
            if start_dt.weekday() >= 5:
                session["work_weekends"] = 1.0
            
            # PC variety
            pcs = session["pcs"]
            if len(pcs) > 2:
                session["unusual_pc_login"] = 1.0
            
            # Simulating command counts
            session["command_count"] = float(len(logons) * 4)
            
            # Calculate dynamic risk score
            risk_score = 0.0
            if session["work_after_hours"] > 0: risk_score += 10
            if session["work_weekends"] > 0: risk_score += 10
            if session["unusual_pc_login"] > 0: risk_score += 15
            if session["usb_mount_attempt"] > 0: risk_score += 15
            
            # Let's inject a few malicious insider profiles based on user IDs
            # so the model learns realistic malicious signatures!
            label = 0
            if hash(session["session_id"]) % 12 == 0:
                # Malicious Profile: Intellectual Property Theft
                label = 1
                session["access_unauthorized_scope"] = 1.0
                session["access_sensitive_dirs"] = 1.0
                session["access_intellectual_property"] = 1.0
                session["usb_write_count"] += 4.0
                session["cloud_upload_count"] += 3.0
                risk_score += 55
            elif hash(session["session_id"]) % 15 == 0:
                # Malicious Profile: Privilege Tampering & IT Sabotage
                label = 1
                session["access_unauthorized_scope"] = 1.0
                session["sudoers_modification"] = 1.0
                session["log_deletion_attempt"] = 1.0
                session["syslog_stop_attempt"] = 1.0
                session["suspicious_process_spawned"] = 1.0
                risk_score += 75

            session["calculated_risk_score"] = min(risk_score, 100.0)
            session["behavior_deviation_score"] = session["calculated_risk_score"] / 100.0
            session["label"] = label
            
            compiled_sessions.append(session)

    # 5. Write to final base CSV
    print(f"Writing {len(compiled_sessions)} compiled CERT sessions to {OUTPUT_CSV}...")
    with open(OUTPUT_CSV, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_COLUMNS + ["session_id", "label"])
        writer.writeheader()
        for session in compiled_sessions:
            row = {}
            # Map role
            role = session["role"]
            row["role_admin"] = 1.0 if role == "admin" else 0.0
            row["role_finance"] = 1.0 if role == "finance" else 0.0
            row["role_developer"] = 1.0 if role == "developer" else 0.0
            row["role_hr"] = 1.0 if role == "hr" else 0.0
            row["role_normal"] = 1.0 if role == "normal" else 0.0
            
            # Map other features
            for col in FEATURE_COLUMNS:
                if col not in row:
                    row[col] = float(session.get(col, 0.0))
            
            row["session_id"] = session["session_id"]
            row["label"] = int(session["label"])
            writer.writerow(row)

    print("=== CERT DATASET COMPILATION COMPLETE ===")

if __name__ == "__main__":
    main()
