import os
import csv
import shutil
from typing import List, Dict, Any
from .internal_insider_dataset import extract_features, determine_label, FEATURE_COLUMNS

def create_synthetic_sessions() -> List[Dict[str, Any]]:
    sessions = []

    # 1. Normal Admin Session
    sessions.append({
        "session_id": "normal_admin_01",
        "role": "admin",
        "work_after_hours": 0,
        "work_weekends": 0,
        "unusual_login_time": 0,
        "unusual_pc_login": 0,
        "access_unauthorized_scope": 0,
        "access_sensitive_dirs": 1,  # Admin legitimately accesses logs or etc
        "access_intellectual_property": 0,
        "access_hr_db": 0,
        "access_finance_system": 0,
        "high_volume_download": 0,
        "download_count": 2,
        "usb_write_count": 0,
        "usb_mount_attempt": 0,
        "cloud_upload_count": 0,
        "printing_sensitive_files": 0,
        "log_deletion_attempt": 0,
        "sudoers_modification": 0,
        "cron_tampering": 0,
        "syslog_stop_attempt": 0,
        "credential_sharing_indicators": 0,
        "switch_user_count": 1,
        "duration_sec": 300,
        "failed_sudo_count": 0,
        "obfuscated_command_count": 0,
        "network_connection_count": 1,
        "suspicious_process_spawned": 0,
        "behavior_deviation_score": 0.05,
        "explicit_label": 0
    })

    # 2. Normal Finance Session
    sessions.append({
        "session_id": "normal_finance_01",
        "role": "finance",
        "work_after_hours": 0,
        "work_weekends": 0,
        "unusual_login_time": 0,
        "unusual_pc_login": 0,
        "access_unauthorized_scope": 0,
        "access_sensitive_dirs": 0,
        "access_intellectual_property": 0,
        "access_hr_db": 0,
        "access_finance_system": 1,  # Finance accesses ledger
        "high_volume_download": 0,
        "download_count": 1,
        "usb_write_count": 0,
        "usb_mount_attempt": 0,
        "cloud_upload_count": 0,
        "printing_sensitive_files": 0,
        "log_deletion_attempt": 0,
        "sudoers_modification": 0,
        "cron_tampering": 0,
        "syslog_stop_attempt": 0,
        "credential_sharing_indicators": 0,
        "switch_user_count": 0,
        "duration_sec": 1200,
        "failed_sudo_count": 0,
        "obfuscated_command_count": 0,
        "network_connection_count": 2,
        "suspicious_process_spawned": 0,
        "behavior_deviation_score": 0.02,
        "explicit_label": 0
    })

    # 3. Normal Developer Session
    sessions.append({
        "session_id": "normal_dev_01",
        "role": "developer",
        "work_after_hours": 1,  # Devs sometimes work late
        "work_weekends": 0,
        "unusual_login_time": 0,
        "unusual_pc_login": 0,
        "access_unauthorized_scope": 0,
        "access_sensitive_dirs": 0,
        "access_intellectual_property": 1,  # Accessing source code
        "access_hr_db": 0,
        "access_finance_system": 0,
        "high_volume_download": 0,
        "download_count": 5,
        "usb_write_count": 0,
        "usb_mount_attempt": 0,
        "cloud_upload_count": 1,  # Pull/push code to remote git
        "printing_sensitive_files": 0,
        "log_deletion_attempt": 0,
        "sudoers_modification": 0,
        "cron_tampering": 0,
        "syslog_stop_attempt": 0,
        "credential_sharing_indicators": 0,
        "switch_user_count": 0,
        "duration_sec": 7200,
        "failed_sudo_count": 0,
        "obfuscated_command_count": 0,
        "network_connection_count": 12,
        "suspicious_process_spawned": 0,
        "behavior_deviation_score": 0.1,
        "explicit_label": 0
    })

    # 4. Normal HR Session
    sessions.append({
        "session_id": "normal_hr_01",
        "role": "hr",
        "work_after_hours": 0,
        "work_weekends": 0,
        "unusual_login_time": 0,
        "unusual_pc_login": 0,
        "access_unauthorized_scope": 0,
        "access_sensitive_dirs": 0,
        "access_intellectual_property": 0,
        "access_hr_db": 1,  # HR accesses HR db
        "access_finance_system": 0,
        "high_volume_download": 0,
        "download_count": 3,
        "usb_write_count": 0,
        "usb_mount_attempt": 0,
        "cloud_upload_count": 0,
        "printing_sensitive_files": 0,
        "log_deletion_attempt": 0,
        "sudoers_modification": 0,
        "cron_tampering": 0,
        "syslog_stop_attempt": 0,
        "credential_sharing_indicators": 0,
        "switch_user_count": 0,
        "duration_sec": 1800,
        "failed_sudo_count": 0,
        "obfuscated_command_count": 0,
        "network_connection_count": 3,
        "suspicious_process_spawned": 0,
        "behavior_deviation_score": 0.03,
        "explicit_label": 0
    })

    # 5. Normal Employee Session
    sessions.append({
        "session_id": "normal_employee_01",
        "role": "normal",
        "work_after_hours": 0,
        "work_weekends": 0,
        "unusual_login_time": 0,
        "unusual_pc_login": 0,
        "access_unauthorized_scope": 0,
        "access_sensitive_dirs": 0,
        "access_intellectual_property": 0,
        "access_hr_db": 0,
        "access_finance_system": 0,
        "high_volume_download": 0,
        "download_count": 1,
        "usb_write_count": 0,
        "usb_mount_attempt": 0,
        "cloud_upload_count": 0,
        "printing_sensitive_files": 0,
        "log_deletion_attempt": 0,
        "sudoers_modification": 0,
        "cron_tampering": 0,
        "syslog_stop_attempt": 0,
        "credential_sharing_indicators": 0,
        "switch_user_count": 0,
        "duration_sec": 900,
        "failed_sudo_count": 0,
        "obfuscated_command_count": 0,
        "network_connection_count": 2,
        "suspicious_process_spawned": 0,
        "behavior_deviation_score": 0.01,
        "explicit_label": 0
    })

    # 6. Finance Fraud (payroll exfiltration)
    sessions.append({
        "session_id": "malicious_finance_fraud",
        "role": "finance",
        "work_after_hours": 1,  # Done late at night
        "work_weekends": 1,  # Done on weekend
        "unusual_login_time": 1,
        "unusual_pc_login": 0,
        "access_unauthorized_scope": 1,  # Accesses system files
        "access_sensitive_dirs": 1,
        "access_intellectual_property": 0,
        "access_hr_db": 1,  # Crosses scope to HR database for payroll bank details
        "access_finance_system": 1,
        "high_volume_download": 1,
        "download_count": 25,
        "usb_write_count": 15,  # Exfiltrates via USB
        "usb_mount_attempt": 1,
        "cloud_upload_count": 0,
        "printing_sensitive_files": 1,
        "log_deletion_attempt": 1,  # Tries to cover tracks
        "sudoers_modification": 0,
        "cron_tampering": 0,
        "syslog_stop_attempt": 0,
        "credential_sharing_indicators": 0,
        "switch_user_count": 2,
        "duration_sec": 3600,
        "failed_sudo_count": 1,
        "obfuscated_command_count": 0,
        "network_connection_count": 4,
        "suspicious_process_spawned": 0,
        "behavior_deviation_score": 0.85,
        "explicit_label": 0
    })

    # 7. IP Theft (source code via cloud)
    sessions.append({
        "session_id": "malicious_ip_theft",
        "role": "developer",
        "work_after_hours": 1,
        "work_weekends": 1,
        "unusual_login_time": 1,
        "unusual_pc_login": 0,
        "access_unauthorized_scope": 1,
        "access_sensitive_dirs": 0,
        "access_intellectual_property": 1,
        "access_hr_db": 0,
        "access_finance_system": 0,
        "high_volume_download": 1,  # Massive git clone of whole org repo
        "download_count": 120,
        "usb_write_count": 0,
        "usb_mount_attempt": 0,
        "cloud_upload_count": 8,  # Uploads entire code archive to Mega
        "printing_sensitive_files": 0,
        "log_deletion_attempt": 1,  # Clears shell history
        "sudoers_modification": 0,
        "cron_tampering": 0,
        "syslog_stop_attempt": 0,
        "credential_sharing_indicators": 0,
        "switch_user_count": 0,
        "duration_sec": 4800,
        "failed_sudo_count": 0,
        "obfuscated_command_count": 1,
        "network_connection_count": 25,
        "suspicious_process_spawned": 0,
        "behavior_deviation_score": 0.90,
        "explicit_label": 0
    })

    # 8. HR Espionage (employee PII)
    sessions.append({
        "session_id": "malicious_hr_espionage",
        "role": "hr",
        "work_after_hours": 1,
        "work_weekends": 0,
        "unusual_login_time": 1,
        "unusual_pc_login": 1,  # Logs in from colleague's PC
        "access_unauthorized_scope": 1,
        "access_sensitive_dirs": 1,
        "access_intellectual_property": 0,
        "access_hr_db": 1,
        "access_finance_system": 0,
        "high_volume_download": 1,
        "download_count": 50,
        "usb_write_count": 0,
        "usb_mount_attempt": 0,
        "cloud_upload_count": 5,  # Exfiltrates via cloud
        "printing_sensitive_files": 1,  # Prints out physical folders
        "log_deletion_attempt": 1,
        "sudoers_modification": 0,
        "cron_tampering": 0,
        "syslog_stop_attempt": 1,  # Disables audit logs
        "credential_sharing_indicators": 1,
        "switch_user_count": 1,
        "duration_sec": 2400,
        "failed_sudo_count": 0,
        "obfuscated_command_count": 0,
        "network_connection_count": 8,
        "suspicious_process_spawned": 0,
        "behavior_deviation_score": 0.78,
        "explicit_label": 0
    })

    # 9. Admin Sabotage (filesystem destruction)
    sessions.append({
        "session_id": "malicious_admin_sabotage",
        "role": "admin",
        "work_after_hours": 1,
        "work_weekends": 1,
        "unusual_login_time": 1,
        "unusual_pc_login": 1,
        "access_unauthorized_scope": 1,
        "access_sensitive_dirs": 1,
        "access_intellectual_property": 0,
        "access_hr_db": 0,
        "access_finance_system": 0,
        "high_volume_download": 0,
        "download_count": 0,
        "usb_write_count": 0,
        "usb_mount_attempt": 0,
        "cloud_upload_count": 0,
        "printing_sensitive_files": 0,
        "log_deletion_attempt": 1,
        "sudoers_modification": 1,  # Changes sudoers to allow all lockouts
        "cron_tampering": 1,  # Stealthy cron persistence to trigger rm -rf later
        "syslog_stop_attempt": 1,  # Kills audit logging first
        "credential_sharing_indicators": 0,
        "switch_user_count": 5,
        "duration_sec": 1800,
        "failed_sudo_count": 0,
        "obfuscated_command_count": 2,
        "network_connection_count": 1,
        "suspicious_process_spawned": 1,  # Installs backdoors
        "behavior_deviation_score": 0.98,
        "explicit_label": 0
    })

    # 10. Data Sale (customer PII trafficking)
    sessions.append({
        "session_id": "malicious_data_sale",
        "role": "normal",
        "work_after_hours": 0,
        "work_weekends": 1,
        "unusual_login_time": 1,
        "unusual_pc_login": 0,
        "access_unauthorized_scope": 1,  # Normal staff member accessing database files
        "access_sensitive_dirs": 1,
        "access_intellectual_property": 0,
        "access_hr_db": 0,
        "access_finance_system": 1,  # Billing databases
        "high_volume_download": 1,
        "download_count": 40,
        "usb_write_count": 10,
        "usb_mount_attempt": 1,
        "cloud_upload_count": 0,
        "printing_sensitive_files": 0,
        "log_deletion_attempt": 0,
        "sudoers_modification": 0,
        "cron_tampering": 0,
        "syslog_stop_attempt": 0,
        "credential_sharing_indicators": 0,
        "switch_user_count": 0,
        "duration_sec": 3600,
        "failed_sudo_count": 4,  # Multiple failed privilege elevations
        "obfuscated_command_count": 0,
        "network_connection_count": 5,
        "suspicious_process_spawned": 0,
        "behavior_deviation_score": 0.70,
        "explicit_label": 0
    })

    # 11. Credential Trafficking (SSH key theft)
    sessions.append({
        "session_id": "malicious_cred_trafficking",
        "role": "developer",
        "work_after_hours": 1,
        "work_weekends": 0,
        "unusual_login_time": 1,
        "unusual_pc_login": 0,
        "access_unauthorized_scope": 1,
        "access_sensitive_dirs": 1,  # Harvesting ~/.ssh/ keys
        "access_intellectual_property": 0,
        "access_hr_db": 0,
        "access_finance_system": 0,
        "high_volume_download": 0,
        "download_count": 5,
        "usb_write_count": 1,
        "usb_mount_attempt": 0,
        "cloud_upload_count": 2,  # Uploading private keys
        "printing_sensitive_files": 0,
        "log_deletion_attempt": 1,
        "sudoers_modification": 0,
        "cron_tampering": 0,
        "syslog_stop_attempt": 0,
        "credential_sharing_indicators": 1,  # Key is shared and used concurrently
        "switch_user_count": 1,
        "duration_sec": 1200,
        "failed_sudo_count": 1,
        "obfuscated_command_count": 1,
        "network_connection_count": 4,
        "suspicious_process_spawned": 0,
        "behavior_deviation_score": 0.80,
        "explicit_label": 0
    })

    # Add 1000 randomized normal and malicious sessions to make a robust dataset
    import random
    random.seed(42)  # For reproducibility

    roles = ["developer", "finance", "admin", "hr", "normal"]
    role_weights = [0.30, 0.15, 0.05, 0.10, 0.40]

    for i in range(1000):
        # 90% normal users, 10% malicious insiders
        is_malicious = random.random() < 0.10
        role = random.choices(roles, weights=role_weights)[0]
        
        session_id = f"simulated_{'malicious' if is_malicious else 'normal'}_{role}_{i:04d}"
        
        session = {
            "session_id": session_id,
            "role": role,
            "work_after_hours": 0,
            "work_weekends": 0,
            "unusual_login_time": 0,
            "unusual_pc_login": 0,
            "access_unauthorized_scope": 0,
            "access_sensitive_dirs": 0,
            "access_intellectual_property": 0,
            "access_hr_db": 0,
            "access_finance_system": 0,
            "high_volume_download": 0,
            "download_count": 0,
            "usb_write_count": 0,
            "usb_mount_attempt": 0,
            "cloud_upload_count": 0,
            "printing_sensitive_files": 0,
            "log_deletion_attempt": 0,
            "sudoers_modification": 0,
            "cron_tampering": 0,
            "syslog_stop_attempt": 0,
            "credential_sharing_indicators": 0,
            "switch_user_count": 0,
            "duration_sec": random.randint(300, 7200),
            "failed_sudo_count": 0,
            "obfuscated_command_count": 0,
            "network_connection_count": random.randint(1, 10),
            "suspicious_process_spawned": 0,
            "behavior_deviation_score": 0.0,
            "explicit_label": 0
        }
        
        if not is_malicious:
            # Configure typical normal behaviors depending on role
            session["work_after_hours"] = 1 if (random.random() < 0.20 if role == "developer" else random.random() < 0.05) else 0
            session["work_weekends"] = 1 if random.random() < 0.05 else 0
            session["unusual_login_time"] = 1 if random.random() < 0.05 else 0
            session["unusual_pc_login"] = 1 if random.random() < 0.02 else 0
            
            if role == "developer":
                session["access_intellectual_property"] = 1 if random.random() < 0.85 else 0
                session["download_count"] = random.randint(1, 10)
                session["cloud_upload_count"] = random.randint(0, 2)
            elif role == "finance":
                session["access_finance_system"] = 1 if random.random() < 0.90 else 0
                session["download_count"] = random.randint(1, 5)
            elif role == "admin":
                session["access_sensitive_dirs"] = 1 if random.random() < 0.80 else 0
                session["switch_user_count"] = random.randint(0, 2)
                session["download_count"] = random.randint(1, 5)
            elif role == "hr":
                session["access_hr_db"] = 1 if random.random() < 0.90 else 0
                session["download_count"] = random.randint(1, 6)
            else:
                session["download_count"] = random.randint(0, 3)
                
            session["behavior_deviation_score"] = round(random.uniform(0.01, 0.15), 3)
            
        else:
            # Choose one of the 6 malicious profiles
            profile = random.randint(1, 6)
            session["explicit_label"] = 0
            
            if profile == 1: # Finance Fraud
                session["role"] = "finance"
                session["work_after_hours"] = 1
                session["work_weekends"] = 1
                session["access_unauthorized_scope"] = 1
                session["access_sensitive_dirs"] = 1
                session["access_hr_db"] = 1
                session["access_finance_system"] = 1
                session["high_volume_download"] = 1
                session["download_count"] = random.randint(15, 40)
                session["usb_write_count"] = random.randint(5, 20)
                session["usb_mount_attempt"] = 1
                session["log_deletion_attempt"] = 1
                session["behavior_deviation_score"] = round(random.uniform(0.75, 0.95), 3)
                
            elif profile == 2: # IP Theft
                session["role"] = "developer"
                session["work_after_hours"] = 1
                session["work_weekends"] = 1
                session["access_intellectual_property"] = 1
                session["high_volume_download"] = 1
                session["download_count"] = random.randint(50, 150)
                session["cloud_upload_count"] = random.randint(3, 10)
                session["log_deletion_attempt"] = 1
                session["behavior_deviation_score"] = round(random.uniform(0.80, 0.98), 3)
                
            elif profile == 3: # HR Espionage
                session["role"] = "hr"
                session["work_after_hours"] = 1
                session["unusual_pc_login"] = 1
                session["access_unauthorized_scope"] = 1
                session["access_sensitive_dirs"] = 1
                session["access_hr_db"] = 1
                session["high_volume_download"] = 1
                session["download_count"] = random.randint(20, 80)
                session["cloud_upload_count"] = random.randint(2, 8)
                session["syslog_stop_attempt"] = 1
                session["log_deletion_attempt"] = 1
                session["behavior_deviation_score"] = round(random.uniform(0.70, 0.90), 3)
                
            elif profile == 4: # Admin Sabotage
                session["role"] = "admin"
                session["unusual_pc_login"] = 1
                session["access_sensitive_dirs"] = 1
                session["sudoers_modification"] = 1
                session["cron_tampering"] = 1
                session["syslog_stop_attempt"] = 1
                session["suspicious_process_spawned"] = 1
                session["switch_user_count"] = random.randint(3, 6)
                session["behavior_deviation_score"] = round(random.uniform(0.85, 0.99), 3)
                
            elif profile == 5: # Data Sale
                session["role"] = "normal"
                session["work_weekends"] = 1
                session["access_unauthorized_scope"] = 1
                session["access_finance_system"] = 1
                session["high_volume_download"] = 1
                session["download_count"] = random.randint(20, 60)
                session["usb_write_count"] = random.randint(5, 15)
                session["usb_mount_attempt"] = 1
                session["failed_sudo_count"] = random.randint(3, 6)
                session["behavior_deviation_score"] = round(random.uniform(0.65, 0.85), 3)
                
            elif profile == 6: # Credential Trafficking
                session["role"] = "developer"
                session["work_after_hours"] = 1
                session["access_unauthorized_scope"] = 1
                session["access_sensitive_dirs"] = 1
                session["cloud_upload_count"] = random.randint(1, 5)
                session["credential_sharing_indicators"] = 1
                session["log_deletion_attempt"] = 1
                session["behavior_deviation_score"] = round(random.uniform(0.70, 0.90), 3)
                
        sessions.append(session)

    return sessions

def main():
    print("Generating synthetic internal malicious insider sessions...")
    raw_sessions = create_synthetic_sessions()

    processed_rows = []
    for raw in raw_sessions:
        features = extract_features(raw)
        label, reason = determine_label(features, raw.get("explicit_label", 0))

        row = {
            "session_id": raw["session_id"],
            "role": raw["role"],
            **features,
            "label": label,
            "label_reason": reason
        }
        processed_rows.append(row)

    # Prepare directories
    os.makedirs("./data/insider", exist_ok=True)
    base_csv_path = "./data/insider/internal_insider_dataset_base.csv"
    live_csv_path = "./data/insider/internal_insider_dataset_live.csv"

    # Write base csv
    fieldnames = ["session_id", "role"] + FEATURE_COLUMNS + ["label", "label_reason"]
    with open(base_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(processed_rows)
    print(f"Dataset 2 (Base Baseline) successfully written to: {base_csv_path} ({len(processed_rows)} rows)")

    # Copy to live csv as dynamic copy
    shutil.copyfile(base_csv_path, live_csv_path)
    print(f"Dataset 3 (Live Active Baseline Copy) successfully copied to: {live_csv_path}")

if __name__ == "__main__":
    main()
