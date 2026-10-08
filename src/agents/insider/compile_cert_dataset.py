"""
Compile CERT r4.2 Dataset into Universal Behavioral Telemetry Dataset
====================================================================
Streams and aggregates CERT r4.2 logs (logon, device, file, email, http, LDAP)
into daily user behavioral vectors, computes user-specific historical deviation
metrics (Z-scores), and applies ground-truth labels from answers/insiders.csv.
"""

import os
import glob
import re
import time
from datetime import datetime
from collections import defaultdict
import numpy as np
import pandas as pd

# Paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
CERT_DIR = os.path.join(BASE_DIR, "data", "cert_r4.2")
ANSWERS_PATH = os.path.join(BASE_DIR, "data", "cert_answers", "insiders.csv")
OUTPUT_DIR = os.path.join(BASE_DIR, "data", "insider")
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "internal_insider_dataset_base.csv")

# 35 Universal Feature Columns
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

def load_ldap_metadata(cert_dir: str):
    """Parses LDAP monthly snapshots to map users to roles, departments, and assigned PCs."""
    print("[1/8] Parsing LDAP organizational metadata...")
    user_metadata = {}
    ldap_files = sorted(glob.glob(os.path.join(cert_dir, "LDAP", "*.csv")))
    if not ldap_files:
        print("  WARNING: No LDAP files found. Using default normal role.")
        return user_metadata

    for fpath in ldap_files:
        df = pd.read_csv(fpath)
        for _, row in df.iterrows():
            uid = row["user_id"]
            if uid not in user_metadata:
                role_str = str(row.get("role", "")).lower()
                dept_str = str(row.get("department", "")).lower()
                func_str = str(row.get("functional_unit", "")).lower()

                is_admin = 1.0 if "itadmin" in role_str or "security" in dept_str else 0.0
                is_dev = 1.0 if "engineer" in role_str or "programmer" in role_str or "research" in func_str else 0.0
                is_fin = 1.0 if "finance" in func_str or "account" in role_str or "payroll" in dept_str else 0.0
                is_hr = 1.0 if "humanresource" in role_str or "personnel" in dept_str else 0.0
                is_normal = 1.0 if not (is_admin or is_dev or is_fin or is_hr) else 0.0

                user_metadata[uid] = {
                    "role_admin": is_admin,
                    "role_developer": is_dev,
                    "role_finance": is_fin,
                    "role_hr": is_hr,
                    "role_normal": is_normal,
                    "department": dept_str,
                    "functional_unit": func_str,
                    "raw_role": role_str
                }
    print(f"  Loaded metadata for {len(user_metadata)} employees from LDAP.")
    return user_metadata

def load_ground_truth(answers_path: str):
    """Loads malicious campaign intervals from answers/insiders.csv."""
    print("[2/8] Loading ground-truth malicious attack windows...")
    if not os.path.exists(answers_path):
        raise FileNotFoundError(f"Answers file not found at {answers_path}")

    df = pd.read_csv(answers_path)
    r42 = df[df["dataset"] == 4.2].copy()
    r42["start_dt"] = pd.to_datetime(r42["start"])
    r42["end_dt"] = pd.to_datetime(r42["end"])

    user_intervals = defaultdict(list)
    for _, row in r42.iterrows():
        user_intervals[row["user"]].append((row["start_dt"], row["end_dt"], int(row["scenario"])))

    print(f"  Loaded {len(r42)} malicious campaigns across {len(user_intervals)} unique insider users.")
    return user_intervals

def compile_dataset():
    start_total = time.time()
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    user_metadata = load_ldap_metadata(CERT_DIR)
    ground_truth = load_ground_truth(ANSWERS_PATH)

    # Master aggregation store: key = (user, date_str 'YYYY-MM-DD')
    records = defaultdict(lambda: {
        "logon_count": 0,
        "logoff_count": 0,
        "work_after_hours": 0.0,
        "work_weekends": 0.0,
        "duration_sec": 0.0,
        "first_logon_hour": None,
        "pcs": set(),
        "usb_mount_attempt": 0.0,
        "usb_disconnect_count": 0.0,
        "file_copy_count": 0.0,
        "file_sensitive_count": 0.0,
        "email_count": 0.0,
        "email_external_count": 0.0,
        "email_attachment_count": 0.0,
        "email_size_bytes": 0.0,
        "http_count": 0.0,
        "cloud_upload_count": 0.0,
        "job_search_count": 0.0,
        "malware_download_count": 0.0
    })

    # User primary PC mapping
    user_pc_counts = defaultdict(lambda: defaultdict(int))

    # --- Step 3: Logon.csv ---
    logon_path = os.path.join(CERT_DIR, "logon.csv")
    print(f"[3/8] Processing logon events from {logon_path}...")
    t0 = time.time()
    
    # Track open sessions per (user, pc): start_dt
    open_sessions = {}
    
    with open(logon_path, "r", encoding="utf-8") as f:
        header = f.readline()
        for line in f:
            parts = line.strip().split(",")
            if len(parts) < 5:
                continue
            # id, date, user, pc, activity
            _, date_str, user, pc, activity = parts[0], parts[1], parts[2], parts[3], parts[4].lower()
            try:
                dt = datetime.strptime(date_str, "%m/%d/%Y %H:%M:%S")
            except Exception:
                continue

            day_key = dt.strftime("%Y-%m-%d")
            rec = records[(user, day_key)]
            rec["pcs"].add(pc)
            user_pc_counts[user][pc] += 1

            if dt.hour < 7 or dt.hour >= 19:
                rec["work_after_hours"] = 1.0
            if dt.weekday() >= 5:
                rec["work_weekends"] = 1.0

            if rec["first_logon_hour"] is None:
                rec["first_logon_hour"] = dt.hour + (dt.minute / 60.0)

            sess_key = (user, pc)
            if activity == "logon":
                rec["logon_count"] += 1
                open_sessions[sess_key] = dt
            elif activity == "logoff":
                rec["logoff_count"] += 1
                if sess_key in open_sessions:
                    start_dt = open_sessions.pop(sess_key)
                    dur = max(1.0, (dt - start_dt).total_seconds())
                    rec["duration_sec"] += dur

    print(f"  Completed logon processing in {time.time() - t0:.2f}s. Unique user-days: {len(records)}")

    # Compute assigned PC per user (the PC used most frequently)
    user_assigned_pc = {}
    for user, pcs in user_pc_counts.items():
        user_assigned_pc[user] = max(pcs.items(), key=lambda x: x[1])[0]

    # --- Step 4: Device.csv ---
    device_path = os.path.join(CERT_DIR, "device.csv")
    print(f"[4/8] Processing removable device events from {device_path}...")
    t0 = time.time()
    with open(device_path, "r", encoding="utf-8") as f:
        header = f.readline()
        for line in f:
            parts = line.strip().split(",")
            if len(parts) < 5:
                continue
            _, date_str, user, pc, activity = parts[0], parts[1], parts[2], parts[3], parts[4].lower()
            try:
                dt = datetime.strptime(date_str, "%m/%d/%Y %H:%M:%S")
            except Exception:
                continue
            day_key = dt.strftime("%Y-%m-%d")
            rec = records[(user, day_key)]
            if activity == "connect":
                rec["usb_mount_attempt"] += 1.0
            elif activity == "disconnect":
                rec["usb_disconnect_count"] += 1.0
    print(f"  Completed device processing in {time.time() - t0:.2f}s.")

    # --- Step 5: File.csv ---
    file_path = os.path.join(CERT_DIR, "file.csv")
    print(f"[5/8] Processing file transfer events from {file_path}...")
    t0 = time.time()
    sensitive_exts = {".doc", ".pdf", ".zip", ".exe", ".rar", ".tar", ".gz", ".csv", ".xlsx", ".py"}
    with open(file_path, "r", encoding="utf-8") as f:
        header = f.readline()
        for line in f:
            parts = line.strip().split(",")
            if len(parts) < 5:
                continue
            _, date_str, user, pc, filename = parts[0], parts[1], parts[2], parts[3], parts[4]
            try:
                dt = datetime.strptime(date_str, "%m/%d/%Y %H:%M:%S")
            except Exception:
                continue
            day_key = dt.strftime("%Y-%m-%d")
            rec = records[(user, day_key)]
            rec["file_copy_count"] += 1.0
            ext = os.path.splitext(filename)[1].lower()
            if ext in sensitive_exts:
                rec["file_sensitive_count"] += 1.0
    print(f"  Completed file processing in {time.time() - t0:.2f}s.")

    # --- Step 6: Email.csv ---
    email_path = os.path.join(CERT_DIR, "email.csv")
    print(f"[6/8] Processing email communications from {email_path}...")
    t0 = time.time()
    with open(email_path, "r", encoding="utf-8") as f:
        header = f.readline()
        for line in f:
            parts = line.strip().split(",")
            if len(parts) < 11:
                continue
            # id, date, user, pc, to, cc, bcc, from, size, attachments, content
            date_str, user, to_field, size_str, att_str = parts[1], parts[2], parts[4], parts[8], parts[9]
            try:
                dt = datetime.strptime(date_str, "%m/%d/%Y %H:%M:%S")
            except Exception:
                continue
            day_key = dt.strftime("%Y-%m-%d")
            rec = records[(user, day_key)]
            rec["email_count"] += 1.0

            # Check external recipients (non-dtaa.com)
            if "@" in to_field and not all("dtaa.com" in addr for addr in to_field.split(";")):
                rec["email_external_count"] += 1.0

            try:
                rec["email_attachment_count"] += float(att_str)
                rec["email_size_bytes"] += float(size_str)
            except Exception:
                pass
    print(f"  Completed email processing in {time.time() - t0:.2f}s.")

    # --- Step 7: Http.csv (Chunked Streaming Scan) ---
    http_path = os.path.join(CERT_DIR, "http.csv")
    print(f"[7/8] Processing HTTP web traffic (28.4M lines) in chunks from {http_path}...")
    t0 = time.time()

    cloud_regex = re.compile(r'wikileaks|dropbox|mega\.nz|drive\.google|box\.com|mediafire', re.IGNORECASE)
    job_regex = re.compile(r'monster\.com|careerbuilder|jobhuntersbible|craigslist|indeed', re.IGNORECASE)
    malware_regex = re.compile(r'keylogger|spectorsoft|malware', re.IGNORECASE)

    chunk_idx = 0
    total_http_lines = 0
    for chunk in pd.read_csv(http_path, chunksize=2_000_000, usecols=["date", "user", "url"]):
        chunk_idx += 1
        total_http_lines += len(chunk)
        chunk["day"] = chunk["date"].str[:10]

        # Vectorized string checks
        chunk["is_cloud"] = chunk["url"].str.contains(cloud_regex, na=False).astype(int)
        chunk["is_job"] = chunk["url"].str.contains(job_regex, na=False).astype(int)
        chunk["is_malware"] = chunk["url"].str.contains(malware_regex, na=False).astype(int)

        agg = chunk.groupby(["user", "day"])[["is_cloud", "is_job", "is_malware"]].agg(["count", "sum"])

        for (u, d), vals in agg.iterrows():
            # Convert date format if needed (http is MM/DD/YYYY)
            try:
                dt_obj = datetime.strptime(d, "%m/%d/%Y")
                day_key = dt_obj.strftime("%Y-%m-%d")
            except Exception:
                continue

            rec = records[(u, day_key)]
            rec["http_count"] += float(vals[("is_cloud", "count")])
            rec["cloud_upload_count"] += float(vals[("is_cloud", "sum")])
            rec["job_search_count"] += float(vals[("is_job", "sum")])
            rec["malware_download_count"] += float(vals[("is_malware", "sum")])

        if chunk_idx % 3 == 0:
            print(f"    Scanned {total_http_lines / 1e6:.1f}M HTTP records... ({time.time() - t0:.1f}s)")

    print(f"  Completed HTTP processing in {time.time() - t0:.2f}s.")

    # --- Step 8: Build User Historical Baselines & Deviation Vectors ---
    print("[8/8] Computing user-specific historical baselines and synthesizing 35 universal features...")
    t0 = time.time()

    # Pre-calculate user historical distributions (mean & std)
    user_daily_history = defaultdict(lambda: {
        "durations": [],
        "usb_mounts": [],
        "file_copies": [],
        "email_counts": [],
        "http_counts": [],
        "logon_hours": []
    })

    for (user, day_key), rec in records.items():
        hist = user_daily_history[user]
        hist["durations"].append(rec["duration_sec"])
        hist["usb_mounts"].append(rec["usb_mount_attempt"])
        hist["file_copies"].append(rec["file_copy_count"])
        hist["email_counts"].append(rec["email_count"])
        hist["http_counts"].append(rec["http_count"])
        if rec["first_logon_hour"] is not None:
            hist["logon_hours"].append(rec["first_logon_hour"])

    user_baselines = {}
    for user, hist in user_daily_history.items():
        user_baselines[user] = {
            "mean_dur": np.mean(hist["durations"]) if hist["durations"] else 3600.0,
            "std_dur": np.std(hist["durations"]) if hist["durations"] else 1800.0,
            "mean_usb": np.mean(hist["usb_mounts"]) if hist["usb_mounts"] else 0.0,
            "std_usb": np.std(hist["usb_mounts"]) if hist["usb_mounts"] else 0.5,
            "mean_files": np.mean(hist["file_copies"]) if hist["file_copies"] else 0.0,
            "std_files": np.std(hist["file_copies"]) if hist["file_copies"] else 1.0,
            "mean_email": np.mean(hist["email_counts"]) if hist["email_counts"] else 5.0,
            "std_email": np.std(hist["email_counts"]) if hist["email_counts"] else 3.0,
            "mean_http": np.mean(hist["http_counts"]) if hist["http_counts"] else 20.0,
            "std_http": np.std(hist["http_counts"]) if hist["http_counts"] else 10.0,
            "mean_hour": np.mean(hist["logon_hours"]) if hist["logon_hours"] else 8.5,
            "std_hour": np.std(hist["logon_hours"]) if hist["logon_hours"] else 1.0,
        }

    # Generate final rows
    output_rows = []
    malicious_count = 0

    for (user, day_key), rec in records.items():
        meta = user_metadata.get(user, {
            "role_admin": 0.0, "role_developer": 0.0, "role_finance": 0.0, "role_hr": 0.0, "role_normal": 1.0
        })
        base = user_baselines.get(user, {})
        primary_pc = user_assigned_pc.get(user, "")

        # Check unusual PC
        pcs = rec["pcs"]
        unusual_pc = 1.0 if any(pc != primary_pc for pc in pcs) else 0.0

        # Unusual login time (Z-score > 2.0)
        curr_hour = rec["first_logon_hour"] if rec["first_logon_hour"] is not None else 8.5
        hour_diff = abs(curr_hour - base["mean_hour"])
        unusual_login = 1.0 if (hour_diff / (base["std_hour"] + 0.1)) > 2.0 else 0.0

        # Scope violation indicators
        # Scenario 1 (Wikileaks/USB) or Scenario 3 (Admin sabotage) or foreign department file access
        scope_violation = 0.0
        if rec["cloud_upload_count"] > 0 and meta["role_admin"] == 0.0 and meta["role_developer"] == 0.0:
            scope_violation = 1.0
        if rec["file_sensitive_count"] > 10 and meta["role_hr"] == 0.0 and meta["role_finance"] == 0.0:
            scope_violation = 1.0

        # High volume download / file copy
        file_dev = (rec["file_copy_count"] - base["mean_files"]) / (base["std_files"] + 0.1)
        high_vol = 1.0 if file_dev > 3.0 or rec["file_copy_count"] > 20 else 0.0

        # Total command / event volume
        total_events = rec["logon_count"] + rec["usb_mount_attempt"] + rec["file_copy_count"] + rec["email_count"] + rec["http_count"]
        duration = max(rec["duration_sec"], 60.0)
        density = total_events / duration

        # Malicious process / keylogger
        suspicious_proc = 1.0 if rec["malware_download_count"] > 0 else 0.0

        # Cover-up / Persistence
        log_del = 1.0 if suspicious_proc and rec["usb_mount_attempt"] > 0 else 0.0
        cron_tamp = 1.0 if suspicious_proc and meta["role_admin"] == 1.0 else 0.0

        # Composite mathematical deviation score (Z-score root-mean-square)
        usb_z = max(0.0, (rec["usb_mount_attempt"] - base["mean_usb"]) / (base["std_usb"] + 0.1))
        file_z = max(0.0, (rec["file_copy_count"] - base["mean_files"]) / (base["std_files"] + 0.1))
        email_z = max(0.0, (rec["email_external_count"] - 0.5) / 1.5)
        http_z = max(0.0, (rec["cloud_upload_count"] * 3.0) + (rec["job_search_count"] * 2.0))
        hour_z = max(0.0, hour_diff / (base["std_hour"] + 0.1))

        dev_score = np.sqrt(np.mean([usb_z**2, file_z**2, email_z**2, http_z**2, hour_z**2]))
        dev_score = float(np.clip(dev_score / 5.0, 0.0, 1.0))

        # Dynamic calculated risk score
        risk_score = min(100.0, (
            (30.0 * scope_violation) +
            (25.0 * (1.0 if rec["cloud_upload_count"] > 0 else 0.0)) +
            (20.0 * high_vol) +
            (15.0 * rec["work_after_hours"]) +
            (10.0 * unusual_pc) +
            (20.0 * suspicious_proc)
        ))

        # Ground-truth label evaluation
        dt_day = datetime.strptime(day_key, "%Y-%m-%d")
        is_malicious = 0
        label_reason = "Normal business activity"

        if user in ground_truth:
            for s_dt, e_dt, scenario in ground_truth[user]:
                if s_dt.date() <= dt_day.date() <= e_dt.date():
                    is_malicious = 1
                    label_reason = f"CERT Scenario {scenario} active malicious window"
                    break

        if is_malicious:
            malicious_count += 1

        row = {
            "session_id": f"cert_{user}_{day_key}",
            "role": meta.get("raw_role", "normal"),
            "role_admin": meta["role_admin"],
            "role_finance": meta["role_finance"],
            "role_developer": meta["role_developer"],
            "role_hr": meta["role_hr"],
            "role_normal": meta["role_normal"],
            "work_after_hours": rec["work_after_hours"],
            "work_weekends": rec["work_weekends"],
            "unusual_login_time": unusual_login,
            "unusual_pc_login": unusual_pc,
            "access_unauthorized_scope": scope_violation,
            "access_sensitive_dirs": 1.0 if rec["file_sensitive_count"] > 0 else 0.0,
            "access_intellectual_property": 1.0 if meta["role_developer"] and rec["file_copy_count"] > 0 else 0.0,
            "access_hr_db": 1.0 if scope_violation and "hr" in meta.get("department", "") else 0.0,
            "access_finance_system": 1.0 if scope_violation and "finance" in meta.get("department", "") else 0.0,
            "high_volume_download": high_vol,
            "download_count": rec["file_copy_count"],
            "usb_write_count": rec["file_copy_count"],
            "usb_mount_attempt": rec["usb_mount_attempt"],
            "cloud_upload_count": rec["cloud_upload_count"],
            "printing_sensitive_files": 0.0,
            "log_deletion_attempt": log_del,
            "sudoers_modification": 0.0,
            "cron_tampering": cron_tamp,
            "syslog_stop_attempt": 0.0,
            "credential_sharing_indicators": unusual_pc,
            "switch_user_count": 1.0 if len(pcs) > 1 else 0.0,
            "command_count": total_events,
            "duration_sec": duration,
            "command_density": density,
            "failed_sudo_count": 0.0,
            "obfuscated_command_count": 0.0,
            "network_connection_count": rec["http_count"] + rec["email_count"],
            "suspicious_process_spawned": suspicious_proc,
            "calculated_risk_score": risk_score,
            "behavior_deviation_score": dev_score,
            "label": is_malicious,
            "label_reason": label_reason
        }
        output_rows.append(row)

    print(f"  Processed all records in {time.time() - t0:.2f}s.")
    print(f"  Total user-days compiled: {len(output_rows)}")
    print(f"  Malicious user-days (Class 1): {malicious_count} ({malicious_count / len(output_rows) * 100:.3f}%)")
    print(f"  Normal user-days (Class 0):    {len(output_rows) - malicious_count} ({(len(output_rows) - malicious_count) / len(output_rows) * 100:.3f}%)")

    # Write output CSV
    print(f"Saving compiled dataset to {OUTPUT_CSV}...")
    fieldnames = ["session_id", "role"] + FEATURE_COLUMNS + ["label", "label_reason"]
    df_out = pd.DataFrame(output_rows)
    df_out.to_csv(OUTPUT_CSV, index=False, columns=fieldnames)
    print(f"Successfully created {OUTPUT_CSV} in {time.time() - start_total:.2f}s total.")

if __name__ == "__main__":
    compile_dataset()
