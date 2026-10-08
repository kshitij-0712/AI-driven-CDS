import os
import sys
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

# Add parent directories to path if necessary
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from interfaces.insider_contract import UserBehaviorSignal, InsiderThreatScore
from agents.insider.internal_insider_inference import load_internal_insider_model, predict_session_risk
from agents.insider.corporate_directory import CorporateDirectory

class AdaptiveInsiderDetector:
    def __init__(self, model_path: str = "./models/internal_insider_model.pkl", directory_db_path: Optional[str] = None):
        self.model_bundle = load_internal_insider_model(model_path)
        if self.model_bundle is None:
            print(f"Warning: Could not load internal insider model from {model_path}. Running with rule-based fallback only.")
        else:
            print(f"Loaded internal insider model from {model_path}")

        # Corporate Directory & Company Policy Profile
        if directory_db_path:
            self.corporate_dir = CorporateDirectory(db_path=directory_db_path)
        else:
            self.corporate_dir = CorporateDirectory()
        self.company_profile = self.corporate_dir.get_company_profile()
            
        # In-memory session tracking for live user state
        self.session_states: Dict[str, Dict[str, Any]] = {}

    def reset_session_state(self, session_id: str):
        if session_id in self.session_states:
            del self.session_states[session_id]

    def _get_or_create_session_state(self, signal: UserBehaviorSignal) -> Dict[str, Any]:
        session_id = signal.session_id
        if session_id not in self.session_states:
            # Resolve corporate profile if user_id is recognized
            user_id = signal.user_id
            emp = self.corporate_dir.get_employee(user_id) if user_id else None
            role = signal.action_details.get("role") or (emp["role"] if emp else "normal")
            dept = signal.action_details.get("department") or (emp["department"] if emp else "General_Staff")

            self.session_states[session_id] = {
                "session_id": session_id,
                "user_id": user_id,
                "role": role,
                "department": dept,
                "employee_name": emp["name"] if emp else user_id,
                "assigned_ip": emp["assigned_ip"] if emp else "",
                "assigned_device": emp["assigned_device"] if emp else "",
                "commands": [],
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
                "duration_sec": 0,
                "failed_sudo_count": 0,
                "obfuscated_command_count": 0,
                "network_connection_count": 0,
                "suspicious_process_spawned": 0,
                "first_seen": None,
                "src_ip": signal.source_ip
            }
        return self.session_states[session_id]

    def _update_session_with_signal(self, state: Dict[str, Any], signal: UserBehaviorSignal):
        # Update user metadata dynamically if passed
        if signal.action_details.get("role"):
            state["role"] = signal.action_details.get("role")
        if signal.action_details.get("department"):
            state["department"] = signal.action_details.get("department")

        # 1. Update temporal factors using timestamp & company work policy
        try:
            dt = datetime.fromisoformat(signal.timestamp.replace("Z", "+00:00"))
        except Exception:
            try:
                dt = datetime.strptime(signal.timestamp, "%Y-%m-%d %H:%M:%S")
            except Exception:
                dt = datetime.now()

        if state["first_seen"] is None:
            state["first_seen"] = dt
            
        duration = (dt - state["first_seen"]).total_seconds()
        state["duration_sec"] = max(duration, 1.0)

        # Dynamic work policy from company_profile.json
        work_policy = self.company_profile.get("work_policy", {})
        std_start = work_policy.get("standard_start_hour", 8)
        std_end = work_policy.get("standard_end_hour", 18)
        early_threshold = work_policy.get("early_hours_threshold", 7)
        after_threshold = work_policy.get("after_hours_threshold", 19)
        work_days = work_policy.get("work_days", [0, 1, 2, 3, 4])

        if dt.hour < early_threshold or dt.hour >= after_threshold:
            state["work_after_hours"] = 1
        if dt.weekday() not in work_days:
            state["work_weekends"] = 1
        if dt.hour < std_start or dt.hour >= std_end:
            state["unusual_login_time"] = 1

        # 2. Remote / Client IP Whitelist Check
        client_ip = signal.source_ip
        user_id = state.get("user_id") or signal.user_id
        if user_id and client_ip:
            is_whitelisted = self.corporate_dir.check_ip_whitelist(user_id, client_ip)
            if not is_whitelisted and client_ip not in ("127.0.0.1", "::1", "localhost", "192.168.1.50", "192.168.1.100"):
                state["unusual_pc_login"] = 1

        # 3. Command and Process Extraction
        command = signal.action_details.get("command", "")
        if command:
            state["commands"].append(command)
            cmd_lower = command.lower()
            
            # Count su/sudo switches
            if "su " in cmd_lower or "sudo " in cmd_lower:
                state["switch_user_count"] += 1
                
            # Log deletion cover-up indicators
            if any(k in cmd_lower for k in ["rm -rf /var/log", "history -c", "shred ", "clear_history"]):
                state["log_deletion_attempt"] = 1
                
            # Sudoers modification
            if "/etc/sudoers" in cmd_lower:
                state["sudoers_modification"] = 1
                
            # Cron persistence
            if "crontab " in cmd_lower or "systemd" in cmd_lower or "/etc/cron" in cmd_lower:
                state["cron_tampering"] = 1
                
            # Syslog stopping
            if "systemctl stop syslog" in cmd_lower or "service rsyslog stop" in cmd_lower or "systemctl stop auditd" in cmd_lower:
                state["syslog_stop_attempt"] = 1
                
            # Failed sudo attempts
            if signal.action_details.get("sudo_failed", False):
                state["failed_sudo_count"] += 1
                
            # Network connections
            if any(k in cmd_lower for k in ["nc ", "curl ", "wget ", "ping ", "netstat"]):
                state["network_connection_count"] += 1
                
            # Suspicious processes (netcat, reverse shells, etc.)
            if any(k in cmd_lower for k in ["nc -e", "/bin/bash -i", "/bin/sh -i", "nmap "]):
                state["suspicious_process_spawned"] = 1

            # Obfuscation (base64, hex encoding)
            if "base64 " in cmd_lower or "xxd " in cmd_lower or "hex " in cmd_lower:
                state["obfuscated_command_count"] += 1

            # Policy high-risk commands check
            ssh_policy = self.company_profile.get("ssh_policy", {})
            for hr_cmd in ssh_policy.get("high_risk_commands", []):
                if hr_cmd.lower() in cmd_lower:
                    state["access_unauthorized_scope"] = 1
                    state["suspicious_process_spawned"] = 1

        # 4. File accesses, Scopes, and Exfiltration details
        file_path = (signal.action_details.get("file_path") or "").lower()
        cmd_lower = command.lower() if command else ""
        combined_path = f"{file_path} {cmd_lower}".strip()

        if combined_path:
            # Sensitive directories
            if any(k in combined_path for k in ["/etc/shadow", "/etc/passwd", "/payroll", "/var/log", "/vault/"]):
                state["access_sensitive_dirs"] = 1
                
            # Intellectual property
            if any(k in combined_path for k in ["/src/", "/git/", "/repo/", "/design/", "/patent", "/models/", "/weights/"]):
                state["access_intellectual_property"] = 1
                
            # HR database
            if any(k in combined_path for k in ["/hr/", "/employee/", "/pii/"]):
                state["access_hr_db"] = 1
                
            # Finance system
            if any(k in combined_path for k in ["/billing/", "/accounting/", "/ledger/", "/finance/"]):
                state["access_finance_system"] = 1

        # 5. Dynamic Department Boundary Enforcement from company_profile.json
        department = state.get("department", "")
        dept_cfg = self.company_profile.get("departments", {}).get(department)
        
        # If department is not found directly, try fuzzy match against role
        if not dept_cfg:
            role_str = state.get("role", "").lower()
            for d_name, d_val in self.company_profile.get("departments", {}).items():
                if d_name.lower() in role_str or role_str in d_name.lower():
                    dept_cfg = d_val
                    break

        if dept_cfg and combined_path:
            restricted = dept_cfg.get("restricted_scopes", [])
            authorized = dept_cfg.get("authorized_scopes", [])

            # Hard boundary violation: Touching a restricted scope
            if any(r.lower() in combined_path for r in restricted):
                state["access_unauthorized_scope"] = 1
                state["access_sensitive_dirs"] = 1
            # Boundary violation: Outside authorized scopes when accessing protected corporate resources
            elif authorized:
                is_authorized = any(a.lower() in combined_path for a in authorized)
                is_protected_resource = any(p in combined_path for p in [
                    "/vault/", "/models/", "/hr/", "/finance/", "/infrastructure/",
                    "/kubernetes/", "/src/", "/experiments/", "/legal/"
                ])
                if is_protected_resource and not is_authorized:
                    state["access_unauthorized_scope"] = 1

        # Fallback role boundaries if company_profile was missing
        if not dept_cfg and combined_path:
            role = state["role"].lower()
            if "finance" in role and (state["access_intellectual_property"] or state["access_hr_db"]):
                state["access_unauthorized_scope"] = 1
            elif "developer" in role and (state["access_hr_db"] or state["access_finance_system"]):
                state["access_unauthorized_scope"] = 1
            elif "hr" in role and (state["access_intellectual_property"] or state["access_finance_system"]):
                state["access_unauthorized_scope"] = 1
            elif role == "normal" and (state["access_sensitive_dirs"] or state["access_hr_db"] or state["access_finance_system"] or state["access_intellectual_property"]):
                state["access_unauthorized_scope"] = 1

        # USB writes / mounts
        if signal.action_details.get("usb_write", False):
            state["usb_write_count"] += 1
        if signal.action_details.get("usb_mount", False):
            state["usb_mount_attempt"] = 1

        # Cloud uploads
        if signal.action_details.get("cloud_upload", False) or (command and any(k in command.lower() for k in ["mega.nz", "dropbox.com", "drive.google", "scp ", "rsync "])):
            state["cloud_upload_count"] += 1

        # Printing sensitive files
        if signal.action_details.get("print_job", False) and any(k in file_path for k in ["confidential", "salary", "code", "design"]):
            state["printing_sensitive_files"] = 1

        # Dynamic multi-dimensional behavior deviation score
        active_vectors = [
            float(state["work_after_hours"]),
            float(state["work_weekends"]),
            float(state["access_unauthorized_scope"]),
            float(state["access_sensitive_dirs"]),
            float(min(1.0, state["cloud_upload_count"])),
            float(min(1.0, state["usb_mount_attempt"])),
            float(state["log_deletion_attempt"]),
            float(state["suspicious_process_spawned"]),
            float(state["unusual_pc_login"])
        ]
        state["behavior_deviation_score"] = float(round(sum(active_vectors) / len(active_vectors), 3))

    def analyze_signal(self, signal: UserBehaviorSignal) -> InsiderThreatScore:
        """
        Translates a UserBehaviorSignal from the interceptor proxy into an InsiderThreatScore.
        """
        # Get session state
        state = self._get_or_create_session_state(signal)
        
        # Update state with the new signal details
        self._update_session_with_signal(state, signal)
        
        # Run prediction
        result = predict_session_risk(state, self.model_bundle)

        risk_score = result["risk_score"]
        explanation = result["explanation"]
        label = result["label"]
        
        recommendation = "ALLOW"
        if label == "MALICIOUS_INSIDER":
            if risk_score >= 80.0:
                recommendation = "CONTAIN_IN_DECOY"
            elif risk_score >= 50.0:
                recommendation = "REDIRECT_TO_DECOY"
            else:
                recommendation = "ALERT_SECURITY_ANALYST"

        return InsiderThreatScore(
            user_id=signal.user_id,
            risk_score=risk_score,
            anomaly_factors=explanation,
            recommendation=recommendation,
            features=result.get("features", {})
        )
