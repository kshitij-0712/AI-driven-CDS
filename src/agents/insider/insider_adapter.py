import os
import sys
from datetime import datetime
from typing import Dict, Any, List

# Add parent directories to path if necessary
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from interfaces.insider_contract import UserBehaviorSignal, InsiderThreatScore
from agents.insider.internal_insider_inference import load_internal_insider_model, predict_session_risk

class AdaptiveInsiderDetector:
    def __init__(self, model_path: str = "./models/internal_insider_model.pkl"):
        self.model_bundle = load_internal_insider_model(model_path)
        if self.model_bundle is None:
            print(f"Warning: Could not load internal insider model from {model_path}. Running with rule-based fallback only.")
        else:
            print(f"Loaded internal insider model from {model_path}")
            
        # In-memory session tracking for live user state
        self.session_states: Dict[str, Dict[str, Any]] = {}

    def _get_or_create_session_state(self, signal: UserBehaviorSignal) -> Dict[str, Any]:
        session_id = signal.session_id
        if session_id not in self.session_states:
            # Initialize a new session tracking state
            self.session_states[session_id] = {
                "session_id": session_id,
                "role": signal.action_details.get("role", "normal"),
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
        # 1. Update temporal factors using timestamp
        try:
            # Parse ISO or simple timestamp
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

        # Check working hours (standard: 8 AM to 6 PM, Monday-Friday)
        if dt.hour < 8 or dt.hour >= 18:
            state["work_after_hours"] = 1
        if dt.weekday() >= 5: # Saturday/Sunday
            state["work_weekends"] = 1

        # 2. Command and Process Extraction
        action_type = signal.action_type.lower()
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

        # 3. File accesses and Exfiltration details
        file_path = signal.action_details.get("file_path", "").lower()
        command = signal.action_details.get("command", "")
        cmd_lower = command.lower() if command else ""
        combined_path = f"{file_path} {cmd_lower}"
        if combined_path:
            # Sensitive directories
            if any(k in combined_path for k in ["/etc/shadow", "/etc/passwd", "/payroll", "/var/log"]):
                state["access_sensitive_dirs"] = 1
                
            # Intellectual property
            if any(k in combined_path for k in ["/src/", "/git/", "/repo/", "/design/", "/patent"]):
                state["access_intellectual_property"] = 1
                
            # HR database
            if any(k in combined_path for k in ["/hr/", "/employee/", "/pii/"]):
                state["access_hr_db"] = 1
                
            # Finance system
            if any(k in combined_path for k in ["/billing/", "/accounting/", "/ledger/"]):
                state["access_finance_system"] = 1

        # USB writes / mounts
        if signal.action_details.get("usb_write", False):
            state["usb_write_count"] += 1
        if signal.action_details.get("usb_mount", False):
            state["usb_mount_attempt"] = 1

        # Cloud uploads (connections to Mega, Dropbox, etc.)
        if signal.action_details.get("cloud_upload", False) or (command and any(k in command.lower() for k in ["mega.nz", "dropbox.com", "drive.google", "scp ", "rsync "])):
            state["cloud_upload_count"] += 1

        # Printing sensitive files
        if signal.action_details.get("print_job", False) and any(k in file_path for k in ["confidential", "salary", "code", "design"]):
            state["printing_sensitive_files"] = 1

        # Check scope anomalies
        role = state["role"]
        if role == "finance" and (state["access_intellectual_property"] or state["access_hr_db"]):
            state["access_unauthorized_scope"] = 1
        elif role == "developer" and (state["access_hr_db"] or state["access_finance_system"]):
            state["access_unauthorized_scope"] = 1
        elif role == "hr" and (state["access_intellectual_property"] or state["access_finance_system"]):
            state["access_unauthorized_scope"] = 1
        elif role == "normal" and (state["access_sensitive_dirs"] or state["access_hr_db"] or state["access_finance_system"] or state["access_intellectual_property"]):
            state["access_unauthorized_scope"] = 1

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
        
        # Print debug state
        print(f"[DEBUG ADAPTER] Session: {state['session_id']}, Role: {state['role']}, Features: { {k: v for k, v in result['features'].items() if v > 0} }")
        print(f"[DEBUG ADAPTER] Verdict: {result['label']}, Score: {result['risk_score']}, Reason: {result['explanation']}")

        # Package threat score details
        risk_score = result["risk_score"]
        explanation = result["explanation"]
        label = result["label"]
        
        recommendation = "ALLOW"
        if label == "MALICIOUS_INSIDER":
            if risk_score >= 80.0:
                recommendation = "TERMINATE_SESSION_AND_BLOCK_IP"
            elif risk_score >= 50.0:
                recommendation = "CHALLENGE_WITH_MFA_OR_THROTTLE"
            else:
                recommendation = "ALERT_SECURITY_ANALYST"

        return InsiderThreatScore(
            user_id=signal.user_id,
            risk_score=risk_score,
            anomaly_factors=explanation,
            recommendation=recommendation,
            features=result.get("features", {})
        )
