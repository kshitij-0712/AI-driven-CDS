import os
import csv
import pickle
from typing import Any, Dict, List, Optional, Tuple
from .internal_insider_dataset import extract_features, determine_label, FEATURE_COLUMNS

def load_internal_insider_model(model_path: str = "./models/internal_insider_model.pkl") -> Optional[Dict[str, Any]]:
    if not os.path.exists(model_path):
        return None
    try:
        with open(model_path, "rb") as f:
            return pickle.load(f)
    except Exception as e:
        print(f"Error loading internal insider model: {e}")
        return None

def predict_session_risk(session: Dict[str, Any], model_bundle: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Extracts universal behavioral features and runs Random Forest ML inference.
    Falls back to baseline rules only if model bundle is unavailable.
    """
    features = extract_features(session)
    explanation = []

    if model_bundle is not None:
        try:
            model = model_bundle["model"]
            scaler = model_bundle["scaler"]
            feat_names = model_bundle["feature_names"]
            
            vector = [features.get(col, 0.0) for col in feat_names]
            X_scaled = scaler.transform([vector])
            
            probs = model.predict_proba(X_scaled)
            ml_score = float(probs[0][1] if probs.shape[1] > 1 else probs[0][0])
            
            # Policy-level risk floor: Deterministically enforce department scopes and stolen cookies
            policy_risk = float(features.get("calculated_risk_score", 0.0))
            if features.get("access_unauthorized_scope", 0.0) > 0:
                policy_risk = max(policy_risk, 75.0)
            if features.get("unusual_pc_login", 0.0) > 0:
                policy_risk = max(policy_risk, 65.0)

            # Blended risk: max of RF model anomaly and explicit policy risk
            risk_score = round(max(ml_score * 100.0, policy_risk), 1)
            final_label = "MALICIOUS_INSIDER" if risk_score >= 50.0 else "NORMAL"

            if final_label == "MALICIOUS_INSIDER":
                if features.get("access_unauthorized_scope", 0.0) > 0:
                    explanation.append("Unauthorized department boundary breach: access to restricted corporate scope")
                if features.get("unusual_pc_login", 0.0) > 0:
                    explanation.append("Suspicious session origin: Client IP not in employee authorized whitelist (Possible Cookie Theft / Session Hijack)")
                active_threats = [k for k in ["access_unauthorized_scope", "unusual_pc_login", "cloud_upload_count", "usb_mount_attempt", "log_deletion_attempt", "work_after_hours"] if features.get(k, 0) > 0]
                if active_threats:
                    explanation.append(f"Contributing anomalous vectors: {', '.join(active_threats)}")
                explanation.append(f"Threat Score: {risk_score} (ML Prob: {ml_score:.3f}, Policy Risk: {policy_risk})")
            else:
                explanation.append(f"Normal session behavior (Risk score: {risk_score}, ML threat probability: {ml_score:.3f})")

            return {
                "session_id": session.get("session_id", "unknown"),
                "role": session.get("role", "normal"),
                "risk_score": risk_score,
                "label": final_label,
                "explanation": explanation,
                "features": features
            }
        except Exception as e:
            print(f"Error running ML inference, using fallback: {e}")

    # Fallback to rule engine only if ML bundle is missing
    rule_label, rule_reason = determine_label(features, session.get("explicit_label", 0))
    final_label = "MALICIOUS_INSIDER" if rule_label == 1 else "NORMAL"
    risk_score = float(features.get("calculated_risk_score", 50.0 if rule_label == 1 else 10.0))
    explanation.append(f"Fallback Rule verdict: {rule_reason}")

    return {
        "session_id": session.get("session_id", "unknown"),
        "role": session.get("role", "normal"),
        "risk_score": risk_score,
        "label": final_label,
        "explanation": explanation,
        "features": features
    }

def record_live_feedback(session: Dict[str, Any], true_label: int, feedback_reason: str, csv_path: str = "./data/insider/internal_insider_dataset_live.csv"):
    """
    Reinforcement loop: appends a live user session behavior and label to Dataset 3.
    """
    features = extract_features(session)
    row = {
        "session_id": session.get("session_id", "live_session"),
        "role": session.get("role", "normal"),
        **features,
        "label": true_label,
        "label_reason": f"Reinforcement Feedback: {feedback_reason}"
    }

    # Append to the live active dataset CSV
    file_exists = os.path.exists(csv_path)
    fieldnames = ["session_id", "role"] + FEATURE_COLUMNS + ["label", "label_reason"]
    
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)
    print(f"Reinforcement Update: Logged live session {row['session_id']} to {csv_path}")
