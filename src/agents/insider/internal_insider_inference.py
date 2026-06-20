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
    Extracts features, runs rule-based label/reason check, and runs ML prediction.
    """
    features = extract_features(session)
    rule_label, rule_reason = determine_label(features, session.get("explicit_label", 0))

    ml_score = 0.0
    ml_label = "NORMAL"

    if model_bundle is not None:
        try:
            model = model_bundle["model"]
            scaler = model_bundle["scaler"]
            feat_names = model_bundle["feature_names"]
            
            vector = [features[col] for col in feat_names]
            X_scaled = scaler.transform([vector])
            
            probs = model.predict_proba(X_scaled)
            ml_score = float(probs[0][1] if probs.shape[1] > 1 else probs[0][0])
            ml_label = "MALICIOUS_INSIDER" if ml_score >= 0.5 else "NORMAL"
        except Exception as e:
            print(f"Error running ML inference: {e}")

    # Combine Rules and ML (Flag if either detects)
    is_malicious = (rule_label == 1) or (ml_label == "MALICIOUS_INSIDER")
    final_label = "MALICIOUS_INSIDER" if is_malicious else "NORMAL"
    
    explanation = []
    if rule_label == 1:
        explanation.append(f"Rule alert: {rule_reason}")
    if ml_label == "MALICIOUS_INSIDER":
        explanation.append(f"ML threat confidence: {ml_score:.3f}")
    if not explanation:
        explanation.append(f"Normal behavior. ML score={ml_score:.3f}")

    return {
        "session_id": session.get("session_id", "unknown"),
        "role": session.get("role", "normal"),
        "risk_score": max(features["calculated_risk_score"], ml_score * 100.0),
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
