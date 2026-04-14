def detect_insider_behavior(session):
    risk = 0
    explanation = []

    commands = session.get("commands", [])
    downloads = session.get("download_shas", [])

    duration = session.get("last_ts", 0) - session.get("first_ts", 0)

    if duration < 5:
        risk += 2
        explanation.append("Very short session")

    if len(commands) == 0:
        risk += 2
        explanation.append("No commands executed")

    if len(commands) < 2:
        risk += 1
        explanation.append("Low interaction")

    if len(downloads) == 0:
        risk += 1
        explanation.append("No downloads")

    if duration < 5 and len(commands) < 2:
        risk += 2
        explanation.append("Stealthy behavior")

    return risk, explanation


import os
from .inference import load_insider_model, predict_insider

MODEL_PATH = os.path.abspath("./models/insider_model.pkl")
_model_bundle = None


def compute_cert_risk(session):
    commands = session.get("commands", [])

    risk = 0
    explanation = []

    if len(commands) > 10:
        risk += 2
        explanation.append("High activity")

    if len(commands) == 0:
        risk += 1
        explanation.append("Unusual inactivity")

    return risk, explanation


def _load_insider_model():
    global _model_bundle
    if _model_bundle is not None:
        return _model_bundle
    if os.path.exists(MODEL_PATH):
        try:
            _model_bundle = load_insider_model(MODEL_PATH)
        except Exception:
            _model_bundle = None
    return _model_bundle


def analyze_session(session):
    bundle = _load_insider_model()
    if bundle is not None:
        result = predict_insider(bundle, session)
        return {
            "session_id": session.get("session_id", ""),
            "src_ip": session.get("src_ip", ""),
            "insider_flag": result["label"],
            "risk_score": result["score"],
            "explanation": [f"ML insider score={result['score']:.3f}"],
        }

    insider_risk, insider_exp = detect_insider_behavior(session)
    cert_risk, cert_exp = compute_cert_risk(session)

    total_risk = insider_risk + cert_risk
    explanation = insider_exp + cert_exp

    return {
        "insider_flag": "INSIDER_AWARE_ATTACK" if total_risk >= 4 else "NORMAL",
        "risk_score": total_risk,
        "explanation": explanation
    }