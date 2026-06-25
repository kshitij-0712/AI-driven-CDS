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

MODEL_PATH = os.path.abspath(os.getenv("INSIDER_MODEL_PATH", "./models/insider_model.pkl"))
_model_bundle = None


def _load_insider_model(model_path: str = None):
    global _model_bundle
    if _model_bundle is not None and model_path is None:
        return _model_bundle
    if model_path is None:
        model_path = MODEL_PATH
    if os.path.exists(model_path):
        try:
            _model_bundle = load_insider_model(model_path)
        except Exception:
            _model_bundle = None
    return _model_bundle


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




def analyze_session(session, model_path: str = None):
    bundle = _load_insider_model(model_path)
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