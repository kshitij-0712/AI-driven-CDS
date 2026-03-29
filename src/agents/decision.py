import pickle


def load_model(model_path, vectorizer_path):
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    with open(vectorizer_path, 'rb') as f:
        vectorizer = pickle.load(f)
    return model, vectorizer


# 🔥 Insider-aware detection logic
def detect_insider_behavior(session):
    risk = 0
    explanation = []

    commands = session.get("commands", [])
    downloads = session.get("download_shas", [])

    first_ts = session.get("first_ts")
    last_ts = session.get("last_ts")

    duration = 0
    if first_ts is not None and last_ts is not None:
        duration = last_ts - first_ts

    # Rules
    if duration < 5:
        risk += 2
        explanation.append("Very short session duration")

    if len(commands) == 0:
        risk += 2
        explanation.append("No commands executed")

    if len(commands) < 2:
        risk += 1
        explanation.append("Low interaction")

    if len(downloads) == 0:
        risk += 1
        explanation.append("No payload/download activity")

    if duration < 5 and len(commands) < 2:
        risk += 2
        explanation.append("Stealthy behavior pattern")

    explanation_text = ", ".join(explanation)

    return {
        "insider_flag": "INSIDER_AWARE_ATTACK" if risk >= 4 else "NORMAL",
        "risk_score": risk,
        "insider_explanation": explanation_text
    }


# 🔥 CERT-based behavioral risk (light integration)
def compute_cert_risk(session):
    commands = session.get("commands", [])
    downloads = session.get("download_shas", [])

    risk = 0
    explanation = []

    # CERT-inspired patterns
    if len(commands) > 10:
        risk += 2
        explanation.append("High command activity (abnormal behavior)")

    if len(downloads) > 2:
        risk += 2
        explanation.append("Multiple downloads (possible data exfiltration)")

    if len(commands) == 0:
        risk += 1
        explanation.append("Unusual inactivity")

    return risk, explanation


# 🔥 FINAL prediction function
def predict_intent(model, vectorizer, session, class_labels):

    commands = session.get("commands", [])

    # ===== ML logic =====
    if model is None or vectorizer is None or not commands:
        base_result = {
            "label": "Safe",
            "confidence": 0.0,
        }
    else:
        X = vectorizer.transform(commands)
        probs = model.predict_proba(X)
        mean_probs = probs.mean(axis=0)
        idx = int(mean_probs.argmax())
        label = class_labels[idx]
        confidence = float(mean_probs[idx])

        base_result = {
            "label": label,
            "confidence": confidence,
        }

    # ===== YOUR INSIDER LOGIC =====
    insider_result = detect_insider_behavior(session)

    # ===== CERT LOGIC =====
    cert_risk, cert_explanation = compute_cert_risk(session)

    # ===== COMBINE EVERYTHING =====
    total_risk = insider_result["risk_score"] + cert_risk

    combined_explanation = insider_result["insider_explanation"]
    if cert_explanation:
        combined_explanation += ", " + ", ".join(cert_explanation)

    base_result.update({
        "insider_flag": insider_result["insider_flag"],
        "risk_score": total_risk,
        "cert_risk": cert_risk,
        "insider_explanation": combined_explanation
    })

    return base_result