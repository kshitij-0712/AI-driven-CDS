import pickle


def load_model(model_path, vectorizer_path):
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    with open(vectorizer_path, 'rb') as f:
        vectorizer = pickle.load(f)
    return model, vectorizer


# 🔥 NEW: Insider-aware detection logic
def detect_insider_behavior(session):
    risk = 0
    explanation = []

    commands = session.get("commands", [])
    downloads = session.get("download_shas", [])

    first_ts = session.get("first_ts")
    last_ts = session.get("last_ts")

    # Safe duration calculation
    duration = 0
    if first_ts is not None and last_ts is not None:
        duration = last_ts - first_ts

    # 🚨 Rule 1: Very short session
    if duration < 5:
        risk += 2
        explanation.append("Very short session duration")

    # 🚨 Rule 2: No commands
    if len(commands) == 0:
        risk += 2
        explanation.append("No commands executed")

    # 🚨 Rule 3: Low interaction
    if len(commands) < 2:
        risk += 1
        explanation.append("Low interaction")

    # 🚨 Rule 4: No downloads (clean behavior)
    if len(downloads) == 0:
        risk += 1
        explanation.append("No payload/download activity")

    # 🚨 Rule 5: Strong stealth pattern
    if duration < 5 and len(commands) < 2:
        risk += 2
        explanation.append("Stealthy behavior pattern")

    if risk >= 4:
        return "INSIDER_AWARE", explanation
    else:
        return "NORMAL", explanation


# 🔥 UPDATED: now takes session instead of just commands
def predict_intent(model, vectorizer, session, class_labels):

    commands = session.get("commands", [])

    # ===== Existing ML logic =====
    if not commands:
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

    # ===== YOUR ADDITION =====
    insider_flag, explanation = detect_insider_behavior(session)

    base_result["insider_flag"] = insider_flag
    base_result["insider_explanation"] = explanation

    return base_result
