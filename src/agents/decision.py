import pickle


def load_model(model_path, vectorizer_path):
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    with open(vectorizer_path, 'rb') as f:
        vectorizer = pickle.load(f)
    return model, vectorizer


def predict_intent(model, vectorizer, commands, class_labels):
    if not commands:
        return {
            "label": "Safe",
            "confidence": 0.0,
        }
    X = vectorizer.transform(commands)
    probs = model.predict_proba(X)
    mean_probs = probs.mean(axis=0)
    idx = int(mean_probs.argmax())
    label = class_labels[idx]
    confidence = float(mean_probs[idx])
    return {
        "label": label,
        "confidence": confidence,
    }
