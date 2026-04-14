import os
import pickle
from typing import Any, Dict, List, Tuple

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score


def train_insider_classifier(
    X: List[List[float]],
    y: List[int],
    n_estimators: int = 200,
    max_depth: int = 30,
    random_state: int = 42,
) -> Tuple[RandomForestClassifier, StandardScaler, Dict[str, Any]]:
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(np.array(X, dtype=float))

    model = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight="balanced",
        n_jobs=-1,
        random_state=random_state,
    )
    model.fit(X_scaled, np.array(y, dtype=int))

    report = {
        "accuracy": float(accuracy_score(y, model.predict(X_scaled))),
        "classification_report": classification_report(y, model.predict(X_scaled), output_dict=True),
    }

    return model, scaler, report


def save_insider_model(
    model: RandomForestClassifier,
    scaler: StandardScaler,
    feature_names: List[str],
    model_path: str,
) -> None:
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    bundle = {
        "model": model,
        "scaler": scaler,
        "feature_names": feature_names,
    }
    with open(model_path, "wb") as f:
        pickle.dump(bundle, f)


def load_insider_model(model_path: str) -> Dict[str, Any]:
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Insider model not found: {model_path}")
    with open(model_path, "rb") as f:
        bundle = pickle.load(f)
    if not all(key in bundle for key in ("model", "scaler", "feature_names")):
        raise ValueError("Insider model bundle is missing required keys.")
    return bundle
