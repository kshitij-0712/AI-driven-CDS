import os
import pickle
import json
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, accuracy_score


# Class name mapping for readable reports
CLASS_NAMES = {
    0: "Safe",
    1: "Recon",
    2: "Downloader",
    3: "Exploit",
    4: "Destructive",
    5: "ADVANCED_APT",
}


def load_data(processed_dir):
    X_path = os.path.join(processed_dir, "ai_ready", "X_deep_sparse.pkl")
    y_path = os.path.join(processed_dir, "ai_ready", "y_deep.pkl")

    if not (os.path.exists(X_path) and os.path.exists(y_path)):
        raise FileNotFoundError("Processed datasets not found. Run vectorizer first.")

    with open(X_path, 'rb') as f:
        X = pickle.load(f)
    with open(y_path, 'rb') as f:
        y = pickle.load(f)

    return X, y


def load_enriched_data(processed_dir):
    """
    Load the enriched dataset (TF-IDF + binary features) produced
    by vectorizer.build_enriched_dataset().
    """
    X_path = os.path.join(processed_dir, "ai_ready", "X_enriched_sparse.pkl")
    y_path = os.path.join(processed_dir, "ai_ready", "y_enriched.pkl")

    if not (os.path.exists(X_path) and os.path.exists(y_path)):
        raise FileNotFoundError(
            "Enriched datasets not found. Run: "
            "vectorizer.build_enriched_dataset() first."
        )

    with open(X_path, 'rb') as f:
        X = pickle.load(f)
    with open(y_path, 'rb') as f:
        y = pickle.load(f)

    # Also load feature names if available
    names_path = os.path.join(processed_dir, "ai_ready", "feature_names_enriched.json")
    feature_info = None
    if os.path.exists(names_path):
        with open(names_path, 'r') as f:
            feature_info = json.load(f)

    return X, y, feature_info


def train_random_forest(X, y):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=150, max_depth=35, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, output_dict=True)

    return clf, acc, report


def train_enriched_model(X, y, feature_info=None):
    """
    Train a RandomForest on the enriched dataset with cross-validation
    and feature importance analysis.

    Returns (model, accuracy, report, extras) where extras contains
    cross-val scores and feature importance info.
    """
    # Stratified split to preserve class distribution
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )

    # Slightly larger forest to handle the extra binary features
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=40,
        min_samples_split=5,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",  # handle class imbalance from real data
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    # Generate readable class names for the report
    present_classes = sorted(set(y_test) | set(y_pred))
    target_names = [CLASS_NAMES.get(c, f"class_{c}") for c in present_classes]
    report = classification_report(
        y_test, y_pred,
        labels=present_classes,
        target_names=target_names,
        output_dict=True,
    )

    # Cross-validation (3-fold because dataset may be small)
    n_unique = len(set(y))
    n_folds = min(3, min(np.bincount(y)))  # ensure each fold has all classes
    n_folds = max(2, n_folds)
    try:
        cv = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)
        cv_scores = cross_val_score(clf, X, y, cv=cv, scoring="accuracy")
    except Exception:
        cv_scores = np.array([acc])

    # Feature importance for binary feature columns
    importances = clf.feature_importances_
    extras = {
        "cv_scores": cv_scores.tolist(),
        "cv_mean": float(cv_scores.mean()),
        "cv_std": float(cv_scores.std()),
    }

    if feature_info:
        n_tfidf = feature_info.get("tfidf_features", 0)
        binary_cols = feature_info.get("binary_feature_columns", [])
        if binary_cols and n_tfidf > 0:
            # Extract importance of binary features specifically
            binary_importances = importances[n_tfidf:n_tfidf + len(binary_cols)]
            extras["binary_feature_importance"] = {
                col: round(float(imp), 6)
                for col, imp in zip(binary_cols, binary_importances)
            }
            extras["tfidf_total_importance"] = round(float(importances[:n_tfidf].sum()), 6)
            extras["binary_total_importance"] = round(float(binary_importances.sum()), 6)

    return clf, acc, report, extras


def save_model(model, models_dir, name="brain_v2_deep.pkl"):
    os.makedirs(models_dir, exist_ok=True)
    out_path = os.path.join(models_dir, name)
    with open(out_path, 'wb') as f:
        pickle.dump(model, f)
    return out_path


def save_report(report, processed_dir, acc, extras=None):
    os.makedirs(processed_dir, exist_ok=True)
    out_path = os.path.join(processed_dir, "training_report.json")
    result = {"accuracy": acc, "report": report}
    if extras:
        result["extras"] = extras
    with open(out_path, 'w') as f:
        json.dump(result, f, indent=2, default=str)
    return out_path


def main():
    processed_dir = "./data/processed"
    models_dir = "./models"

    X, y = load_data(processed_dir)
    model, acc, report = train_random_forest(X, y)
    model_path = save_model(model, models_dir)
    report_path = save_report(report, processed_dir, acc)

    print(f"Model saved to {model_path}")
    print(f"Training report saved to {report_path}")
    print(f"Accuracy: {acc * 100:.2f}%")


def main_enriched():
    """
    Train using the enriched dataset (TF-IDF + binary features).
    Call this instead of main() after running the Phase 1 pipeline.
    """
    processed_dir = "./data/processed"
    models_dir = "./models"

    print("Loading enriched dataset...")
    X, y, feature_info = load_enriched_data(processed_dir)
    print(f"  Shape: {X.shape}, Classes: {sorted(set(y))}")
    print(f"  Label distribution: {dict(zip(*np.unique(y, return_counts=True)))}")

    print("Training enriched model...")
    model, acc, report, extras = train_enriched_model(X, y, feature_info)

    model_path = save_model(model, models_dir, name="brain_v3_enriched.pkl")
    report_path = save_report(report, processed_dir, acc, extras)

    print(f"\nEnriched model saved to {model_path}")
    print(f"Training report saved to {report_path}")
    print(f"Accuracy: {acc * 100:.2f}%")
    print(f"Cross-val: {extras['cv_mean']*100:.2f}% +/- {extras['cv_std']*100:.2f}%")

    if "binary_feature_importance" in extras:
        print("\nBinary feature importance:")
        for col, imp in sorted(extras["binary_feature_importance"].items(), key=lambda x: -x[1]):
            bar = "#" * int(imp * 500)
            print(f"  {col:30s}: {imp:.6f} {bar}")
        print(f"\n  TF-IDF total importance:  {extras.get('tfidf_total_importance', 0):.4f}")
        print(f"  Binary total importance:  {extras.get('binary_total_importance', 0):.4f}")


if __name__ == "__main__":
    import sys
    if "--enriched" in sys.argv:
        main_enriched()
    else:
        main()
