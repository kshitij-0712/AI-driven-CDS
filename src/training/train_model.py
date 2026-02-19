import os
import pickle
import json
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score


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


def train_random_forest(X, y):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=150, max_depth=35, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, output_dict=True)

    return clf, acc, report


def save_model(model, models_dir, name="brain_v2_deep.pkl"):
    os.makedirs(models_dir, exist_ok=True)
    out_path = os.path.join(models_dir, name)
    with open(out_path, 'wb') as f:
        pickle.dump(model, f)
    return out_path


def save_report(report, processed_dir, acc):
    os.makedirs(processed_dir, exist_ok=True)
    out_path = os.path.join(processed_dir, "training_report.json")
    with open(out_path, 'w') as f:
        json.dump({"accuracy": acc, "report": report}, f, indent=2)
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


if __name__ == "__main__":
    main()
