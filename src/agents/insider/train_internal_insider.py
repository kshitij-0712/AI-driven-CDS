import os
import csv
import json
import argparse
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from .internal_insider_dataset import FEATURE_COLUMNS

def train_pipeline(csv_path: str, model_path: str, test_size: float = 0.2, random_state: int = 42):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset path does not exist: {csv_path}")

    X = []
    y = []
    
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            vector = [float(row[col]) for col in FEATURE_COLUMNS]
            X.append(vector)
            y.append(int(row["label"]))

    X = np.array(X, dtype=float)
    y = np.array(y, dtype=int)

    print(f"Loaded {len(X)} samples from {csv_path}.")
    print(f"Labels: Normal (0) = {np.sum(y == 0)}, Malicious Insider (1) = {np.sum(y == 1)}")

    # Split
    if len(np.unique(y)) > 1:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, stratify=y, random_state=random_state
        )
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state
        )

    # Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train Random Forest Model
    print("Training RandomForest model on internal insider features...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1
    )
    model.fit(X_train_scaled, y_train)

    # Eval
    y_pred_train = model.predict(X_train_scaled)
    y_pred_test = model.predict(X_test_scaled)

    train_acc = accuracy_score(y_train, y_pred_train)
    test_acc = accuracy_score(y_test, y_pred_test)

    print(f"Training Accuracy: {train_acc:.4f}")
    print(f"Test Accuracy: {test_acc:.4f}")

    test_report = classification_report(y_test, y_pred_test, output_dict=True, zero_division=0)
    print("Test Set Classification Report:")
    print(classification_report(y_test, y_pred_test, zero_division=0))

    # Save Bundle
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    bundle = {
        "model": model,
        "scaler": scaler,
        "feature_names": FEATURE_COLUMNS
    }
    with open(model_path, "wb") as f:
        pickle.dump(bundle, f)
    print(f"Saved trained internal insider model bundle to: {model_path}")

    # Save metadata
    metadata_path = os.path.splitext(model_path)[0] + "_metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump({
            "dataset_source": csv_path,
            "training_samples": len(X_train),
            "test_samples": len(X_test),
            "test_accuracy": test_acc,
            "feature_names": FEATURE_COLUMNS,
            "test_report": test_report
        }, f, indent=2)
    print(f"Saved model metadata to: {metadata_path}")

def main():
    parser = argparse.ArgumentParser(description="Train Internal Malicious Insider Detection model.")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Train using Dataset 3 (Live dataset) instead of Dataset 2 (Base dataset)"
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default="./models/internal_insider_model.pkl",
        help="Path to save the trained model bundle"
    )
    args = parser.parse_args()

    if args.live:
        csv_path = "./data/insider/internal_insider_dataset_live.csv"
        print("Training on Dataset 3 (Live Active dataset)")
    else:
        csv_path = "./data/insider/internal_insider_dataset_base.csv"
        print("Training on Dataset 2 (Base Immutable baseline)")

    train_pipeline(csv_path, args.model_path)

if __name__ == "__main__":
    main()
