import os
import csv
import json
import argparse
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    roc_auc_score,
    average_precision_score
)
from .internal_insider_dataset import FEATURE_COLUMNS

def train_pipeline(csv_path: str, model_path: str, test_size: float = 0.2, random_state: int = 42):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset path does not exist: {csv_path}")

    print(f"Loading compiled dataset from: {csv_path}...")
    df = pd.read_csv(csv_path)

    X = df[FEATURE_COLUMNS].values.astype(float)
    y = df["label"].values.astype(int)

    total_samples = len(X)
    normal_count = int(np.sum(y == 0))
    malicious_count = int(np.sum(y == 1))

    print(f"Loaded {total_samples} samples.")
    print(f"Class Distribution: Normal (0) = {normal_count} ({normal_count / total_samples * 100:.2f}%), "
          f"Malicious (1) = {malicious_count} ({malicious_count / total_samples * 100:.2f}%)")

    # Stratified Split to preserve exact class proportion in train and test
    print(f"Splitting into train ({1.0 - test_size:.0%}) and test ({test_size:.0%}) sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=random_state
    )

    print(f"  Training samples: {len(X_train)} (Malicious: {np.sum(y_train == 1)})")
    print(f"  Test samples:     {len(X_test)} (Malicious: {np.sum(y_test == 1)})")

    # Fit Scaler on training data only (prevent data leakage)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train Cost-Sensitive Random Forest (learning normal patterns while penalizing minority misclassifications)
    print("Training Balanced Random Forest on Universal Behavioral Telemetry...")
    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=20,
        class_weight="balanced_subsample",
        random_state=random_state,
        n_jobs=-1
    )
    model.fit(X_train_scaled, y_train)

    # Predictions & Probabilities
    y_pred_train = model.predict(X_train_scaled)
    y_pred_test = model.predict(X_test_scaled)
    y_prob_test = model.predict_proba(X_test_scaled)[:, 1]

    train_acc = accuracy_score(y_train, y_pred_train)
    test_acc = accuracy_score(y_test, y_pred_test)
    roc_auc = roc_auc_score(y_test, y_prob_test)
    pr_auc = average_precision_score(y_test, y_prob_test)

    print("\n" + "=" * 60)
    print("  MODEL EVALUATION RESULTS (CERT r4.2 TEST SET)")
    print("=" * 60)
    print(f"Training Accuracy:          {train_acc:.4f}")
    print(f"Test Accuracy:              {test_acc:.4f}")
    print(f"ROC-AUC Score:              {roc_auc:.4f}")
    print(f"PR-AUC (Avg Precision):     {pr_auc:.4f}")
    print("\nClassification Report (Test Set):")
    print(classification_report(y_test, y_pred_test, target_names=["Normal", "Malicious Insider"], digits=4))

    # Feature Importances
    importances = model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    feature_ranking = [
        {"feature": FEATURE_COLUMNS[i], "importance": float(importances[i])}
        for i in sorted_idx
    ]

    print("Top 10 Most Predictive Behavioral Features:")
    for rank, item in enumerate(feature_ranking[:10], 1):
        print(f"  {rank:2d}. {item['feature']:<30} {item['importance']:.4f}")

    # Save Bundle
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    bundle = {
        "model": model,
        "scaler": scaler,
        "feature_names": FEATURE_COLUMNS
    }
    with open(model_path, "wb") as f:
        pickle.dump(bundle, f)
    print(f"\nSaved trained model bundle to: {model_path}")

    # Save Metadata with full metrics & feature importances
    metadata_path = os.path.splitext(model_path)[0] + "_metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump({
            "dataset_source": csv_path,
            "training_samples": len(X_train),
            "test_samples": len(X_test),
            "normal_samples": normal_count,
            "malicious_samples": malicious_count,
            "test_accuracy": test_acc,
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
            "classification_report": classification_report(y_test, y_pred_test, output_dict=True),
            "feature_importances": feature_ranking,
            "feature_names": FEATURE_COLUMNS
        }, f, indent=2)
    print(f"Saved model metadata & feature importances to: {metadata_path}")

def main():
    parser = argparse.ArgumentParser(description="Train Internal Malicious Insider Detection model on CERT telemetry.")
    parser.add_argument(
        "--dataset",
        type=str,
        default="./data/insider/internal_insider_dataset_base.csv",
        help="Path to compiled CERT feature dataset"
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default="./models/internal_insider_model.pkl",
        help="Path to save the trained model bundle"
    )
    args = parser.parse_args()

    train_pipeline(args.dataset, args.model_path)

if __name__ == "__main__":
    main()
