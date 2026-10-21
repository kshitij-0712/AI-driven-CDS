"""
Calibration and Threshold Sweep for AdaptiveShield Internal Insider Model.

Evaluates internal_insider_model on data/insider/internal_insider_dataset_base.csv,
computes PR/ROC curves, sweeps candidate risk-floor thresholds, and outputs
models/internal_insider_calibration.json for runtime risk-band mapping and paper reporting.
"""

import os
import json
import pickle
import logging
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_recall_curve,
    roc_curve,
    roc_auc_score,
    average_precision_score,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("calibrate_thresholds")

REPO_ROOT = Path(__file__).resolve().parents[3]
DATASET_PATH = REPO_ROOT / "data" / "insider" / "internal_insider_dataset_base.csv"
MODEL_PATH = REPO_ROOT / "models" / "internal_insider_model.pkl"
OUTPUT_CALIBRATION_PATH = REPO_ROOT / "models" / "internal_insider_calibration.json"


def calibrate():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found at {DATASET_PATH}")
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Trained model bundle not found at {MODEL_PATH}")

    logger.info(f"Loading model bundle from {MODEL_PATH}...")
    with open(MODEL_PATH, "rb") as f:
        bundle = pickle.load(f)

    model = bundle["model"]
    scaler = bundle["scaler"]
    feature_names = bundle["feature_names"]

    logger.info(f"Loading dataset from {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH)
    logger.info(f"Total user-days loaded: {len(df):,}")

    X = df[feature_names].values
    y = df["label"].values.astype(int)

    logger.info("Scaling features and generating probability predictions...")
    X_scaled = scaler.transform(X)
    probs = model.predict_proba(X_scaled)[:, 1]

    roc_auc = float(roc_auc_score(y, probs))
    pr_auc = float(average_precision_score(y, probs))
    logger.info(f"Global ROC-AUC: {roc_auc:.4f} | PR-AUC: {pr_auc:.4f}")

    # Compute PR Curve
    precisions, recalls, thresholds = precision_recall_curve(y, probs)

    # Candidate probability thresholds for evaluation
    candidate_thresholds = [0.01, 0.02, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.85]
    operating_points = []

    for t in candidate_thresholds:
        preds = (probs >= t).astype(int)
        tp = int(np.sum((preds == 1) & (y == 1)))
        fp = int(np.sum((preds == 1) & (y == 0)))
        tn = int(np.sum((preds == 0) & (y == 0)))
        fn = int(np.sum((preds == 0) & (y == 1)))

        prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        operating_points.append({
            "threshold": float(t),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 5),
            "tp": tp,
            "fp": fp,
            "fn": fn
        })

    # Find optimal F1 threshold
    f1_curve = 2 * (precisions * recalls) / (precisions + recalls + 1e-10)
    best_idx = int(np.argmax(f1_curve))
    best_threshold = float(thresholds[best_idx]) if best_idx < len(thresholds) else 0.5
    best_f1 = float(f1_curve[best_idx])
    best_prec = float(precisions[best_idx])
    best_rec = float(recalls[best_idx])

    logger.info(f"Optimal F1 Operating Point: Threshold={best_threshold:.4f}, Prec={best_prec:.4f}, Rec={best_rec:.4f}, F1={best_f1:.4f}")

    recommended_bands = {
        "NORMAL_max_prob": 0.10,
        "MONITOR_max_prob": 0.30,
        "ALERT_max_prob": 0.60,
        "CONTAIN_min_prob": 0.60,
        "optimal_f1_threshold": round(best_threshold, 4)
    }

    # Ablation Evaluation (T1 Study):
    # Arm 1: Policy-only (rules: scope violation, after-hours, high volume)
    # Arm 2: ML-only (raw RF probability >= 0.50)
    # Arm 3: Calibrated ML (raw RF probability >= optimal threshold)
    # Arm 4: Blended (Hybrid Policy + Calibrated ML)
    policy_flag = (
        (df["access_unauthorized_scope"] > 0) |
        ((df["work_after_hours"] > 0) & (df["usb_mount_attempt"] > 0)) |
        (df["cloud_upload_count"] > 5) |
        (df["log_deletion_attempt"] > 0)
    ).values.astype(int)

    def evaluate_binary(pred_binary, y_true):
        tp = int(np.sum((pred_binary == 1) & (y_true == 1)))
        fp = int(np.sum((pred_binary == 1) & (y_true == 0)))
        fn = int(np.sum((pred_binary == 0) & (y_true == 1)))
        p = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        r = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = float(2 * p * r / (p + r)) if (p + r) > 0 else 0.0
        return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4), "tp": tp, "fp": fp}

    ml_default = (probs >= 0.50).astype(int)
    ml_calibrated = (probs >= best_threshold).astype(int)
    blended = ((probs >= best_threshold) | (policy_flag == 1)).astype(int)

    ablation_t1 = {
        "arm_1_policy_only": evaluate_binary(policy_flag, y),
        "arm_2_ml_default_0.5": evaluate_binary(ml_default, y),
        "arm_3_ml_calibrated": evaluate_binary(ml_calibrated, y),
        "arm_4_blended_hybrid": evaluate_binary(blended, y)
    }

    calibration_artifact = {
        "metadata": {
            "dataset_rows": len(df),
            "normal_samples": int(np.sum(y == 0)),
            "malicious_samples": int(np.sum(y == 1)),
            "roc_auc": round(roc_auc, 4),
            "pr_auc": round(pr_auc, 4)
        },
        "optimal_f1": {
            "threshold": round(best_threshold, 4),
            "precision": round(best_prec, 4),
            "recall": round(best_rec, 4),
            "f1": round(best_f1, 4)
        },
        "recommended_bands": recommended_bands,
        "operating_points": operating_points,
        "ablation_table_t1": ablation_t1
    }

    OUTPUT_CALIBRATION_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_CALIBRATION_PATH, "w", encoding="utf-8") as f:
        json.dump(calibration_artifact, f, indent=2)

    logger.info(f"Calibration artifact written to {OUTPUT_CALIBRATION_PATH}")
    return calibration_artifact


if __name__ == "__main__":
    calibrate()
