#!/usr/bin/env python3
"""
Phase 4: Deep Binary Analysis Training Pipeline
================================================

End-to-end orchestrator that builds the ML model using ALL binary analysis
data from Phases 1-3. This is the upgrade to run_enriched_pipeline.py.

The pipeline has 4 steps:

  1. Correlate downloads from logs (same as Phase 1)
  2. Enrich sessions with DEEP features (triage + Ghidra + angr + scripts)
  3. Build deep dataset (TF-IDF + 79 binary feature columns)
  4. Train deep v4 model and evaluate

Key differences from Phase 1 pipeline (run_enriched_pipeline.py):
  - Step 2 uses enrich_sessions_with_deep_features() instead of
    enrich_sessions_with_binary_features() — adds 79-column deep vector
  - Step 3 uses build_deep_dataset() instead of build_enriched_dataset()
    — incorporates Ghidra/angr/script features alongside TF-IDF
  - Step 4 uses train_deep_v4_model() with per-source importance analysis

Usage:
    PYTHONPATH=src .venv/bin/python src/run_deep_pipeline.py
    PYTHONPATH=src .venv/bin/python src/run_deep_pipeline.py --from-step 2
    PYTHONPATH=src .venv/bin/python src/run_deep_pipeline.py --from-step 3
    PYTHONPATH=src .venv/bin/python src/run_deep_pipeline.py --from-step 4
"""

import json
import os
import pickle
import sys
import time
import glob
import numpy as np

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from agents.analysis import (
    correlate_downloads_from_logs,
    enrich_sessions_with_deep_features,
)
from core.processing.vectorizer import build_deep_dataset
from training.train_model import train_deep_v4_model, save_model, save_report


# ---- Paths ----
COWRIE_LOG_DIR = "data/cowrie/log/cowrie"
COWRIE_DOWNLOADS_DIR = "data/cowrie/lib/cowrie/downloads"
TRIAGE_RESULTS = "data/processed/binary_triage/all_triage_results.json"
OUTPUT_DIR = "data/processed/ai_ready"
MODELS_DIR = "models"

# Checkpoint files — reuse Phase 1's step 1 checkpoint (same data)
CHECKPOINT_CORRELATED = "data/processed/ai_ready/checkpoint_correlated.pkl"
CHECKPOINT_DEEP_ENRICHED = "data/processed/ai_ready/checkpoint_deep_enriched.pkl"


def step1_correlate():
    """Step 1: Parse all Cowrie logs and correlate downloads to sessions."""
    print("=" * 70)
    print("STEP 1: Correlate downloads from Cowrie log events")
    print("=" * 70)

    # Try to reuse Phase 1 checkpoint if available
    if os.path.isfile(CHECKPOINT_CORRELATED):
        print("  Found existing Phase 1 checkpoint, reusing...")
        with open(CHECKPOINT_CORRELATED, "rb") as f:
            correlated = pickle.load(f)
        stats = correlated["stats"]
        print(f"  Total sessions:            {stats['total_sessions']:,}")
        print(f"  Sessions with downloads:   {stats['sessions_with_downloads']:,}")
        print(f"  Total download events:     {stats['total_download_events']:,}")
        return correlated

    log_pattern = os.path.join(COWRIE_LOG_DIR, "cowrie.json*")
    log_files = sorted(glob.glob(log_pattern))
    print(f"  Found {len(log_files)} Cowrie log files")

    if not log_files:
        print("ERROR: No Cowrie log files found!")
        sys.exit(1)

    t1 = time.time()
    correlated = correlate_downloads_from_logs(
        cowrie_log_paths=log_files,
        download_dir=COWRIE_DOWNLOADS_DIR,
    )
    elapsed1 = time.time() - t1

    stats = correlated["stats"]
    print(f"\n  Completed in {elapsed1:.1f}s")
    print(f"  Total sessions:            {stats['total_sessions']:,}")
    print(f"  Sessions with downloads:   {stats['sessions_with_downloads']:,}")
    print(f"  Total download events:     {stats['total_download_events']:,}")
    print(f"  Unique SHA256s:            {stats['unique_sha256s']:,}")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(CHECKPOINT_CORRELATED, "wb") as f:
        pickle.dump(correlated, f, protocol=pickle.HIGHEST_PROTOCOL)
    print(f"  Checkpoint saved to {CHECKPOINT_CORRELATED}")

    return correlated


def step2_enrich_deep(correlated):
    """Step 2: Enrich sessions with deep features from ALL analysis phases."""
    print("\n" + "=" * 70)
    print("STEP 2: Enrich sessions with deep binary features (Phase 1-3)")
    print("=" * 70)

    if not os.path.isfile(TRIAGE_RESULTS):
        print(f"ERROR: Triage results not found at {TRIAGE_RESULTS}")
        sys.exit(1)

    t2 = time.time()
    enriched = enrich_sessions_with_deep_features(correlated, TRIAGE_RESULTS)
    elapsed2 = time.time() - t2

    # Count sessions that got deep features
    sessions_with_features = 0
    sessions_with_deep_tools = 0
    feature_label_counts = {}
    for session in enriched["sessions"]:
        bf = session.get("binary_features", {})
        if bf and bf.get("num_downloads", 0) > 0:
            sessions_with_features += 1
            for lbl in bf.get("binary_labels", []):
                feature_label_counts[lbl] = feature_label_counts.get(lbl, 0) + 1

        # Check if deep vector has any Ghidra/angr data
        dv = session.get("deep_feature_vector", [])
        if dv and any(v > 0 for v in dv):
            sessions_with_deep_tools += 1

    print(f"\n  Completed in {elapsed2:.1f}s")
    print(f"  Sessions with binary features: {sessions_with_features:,}")
    print(f"  Sessions with nonzero deep vector: {sessions_with_deep_tools:,}")
    print(f"  Binary label distribution:")
    for lbl, cnt in sorted(feature_label_counts.items(), key=lambda x: -x[1]):
        print(f"    {lbl:30s}: {cnt:,} sessions")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(CHECKPOINT_DEEP_ENRICHED, "wb") as f:
        pickle.dump(enriched, f, protocol=pickle.HIGHEST_PROTOCOL)
    sz_mb = os.path.getsize(CHECKPOINT_DEEP_ENRICHED) / (1024 * 1024)
    print(f"\n  Checkpoint saved to {CHECKPOINT_DEEP_ENRICHED} ({sz_mb:.1f} MB)")

    return enriched


def step3_build_dataset(enriched):
    """Step 3: Build TF-IDF + 79-column deep feature matrix."""
    print("\n" + "=" * 70)
    print("STEP 3: Build deep TF-IDF + 79 binary feature dataset")
    print("=" * 70)

    t3 = time.time()
    dataset_stats = build_deep_dataset(
        enriched_sessions=enriched,
        output_dir=OUTPUT_DIR,
        synthetic_multiplier=200,
        tfidf_max_features=3000,
    )
    elapsed3 = time.time() - t3

    print(f"\n  Completed in {elapsed3:.1f}s")
    print(f"  Total samples:         {dataset_stats['total_samples']:,}")
    print(f"  Real sessions:         {dataset_stats['real_sessions']:,}")
    print(f"  Synthetic samples:     {dataset_stats['synthetic_samples']:,}")
    print(f"  Labeled from binary:   {dataset_stats['labeled_from_binary']:,}")
    print(f"  Labeled default Safe:  {dataset_stats['labeled_default_benign']:,}")
    print(f"  Feature shape:         {dataset_stats['feature_shape']}")
    print(f"  TF-IDF features:       {dataset_stats['tfidf_features']:,}")
    print(f"  Deep features:         {dataset_stats['deep_features']:,}")

    label_names = {0: "Safe", 1: "Recon", 2: "Downloader", 3: "Exploit", 4: "Destructive", 5: "APT"}
    print(f"\n  Label distribution:")
    for lid, count in sorted(dataset_stats["label_distribution"].items(), key=lambda x: int(x[0])):
        name = label_names.get(int(lid), f"class_{lid}")
        print(f"    {int(lid)} ({name:12s}): {count:,}")

    return dataset_stats


def step4_train():
    """Step 4: Train deep v4 model and evaluate."""
    print("\n" + "=" * 70)
    print("STEP 4: Train deep v4 RandomForest model")
    print("=" * 70)

    X_path = os.path.join(OUTPUT_DIR, "X_deep_v4_sparse.pkl")
    y_path = os.path.join(OUTPUT_DIR, "y_deep_v4.pkl")
    names_path = os.path.join(OUTPUT_DIR, "feature_names_deep_v4.json")

    with open(X_path, "rb") as f:
        X = pickle.load(f)
    with open(y_path, "rb") as f:
        y = pickle.load(f)
    feature_info = None
    if os.path.exists(names_path):
        with open(names_path, "r") as f:
            feature_info = json.load(f)

    print(f"  Dataset: {X.shape[0]:,} samples x {X.shape[1]:,} features")
    print(f"  Classes: {sorted(set(y))}")
    print(f"  Distribution: {dict(zip(*np.unique(y, return_counts=True)))}")

    t4 = time.time()
    model, acc, report, extras = train_deep_v4_model(X, y, feature_info)
    elapsed4 = time.time() - t4

    print(f"\n  Training completed in {elapsed4:.1f}s")
    print(f"  Accuracy:    {acc * 100:.2f}%")
    print(f"  Cross-val:   {extras['cv_mean']*100:.2f}% +/- {extras['cv_std']*100:.2f}%")

    # Save model and report
    model_path = save_model(model, MODELS_DIR, name="brain_v4_deep.pkl")
    report_path = save_report(report, "data/processed", acc, extras)
    print(f"\n  Model saved:  {model_path}")
    print(f"  Report saved: {report_path}")

    # Feature importance by source
    if "importance_by_source" in extras:
        print(f"\n  Feature importance by source:")
        for src, imp in extras["importance_by_source"].items():
            bar = "#" * int(imp * 200)
            print(f"    {src:12s}: {imp:.6f} {bar}")

    # Top deep features
    if "deep_feature_importance" in extras:
        print(f"\n  Top 15 deep features:")
        sorted_feats = sorted(
            extras["deep_feature_importance"].items(),
            key=lambda x: -x[1],
        )
        for col, imp in sorted_feats[:15]:
            bar = "#" * int(imp * 500)
            print(f"    {col:40s}: {imp:.6f} {bar}")

        print(f"\n    TF-IDF total importance: {extras.get('tfidf_total_importance', 0):.4f}")
        print(f"    Deep total importance:   {extras.get('deep_total_importance', 0):.4f}")

    # Classification report
    print(f"\n  Classification report:")
    for cls_name in sorted(report.keys()):
        if cls_name in ("accuracy", "macro avg", "weighted avg"):
            continue
        metrics = report[cls_name]
        if isinstance(metrics, dict):
            p = metrics.get("precision", 0)
            r = metrics.get("recall", 0)
            f1 = metrics.get("f1-score", 0)
            sup = metrics.get("support", 0)
            print(f"    {cls_name:15s}: P={p:.3f}  R={r:.3f}  F1={f1:.3f}  n={sup}")
    for avg_name in ("macro avg", "weighted avg"):
        if avg_name in report:
            m = report[avg_name]
            print(f"    {avg_name:15s}: P={m['precision']:.3f}  R={m['recall']:.3f}  F1={m['f1-score']:.3f}")

    return acc, extras


def main():
    from_step = 1
    if "--from-step" in sys.argv:
        idx = sys.argv.index("--from-step")
        if idx + 1 < len(sys.argv):
            from_step = int(sys.argv[idx + 1])
    print(f"Starting Phase 4 deep pipeline from step {from_step}")

    t0 = time.time()

    # Step 1 — Correlate downloads from logs
    correlated = None
    if from_step <= 1:
        correlated = step1_correlate()

    # Step 2 — Enrich sessions with deep features
    enriched = None
    if from_step <= 2:
        if correlated is None:
            print(f"\n  Loading correlation checkpoint...")
            with open(CHECKPOINT_CORRELATED, "rb") as f:
                correlated = pickle.load(f)
            print(f"  Loaded {len(correlated['sessions']):,} sessions")
        enriched = step2_enrich_deep(correlated)
        del correlated
        correlated = None

    # Step 3 — Build deep dataset
    if from_step <= 3:
        if enriched is None:
            print(f"\n  Loading deep enriched checkpoint...")
            with open(CHECKPOINT_DEEP_ENRICHED, "rb") as f:
                enriched = pickle.load(f)
            print(f"  Loaded {len(enriched['sessions']):,} sessions")
        dataset_stats = step3_build_dataset(enriched)
        del enriched
    else:
        print(f"\n  Skipping Steps 1-3, loading dataset directly in Step 4...")

    # Step 4
    acc, extras = step4_train()

    # Summary
    total_elapsed = time.time() - t0
    print("\n" + "=" * 70)
    print("PHASE 4 PIPELINE COMPLETE")
    print("=" * 70)
    print(f"  Total time:   {total_elapsed:.1f}s")
    print(f"  Accuracy:     {acc*100:.2f}%")
    print(f"  Cross-val:    {extras['cv_mean']*100:.2f}% +/- {extras['cv_std']*100:.2f}%")
    print(f"  Model:        models/brain_v4_deep.pkl")


if __name__ == "__main__":
    main()
