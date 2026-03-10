#!/usr/bin/env python3
"""
End-to-end enriched training pipeline.

This script chains together the four steps that were previously disconnected:

  1. correlate_downloads_from_logs()  — scan all 64 Cowrie JSON logs for
     cowrie.session.file_download events, linking SHA256 hashes to sessions
  2. enrich_sessions_with_binary_features()  — look up each SHA256 in the
     Phase 1 triage index and compute per-session binary feature vectors
  3. build_enriched_dataset()  — build TF-IDF + binary feature matrix
     with labels derived from actual binary behavior (not synthetic)
  4. train_enriched_model()  — train RandomForest and evaluate

The previous run used the broken mtime-based correlator (correlate_downloads_to_sessions)
which matched 0 downloads because all file mtimes were 2026-02-25 (copy date) while
sessions spanned 2025-11-29 to 2026-01-31.  This run fixes that by using log events.

Supports --from-step N to resume from a specific step (skipping earlier steps
by loading serialized intermediate results).

Usage:
    PYTHONPATH=src .venv/bin/python src/run_enriched_pipeline.py
    PYTHONPATH=src .venv/bin/python src/run_enriched_pipeline.py --from-step 2
    PYTHONPATH=src .venv/bin/python src/run_enriched_pipeline.py --from-step 3
    PYTHONPATH=src .venv/bin/python src/run_enriched_pipeline.py --from-step 4
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
    enrich_sessions_with_binary_features,
)
from core.processing.vectorizer import build_enriched_dataset
from training.train_model import train_enriched_model, save_model, save_report


# ---- Paths (relative to project root) ----
COWRIE_LOG_DIR = "data/cowrie/log/cowrie"
COWRIE_DOWNLOADS_DIR = "data/cowrie/lib/cowrie/downloads"
TRIAGE_RESULTS = "data/processed/binary_triage/all_triage_results.json"
OUTPUT_DIR = "data/processed/ai_ready"
MODELS_DIR = "models"

# Checkpoint files (serialized intermediate results)
CHECKPOINT_CORRELATED = "data/processed/ai_ready/checkpoint_correlated.pkl"
CHECKPOINT_ENRICHED = "data/processed/ai_ready/checkpoint_enriched.pkl"


def step1_correlate():
    """Step 1: Parse all Cowrie logs and correlate downloads to sessions."""
    print("=" * 70)
    print("STEP 1: Correlate downloads from Cowrie log events")
    print("=" * 70)

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
    print(f"  Sessions with commands:     {stats['sessions_with_commands']:,}")
    print(f"  Sessions with downloads:    {stats['sessions_with_downloads']:,}")
    print(f"  Total download events:      {stats['total_download_events']:,}")
    print(f"  Unique SHA256s:             {stats['unique_sha256s']:,}")
    print(f"  SHA256s found on disk:      {stats['sha256s_on_disk']:,}")

    # Save checkpoint (sessions are large but pickle is fast)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(CHECKPOINT_CORRELATED, "wb") as f:
        pickle.dump(correlated, f, protocol=pickle.HIGHEST_PROTOCOL)
    print(f"\n  Checkpoint saved to {CHECKPOINT_CORRELATED}")
    sz_mb = os.path.getsize(CHECKPOINT_CORRELATED) / (1024 * 1024)
    print(f"  Checkpoint size: {sz_mb:.1f} MB")

    # Also save stats as JSON for human inspection
    corr_path = os.path.join(OUTPUT_DIR, "correlation_stats.json")
    with open(corr_path, "w") as f:
        json.dump(stats, f, indent=2)

    return correlated

def step2_enrich(correlated):
    """Step 2: Look up triage results and compute per-session binary features."""
    print("\n" + "=" * 70)
    print("STEP 2: Enrich sessions with binary triage features")
    print("=" * 70)

    if not os.path.isfile(TRIAGE_RESULTS):
        print(f"ERROR: Triage results not found at {TRIAGE_RESULTS}")
        print("  Run: PYTHONPATH=src .venv/bin/python src/core/malware/run_triage.py first")
        sys.exit(1)

    t2 = time.time()
    enriched = enrich_sessions_with_binary_features(correlated, TRIAGE_RESULTS)
    elapsed2 = time.time() - t2

    # Count sessions that got actual binary features
    sessions_with_features = 0
    feature_label_counts = {}
    for session in enriched["sessions"]:
        bf = session.get("binary_features", {})
        if bf and bf.get("num_downloads", 0) > 0:
            sessions_with_features += 1
            for lbl in bf.get("binary_labels", []):
                feature_label_counts[lbl] = feature_label_counts.get(lbl, 0) + 1

    print(f"\n  Completed in {elapsed2:.1f}s")
    print(f"  Sessions with binary features: {sessions_with_features:,}")
    print(f"  Binary label distribution across sessions:")
    for lbl, cnt in sorted(feature_label_counts.items(), key=lambda x: -x[1]):
        print(f"    {lbl:30s}: {cnt:,} sessions")

    # Save checkpoint
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(CHECKPOINT_ENRICHED, "wb") as f:
        pickle.dump(enriched, f, protocol=pickle.HIGHEST_PROTOCOL)
    sz_mb = os.path.getsize(CHECKPOINT_ENRICHED) / (1024 * 1024)
    print(f"\n  Checkpoint saved to {CHECKPOINT_ENRICHED} ({sz_mb:.1f} MB)")

    return enriched


def step3_build_dataset(enriched):
    """Step 3: Build TF-IDF + binary feature matrix with enriched labels."""
    print("\n" + "=" * 70)
    print("STEP 3: Build enriched TF-IDF + binary feature dataset")
    print("=" * 70)

    t3 = time.time()
    dataset_stats = build_enriched_dataset(
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
    label_names = {0: "Safe", 1: "Recon", 2: "Downloader", 3: "Exploit", 4: "Destructive", 5: "APT"}
    print(f"\n  Label distribution:")
    for lid, count in sorted(dataset_stats["label_distribution"].items(), key=lambda x: int(x[0])):
        name = label_names.get(int(lid), f"class_{lid}")
        print(f"    {int(lid)} ({name:12s}): {count:,}")
    print(f"\n  Label sources:")
    for src, count in sorted(dataset_stats["label_source_distribution"].items(), key=lambda x: -x[1]):
        print(f"    {src:40s}: {count:,}")

    return dataset_stats


def step4_train():
    """Step 4: Load the dataset, train RandomForest, evaluate."""
    print("\n" + "=" * 70)
    print("STEP 4: Train enriched RandomForest model")
    print("=" * 70)

    X_path = os.path.join(OUTPUT_DIR, "X_enriched_sparse.pkl")
    y_path = os.path.join(OUTPUT_DIR, "y_enriched.pkl")
    names_path = os.path.join(OUTPUT_DIR, "feature_names_enriched.json")

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
    model, acc, report, extras = train_enriched_model(X, y, feature_info)
    elapsed4 = time.time() - t4

    print(f"\n  Training completed in {elapsed4:.1f}s")
    print(f"  Accuracy:    {acc * 100:.2f}%")
    print(f"  Cross-val:   {extras['cv_mean']*100:.2f}% +/- {extras['cv_std']*100:.2f}%")

    # Save model and report
    model_path = save_model(model, MODELS_DIR, name="brain_v3_enriched.pkl")
    report_path = save_report(report, "data/processed", acc, extras)
    print(f"\n  Model saved:  {model_path}")
    print(f"  Report saved: {report_path}")

    # Print binary feature importance
    if "binary_feature_importance" in extras:
        print(f"\n  Binary feature importance:")
        for col, imp in sorted(extras["binary_feature_importance"].items(), key=lambda x: -x[1]):
            bar = "#" * int(imp * 500)
            print(f"    {col:30s}: {imp:.6f} {bar}")
        print(f"\n    TF-IDF total importance:  {extras.get('tfidf_total_importance', 0):.4f}")
        print(f"    Binary total importance:  {extras.get('binary_total_importance', 0):.4f}")

    # Print classification report
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
    # Parse --from-step argument
    from_step = 1
    if "--from-step" in sys.argv:
        idx = sys.argv.index("--from-step")
        if idx + 1 < len(sys.argv):
            from_step = int(sys.argv[idx + 1])
    print(f"Starting from step {from_step}")

    t0 = time.time()

    # ---- Step 1 ----
    if from_step <= 1:
        correlated = step1_correlate()
    else:
        print(f"\n  Skipping Step 1, loading checkpoint...")
        if not os.path.isfile(CHECKPOINT_CORRELATED):
            print(f"  ERROR: Checkpoint not found at {CHECKPOINT_CORRELATED}")
            print(f"  Run without --from-step first to generate it.")
            sys.exit(1)
        with open(CHECKPOINT_CORRELATED, "rb") as f:
            correlated = pickle.load(f)
        print(f"  Loaded {len(correlated['sessions']):,} sessions from checkpoint")

    # ---- Step 2 ----
    if from_step <= 2:
        enriched = step2_enrich(correlated)
    else:
        print(f"\n  Skipping Step 2, loading checkpoint...")
        if not os.path.isfile(CHECKPOINT_ENRICHED):
            print(f"  ERROR: Checkpoint not found at {CHECKPOINT_ENRICHED}")
            print(f"  Run with --from-step 2 first to generate it.")
            sys.exit(1)
        with open(CHECKPOINT_ENRICHED, "rb") as f:
            enriched = pickle.load(f)
        print(f"  Loaded {len(enriched['sessions']):,} enriched sessions from checkpoint")

    # ---- Step 3 ----
    if from_step <= 3:
        dataset_stats = step3_build_dataset(enriched)
        # Free memory — enriched sessions no longer needed
        del enriched
        del correlated
    else:
        print(f"\n  Skipping Step 3, will load dataset directly in Step 4...")

    # ---- Step 4 ----
    acc, extras = step4_train()

    # ---- Summary ----
    total_elapsed = time.time() - t0
    print("\n" + "=" * 70)
    print("PIPELINE COMPLETE")
    print("=" * 70)
    print(f"  Total time:   {total_elapsed:.1f}s")
    print(f"  Accuracy:     {acc*100:.2f}%")
    print(f"  Cross-val:    {extras['cv_mean']*100:.2f}% +/- {extras['cv_std']*100:.2f}%")


if __name__ == "__main__":
    main()
