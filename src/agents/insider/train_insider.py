import argparse
import os
import random
import json
from typing import List

from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from .cert_parser import build_cert_baseline_dataset, save_cert_dataset
from .dataset import (
    load_export_dataset,
    build_insider_dataset,
    save_insider_dataset,
    count_internal_sessions,
)
from .model import train_insider_classifier, save_insider_model


def _downsample_safe_examples(
    X: List[List[float]],
    y: List[int],
    rows: List[dict],
    max_safe: int,
    random_state: int,
):
    if max_safe is None or max_safe < 0:
        return X, y, rows

    safe_indices = [idx for idx, label in enumerate(y) if label == 0]
    if len(safe_indices) <= max_safe:
        return X, y, rows

    random.seed(random_state)
    keep_safe = set(random.sample(safe_indices, max_safe))
    filtered = [idx for idx in range(len(y)) if y[idx] != 0 or idx in keep_safe]

    return [X[i] for i in filtered], [y[i] for i in filtered], [rows[i] for i in filtered]


def main() -> None:
    parser = argparse.ArgumentParser(description="Train insider-resilient detection model")
    parser.add_argument(
        "--export-csv",
        type=str,
        default="./data/exports/sessions_complete.csv",
        help="Path to the exported sessions_complete.csv dataset",
    )
    parser.add_argument(
        "--output-dataset",
        type=str,
        default="./data/exports/insider_dataset.csv",
        help="Path to save the insider feature dataset",
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default="./models/insider_model.pkl",
        help="Path to save the trained insider model bundle",
    )
    parser.add_argument(
        "--downsample-safe",
        type=int,
        default=5000,
        help="Maximum number of safe examples to retain when training",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Fraction of data saved for test evaluation",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for training and downsampling",
    )
    parser.add_argument(
        "--cert-dir",
        type=str,
        default="./data/cert-outputs",
        help="Path to CERT output files for baseline dataset generation",
    )
    parser.add_argument(
        "--cert-output",
        type=str,
        default="./data/exports/cert_baseline_dataset.csv",
        help="Path to save the generated CERT baseline dataset",
    )
    args = parser.parse_args()

    print(f"Loading export dataset from: {args.export_csv}")
    rows = load_export_dataset(args.export_csv)
    internal_count = count_internal_sessions(rows)
    if internal_count == 0:
        print("WARNING: No internal source sessions were found in the export dataset.")
        print("This means the current model is training on attacker/honeypot sessions and will be a proxy for suspicious insider-like behavior rather than true internal user compromise.")
    else:
        print(f"Internal source sessions detected: {internal_count}")

    X, y, feature_names, output_rows = build_insider_dataset(rows)

    print(f"Generated {len(X)} examples from the export dataset")
    original_counts = {0: y.count(0), 1: y.count(1)}
    print(f"Initial label counts: {original_counts}")

    if args.downsample_safe is not None and args.downsample_safe >= 0:
        X, y, output_rows = _downsample_safe_examples(
            X, y, output_rows, args.downsample_safe, args.random_state
        )
        print(f"Downsampled safe examples; total examples after sampling: {len(X)}")
        print(f"Post-sampling label counts: {{0: {y.count(0)}, 1: {y.count(1)}}}")

    print(f"Saving insider dataset to: {args.output_dataset}")
    save_insider_dataset(output_rows, args.output_dataset)

    if args.cert_dir and os.path.isdir(args.cert_dir):
        print(f"Building CERT baseline dataset from: {args.cert_dir}")
        cert_rows, cert_feature_names = build_cert_baseline_dataset(
            args.cert_dir,
            max_rows=None,
        )
        save_cert_dataset(cert_rows, args.cert_output)
        print(f"Saved CERT baseline dataset to: {args.cert_output} ({len(cert_rows)} rows)")

    print("Splitting training and test data...")
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=args.test_size,
        stratify=y,
        random_state=args.random_state,
    )
    print(f"Training examples: {len(X_train)}, test examples: {len(X_test)}")

    print("Training insider model...")
    model, scaler, train_report = train_insider_classifier(
        X_train,
        y_train,
        random_state=args.random_state,
    )

    X_test_scaled = scaler.transform(X_test)
    y_pred = model.predict(X_test_scaled)
    test_report = classification_report(y_test, y_pred, output_dict=True)
    test_accuracy = float(accuracy_score(y_test, y_pred))

    save_insider_model(model, scaler, feature_names, args.model_path)
    print(f"Saved insider model to: {args.model_path}")

    summary = {
        "examples": len(X),
        "label_counts": {
            "normal": y.count(0),
            "insider_like": y.count(1),
        },
        "train_report": train_report,
        "test_accuracy": test_accuracy,
        "test_report": test_report,
    }
    print(json.dumps(summary, indent=2))

    metadata_path = os.path.splitext(args.model_path)[0] + "_metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump({"feature_names": feature_names, "summary": summary}, f, indent=2)
    print(f"Saved metadata to: {metadata_path}")


if __name__ == "__main__":
    main()
