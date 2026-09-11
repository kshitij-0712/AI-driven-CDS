#!/usr/bin/env python3
"""
Quick retrain script for the MITRE-only semantic balanced neural model.
This is a wrapper to call train_neural.py with appropriate arguments.
"""

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent

print("\n" + "="*80)
print(" RETRAINING NEURAL MODEL WITH MITRE-ONLY SEMANTIC BALANCED LABELS")
print("="*80)

# Training arguments optimized for MITRE-only semantic balanced labeling
cmd = [
    sys.executable, 
    str(PROJECT_ROOT / "src" / "training" / "neural" / "train_neural.py"),
    "--label-mode", "mitre_only_semantic_balanced",
    "--mitre-only",  # Use MITRE features only (21-dim)
    "--use-semantic-labels",  # Enable semantic labeling
    "--epochs", "40",
    "--batch-size", "64",
    "--downsample-safe", "2000",
    "--synthetic-recon", "1500",
    "--synthetic-exploit", "1500",
    "--patience", "7",
    "--model-name", "brain_v5_mitre_only_semantic_balanced_v2",
    "--loss", "combined",
    "--lr", "1e-3",
]

print("\nTraining command:")
print(" ".join(cmd))
print()

# Run training
result = subprocess.run(cmd, cwd=PROJECT_ROOT)
sys.exit(result.returncode)
