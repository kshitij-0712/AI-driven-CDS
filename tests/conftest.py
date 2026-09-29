"""
Shared test fixtures for AdaptiveShield test suite.

This file is automatically loaded by pytest.
It provides reusable model instances, sample data,
and helper functions used across all test modules.
"""

import sys
import pytest
import torch
import numpy as np
from pathlib import Path

# Add src to Python path
SRC_DIR = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

PROJECT_ROOT = Path(__file__).parent.parent

CLASS_NAMES = [
    'Safe', 'Recon', 'Downloader',
    'Exploit', 'Destructive', 'ADVANCED_APT'
]


@pytest.fixture(scope="session")
def model():
    """Load the UnifiedThreatClassifier once for the session."""
    from training.neural.model import UnifiedThreatClassifier

    # Try loading the latest trained model
    model_paths = [
        PROJECT_ROOT / "models" / "brain_v5_neural.pt",
        PROJECT_ROOT / "models" / "brain_v6_unified.pt",
    ]

    for path in model_paths:
        if path.exists():
            checkpoint = torch.load(
                str(path),
                map_location='cpu',
                weights_only=False
            )
            m = UnifiedThreatClassifier()
            m.load_state_dict(checkpoint['model_state_dict'])
            m.eval()
            return m

    pytest.skip("No trained model file found")


@pytest.fixture(scope="session")
def tokenizer():
    """Create a CommandTokenizer."""
    from training.neural.dataset import CommandTokenizer
    return CommandTokenizer(max_length=2048)


def encode_commands(text, max_length=2048):
    """Encode a command string to tensor."""
    indices = []
    for char in text[:max_length]:
        code = ord(char)
        indices.append(code if code < 256 else 1)
    length = len(indices)
    if len(indices) < max_length:
        indices += [0] * (max_length - len(indices))
    indices = indices[:max_length]
    return (
        torch.tensor([indices], dtype=torch.long),
        torch.tensor([min(length, max_length)], dtype=torch.long),
    )


def extract_mitre(commands):
    """Extract 21-dim MITRE features."""
    from core.mitre.session_annotator import (
        annotate_session,
        annotation_to_flat_dict,
        get_mitre_feature_columns,
    )
    cmd_list = [
        c.strip()
        for c in commands.replace("&&", ";")
            .replace("||", ";")
            .replace("\\n", ";")
            .split(";")
        if c.strip()
    ]
    if not cmd_list:
        cmd_list = [commands]
    annotation = annotate_session(cmd_list)
    flat = annotation_to_flat_dict(annotation)
    cols = get_mitre_feature_columns()
    return [flat.get(col, 0.0) for col in cols]


def predict_single(model, commands, is_http=False):
    """Run inference on a single command string.

    Returns: (pred_class_id, pred_name, confidence, probs_dict)
    """
    from training.neural.dataset import clean_payload

    if is_http:
        commands = clean_payload(commands)

    encoded, lengths = encode_commands(commands, 2048)
    mitre_features = extract_mitre(commands)
    mitre = torch.tensor(
        [mitre_features], dtype=torch.float32
    )

    changes = torch.zeros((1, 21), dtype=torch.float32)
    if is_http:
        changes[0, 20] = 1.0

    triage = torch.zeros((1, 70), dtype=torch.float32)
    modality_mask = torch.tensor(
        [[False, False, not is_http, True]],
        dtype=torch.bool
    )

    with torch.no_grad():
        preds, probs = model.predict(
            encoded, mitre, changes,
            triage, lengths, modality_mask
        )

    pred_id = preds[0].item()
    probs_arr = probs[0].cpu().numpy()
    return (
        pred_id,
        CLASS_NAMES[pred_id],
        float(probs_arr[pred_id]),
        {CLASS_NAMES[i]: float(probs_arr[i]) for i in range(6)}
    )
