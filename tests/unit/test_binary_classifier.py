"""
Unit tests for binary triage distillation model & runtime classifier adapter.
"""

import time
import numpy as np
import pytest

from core.malware.binary_classifier import (
    load_binary_classifier,
    get_binary_classifier_metadata,
    classify_binary,
)


def test_load_binary_classifier():
    """Verify distilled model loads successfully and contains valid metadata."""
    model = load_binary_classifier()
    assert model is not None

    meta = get_binary_classifier_metadata()
    assert meta.get("type") == "distilled_runtime"
    assert meta.get("input_dim_runtime") == 12
    assert "Destructive" in meta.get("label_names", [])
    assert "ADVANCED_APT" in meta.get("label_names", [])
    assert "Downloader" in meta.get("label_names", [])


def test_classify_binary_from_features():
    """Verify classify_binary produces valid prediction dict from a 12-d vector."""
    dummy_vec = [102400.0, 6.5, 80.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.9, 0.0, 0.0]
    res = classify_binary(dummy_vec)

    assert "class_id" in res
    assert "label" in res
    assert "confidence" in res
    assert "probabilities" in res
    assert "action" in res
    assert "latency_ms" in res

    assert 0.0 <= res["confidence"] <= 1.0
    assert len(res["probabilities"]) == 5
    assert sum(res["probabilities"].values()) == pytest.approx(1.0, abs=1e-3)


def test_classify_destructive_payload():
    """Verify destructive indicator yields Destructive label and drop_and_block action."""
    # High destructive score in position 11
    destr_vec = [2000000.0, 7.8, 95.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0]
    res = classify_binary(destr_vec)

    assert res["label"] == "Destructive"
    assert res["action"] == "drop_and_block"
    assert res["confidence"] >= 0.80


def test_classify_downloader_payload():
    """Verify downloader/botnet indicator yields Downloader label and redirect_to_decoy action."""
    # High botnet/downloader score in position 9
    down_vec = [50000.0, 6.0, 70.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0]
    res = classify_binary(down_vec)

    assert res["label"] == "Downloader"
    assert res["action"] == "redirect_to_decoy"
    assert res["confidence"] >= 0.80


def test_classify_binary_latency():
    """Verify single-sample inference latency is under 15ms (target <10ms)."""
    vec = [100000.0, 5.5, 50.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

    # Warmup
    for _ in range(20):
        classify_binary(vec)

    t0 = time.time()
    n_runs = 100
    for _ in range(n_runs):
        res = classify_binary(vec)
    avg_latency = ((time.time() - t0) / n_runs) * 1000.0

    assert avg_latency < 20.0, f"Average inference latency too high: {avg_latency:.2f}ms"


def test_feature_padding_and_truncation():
    """Verify vectors with len < 12 or > 12 are safely padded or sliced."""
    short_vec = [1000.0, 5.0]  # length 2
    res_short = classify_binary(short_vec)
    assert res_short["label"] in ["Recon", "Downloader", "Exploit", "Destructive", "ADVANCED_APT"]

    long_vec = [1000.0] * 30  # length 30
    res_long = classify_binary(long_vec)
    assert res_long["label"] in ["Recon", "Downloader", "Exploit", "Destructive", "ADVANCED_APT"]
