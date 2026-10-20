"""
Unit tests for the static PE fallback extractor and feature merger compatibility.
"""

import os
import pytest
from src.core.malware.pe_fallback import (
    generate_ghidra_fallback,
    generate_angr_fallback,
    extract_raw_pe_metadata,
)
from src.core.malware.feature_merger import (
    _extract_ghidra_features,
    _extract_angr_features,
    _compute_derived_features,
    get_feature_vector,
    DEEP_FEATURE_COLUMNS,
)

SAMPLE_DIR = "/media/sf_Linux_Shared_Folder/AdaptiveShield_datasets/motif/extracted_binaries"


@pytest.fixture
def sample_binary_path():
    if os.path.isdir(SAMPLE_DIR):
        files = [f for f in os.listdir(SAMPLE_DIR) if f.endswith(".exe")]
        if files:
            return os.path.join(SAMPLE_DIR, files[0])
    return None


def test_ghidra_fallback_schema(sample_binary_path):
    if not sample_binary_path:
        pytest.skip("Shared dataset directory not mounted.")

    sha = os.path.basename(sample_binary_path).replace(".exe", "")
    fb = generate_ghidra_fallback(sample_binary_path, sha, reason="timeout")

    assert fb["partial"] is True
    assert fb["timed_out"] is True
    assert fb["fallback"] == "pefile_static"
    assert "basic" in fb
    assert "sections" in fb
    assert "imports" in fb
    assert "import_categories" in fb
    assert "data_patterns" in fb
    assert "string_indicators" in fb
    assert "functions" in fb

    # Test compatibility with feature_merger
    feats = _extract_ghidra_features(fb)
    assert isinstance(feats, dict)
    assert "ghidra_function_count" in feats
    assert "ghidra_imports_file_io" in feats
    assert "ghidra_imports_network" in feats
    assert "ghidra_has_aes_sbox" in feats


def test_angr_fallback_schema(sample_binary_path):
    if not sample_binary_path:
        pytest.skip("Shared dataset directory not mounted.")

    sha = os.path.basename(sample_binary_path).replace(".exe", "")
    fb = generate_angr_fallback(sample_binary_path, sha, reason="timeout")

    assert fb["partial"] is True
    assert fb["timed_out"] is True
    assert fb["fallback"] == "pefile_static"
    assert "cfg_metrics" in fb
    assert "behavioral_summary" in fb
    assert "syscalls" in fb
    assert "strings" in fb

    # Test compatibility with feature_merger
    feats = _extract_angr_features(fb)
    assert isinstance(feats, dict)
    assert "angr_basic_blocks" in feats
    assert "angr_cyclomatic_complexity" in feats
    assert "angr_has_network" in feats
    assert feats["angr_is_partial"] == 1.0


def test_fallback_full_vector_generation(sample_binary_path):
    if not sample_binary_path:
        pytest.skip("Shared dataset directory not mounted.")

    sha = os.path.basename(sample_binary_path).replace(".exe", "")
    g_fb = generate_ghidra_fallback(sample_binary_path, sha, reason="timeout")
    a_fb = generate_angr_fallback(sample_binary_path, sha, reason="timeout")

    gf = _extract_ghidra_features(g_fb)
    af = _extract_angr_features(a_fb)
    df = _compute_derived_features({}, gf, af, {})

    entry = {"sha256": sha}
    entry.update(gf)
    entry.update(af)
    entry.update(df)

    vec = get_feature_vector(entry)
    assert len(vec) == len(DEEP_FEATURE_COLUMNS)
    assert all(isinstance(v, float) for v in vec)
