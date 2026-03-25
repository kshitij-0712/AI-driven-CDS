#!/usr/bin/env python3
"""
AdaptiveShield Statistics Generator - No PyTorch Required

Generates statistics and summaries for the Capstone presentation
without requiring the full neural model stack.

Run with: python src/generate_stats.py
"""

import sys
import json
import csv
from pathlib import Path
from collections import Counter
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

PROJECT_ROOT = Path(__file__).parent.parent
EXPORTS_PATH = PROJECT_ROOT / "data" / "exports"
MODELS_PATH = PROJECT_ROOT / "models"

# ============================================================================
# MITRE Stats (no torch needed)
# ============================================================================

def load_mitre_stats():
    """Load and display MITRE knowledge base statistics."""
    print("\n" + "=" * 70)
    print(" MITRE ATT&CK KNOWLEDGE BASE STATISTICS")
    print("=" * 70)
    
    # Import MITRE module
    from core.mitre.attack_mapping import ATTACK_PATTERNS, TACTICS, TACTIC_NAMES
    
    print(f"\n  Total Command Patterns: {len(ATTACK_PATTERNS)}")
    
    # Unique techniques
    techniques = set(p['technique_id'] for p in ATTACK_PATTERNS)
    print(f"  Unique Techniques: {len(techniques)}")
    print(f"  Tactics Defined: {len(TACTICS)}")
    
    # Count by tactic
    tactic_counts = Counter(p['tactic'] for p in ATTACK_PATTERNS)
    print(f"\n  Patterns by Tactic:")
    for tactic in TACTIC_NAMES:
        count = tactic_counts.get(tactic, 0)
        if count > 0:
            tactic_id = TACTICS[tactic]['id']
            bar = "█" * (count // 2) + "░" * ((15 - count) // 2)
            print(f"    {tactic.replace('_', ' ').title():28s} ({tactic_id}): {bar} {count}")
    
    # Severity distribution
    severity_counts = Counter(p['severity'] for p in ATTACK_PATTERNS)
    print(f"\n  Severity Distribution:")
    for sev in range(1, 11):
        count = severity_counts.get(sev, 0)
        bar = "█" * count
        print(f"    Severity {sev:2d}: {bar} {count}")
    
    return len(ATTACK_PATTERNS), len(techniques)

# ============================================================================
# Dataset Stats
# ============================================================================

def load_dataset_stats():
    """Load and display dataset statistics."""
    print("\n" + "=" * 70)
    print(" TRAINING DATASET STATISTICS")
    print("=" * 70)
    
    # Load manifest
    manifest_path = EXPORTS_PATH / "export_manifest.json"
    if manifest_path.exists():
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        
        prov = manifest.get('data_provenance', {})
        print(f"\n  Data Provenance:")
        print(f"    Honeypot Duration:   {prov.get('honeypot_duration_days', 'N/A')} days")
        print(f"    Cowrie Log Files:    {prov.get('cowrie_log_files', 'N/A')}")
        print(f"    Total Sessions:      {prov.get('total_sessions', 'N/A'):,}")
        print(f"    Sessions w/ Commands:{prov.get('sessions_with_commands', 'N/A'):,}")
        print(f"    Download Events:     {prov.get('total_download_events', 'N/A'):,}")
        print(f"    Unique Binaries:     {prov.get('unique_binaries', 'N/A')}")
        print(f"    Deep-Analyzed:       {prov.get('binaries_with_ghidra', 'N/A')}")
    
    # Load sessions CSV header
    sessions_path = EXPORTS_PATH / "sessions_complete.csv"
    if sessions_path.exists():
        with open(sessions_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader)
            row_count = sum(1 for _ in reader)
        
        print(f"\n  Feature Engineering:")
        print(f"    Total Sessions:      {row_count:,}")
        print(f"    Feature Columns:     {len(header)}")
        
        # Count feature types
        mitre_cols = sum(1 for c in header if c.startswith('mitre_'))
        triage_cols = sum(1 for c in header if c.startswith('triage_'))
        ghidra_cols = sum(1 for c in header if c.startswith('ghidra_'))
        angr_cols = sum(1 for c in header if c.startswith('angr_'))
        script_cols = sum(1 for c in header if c.startswith('script_'))
        deep_cols = sum(1 for c in header if c.startswith('deep_') or c.startswith('has_'))
        
        print(f"\n  Feature Breakdown:")
        print(f"    MITRE ATT&CK:        {mitre_cols} features")
        print(f"    Phase 1 Triage:      {triage_cols} features")
        print(f"    Phase 2 Ghidra:      {ghidra_cols} features")
        print(f"    Phase 3 angr:        {angr_cols} features")
        print(f"    Script Analysis:     {script_cols} features")
        print(f"    Derived/Cross-src:   {deep_cols} features")
        
        return row_count, len(header)
    
    return 0, 0

# ============================================================================
# Model Stats
# ============================================================================

def load_model_stats():
    """Load and display model training statistics."""
    print("\n" + "=" * 70)
    print(" NEURAL MODEL STATISTICS")
    print("=" * 70)
    
    results_path = MODELS_PATH / "brain_v5_semantic_balanced_results.json"
    if not results_path.exists():
        print(f"  Model results not found at {results_path}")
        return
    
    with open(results_path, 'r') as f:
        results = json.load(f)
    
    # Training stats
    training = results.get('training', {})
    print(f"\n  Training:")
    print(f"    Epochs Trained:      {training.get('epochs_trained', 'N/A')}")
    print(f"    Best Val F1:         {training.get('best_val_f1', 0):.4f}")
    print(f"    Training Time:       {training.get('total_time_seconds', 0)/60:.1f} minutes")
    
    # Test stats
    test = results.get('test', {})
    print(f"\n  Test Performance:")
    print(f"    Accuracy:            {test.get('accuracy', 0)*100:.2f}%")
    print(f"    Macro F1:            {test.get('macro_f1', 0):.4f}")
    print(f"    Weighted F1:         {test.get('weighted_f1', 0):.4f}")
    
    # Per-class F1
    class_names = ['Safe', 'Recon', 'Downloader', 'Exploit', 'Destructive', 'APT']
    per_class_f1 = test.get('per_class_f1', [])
    if per_class_f1:
        print(f"\n  Per-Class F1 Scores:")
        for name, f1 in zip(class_names, per_class_f1):
            bar = "█" * int(f1 * 20) + "░" * (20 - int(f1 * 20))
            print(f"    {name:12s}: [{bar}] {f1:.4f}")
    
    # Model config
    config = results.get('model_config', {})
    print(f"\n  Architecture:")
    print(f"    Vocab Size:          {config.get('vocab_size', 'N/A')}")
    print(f"    Embedding Dim:       {config.get('embed_dim', 'N/A')}")
    print(f"    LSTM Hidden:         {config.get('lstm_hidden', 'N/A')}")
    print(f"    LSTM Layers:         {config.get('lstm_layers', 'N/A')}")
    print(f"    Structured Input:    {config.get('structured_dim', 'N/A')}")
    print(f"    Output Classes:      {config.get('num_classes', 'N/A')}")

# ============================================================================
# Binary Analysis Stats  
# ============================================================================

def load_binary_stats():
    """Load and display binary analysis statistics."""
    print("\n" + "=" * 70)
    print(" BINARY ANALYSIS STATISTICS")
    print("=" * 70)
    
    binary_path = EXPORTS_PATH / "binary_features.csv"
    if not binary_path.exists():
        print(f"  Binary features not found at {binary_path}")
        return
    
    with open(binary_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        binaries = list(reader)
    
    print(f"\n  Total Binaries Analyzed: {len(binaries)}")
    
    # Count by type
    go_count = sum(1 for b in binaries if b.get('triage_is_go', '0') == '1' or b.get('triage_is_go', '0') == 'True')
    packed_count = sum(1 for b in binaries if b.get('triage_is_packed', '0') == '1' or b.get('triage_is_packed', '0') == 'True')
    ghidra_count = sum(1 for b in binaries if b.get('has_ghidra_results', '0') == '1' or b.get('has_ghidra_results', '0') == 'True')
    angr_count = sum(1 for b in binaries if b.get('has_angr_results', '0') == '1' or b.get('has_angr_results', '0') == 'True')
    
    print(f"    Go Binaries:         {go_count}")
    print(f"    Packed/Obfuscated:   {packed_count}")
    print(f"    Ghidra Analyzed:     {ghidra_count}")
    print(f"    angr Analyzed:       {angr_count}")

# ============================================================================
# Label Distribution
# ============================================================================

def load_label_stats():
    """Load and display label distribution."""
    print("\n" + "=" * 70)
    print(" LABEL DISTRIBUTION")
    print("=" * 70)
    
    labels_path = EXPORTS_PATH / "session_labels.csv"
    if not labels_path.exists():
        # Try sessions_complete
        labels_path = EXPORTS_PATH / "sessions_complete.csv"
    
    if not labels_path.exists():
        print(f"  Labels not found")
        return
    
    label_counts = Counter()
    with open(labels_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            label = row.get('label_name', row.get('label_id', 'Unknown'))
            label_counts[label] += 1
    
    class_names = ['Safe', 'Recon', 'Downloader', 'Exploit', 'Destructive', 'ADVANCED_APT']
    total = sum(label_counts.values())
    
    print(f"\n  Total Sessions: {total:,}")
    print(f"\n  Distribution:")
    for name in class_names:
        count = label_counts.get(name, 0)
        pct = count / total * 100 if total > 0 else 0
        bar_width = int(pct / 2)
        bar = "█" * bar_width + "░" * (50 - bar_width)
        print(f"    {name:15s}: {count:7,} ({pct:5.2f}%) [{bar}]")

# ============================================================================
# Generate Summary Table (for slides)
# ============================================================================

def generate_summary_table():
    """Generate a summary table for slides."""
    print("\n" + "=" * 70)
    print(" SUMMARY TABLE (FOR SLIDES)")
    print("=" * 70)
    
    print("""
    +---------------------------+------------------+
    | Metric                    | Value            |
    +---------------------------+------------------+
    | Honeypot Duration         | 63 days          |
    | Total Sessions            | 78,504           |
    | Download Events           | 50,520           |
    | Unique Binaries           | 185              |
    | Deep-Analyzed Binaries    | 41               |
    | MITRE Patterns            | 76               |
    | MITRE Techniques          | 53               |
    | Feature Dimensions        | 111              |
    | Neural Model Parameters   | 706,574          |
    | Test Macro F1             | 0.9655           |
    | Test Accuracy             | 98.37%           |
    | Lines of Code             | ~12,600          |
    +---------------------------+------------------+
    """)

# ============================================================================
# Main
# ============================================================================

def main():
    print("\n" + "=" * 70)
    print("    ADAPTIVESHIELD - CAPSTONE STATISTICS REPORT")
    print(f"    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    try:
        load_mitre_stats()
    except ImportError as e:
        print(f"  Could not load MITRE stats: {e}")
    
    load_dataset_stats()
    load_model_stats()
    load_binary_stats()
    load_label_stats()
    generate_summary_table()
    
    print("\n" + "=" * 70)
    print("                    Report Complete")
    print("=" * 70 + "\n")

if __name__ == '__main__':
    main()
