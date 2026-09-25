"""
Dataset and tokenization utilities for neural model training (Phase 2 Unified Architecture).
"""

import torch
from torch.utils.data import Dataset, DataLoader
import pandas as pd
import numpy as np
from typing import Tuple, List, Optional, Dict
from pathlib import Path
import ast
import re

def clean_payload(text: str) -> str:
    """Strip HTTP method and version, keep URL path, headers, and body."""
    if not isinstance(text, str):
        return text
    # Remove standard HTTP methods and version
    text = re.sub(r'^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+', '', text)
    text = re.sub(r'\s+HTTP/1\.[01]', '', text)
    return text
    
class CommandTokenizer:
    PAD_TOKEN = 0
    UNK_TOKEN = 1
    
    def __init__(self, max_length: int = 512):
        self.max_length = max_length
        self.vocab_size = 256
    
    def encode(self, text: str) -> List[int]:
        indices = []
        for char in text[:self.max_length]:
            code = ord(char)
            if code < 256:
                indices.append(code)
            else:
                indices.append(self.UNK_TOKEN)
        return indices
    
    def decode(self, indices: List[int]) -> str:
        chars = []
        for idx in indices:
            if idx == self.PAD_TOKEN:
                break
            if idx == self.UNK_TOKEN:
                chars.append('?')
            else:
                chars.append(chr(idx))
        return ''.join(chars)

class ThreatDataset(Dataset):
    """PyTorch Dataset for Unified Threat Classification."""
    
    MITRE_COLS = [
        'mitre_tactic_reconnaissance', 'mitre_tactic_resource_development',
        'mitre_tactic_initial_access', 'mitre_tactic_execution',
        'mitre_tactic_persistence', 'mitre_tactic_privilege_escalation',
        'mitre_tactic_defense_evasion', 'mitre_tactic_credential_access',
        'mitre_tactic_discovery', 'mitre_tactic_lateral_movement',
        'mitre_tactic_collection', 'mitre_tactic_command_and_control',
        'mitre_tactic_exfiltration', 'mitre_tactic_impact',
        'mitre_severity_max', 'mitre_severity_mean',
        'mitre_severity_weighted', 'mitre_kill_chain_score',
        'mitre_unique_technique_count', 'mitre_total_commands',
        'mitre_matched_commands'
    ]

    TRIAGE_COLS = [
        # Static triage (12)
        'triage_file_size', 'triage_entropy', 'triage_priority',
        'triage_is_go', 'triage_is_packed', 'triage_is_stripped',
        'triage_is_dll', 'triage_is_static', 'triage_score_mining',
        'triage_score_botnet', 'triage_score_recon', 'triage_score_destructive',
        # Ghidra features (23)
        'ghidra_function_count', 'ghidra_total_instructions',
        'ghidra_total_basic_blocks', 'ghidra_max_function_size',
        'ghidra_avg_callers', 'ghidra_max_callers',
        'ghidra_mining_pool_count', 'ghidra_crypto_wallet_count',
        'ghidra_ip_count', 'ghidra_url_count',
        'ghidra_shell_cmd_count', 'ghidra_file_path_count',
        'ghidra_imports_file_io', 'ghidra_imports_process',
        'ghidra_imports_network', 'ghidra_imports_crypto',
        'ghidra_imports_evasion',
        'ghidra_has_aes_sbox', 'ghidra_has_sha256_constants',
        'ghidra_has_rc4_state', 'ghidra_has_xor_loop',
        'ghidra_go_user_functions', 'ghidra_go_runtime_functions',
        # Angr features (25)
        'angr_basic_blocks', 'angr_edges', 'angr_functions_recovered',
        'angr_cyclomatic_complexity', 'angr_function_count',
        'angr_user_functions_listed',
        'angr_syscalls_network', 'angr_syscalls_file_io',
        'angr_syscalls_process', 'angr_syscalls_memory',
        'angr_ip_count', 'angr_url_count',
        'angr_mining_indicator_count', 'angr_shell_cmd_count',
        'angr_has_network', 'angr_has_file_manipulation',
        'angr_has_process_control', 'angr_has_crypto',
        'angr_has_mining', 'angr_has_persistence',
        'angr_has_evasion', 'angr_has_shell_execution',
        'angr_complexity_tier', 'angr_is_partial', 'angr_loaded_as_blob',
        # Derived features (10)
        'has_ghidra_results', 'has_angr_results', 'has_script_results',
        'deep_func_ratio_angr_ghidra', 'deep_mining_signal_count',
        'deep_total_network_indicators', 'deep_total_crypto_indicators',
        'deep_max_complexity', 'deep_total_evasion_indicators',
        'deep_is_go_consensus',
    ]
    
    def __init__(self, data: pd.DataFrame, tokenizer: CommandTokenizer):
        self.tokenizer = tokenizer
        
        # Extract commands, determine protocol, and clean HTTP boilerplate
        raw_commands = data['commands'].fillna('').tolist()
        cleaned_commands = []
        is_http_list = []
        
        for cmd in raw_commands:
            if "HTTP/1." in cmd or "Host:" in cmd:
                is_http_list.append(1.0)
                cleaned_commands.append(clean_payload(cmd))
            else:
                is_http_list.append(0.0)
                cleaned_commands.append(cmd)
                
        self.commands = cleaned_commands
        
        # 1. MITRE (21 dim)
        for col in self.MITRE_COLS:
            if col not in data.columns:
                data[col] = 0.0
        self.mitre = data[self.MITRE_COLS].fillna(0).values.astype(np.float32)
        
        # 2. Triage (70 dim: 12 static + 23 ghidra + 25 angr + 10 derived)
        for col in self.TRIAGE_COLS:
            if col not in data.columns:
                data[col] = 0.0
        self.triage = data[self.TRIAGE_COLS].fillna(0).values.astype(np.float32)
        
        # 3. Changes (21 dim: 20 system changes + 1 protocol flag)
        def parse_changes(x):
            if isinstance(x, str):
                try:
                    return ast.literal_eval(x)
                except:
                    return [0.0] * 20
            elif isinstance(x, list) and len(x) == 20:
                return x
            return [0.0] * 20
            
        if 'change_features' in data.columns:
            changes_list = data['change_features'].apply(parse_changes).tolist()
        else:
            changes_list = [[0.0] * 20 for _ in range(len(data))]
            
        # Append the protocol flag (is_http) as the 21st dimension
        for i in range(len(changes_list)):
            changes_list[i].append(is_http_list[i])
            
        self.changes = np.array(changes_list, dtype=np.float32)

        # 4. Modality Mask logic (True = missing)
        self.mitre_mask = (self.mitre.sum(axis=1) == 0)
        self.changes_mask = (self.changes.sum(axis=1) == 0)
        self.triage_mask = (self.triage.sum(axis=1) == 0)
        
        self.labels = data['label_id'].values.astype(np.int64)

    @property
    def structured_dim(self) -> int:
        """Total dimension of structured features (MITRE + changes + triage)."""
        return self.mitre.shape[1] + self.changes.shape[1] + self.triage.shape[1]
    
    def __len__(self) -> int:
        return len(self.commands)
    
    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        indices = self.tokenizer.encode(self.commands[idx])
        if len(indices) < self.tokenizer.max_length:
            indices = indices + [self.tokenizer.PAD_TOKEN] * (self.tokenizer.max_length - len(indices))
        indices = indices[:self.tokenizer.max_length]
        
        cmd_missing = len(self.commands[idx].strip()) == 0
        mask = [cmd_missing, bool(self.mitre_mask[idx]), bool(self.changes_mask[idx]), bool(self.triage_mask[idx])]
        
        return {
            'commands': torch.tensor(indices, dtype=torch.long),
            'length': torch.tensor(min(len(self.commands[idx]), self.tokenizer.max_length)),
            'mitre': torch.tensor(self.mitre[idx], dtype=torch.float32),
            'changes': torch.tensor(self.changes[idx], dtype=torch.float32),
            'triage': torch.tensor(self.triage[idx], dtype=torch.float32),
            'modality_mask': torch.tensor(mask, dtype=torch.bool),
            'label': torch.tensor(self.labels[idx], dtype=torch.long)
        }

def collate_fn(batch: List[Dict]) -> Dict[str, torch.Tensor]:
    max_len = max(item['length'].item() for item in batch)
    max_len = min(max_len, batch[0]['commands'].size(0))
    
    return {
        'commands': torch.stack([item['commands'][:max_len] for item in batch]),
        'lengths': torch.stack([item['length'] for item in batch]),
        'mitre': torch.stack([item['mitre'] for item in batch]),
        'changes': torch.stack([item['changes'] for item in batch]),
        'triage': torch.stack([item['triage'] for item in batch]),
        'modality_mask': torch.stack([item['modality_mask'] for item in batch]),
        'labels': torch.stack([item['label'] for item in batch])
    }

def load_dataset(
    csv_path: str = 'data/exports/sessions_complete.csv',
    max_length: int = 512,
    test_size: float = 0.15,
    val_size: float = 0.15,
    random_state: int = 42,
    downsample_safe: Optional[int] = 5000,
    include_synthetic: bool = True,
    synthetic_data: Optional[pd.DataFrame] = None,
    **kwargs
) -> Tuple[ThreatDataset, ThreatDataset, ThreatDataset, CommandTokenizer]:
    
    print(f"Loading data from {csv_path}")
    
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        print(f"Warning: {csv_path} not found. Creating empty DataFrame.")
        df = pd.DataFrame(columns=['session_id', 'commands', 'label_id', 'label_name'])
        
    if 'label_id' not in df.columns:
        df['label_id'] = 0
    
    if downsample_safe is not None and downsample_safe > 0 and not df.empty:
        safe_mask = df['label_id'] == 0
        if safe_mask.sum() > downsample_safe:
            safe_subset = df[safe_mask].sample(n=downsample_safe, random_state=random_state)
            malicious_subset = df[~safe_mask]
            df = pd.concat([safe_subset, malicious_subset])
    
    if include_synthetic:
        # Load the manually generated LLM batches
        import os
        synthetic_path = 'data/exports/synthetic_batches.csv'
        if os.path.isfile(synthetic_path):
            print(f"Loading generated synthetic batches from {synthetic_path}")
            syn_df = pd.read_csv(synthetic_path, low_memory=False)
            df = pd.concat([df, syn_df], ignore_index=True)
            
        # Load the Active Learning generated edge cases
        active_learning_path = 'data/exports/active_learning_edges.csv'
        if os.path.isfile(active_learning_path):
            print(f"Loading Active Learning edge cases from {active_learning_path}")
            al_df = pd.read_csv(active_learning_path, low_memory=False)
            df = pd.concat([df, al_df], ignore_index=True)

        if synthetic_data is not None and not synthetic_data.empty:
            df = pd.concat([df, synthetic_data], ignore_index=True)
    
    # Filter out non-numeric label_id rows (e.g. extra CSV headers)
    if 'label_id' in df.columns:
        df['label_id'] = pd.to_numeric(df['label_id'], errors='coerce')
        df = df.dropna(subset=['label_id'])
        df['label_id'] = df['label_id'].astype(int)
    
    # Very basic train/test/val split
    if not df.empty:
        # Shuffle
        df = df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
        
        n_total = len(df)
        n_test = int(n_total * test_size)
        n_val = int(n_total * val_size)
        
        test_df = df.iloc[:n_test]
        val_df = df.iloc[n_test:n_test+n_val]
        train_df = df.iloc[n_test+n_val:]
    else:
        train_df, val_df, test_df = df, df, df
        
    tokenizer = CommandTokenizer(max_length=max_length)
    
    train_dataset = ThreatDataset(train_df, tokenizer)
    val_dataset = ThreatDataset(val_df, tokenizer)
    test_dataset = ThreatDataset(test_df, tokenizer)
    
    return train_dataset, val_dataset, test_dataset, tokenizer

def create_dataloaders(
    train_dataset: ThreatDataset,
    val_dataset: ThreatDataset,
    test_dataset: ThreatDataset,
    batch_size: int = 64,
    num_workers: int = 0
) -> Tuple[DataLoader, DataLoader, DataLoader]:
    
    train_loader = DataLoader(
        train_dataset, batch_size=batch_size, shuffle=True,
        num_workers=num_workers, collate_fn=collate_fn, pin_memory=True
    )
    val_loader = DataLoader(
        val_dataset, batch_size=batch_size, shuffle=False,
        num_workers=num_workers, collate_fn=collate_fn, pin_memory=True
    )
    test_loader = DataLoader(
        test_dataset, batch_size=batch_size, shuffle=False,
        num_workers=num_workers, collate_fn=collate_fn, pin_memory=True
    )
    
    return train_loader, val_loader, test_loader
