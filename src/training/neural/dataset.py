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
        'triage_file_size', 'triage_entropy', 'triage_priority',
        'triage_is_go', 'triage_is_packed', 'triage_is_stripped',
        'triage_is_dll', 'triage_is_static', 'triage_score_mining',
        'triage_score_botnet', 'triage_score_recon', 'triage_score_destructive',
        'triage_ghidra_score', 'triage_angr_score'
    ]
    
    def __init__(self, data: pd.DataFrame, tokenizer: CommandTokenizer):
        self.tokenizer = tokenizer
        self.commands = data['commands'].fillna('').tolist()
        
        # 1. MITRE (21 dim)
        for col in self.MITRE_COLS:
            if col not in data.columns:
                data[col] = 0.0
        self.mitre = data[self.MITRE_COLS].fillna(0).values.astype(np.float32)
        
        # 2. Triage (12 dim)
        for col in self.TRIAGE_COLS:
            if col not in data.columns:
                data[col] = 0.0
        self.triage = data[self.TRIAGE_COLS].fillna(0).values.astype(np.float32)
        
        # 3. Changes (20 dim)
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
        self.changes = np.array(changes_list, dtype=np.float32)
        
        # 4. Modality Mask logic (True = missing)
        self.mitre_mask = (self.mitre.sum(axis=1) == 0)
        self.changes_mask = (self.changes.sum(axis=1) == 0)
        self.triage_mask = (self.triage.sum(axis=1) == 0)
        
        # Get Deep Analysis (Knowledge Distillation) features
        # If missing in legacy data, default to 0.0
        ghidra = data['triage_ghidra_score'] if 'triage_ghidra_score' in data.columns else pd.Series([0.0]*len(data), index=data.index)
        angr = data['triage_angr_score'] if 'triage_angr_score' in data.columns else pd.Series([0.0]*len(data), index=data.index)
        self.deep_analysis = np.column_stack([ghidra.fillna(0.0).values, angr.fillna(0.0).values]).astype(np.float32)
        
        self.labels = data['label_id'].values.astype(np.int64)
        self.structured_dim = 21 + 12 + 20 # For legacy compatibility metric if needed
    
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
            'deep_analysis': torch.tensor(self.deep_analysis[idx], dtype=torch.float32),
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
        'deep_analysis': torch.stack([item['deep_analysis'] for item in batch]),
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
            syn_df = pd.read_csv(synthetic_path)
            df = pd.concat([df, syn_df], ignore_index=True)
            
        # Load the Active Learning generated edge cases
        active_learning_path = 'data/exports/active_learning_edges.csv'
        if os.path.isfile(active_learning_path):
            print(f"Loading Active Learning edge cases from {active_learning_path}")
            al_df = pd.read_csv(active_learning_path)
            df = pd.concat([df, al_df], ignore_index=True)

        if synthetic_data is not None and not synthetic_data.empty:
            df = pd.concat([df, synthetic_data], ignore_index=True)
    
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
