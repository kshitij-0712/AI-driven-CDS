"""
Dataset and tokenization utilities for neural model training.

Handles:
- Character-level tokenization of command strings
- Loading and preprocessing sessions_complete.csv
- Train/val/test splitting with stratification
- DataLoader creation with proper batching
- Semantic labeling based on command behavior (not just binary downloads)
"""

import torch
from torch.utils.data import Dataset, DataLoader
import pandas as pd
import numpy as np
from typing import Tuple, List, Optional, Dict
from pathlib import Path

from training.neural.semantic_labels import (
    create_combined_labels,
    label_sessions_semantic,
    analyze_semantic_coverage
)


class CommandTokenizer:
    """
    Character-level tokenizer for shell commands.
    
    Converts command strings to sequences of character indices.
    Uses ASCII encoding (0-255) with 0 as padding token.
    """
    
    PAD_TOKEN = 0
    UNK_TOKEN = 1  # For non-ASCII characters
    
    def __init__(self, max_length: int = 512):
        """
        Args:
            max_length: Maximum sequence length (truncate longer, pad shorter)
        """
        self.max_length = max_length
        self.vocab_size = 256  # Full ASCII range
    
    def encode(self, text: str) -> List[int]:
        """
        Encode a command string to character indices.
        
        Args:
            text: Command string (semicolon-separated commands)
        Returns:
            List of character indices
        """
        # Convert to ASCII, replacing non-ASCII with UNK
        indices = []
        for char in text[:self.max_length]:
            code = ord(char)
            if code < 256:
                indices.append(code)
            else:
                indices.append(self.UNK_TOKEN)
        
        return indices
    
    def encode_batch(
        self, 
        texts: List[str], 
        return_lengths: bool = True
    ) -> Tuple[torch.Tensor, Optional[torch.Tensor]]:
        """
        Encode a batch of command strings with padding.
        
        Args:
            texts: List of command strings
            return_lengths: Whether to return original lengths
        Returns:
            Padded tensor [batch, max_length] and optional lengths [batch]
        """
        encoded = [self.encode(text) for text in texts]
        lengths = [len(seq) for seq in encoded]
        
        # Pad sequences
        max_len = min(max(lengths), self.max_length)
        padded = []
        for seq in encoded:
            if len(seq) < max_len:
                seq = seq + [self.PAD_TOKEN] * (max_len - len(seq))
            padded.append(seq[:max_len])
        
        tensor = torch.tensor(padded, dtype=torch.long)
        
        if return_lengths:
            lengths_tensor = torch.tensor(
                [min(l, max_len) for l in lengths], 
                dtype=torch.long
            )
            return tensor, lengths_tensor
        
        return tensor, None
    
    def decode(self, indices: List[int]) -> str:
        """Decode indices back to string (for debugging)."""
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
    """
    PyTorch Dataset for threat classification.
    
    Loads sessions_complete.csv and provides:
    - commands: Character indices for BiLSTM
    - structured: MITRE + binary feature vectors
    - labels: Class labels (0-5)
    """
    
    # MITRE feature columns (21)
    MITRE_COLS = [
        'mitre_tactic_reconnaissance',
        'mitre_tactic_resource_development',
        'mitre_tactic_initial_access',
        'mitre_tactic_execution',
        'mitre_tactic_persistence',
        'mitre_tactic_privilege_escalation',
        'mitre_tactic_defense_evasion',
        'mitre_tactic_credential_access',
        'mitre_tactic_discovery',
        'mitre_tactic_lateral_movement',
        'mitre_tactic_collection',
        'mitre_tactic_command_and_control',
        'mitre_tactic_exfiltration',
        'mitre_tactic_impact',
        'mitre_severity_max',
        'mitre_severity_mean',
        'mitre_severity_weighted',
        'mitre_kill_chain_score',
        'mitre_unique_technique_count',
        'mitre_total_commands',
        'mitre_matched_commands'
    ]
    
    # Binary feature prefixes
    BINARY_PREFIXES = ('triage_', 'ghidra_', 'angr_', 'script_', 'deep_', 'has_')
    
    def __init__(
        self,
        data: pd.DataFrame,
        tokenizer: CommandTokenizer,
        structured_cols: Optional[List[str]] = None,
        mitre_only: bool = False
    ):
        """
        Args:
            data: DataFrame with commands, features, and labels
            tokenizer: CommandTokenizer instance
            structured_cols: List of structured feature column names
            mitre_only: If True, use only MITRE columns (ignore binary features)
        """
        self.tokenizer = tokenizer
        
        # Get commands
        self.commands = data['commands'].fillna('').tolist()
        
        # Get structured features
        if structured_cols is None:
            if mitre_only:
                # Use only MITRE columns
                structured_cols = self.MITRE_COLS.copy()
            else:
                # Auto-detect all structured columns
                structured_cols = self.MITRE_COLS.copy()
                for col in data.columns:
                    if any(col.startswith(p) for p in self.BINARY_PREFIXES):
                        if col not in structured_cols:
                            structured_cols.append(col)
        
        self.structured_cols = structured_cols
        self.structured_dim = len(structured_cols)
        
        # Extract and convert to numpy
        self.structured = data[structured_cols].fillna(0).values.astype(np.float32)
        
        # Get labels
        self.labels = data['label_id'].values.astype(np.int64)
        
        # Store session IDs for tracking
        self.session_ids = data['session_id'].values if 'session_id' in data.columns else None
    
    def __len__(self) -> int:
        return len(self.commands)
    
    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        """
        Get a single sample.
        
        Returns dict with:
            - commands: Character indices [max_length]
            - length: Original command length (scalar)
            - structured: Feature vector [structured_dim]
            - label: Class label (scalar)
        """
        # Tokenize command
        indices = self.tokenizer.encode(self.commands[idx])
        
        # Pad to max length
        if len(indices) < self.tokenizer.max_length:
            indices = indices + [self.tokenizer.PAD_TOKEN] * (
                self.tokenizer.max_length - len(indices)
            )
        indices = indices[:self.tokenizer.max_length]
        
        return {
            'commands': torch.tensor(indices, dtype=torch.long),
            'length': torch.tensor(min(len(self.commands[idx]), self.tokenizer.max_length)),
            'structured': torch.tensor(self.structured[idx], dtype=torch.float32),
            'label': torch.tensor(self.labels[idx], dtype=torch.long)
        }


def collate_fn(batch: List[Dict]) -> Dict[str, torch.Tensor]:
    """
    Custom collate function for DataLoader.
    
    Handles variable-length sequences by padding to max length in batch.
    """
    # Find max length in this batch (for efficiency)
    max_len = max(item['length'].item() for item in batch)
    max_len = min(max_len, batch[0]['commands'].size(0))  # Cap at tokenizer max
    
    commands = torch.stack([item['commands'][:max_len] for item in batch])
    lengths = torch.stack([item['length'] for item in batch])
    structured = torch.stack([item['structured'] for item in batch])
    labels = torch.stack([item['label'] for item in batch])
    
    return {
        'commands': commands,
        'lengths': lengths,
        'structured': structured,
        'labels': labels
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
    use_semantic_labels: bool = False,
    label_mode: str = 'combined',
    precomputed_labels_path: Optional[str] = None,
    mitre_only: bool = False
) -> Tuple[ThreatDataset, ThreatDataset, ThreatDataset, CommandTokenizer]:
    """
    Load and split the dataset into train/val/test sets.
    
    Args:
        csv_path: Path to sessions_complete.csv
        max_length: Maximum command sequence length
        test_size: Fraction of data for test set
        val_size: Fraction of training data for validation
        random_state: Random seed for reproducibility
        downsample_safe: Max samples for Safe class (None = no downsampling)
        include_synthetic: Whether to add synthetic samples for rare classes
        synthetic_data: Pre-generated synthetic data (optional)
        use_semantic_labels: If True, use semantic labeling based on command behavior
        label_mode: 'demo-aligned' (optimized for demo test cases), 'semantic' (command behavior only),
                    'combined' (max of semantic + binary), or 'binary' (original binary-based labels)
        precomputed_labels_path: Path to pre-computed semantic labels CSV (faster loading)
        mitre_only: If True, use only MITRE features (21 dims) instead of all features (100 dims)
    
    Returns:
        train_dataset, val_dataset, test_dataset, tokenizer
    """
    from sklearn.model_selection import train_test_split
    
    # Try to load pre-computed labels if semantic labels requested
    if use_semantic_labels and precomputed_labels_path and Path(precomputed_labels_path).exists():
        print(f"Loading pre-computed semantic labels from {precomputed_labels_path}...")
        df = pd.read_csv(precomputed_labels_path)
        print(f"Loaded {len(df)} sessions with pre-computed labels")
        
        # Use the appropriate label column
        if label_mode == 'mitre_only_semantic_balanced' and 'mitre_only_semantic_balanced_label_id' in df.columns:
            df['label_id'] = df['mitre_only_semantic_balanced_label_id']
            df['label_name'] = df['mitre_only_semantic_balanced_label_name']
            print(f"Using MITRE-only semantic balanced labels (matches semantic test case expectations)")
        elif label_mode == 'combined' and 'combined_label_id' in df.columns:
            df['label_id'] = df['combined_label_id']
            df['label_name'] = df['combined_label_name']
            print(f"Using combined labels (max of semantic + binary)")
        elif label_mode == 'semantic' and 'semantic_label_id' in df.columns:
            df['label_id'] = df['semantic_label_id']
            df['label_name'] = df['semantic_label_name']
            print(f"Using semantic-only labels")
        # else: keep original label_id
        
        print("\nLabel distribution:")
        print(df['label_id'].value_counts().sort_index())
    else:
        print(f"Loading dataset from {csv_path}...")
        df = pd.read_csv(csv_path)
        print(f"Loaded {len(df)} sessions")
        
        # Print original class distribution (binary-based)
        print("\nOriginal class distribution (binary-based):")
        print(df['label_id'].value_counts().sort_index())
        
        # Apply semantic labeling if requested (slow path)
        if use_semantic_labels:
            print(f"\nApplying semantic labeling (mode={label_mode})...")
            print("NOTE: This may take ~1 minute. Consider using --precomputed-labels for faster loading.")
            
            if label_mode == 'mitre_only_semantic_balanced':
                # Use MITRE-only semantic balanced labels
                from .semantic_labels import label_sessions_mitre_only_semantic_balanced
                df = label_sessions_mitre_only_semantic_balanced(df)
                df['label_id'] = df['mitre_only_semantic_balanced_label_id']
                df['label_name'] = df['mitre_only_semantic_balanced_label_name']
                print("\nMITRE-only semantic balanced labels:")
            else:
                # Analyze semantic coverage first
                coverage = analyze_semantic_coverage(df)
                print(f"  Sessions with label changes: {coverage['label_changes']:,} / {coverage['total_sessions']:,}")
                
                if label_mode == 'combined':
                    # Use combined labels: max(semantic, binary)
                    df = create_combined_labels(df)
                    df['label_id'] = df['combined_label_id']
                    df['label_name'] = df['combined_label_name']
                    print("\nCombined labels (max of semantic + binary):")
                elif label_mode == 'semantic':
                    # Use semantic-only labels
                    df = label_sessions_semantic(df)
                    df['label_id'] = df['semantic_label_id']
                    df['label_name'] = df['semantic_label_name']
                    print("\nSemantic-only labels (command behavior):")
            
            print(df['label_id'].value_counts().sort_index())
    
    # Downsample Safe class if requested
    if downsample_safe is not None:
        safe_mask = df['label_id'] == 0
        safe_samples = df[safe_mask]
        other_samples = df[~safe_mask]
        
        if len(safe_samples) > downsample_safe:
            safe_samples = safe_samples.sample(n=downsample_safe, random_state=random_state)
            df = pd.concat([safe_samples, other_samples], ignore_index=True)
            print(f"\nAfter downsampling Safe to {downsample_safe}:")
            print(df['label_id'].value_counts().sort_index())
    
    # Downsample Destructive class (label_id=4) to balance with other classes
    # This is important because semantic labeling creates many Destructive samples
    destructive_mask = df['label_id'] == 4
    destructive_samples = df[destructive_mask]
    other_samples = df[~destructive_mask]
    max_destructive = 5000  # Cap at same level as downsampled Safe
    
    if len(destructive_samples) > max_destructive:
        destructive_samples = destructive_samples.sample(n=max_destructive, random_state=random_state)
        df = pd.concat([destructive_samples, other_samples], ignore_index=True)
        print(f"\nAfter downsampling Destructive to {max_destructive}:")
        print(df['label_id'].value_counts().sort_index())
    
    # Add synthetic data if provided
    if include_synthetic and synthetic_data is not None:
        df = pd.concat([df, synthetic_data], ignore_index=True)
        print(f"\nAfter adding synthetic data:")
        print(df['label_id'].value_counts().sort_index())
    
    # Create tokenizer
    tokenizer = CommandTokenizer(max_length=max_length)
    
    # Stratified split
    # First split off test set
    train_val_df, test_df = train_test_split(
        df, 
        test_size=test_size, 
        stratify=df['label_id'],
        random_state=random_state
    )
    
    # Then split train into train/val
    train_df, val_df = train_test_split(
        train_val_df,
        test_size=val_size / (1 - test_size),
        stratify=train_val_df['label_id'],
        random_state=random_state
    )
    
    print(f"\nSplit sizes: train={len(train_df)}, val={len(val_df)}, test={len(test_df)}")
    
    # Create datasets
    train_dataset = ThreatDataset(train_df, tokenizer, mitre_only=mitre_only)
    val_dataset = ThreatDataset(val_df, tokenizer, mitre_only=mitre_only)
    test_dataset = ThreatDataset(test_df, tokenizer, mitre_only=mitre_only)
    
    return train_dataset, val_dataset, test_dataset, tokenizer


def create_dataloaders(
    train_dataset: ThreatDataset,
    val_dataset: ThreatDataset,
    test_dataset: ThreatDataset,
    batch_size: int = 64,
    num_workers: int = 0,  # Windows compatibility
    pin_memory: bool = True
) -> Tuple[DataLoader, DataLoader, DataLoader]:
    """
    Create DataLoaders for training.
    
    Args:
        train_dataset, val_dataset, test_dataset: Dataset instances
        batch_size: Batch size
        num_workers: Number of data loading workers (0 for Windows)
        pin_memory: Pin memory for faster GPU transfer
    
    Returns:
        train_loader, val_loader, test_loader
    """
    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        collate_fn=collate_fn,
        num_workers=num_workers,
        pin_memory=pin_memory
    )
    
    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size,
        shuffle=False,
        collate_fn=collate_fn,
        num_workers=num_workers,
        pin_memory=pin_memory
    )
    
    test_loader = DataLoader(
        test_dataset,
        batch_size=batch_size,
        shuffle=False,
        collate_fn=collate_fn,
        num_workers=num_workers,
        pin_memory=pin_memory
    )
    
    return train_loader, val_loader, test_loader
