"""
Neural model trainer for AdaptiveShield Phase 5.

Handles:
- Training loop with GPU support
- Validation and early stopping
- Learning rate scheduling
- Checkpointing
- Metrics logging (accuracy, F1, precision, recall per class)
- Confusion matrix visualization
"""

import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from torch.optim import Adam, AdamW
from torch.optim.lr_scheduler import ReduceLROnPlateau, CosineAnnealingLR, OneCycleLR
import numpy as np
from pathlib import Path
import pickle
import json
import time
from typing import Dict, List, Optional, Tuple, Union
from datetime import datetime

# Metrics
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report
)


class NeuralTrainer:
    """
    Trainer for ThreatClassifier neural model.
    
    Features:
    - Mixed precision training (AMP) for faster GPU training
    - Gradient accumulation for larger effective batch sizes
    - Early stopping with patience
    - LR scheduling (reduce on plateau or cosine annealing)
    - Best model checkpointing
    - Comprehensive metrics logging
    """
    
    CLASS_NAMES = ['Safe', 'Recon', 'Downloader', 'Exploit', 'Destructive', 'ADVANCED_APT']
    
    def __init__(
        self,
        model: nn.Module,
        loss_fn: nn.Module,
        device: str = 'cuda' if torch.cuda.is_available() else 'cpu',
        lr: float = 1e-3,
        weight_decay: float = 1e-4,
        optimizer: str = 'adamw',
        scheduler: str = 'plateau',
        patience: int = 5,
        checkpoint_dir: str = './checkpoints',
        use_amp: bool = True
    ):
        """
        Args:
            model: ThreatClassifier model
            loss_fn: Loss function (FocalLoss, CombinedLoss, etc.)
            device: 'cuda' or 'cpu'
            lr: Learning rate
            weight_decay: L2 regularization weight
            optimizer: 'adam' or 'adamw'
            scheduler: 'plateau', 'cosine', or 'onecycle'
            patience: Early stopping patience (epochs)
            checkpoint_dir: Directory for saving checkpoints
            use_amp: Use automatic mixed precision (faster on GPU)
        """
        self.model = model.to(device)
        self.loss_fn = loss_fn.to(device) if hasattr(loss_fn, 'to') else loss_fn
        self.device = device
        self.lr = lr
        self.patience = patience
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.use_amp = use_amp and device == 'cuda'
        
        # Optimizer
        if optimizer == 'adamw':
            self.optimizer = AdamW(
                model.parameters(), 
                lr=lr, 
                weight_decay=weight_decay
            )
        else:
            self.optimizer = Adam(
                model.parameters(), 
                lr=lr, 
                weight_decay=weight_decay
            )
        
        # Scheduler (initialized in train())
        self.scheduler_type = scheduler
        self.scheduler = None
        
        # AMP scaler
        self.scaler = torch.amp.GradScaler('cuda') if self.use_amp else None
        
        # Training state
        self.best_val_loss = float('inf')
        self.best_val_f1 = 0.0
        self.epochs_without_improvement = 0
        self.training_history = []
        self.current_epoch = 0
    
    def _init_scheduler(self, train_loader: DataLoader, epochs: int):
        """Initialize learning rate scheduler."""
        if self.scheduler_type == 'plateau':
            self.scheduler = ReduceLROnPlateau(
                self.optimizer, 
                mode='min', 
                factor=0.5, 
                patience=2,
                verbose=True
            )
        elif self.scheduler_type == 'cosine':
            self.scheduler = CosineAnnealingLR(
                self.optimizer,
                T_max=epochs,
                eta_min=1e-6
            )
        elif self.scheduler_type == 'onecycle':
            self.scheduler = OneCycleLR(
                self.optimizer,
                max_lr=self.lr * 10,
                epochs=epochs,
                steps_per_epoch=len(train_loader)
            )
    
    def train_epoch(self, train_loader: DataLoader) -> Dict[str, float]:
        """Train for one epoch."""
        self.model.train()
        
        total_loss = 0.0
        all_preds = []
        all_labels = []
        
        for batch in train_loader:
            # Move to device
            commands = batch['commands'].to(self.device)
            lengths = batch['lengths'].to(self.device)
            structured = batch['structured'].to(self.device)
            labels = batch['labels'].to(self.device)
            
            self.optimizer.zero_grad()
            
            # Forward pass with AMP
            if self.use_amp:
                with torch.amp.autocast('cuda'):
                    logits = self.model(commands, structured, lengths)
                    loss = self.loss_fn(logits, labels)
                
                self.scaler.scale(loss).backward()
                self.scaler.unscale_(self.optimizer)
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
                self.scaler.step(self.optimizer)
                self.scaler.update()
            else:
                logits = self.model(commands, structured, lengths)
                loss = self.loss_fn(logits, labels)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
                self.optimizer.step()
            
            # Update OneCycle scheduler per batch
            if self.scheduler_type == 'onecycle':
                self.scheduler.step()
            
            # Track metrics
            total_loss += loss.item() * labels.size(0)
            preds = torch.argmax(logits, dim=1).cpu().numpy()
            all_preds.extend(preds)
            all_labels.extend(labels.cpu().numpy())
        
        # Compute epoch metrics
        avg_loss = total_loss / len(all_labels)
        accuracy = accuracy_score(all_labels, all_preds)
        precision, recall, f1, _ = precision_recall_fscore_support(
            all_labels, all_preds, average='macro', zero_division=0
        )
        
        return {
            'loss': avg_loss,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1
        }
    
    @torch.no_grad()
    def evaluate(self, data_loader: DataLoader) -> Dict[str, Union[float, np.ndarray]]:
        """Evaluate model on a dataset."""
        self.model.eval()
        
        total_loss = 0.0
        all_preds = []
        all_labels = []
        all_probs = []
        
        for batch in data_loader:
            commands = batch['commands'].to(self.device)
            lengths = batch['lengths'].to(self.device)
            structured = batch['structured'].to(self.device)
            labels = batch['labels'].to(self.device)
            
            if self.use_amp:
                with torch.amp.autocast('cuda'):
                    logits = self.model(commands, structured, lengths)
                    loss = self.loss_fn(logits, labels)
            else:
                logits = self.model(commands, structured, lengths)
                loss = self.loss_fn(logits, labels)
            
            total_loss += loss.item() * labels.size(0)
            
            probs = torch.softmax(logits, dim=1).cpu().numpy()
            preds = np.argmax(probs, axis=1)
            
            all_preds.extend(preds)
            all_labels.extend(labels.cpu().numpy())
            all_probs.extend(probs)
        
        all_labels = np.array(all_labels)
        all_preds = np.array(all_preds)
        all_probs = np.array(all_probs)
        
        # Overall metrics
        avg_loss = total_loss / len(all_labels)
        accuracy = accuracy_score(all_labels, all_preds)
        
        # Per-class metrics
        precision, recall, f1, support = precision_recall_fscore_support(
            all_labels, all_preds, average=None, zero_division=0
        )
        
        # Macro averages
        macro_precision, macro_recall, macro_f1, _ = precision_recall_fscore_support(
            all_labels, all_preds, average='macro', zero_division=0
        )
        
        # Weighted averages
        weighted_precision, weighted_recall, weighted_f1, _ = precision_recall_fscore_support(
            all_labels, all_preds, average='weighted', zero_division=0
        )
        
        # Confusion matrix
        cm = confusion_matrix(all_labels, all_preds)
        
        return {
            'loss': avg_loss,
            'accuracy': accuracy,
            'precision': macro_precision,
            'recall': macro_recall,
            'f1': macro_f1,
            'weighted_f1': weighted_f1,
            'per_class_precision': precision,
            'per_class_recall': recall,
            'per_class_f1': f1,
            'per_class_support': support,
            'confusion_matrix': cm,
            'predictions': all_preds,
            'labels': all_labels,
            'probabilities': all_probs
        }
    
    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        epochs: int = 50,
        verbose: bool = True
    ) -> Dict:
        """
        Full training loop with validation.
        
        Args:
            train_loader: Training data loader
            val_loader: Validation data loader
            epochs: Maximum epochs
            verbose: Print progress
        
        Returns:
            Training history dict
        """
        # Initialize scheduler
        self._init_scheduler(train_loader, epochs)
        
        start_time = time.time()
        
        for epoch in range(epochs):
            self.current_epoch = epoch + 1
            epoch_start = time.time()
            
            # Train
            train_metrics = self.train_epoch(train_loader)
            
            # Validate
            val_metrics = self.evaluate(val_loader)
            
            # Update scheduler (except OneCycle which updates per batch)
            if self.scheduler_type == 'plateau':
                self.scheduler.step(val_metrics['loss'])
            elif self.scheduler_type == 'cosine':
                self.scheduler.step()
            
            # Log metrics
            epoch_time = time.time() - epoch_start
            history_entry = {
                'epoch': self.current_epoch,
                'train_loss': train_metrics['loss'],
                'train_accuracy': train_metrics['accuracy'],
                'train_f1': train_metrics['f1'],
                'val_loss': val_metrics['loss'],
                'val_accuracy': val_metrics['accuracy'],
                'val_f1': val_metrics['f1'],
                'val_weighted_f1': val_metrics['weighted_f1'],
                'lr': self.optimizer.param_groups[0]['lr'],
                'epoch_time': epoch_time
            }
            self.training_history.append(history_entry)
            
            if verbose:
                print(f"\nEpoch {self.current_epoch}/{epochs} ({epoch_time:.1f}s)")
                print(f"  Train - Loss: {train_metrics['loss']:.4f}, Acc: {train_metrics['accuracy']:.4f}, F1: {train_metrics['f1']:.4f}")
                print(f"  Val   - Loss: {val_metrics['loss']:.4f}, Acc: {val_metrics['accuracy']:.4f}, F1: {val_metrics['f1']:.4f}")
                
                # Per-class F1 scores
                print("  Per-class F1:", end=" ")
                n_classes = len(val_metrics['per_class_f1'])
                for i in range(n_classes):
                    name = self.CLASS_NAMES[i] if i < len(self.CLASS_NAMES) else f"C{i}"
                    print(f"{name[:4]}={val_metrics['per_class_f1'][i]:.2f}", end=" ")
                print()
            
            # Check for improvement
            improved = False
            if val_metrics['loss'] < self.best_val_loss:
                self.best_val_loss = val_metrics['loss']
                improved = True
            
            if val_metrics['f1'] > self.best_val_f1:
                self.best_val_f1 = val_metrics['f1']
                improved = True
                # Save best model
                self.save_checkpoint('best_model.pt', val_metrics)
                if verbose:
                    print(f"  ** New best F1: {val_metrics['f1']:.4f} - checkpoint saved")
            
            if improved:
                self.epochs_without_improvement = 0
            else:
                self.epochs_without_improvement += 1
            
            # Early stopping
            if self.epochs_without_improvement >= self.patience:
                if verbose:
                    print(f"\nEarly stopping after {self.patience} epochs without improvement")
                break
        
        total_time = time.time() - start_time
        
        if verbose:
            print(f"\nTraining complete in {total_time/60:.1f} minutes")
            print(f"Best validation F1: {self.best_val_f1:.4f}")
        
        return {
            'history': self.training_history,
            'best_val_f1': self.best_val_f1,
            'best_val_loss': self.best_val_loss,
            'total_time': total_time,
            'epochs_trained': self.current_epoch
        }
    
    def save_checkpoint(self, filename: str, metrics: Optional[Dict] = None):
        """Save model checkpoint."""
        checkpoint = {
            'epoch': self.current_epoch,
            'model_state_dict': self.model.state_dict(),
            'model_config': self.model.config if hasattr(self.model, 'config') else None,
            'optimizer_state_dict': self.optimizer.state_dict(),
            'scheduler_state_dict': self.scheduler.state_dict() if self.scheduler else None,
            'best_val_loss': self.best_val_loss,
            'best_val_f1': self.best_val_f1,
            'training_history': self.training_history,
            'metrics': metrics,
            'timestamp': datetime.now().isoformat()
        }
        
        path = self.checkpoint_dir / filename
        torch.save(checkpoint, path)
    
    def load_checkpoint(self, filename: str):
        """Load model from checkpoint."""
        path = self.checkpoint_dir / filename
        checkpoint = torch.load(path, map_location=self.device)
        
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        
        if checkpoint['scheduler_state_dict'] and self.scheduler:
            self.scheduler.load_state_dict(checkpoint['scheduler_state_dict'])
        
        self.current_epoch = checkpoint['epoch']
        self.best_val_loss = checkpoint['best_val_loss']
        self.best_val_f1 = checkpoint['best_val_f1']
        self.training_history = checkpoint['training_history']
        
        return checkpoint.get('metrics')
    
    def print_classification_report(self, data_loader: DataLoader, title: str = "Classification Report"):
        """Print detailed classification report."""
        metrics = self.evaluate(data_loader)
        
        print(f"\n{'='*60}")
        print(f" {title}")
        print('='*60)
        
        # Get actual classes present
        unique_classes = sorted(set(metrics['labels']) | set(metrics['predictions']))
        n_classes = len(unique_classes)
        class_names = [self.CLASS_NAMES[i] if i < len(self.CLASS_NAMES) else f"Class{i}" 
                       for i in range(n_classes)]
        
        report = classification_report(
            metrics['labels'],
            metrics['predictions'],
            target_names=class_names,
            digits=4,
            zero_division=0
        )
        print(report)
        
        print("\nConfusion Matrix:")
        print("-" * 60)
        cm = metrics['confusion_matrix']
        
        # Header
        header = "          " + "  ".join([f"{name[:6]:>6}" for name in class_names])
        print(header)
        
        # Matrix rows
        for i, row in enumerate(cm):
            name = class_names[i] if i < len(class_names) else f"C{i}"
            row_str = f"{name[:8]:>8}  " + "  ".join([f"{val:>6}" for val in row])
            print(row_str)
        
        return metrics


def print_confusion_matrix(cm: np.ndarray, class_names: List[str]):
    """Pretty print a confusion matrix."""
    print("\nConfusion Matrix:")
    print("-" * 60)
    
    # Header
    header = "          " + "  ".join([f"{name[:6]:>6}" for name in class_names])
    print(header)
    
    # Matrix rows
    for i, row in enumerate(cm):
        row_str = f"{class_names[i][:8]:>8}  " + "  ".join([f"{val:>6}" for val in row])
        print(row_str)


def save_training_results(
    model: nn.Module,
    tokenizer,
    training_results: Dict,
    test_metrics: Dict,
    output_dir: str = './models',
    model_name: str = 'brain_v5_neural'
):
    """
    Save trained model and results in multiple formats.
    
    Saves:
    - {model_name}.pt: PyTorch model state dict
    - {model_name}.pkl: Full model + tokenizer bundle (for inference)
    - {model_name}_results.json: Training metrics and history
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save PyTorch model state
    torch.save({
        'model_state_dict': model.state_dict(),
        'model_config': model.config if hasattr(model, 'config') else None,
    }, output_dir / f"{model_name}.pt")
    
    # Save full bundle for easy inference
    bundle = {
        'model': model.cpu(),
        'tokenizer': tokenizer,
        'config': model.config if hasattr(model, 'config') else None,
        'class_names': NeuralTrainer.CLASS_NAMES,
        'version': '5.0',
        'timestamp': datetime.now().isoformat()
    }
    
    with open(output_dir / f"{model_name}.pkl", 'wb') as f:
        pickle.dump(bundle, f)
    
    # Save training results as JSON
    results = {
        'training': {
            'epochs_trained': training_results['epochs_trained'],
            'best_val_f1': float(training_results['best_val_f1']),
            'best_val_loss': float(training_results['best_val_loss']),
            'total_time_seconds': float(training_results['total_time']),
            'history': [
                {k: float(v) if isinstance(v, (np.floating, float)) else v 
                 for k, v in entry.items()}
                for entry in training_results['history']
            ]
        },
        'test': {
            'loss': float(test_metrics['loss']),
            'accuracy': float(test_metrics['accuracy']),
            'macro_f1': float(test_metrics['f1']),
            'weighted_f1': float(test_metrics['weighted_f1']),
            'per_class_f1': [float(f) for f in test_metrics['per_class_f1']],
            'per_class_precision': [float(p) for p in test_metrics['per_class_precision']],
            'per_class_recall': [float(r) for r in test_metrics['per_class_recall']],
            'confusion_matrix': test_metrics['confusion_matrix'].tolist()
        },
        'model_config': model.config if hasattr(model, 'config') else None,
        'timestamp': datetime.now().isoformat()
    }
    
    with open(output_dir / f"{model_name}_results.json", 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nSaved model and results to {output_dir}/")
    print(f"  - {model_name}.pt (PyTorch state dict)")
    print(f"  - {model_name}.pkl (inference bundle)")
    print(f"  - {model_name}_results.json (metrics)")
