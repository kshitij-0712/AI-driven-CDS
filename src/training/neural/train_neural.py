#!/usr/bin/env python
"""
Train the Phase 5 neural model (brain_v5_neural).

BiLSTM + Structured Features architecture for threat classification.

Usage:
    # From project root on Windows:
    .venv\Scripts\python src\training\neural\train_neural.py
    
    # With options:
    .venv\Scripts\python src\training\neural\train_neural.py --epochs 30 --batch-size 64
"""

import sys
import argparse
from pathlib import Path

# Add src to path for imports
src_path = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_path))

import torch
import numpy as np

from training.neural.model import ThreatClassifier, create_model
from training.neural.dataset import (
    load_dataset, 
    create_dataloaders, 
    ThreatDataset,
    CommandTokenizer
)
from training.neural.synthetic import generate_synthetic_data
from training.neural.losses import create_loss_function, compute_class_weights
from training.neural.trainer import (
    NeuralTrainer, 
    save_training_results,
    print_confusion_matrix
)


def main():
    parser = argparse.ArgumentParser(description='Train brain_v5_neural model')
    
    # Data arguments
    parser.add_argument('--data-path', type=str, default='data/exports/sessions_complete.csv',
                        help='Path to sessions_complete.csv')
    parser.add_argument('--max-length', type=int, default=512,
                        help='Maximum command sequence length')
    parser.add_argument('--downsample-safe', type=int, default=5000,
                        help='Downsample Safe class to this size (0 to disable)')
    
    # Synthetic data arguments
    parser.add_argument('--synthetic-recon', type=int, default=500,
                        help='Number of synthetic Recon sessions')
    parser.add_argument('--synthetic-exploit', type=int, default=500,
                        help='Number of synthetic Exploit sessions')
    parser.add_argument('--no-synthetic', action='store_true',
                        help='Disable synthetic data generation')
    
    # Semantic labeling arguments
    parser.add_argument('--use-semantic-labels', action='store_true',
                        help='Use semantic labeling based on command behavior')
    parser.add_argument('--label-mode', type=str, default='combined',
                        choices=['semantic', 'combined', 'binary'],
                        help='Label mode: semantic (command behavior only), '
                             'combined (max of semantic + binary), '
                             'or binary (original binary-based labels)')
    parser.add_argument('--precomputed-labels', type=str, 
                        default='data/exports/sessions_semantic_labeled.csv',
                        help='Path to pre-computed semantic labels CSV (faster loading)')
    
    # Model arguments
    parser.add_argument('--embed-dim', type=int, default=64,
                        help='Character embedding dimension')
    parser.add_argument('--lstm-hidden', type=int, default=128,
                        help='LSTM hidden dimension')
    parser.add_argument('--lstm-layers', type=int, default=2,
                        help='Number of LSTM layers')
    parser.add_argument('--dropout', type=float, default=0.3,
                        help='Dropout rate')
    
    # Training arguments
    parser.add_argument('--epochs', type=int, default=50,
                        help='Maximum training epochs')
    parser.add_argument('--batch-size', type=int, default=64,
                        help='Batch size')
    parser.add_argument('--lr', type=float, default=1e-3,
                        help='Learning rate')
    parser.add_argument('--weight-decay', type=float, default=1e-4,
                        help='Weight decay (L2 regularization)')
    parser.add_argument('--patience', type=int, default=5,
                        help='Early stopping patience')
    
    # Loss function arguments
    parser.add_argument('--loss', type=str, default='combined',
                        choices=['ce', 'focal', 'cost_sensitive', 'combined'],
                        help='Loss function type')
    parser.add_argument('--focal-gamma', type=float, default=2.0,
                        help='Focal loss gamma parameter')
    
    # Output arguments
    parser.add_argument('--output-dir', type=str, default='models',
                        help='Output directory for model')
    parser.add_argument('--checkpoint-dir', type=str, default='checkpoints',
                        help='Checkpoint directory')
    parser.add_argument('--model-name', type=str, default='brain_v5_neural',
                        help='Model filename (without extension)')
    
    # Other arguments
    parser.add_argument('--seed', type=int, default=42,
                        help='Random seed')
    parser.add_argument('--no-cuda', action='store_true',
                        help='Disable CUDA')
    parser.add_argument('--num-workers', type=int, default=0,
                        help='DataLoader workers (0 for Windows)')
    
    args = parser.parse_args()
    
    # Set random seeds
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed(args.seed)
    
    # Device
    device = 'cuda' if torch.cuda.is_available() and not args.no_cuda else 'cpu'
    print(f"\n{'='*60}")
    print(" AdaptiveShield Phase 5 Neural Model Training")
    print('='*60)
    print(f"Device: {device}")
    if device == 'cuda':
        print(f"GPU: {torch.cuda.get_device_name(0)}")
        print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")
    
    # Generate synthetic data if needed
    synthetic_data = None
    if not args.no_synthetic:
        print(f"\nGenerating synthetic data...")
        print(f"  Recon sessions: {args.synthetic_recon}")
        print(f"  Exploit sessions: {args.synthetic_exploit}")
        synthetic_data = generate_synthetic_data(
            n_recon=args.synthetic_recon,
            n_exploit=args.synthetic_exploit,
            random_seed=args.seed
        )
    
    # Load and split dataset
    print(f"\nLoading dataset from {args.data_path}...")
    if args.use_semantic_labels:
        print(f"Using semantic labels (mode={args.label_mode})")
    train_dataset, val_dataset, test_dataset, tokenizer = load_dataset(
        csv_path=args.data_path,
        max_length=args.max_length,
        downsample_safe=args.downsample_safe if args.downsample_safe > 0 else None,
        include_synthetic=not args.no_synthetic,
        synthetic_data=synthetic_data,
        random_state=args.seed,
        use_semantic_labels=args.use_semantic_labels,
        label_mode=args.label_mode,
        precomputed_labels_path=args.precomputed_labels if args.use_semantic_labels else None
    )
    
    # Get structured feature dimension
    structured_dim = train_dataset.structured_dim
    print(f"Structured feature dimension: {structured_dim}")
    
    # Create data loaders
    train_loader, val_loader, test_loader = create_dataloaders(
        train_dataset, val_dataset, test_dataset,
        batch_size=args.batch_size,
        num_workers=args.num_workers
    )
    
    print(f"\nDataset sizes:")
    print(f"  Train: {len(train_dataset)}")
    print(f"  Val:   {len(val_dataset)}")
    print(f"  Test:  {len(test_dataset)}")
    
    # Create model
    print(f"\nCreating model...")
    model = create_model(
        structured_dim=structured_dim,
        device=device,
        embed_dim=args.embed_dim,
        lstm_hidden=args.lstm_hidden,
        lstm_layers=args.lstm_layers,
        lstm_dropout=args.dropout,
        structured_dropout=args.dropout,
        fusion_dropout=args.dropout
    )
    
    # Count parameters
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"  Total parameters: {total_params:,}")
    print(f"  Trainable parameters: {trainable_params:,}")
    
    # Create loss function
    print(f"\nLoss function: {args.loss}")
    train_labels = np.array([train_dataset[i]['label'].item() for i in range(len(train_dataset))])
    loss_fn = create_loss_function(
        loss_type=args.loss,
        labels=train_labels,
        gamma=args.focal_gamma,
        num_classes=6
    )
    
    # Print class weights if applicable
    if args.loss in ['focal', 'ce']:
        weights = compute_class_weights(train_labels, num_classes=6)
        print(f"  Class weights: {weights.tolist()}")
    
    # Create trainer
    trainer = NeuralTrainer(
        model=model,
        loss_fn=loss_fn,
        device=device,
        lr=args.lr,
        weight_decay=args.weight_decay,
        patience=args.patience,
        checkpoint_dir=args.checkpoint_dir
    )
    
    # Train
    print(f"\n{'='*60}")
    print(" Training")
    print('='*60)
    print(f"Epochs: {args.epochs}")
    print(f"Batch size: {args.batch_size}")
    print(f"Learning rate: {args.lr}")
    print(f"Early stopping patience: {args.patience}")
    
    training_results = trainer.train(
        train_loader=train_loader,
        val_loader=val_loader,
        epochs=args.epochs,
        verbose=True
    )
    
    # Load best model for final evaluation
    print(f"\n{'='*60}")
    print(" Final Evaluation (Best Model)")
    print('='*60)
    trainer.load_checkpoint('best_model.pt')
    
    # Test set evaluation
    test_metrics = trainer.print_classification_report(test_loader, "Test Set Results")
    
    # Save model and results
    save_training_results(
        model=model,
        tokenizer=tokenizer,
        training_results=training_results,
        test_metrics=test_metrics,
        output_dir=args.output_dir,
        model_name=args.model_name
    )
    
    print(f"\n{'='*60}")
    print(" Training Complete!")
    print('='*60)
    print(f"Best validation F1: {training_results['best_val_f1']:.4f}")
    print(f"Test F1 (macro): {test_metrics['f1']:.4f}")
    print(f"Test F1 (weighted): {test_metrics['weighted_f1']:.4f}")
    print(f"Model saved to: {args.output_dir}/{args.model_name}.pkl")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
