"""
Neural model training module for AdaptiveShield Phase 5.

BiLSTM + Structured Features architecture for threat classification.
"""

try:
    from .model import ThreatClassifier, BiLSTMEncoder, StructuredEncoder
    from .dataset import ThreatDataset, CommandTokenizer
    from .losses import FocalLoss, CostSensitiveLoss
    from .trainer import NeuralTrainer
    from .synthetic import SyntheticGenerator

    __all__ = [
        'ThreatClassifier',
        'BiLSTMEncoder', 
        'StructuredEncoder',
        'ThreatDataset',
        'CommandTokenizer',
        'FocalLoss',
        'CostSensitiveLoss',
        'NeuralTrainer',
        'SyntheticGenerator',
    ]
except ImportError:
    # Allow the package to be imported without PyTorch so HybridClassifierV2 can function
    __all__ = []
