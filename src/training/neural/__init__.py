"""
Neural model training module for AdaptiveShield Phase 5.

BiLSTM + Structured Features architecture for threat classification.
"""

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
