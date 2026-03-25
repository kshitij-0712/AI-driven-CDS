"""
Cost-sensitive and focal loss implementations for class-imbalanced training.

Addresses the extreme class imbalance in AdaptiveShield:
- Class 0 (Safe): 78,304 samples (99.7%)
- Class 1-5 (Malicious): 200 samples total (0.3%)

Loss functions:
- FocalLoss: Reduces loss for well-classified samples (gamma parameter)
- CostSensitiveLoss: Higher penalty for missing high-risk classes (APT, Destructive)
- CombinedLoss: Focal + cost-sensitive for optimal handling
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Optional, List, Union
import numpy as np


class FocalLoss(nn.Module):
    """
    Focal Loss for class-imbalanced classification.
    
    FL(p_t) = -alpha_t * (1 - p_t)^gamma * log(p_t)
    
    Where:
    - p_t is the model's estimated probability for the true class
    - gamma (focusing parameter) reduces loss for well-classified examples
    - alpha (class weights) balances importance of different classes
    
    From "Focal Loss for Dense Object Detection" (Lin et al., 2017)
    """
    
    def __init__(
        self,
        alpha: Optional[Union[torch.Tensor, List[float]]] = None,
        gamma: float = 2.0,
        reduction: str = 'mean'
    ):
        """
        Args:
            alpha: Per-class weights [num_classes]. If None, uniform weights.
            gamma: Focusing parameter. gamma=0 is standard CE loss. Higher gamma
                   focuses more on hard examples. Typical values: 0.5, 1, 2, 5.
            reduction: 'none', 'mean', or 'sum'
        """
        super().__init__()
        
        if alpha is not None:
            if isinstance(alpha, (list, np.ndarray)):
                alpha = torch.tensor(alpha, dtype=torch.float32)
            self.register_buffer('alpha', alpha)
        else:
            self.alpha = None
        
        self.gamma = gamma
        self.reduction = reduction
    
    def forward(self, inputs: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        """
        Compute focal loss.
        
        Args:
            inputs: Logits [batch_size, num_classes]
            targets: Class indices [batch_size]
        
        Returns:
            Loss value (scalar if reduction != 'none')
        """
        # Compute softmax probabilities
        p = F.softmax(inputs, dim=1)
        
        # Get probability of true class
        ce_loss = F.cross_entropy(inputs, targets, reduction='none')
        p_t = p.gather(1, targets.unsqueeze(1)).squeeze(1)
        
        # Compute focal weight: (1 - p_t)^gamma
        focal_weight = (1 - p_t) ** self.gamma
        
        # Apply focal weight to cross-entropy loss
        loss = focal_weight * ce_loss
        
        # Apply alpha weighting if provided
        if self.alpha is not None:
            alpha_t = self.alpha.gather(0, targets)
            loss = alpha_t * loss
        
        # Apply reduction
        if self.reduction == 'mean':
            return loss.mean()
        elif self.reduction == 'sum':
            return loss.sum()
        else:
            return loss


class CostSensitiveLoss(nn.Module):
    """
    Cost-sensitive cross-entropy loss with asymmetric misclassification costs.
    
    Different errors have different costs:
    - Missing APT (class 5) is very costly (potential data breach)
    - Missing Destructive (class 4) is very costly (ransomware)
    - Missing Exploit (class 3) is costly
    - False positive on Safe is low cost (just extra analysis)
    
    Uses a cost matrix C where C[i,j] is the cost of predicting class j
    when true class is i.
    """
    
    # Default cost multipliers for AdaptiveShield
    # Higher cost = more penalty for missing this class
    DEFAULT_CLASS_COSTS = {
        0: 1.0,    # Safe - low cost for FP (inconvenience)
        1: 5.0,    # Recon - moderate cost (early warning missed)
        2: 8.0,    # Downloader - high cost (malware delivery)
        3: 10.0,   # Exploit - very high cost (credential theft)
        4: 15.0,   # Destructive - critical (ransomware)
        5: 20.0,   # ADVANCED_APT - maximum cost (APT undetected)
    }
    
    def __init__(
        self,
        class_costs: Optional[dict] = None,
        num_classes: int = 6,
        reduction: str = 'mean'
    ):
        """
        Args:
            class_costs: Dict mapping class_id -> cost multiplier
            num_classes: Number of classes
            reduction: 'none', 'mean', or 'sum'
        """
        super().__init__()
        
        self.num_classes = num_classes
        self.reduction = reduction
        
        # Build cost vector
        costs = class_costs or self.DEFAULT_CLASS_COSTS
        cost_vector = torch.tensor(
            [costs.get(i, 1.0) for i in range(num_classes)],
            dtype=torch.float32
        )
        self.register_buffer('cost_vector', cost_vector)
    
    def forward(self, inputs: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        """
        Compute cost-sensitive cross-entropy loss.
        
        Args:
            inputs: Logits [batch_size, num_classes]
            targets: Class indices [batch_size]
        
        Returns:
            Loss value
        """
        # Standard cross-entropy loss (unreduced)
        ce_loss = F.cross_entropy(inputs, targets, reduction='none')
        
        # Apply class-specific cost multipliers
        costs = self.cost_vector.gather(0, targets)
        loss = costs * ce_loss
        
        # Reduction
        if self.reduction == 'mean':
            return loss.mean()
        elif self.reduction == 'sum':
            return loss.sum()
        else:
            return loss


class CombinedLoss(nn.Module):
    """
    Combined Focal + Cost-Sensitive loss.
    
    Combines the benefits of both approaches:
    - Focal loss handles class imbalance via focusing on hard examples
    - Cost-sensitive loss prioritizes high-risk class detection
    
    Final loss = focal_weight * cost_weight * CE_loss
    """
    
    def __init__(
        self,
        gamma: float = 2.0,
        class_costs: Optional[dict] = None,
        num_classes: int = 6,
        reduction: str = 'mean'
    ):
        """
        Args:
            gamma: Focal loss gamma parameter
            class_costs: Dict mapping class_id -> cost multiplier
            num_classes: Number of classes
            reduction: 'none', 'mean', or 'sum'
        """
        super().__init__()
        
        self.gamma = gamma
        self.num_classes = num_classes
        self.reduction = reduction
        
        # Cost vector
        costs = class_costs or CostSensitiveLoss.DEFAULT_CLASS_COSTS
        cost_vector = torch.tensor(
            [costs.get(i, 1.0) for i in range(num_classes)],
            dtype=torch.float32
        )
        self.register_buffer('cost_vector', cost_vector)
    
    def forward(self, inputs: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        """
        Compute combined focal + cost-sensitive loss.
        """
        # Softmax probabilities
        p = F.softmax(inputs, dim=1)
        
        # Cross-entropy loss (unreduced)
        ce_loss = F.cross_entropy(inputs, targets, reduction='none')
        
        # Focal weight: (1 - p_t)^gamma
        p_t = p.gather(1, targets.unsqueeze(1)).squeeze(1)
        focal_weight = (1 - p_t) ** self.gamma
        
        # Cost weight
        cost_weight = self.cost_vector.gather(0, targets)
        
        # Combined loss
        loss = focal_weight * cost_weight * ce_loss
        
        # Reduction
        if self.reduction == 'mean':
            return loss.mean()
        elif self.reduction == 'sum':
            return loss.sum()
        else:
            return loss


def compute_class_weights(
    labels: Union[np.ndarray, torch.Tensor, List[int]],
    num_classes: int = 6,
    method: str = 'inverse_freq'
) -> torch.Tensor:
    """
    Compute class weights from label distribution.
    
    Args:
        labels: Array of class labels
        num_classes: Total number of classes
        method: 
            - 'inverse_freq': Weight = 1 / frequency
            - 'inverse_sqrt': Weight = 1 / sqrt(frequency)
            - 'effective_num': From "Class-Balanced Loss" paper
    
    Returns:
        Tensor of class weights [num_classes]
    """
    if isinstance(labels, torch.Tensor):
        labels = labels.numpy()
    labels = np.array(labels)
    
    # Count samples per class
    counts = np.bincount(labels, minlength=num_classes).astype(np.float32)
    counts = np.maximum(counts, 1)  # Avoid division by zero
    
    total = len(labels)
    
    if method == 'inverse_freq':
        # Weight inversely proportional to frequency
        weights = total / (num_classes * counts)
    
    elif method == 'inverse_sqrt':
        # Smoother weighting
        weights = np.sqrt(total / (num_classes * counts))
    
    elif method == 'effective_num':
        # From "Class-Balanced Loss Based on Effective Number of Samples"
        beta = 0.9999
        effective_num = (1 - np.power(beta, counts)) / (1 - beta)
        weights = total / (num_classes * effective_num)
    
    else:
        raise ValueError(f"Unknown method: {method}")
    
    # Normalize so weights sum to num_classes
    weights = weights / weights.sum() * num_classes
    
    return torch.tensor(weights, dtype=torch.float32)


def create_loss_function(
    loss_type: str = 'combined',
    labels: Optional[np.ndarray] = None,
    gamma: float = 2.0,
    class_costs: Optional[dict] = None,
    num_classes: int = 6,
    weight_method: str = 'inverse_freq'
) -> nn.Module:
    """
    Factory function to create a loss function.
    
    Args:
        loss_type: 'focal', 'cost_sensitive', 'combined', or 'ce' (cross-entropy)
        labels: Training labels for computing class weights (for focal loss)
        gamma: Focal loss gamma
        class_costs: Cost multipliers for cost-sensitive loss
        num_classes: Number of classes
        weight_method: Method for computing class weights from labels
    
    Returns:
        Loss function module
    """
    if loss_type == 'ce':
        if labels is not None:
            weights = compute_class_weights(labels, num_classes, weight_method)
            return nn.CrossEntropyLoss(weight=weights)
        return nn.CrossEntropyLoss()
    
    elif loss_type == 'focal':
        alpha = None
        if labels is not None:
            alpha = compute_class_weights(labels, num_classes, weight_method)
        return FocalLoss(alpha=alpha, gamma=gamma)
    
    elif loss_type == 'cost_sensitive':
        return CostSensitiveLoss(class_costs=class_costs, num_classes=num_classes)
    
    elif loss_type == 'combined':
        return CombinedLoss(
            gamma=gamma, 
            class_costs=class_costs, 
            num_classes=num_classes
        )
    
    else:
        raise ValueError(f"Unknown loss type: {loss_type}")
