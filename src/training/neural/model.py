"""
Neural model architecture for AdaptiveShield Phase 5.

Architecture: BiLSTM + Structured Features -> Fusion -> Classification
- Command text: Character-level embedding -> BiLSTM -> Attention pooling
- Structured features: BatchNorm -> Dense -> ReLU -> Dropout
- Fusion: Concatenate -> Dense(128) -> Softmax(6)
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple, Optional


class CharacterEmbedding(nn.Module):
    """Character-level embedding for command sequences."""
    
    def __init__(
        self,
        vocab_size: int = 256,  # ASCII characters
        embed_dim: int = 64,
        padding_idx: int = 0
    ):
        super().__init__()
        self.embedding = nn.Embedding(
            num_embeddings=vocab_size,
            embedding_dim=embed_dim,
            padding_idx=padding_idx
        )
        self.embed_dim = embed_dim
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: Character indices [batch, seq_len]
        Returns:
            Embedded sequence [batch, seq_len, embed_dim]
        """
        return self.embedding(x)


class BiLSTMEncoder(nn.Module):
    """
    Bidirectional LSTM encoder for command sequences with attention pooling.
    """
    
    def __init__(
        self,
        vocab_size: int = 256,
        embed_dim: int = 64,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.3,
        use_attention: bool = True
    ):
        super().__init__()
        
        self.embed_dim = embed_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.use_attention = use_attention
        
        # Character embedding
        self.embedding = CharacterEmbedding(vocab_size, embed_dim)
        
        # Bidirectional LSTM
        self.lstm = nn.LSTM(
            input_size=embed_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0
        )
        
        # Attention mechanism
        if use_attention:
            self.attention = nn.Sequential(
                nn.Linear(hidden_dim * 2, hidden_dim),
                nn.Tanh(),
                nn.Linear(hidden_dim, 1, bias=False)
            )
        
        # Output dimension is 2x hidden_dim due to bidirectional
        self.output_dim = hidden_dim * 2
    
    def forward(
        self, 
        x: torch.Tensor, 
        lengths: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """
        Args:
            x: Character indices [batch, seq_len]
            lengths: Original sequence lengths [batch] (optional)
        Returns:
            Encoded sequence [batch, hidden_dim * 2]
        """
        batch_size = x.size(0)
        
        # Embed characters
        embedded = self.embedding(x)  # [batch, seq_len, embed_dim]
        
        # Pack sequences if lengths provided
        if lengths is not None:
            lengths = lengths.cpu()
            packed = nn.utils.rnn.pack_padded_sequence(
                embedded, lengths, batch_first=True, enforce_sorted=False
            )
            lstm_out, (h_n, c_n) = self.lstm(packed)
            lstm_out, _ = nn.utils.rnn.pad_packed_sequence(lstm_out, batch_first=True)
        else:
            lstm_out, (h_n, c_n) = self.lstm(embedded)
        
        # lstm_out: [batch, seq_len, hidden_dim * 2]
        
        if self.use_attention:
            # Attention pooling
            attn_weights = self.attention(lstm_out)  # [batch, seq_len, 1]
            attn_weights = F.softmax(attn_weights, dim=1)
            attended = torch.sum(attn_weights * lstm_out, dim=1)  # [batch, hidden_dim * 2]
            return attended
        else:
            # Use final hidden states (concat forward and backward)
            # h_n: [num_layers * 2, batch, hidden_dim]
            h_forward = h_n[-2, :, :]  # Last layer forward
            h_backward = h_n[-1, :, :]  # Last layer backward
            return torch.cat([h_forward, h_backward], dim=1)


class StructuredEncoder(nn.Module):
    """
    Encoder for structured features (MITRE + binary features).
    
    Input: 100-dim vector (21 MITRE + 79 binary features)
    Output: 64-dim encoded representation
    """
    
    def __init__(
        self,
        input_dim: int = 100,  # 21 MITRE + 79 binary
        hidden_dim: int = 128,
        output_dim: int = 64,
        dropout: float = 0.3
    ):
        super().__init__()
        
        self.input_dim = input_dim
        self.output_dim = output_dim
        
        # Normalize input features
        self.batch_norm = nn.BatchNorm1d(input_dim)
        
        # Two-layer MLP
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, output_dim),
            nn.ReLU(),
            nn.Dropout(dropout)
        )
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: Structured features [batch, input_dim]
        Returns:
            Encoded features [batch, output_dim]
        """
        x = self.batch_norm(x)
        return self.encoder(x)


class ThreatClassifier(nn.Module):
    """
    Complete threat classifier combining BiLSTM and structured features.
    
    Architecture:
        Commands (text) -> BiLSTM + Attention -> 256-dim
        Structured (MITRE + binary) -> MLP -> 64-dim
        Concat -> Dense(128) -> Dense(6) -> Softmax
    """
    
    # Class names for interpretability
    CLASS_NAMES = ['Safe', 'Recon', 'Downloader', 'Exploit', 'Destructive', 'ADVANCED_APT']
    NUM_CLASSES = 6
    
    def __init__(
        self,
        # BiLSTM params
        vocab_size: int = 256,
        embed_dim: int = 64,
        lstm_hidden: int = 128,
        lstm_layers: int = 2,
        lstm_dropout: float = 0.3,
        use_attention: bool = True,
        # Structured encoder params
        structured_dim: int = 100,
        structured_hidden: int = 128,
        structured_output: int = 64,
        structured_dropout: float = 0.3,
        # Fusion params
        fusion_hidden: int = 128,
        fusion_dropout: float = 0.3,
        # Output
        num_classes: int = 6
    ):
        super().__init__()
        
        # Save config for serialization
        self.config = {
            'vocab_size': vocab_size,
            'embed_dim': embed_dim,
            'lstm_hidden': lstm_hidden,
            'lstm_layers': lstm_layers,
            'lstm_dropout': lstm_dropout,
            'use_attention': use_attention,
            'structured_dim': structured_dim,
            'structured_hidden': structured_hidden,
            'structured_output': structured_output,
            'structured_dropout': structured_dropout,
            'fusion_hidden': fusion_hidden,
            'fusion_dropout': fusion_dropout,
            'num_classes': num_classes
        }
        
        # Encoders
        self.text_encoder = BiLSTMEncoder(
            vocab_size=vocab_size,
            embed_dim=embed_dim,
            hidden_dim=lstm_hidden,
            num_layers=lstm_layers,
            dropout=lstm_dropout,
            use_attention=use_attention
        )
        
        self.structured_encoder = StructuredEncoder(
            input_dim=structured_dim,
            hidden_dim=structured_hidden,
            output_dim=structured_output,
            dropout=structured_dropout
        )
        
        # Fusion dimension: BiLSTM output (256) + structured output (64) = 320
        fusion_input_dim = self.text_encoder.output_dim + structured_output
        
        # Fusion and classification layers
        self.fusion = nn.Sequential(
            nn.Linear(fusion_input_dim, fusion_hidden),
            nn.ReLU(),
            nn.Dropout(fusion_dropout),
            nn.Linear(fusion_hidden, num_classes)
        )
        
        self.num_classes = num_classes
    
    def forward(
        self,
        commands: torch.Tensor,
        structured: torch.Tensor,
        lengths: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """
        Args:
            commands: Character indices [batch, seq_len]
            structured: Structured features [batch, structured_dim]
            lengths: Original command sequence lengths [batch]
        Returns:
            Class logits [batch, num_classes]
        """
        # Encode text
        text_features = self.text_encoder(commands, lengths)
        
        # Encode structured features
        struct_features = self.structured_encoder(structured)
        
        # Concatenate and classify
        combined = torch.cat([text_features, struct_features], dim=1)
        logits = self.fusion(combined)
        
        return logits
    
    def predict(
        self,
        commands: torch.Tensor,
        structured: torch.Tensor,
        lengths: Optional[torch.Tensor] = None
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Get predictions and probabilities.
        
        Returns:
            predictions: Class indices [batch]
            probabilities: Class probabilities [batch, num_classes]
        """
        logits = self.forward(commands, structured, lengths)
        probabilities = F.softmax(logits, dim=1)
        predictions = torch.argmax(probabilities, dim=1)
        return predictions, probabilities
    
    def get_attention_weights(
        self,
        commands: torch.Tensor,
        lengths: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """
        Extract attention weights for interpretability.
        
        Returns:
            Attention weights [batch, seq_len]
        """
        if not self.text_encoder.use_attention:
            raise ValueError("Model not using attention")
        
        embedded = self.text_encoder.embedding(commands)
        
        if lengths is not None:
            lengths = lengths.cpu()
            packed = nn.utils.rnn.pack_padded_sequence(
                embedded, lengths, batch_first=True, enforce_sorted=False
            )
            lstm_out, _ = self.text_encoder.lstm(packed)
            lstm_out, _ = nn.utils.rnn.pad_packed_sequence(lstm_out, batch_first=True)
        else:
            lstm_out, _ = self.text_encoder.lstm(embedded)
        
        attn_weights = self.text_encoder.attention(lstm_out)
        attn_weights = F.softmax(attn_weights, dim=1).squeeze(-1)
        
        return attn_weights


def create_model(
    structured_dim: int = 100,
    device: str = 'cuda' if torch.cuda.is_available() else 'cpu',
    model_type: str = 'full',
    **kwargs
) -> nn.Module:
    """
    Factory function to create a threat classifier model.
    
    Args:
        structured_dim: Dimension of structured features (MITRE + binary)
        device: Device to place model on
        model_type: 'full' (default, 100-dim with binary features) or 
                   'mitre_only' (21-dim MITRE features only)
        **kwargs: Override default model parameters
    
    Returns:
        Threat classifier model on specified device
    """
    if model_type == 'mitre_only':
        # MITRE-only model (21 features)
        default_config = {
            'vocab_size': 256,
            'embed_dim': 64,
            'lstm_hidden': 128,
            'lstm_layers': 2,
            'lstm_dropout': 0.3,
            'use_attention': True,
            'mitre_dim': 21,
            'mitre_hidden': 32,
            'mitre_output': 32,
            'mitre_dropout': 0.3,
            'fusion_hidden': 128,
            'fusion_dropout': 0.3,
            'num_classes': 6
        }
        
        # Remove incompatible keys from kwargs if present
        for key in ['structured_dim', 'structured_hidden', 'structured_output', 'structured_dropout']:
            kwargs.pop(key, None)
        
        # Override with provided kwargs
        default_config.update(kwargs)
        
        model = ThreatClassifierMitreOnly(**default_config)
    else:
        # Full model with binary features (100 features)
        default_config = {
            'vocab_size': 256,
            'embed_dim': 64,
            'lstm_hidden': 128,
            'lstm_layers': 2,
            'lstm_dropout': 0.3,
            'use_attention': True,
            'structured_dim': structured_dim,
            'structured_hidden': 128,
            'structured_output': 64,
            'structured_dropout': 0.3,
            'fusion_hidden': 128,
            'fusion_dropout': 0.3,
            'num_classes': 6
        }
        
        # Override with provided kwargs
        default_config.update(kwargs)
        
        model = ThreatClassifier(**default_config)
    
    model = model.to(device)
    
    return model


class MitreEncoder(nn.Module):
    """
    Encoder for MITRE features only (21 dims).
    
    Input: 21-dim vector (14 tactics + 7 severity/coverage metrics)
    Output: Variable-dim encoded representation
    """
    
    def __init__(
        self,
        input_dim: int = 21,  # MITRE features only
        hidden_dim: int = 64,
        output_dim: int = 32,
        dropout: float = 0.3
    ):
        super().__init__()
        
        self.input_dim = input_dim
        self.output_dim = output_dim
        
        # Normalize input features
        self.batch_norm = nn.BatchNorm1d(input_dim)
        
        # Single-layer MLP (lighter than StructuredEncoder)
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout)
        )
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: MITRE features [batch, input_dim]
        Returns:
            Encoded features [batch, hidden_dim]
        """
        x = self.batch_norm(x)
        return self.encoder(x)


class ThreatClassifierMitreOnly(nn.Module):
    """
    MITRE-only threat classifier combining BiLSTM and MITRE features only.
    
    This model is designed for deployment scenarios where binary analysis
    is not available. It uses command text patterns + MITRE tactic vectors.
    
    Architecture:
        Commands (text) -> BiLSTM + Attention -> 256-dim
        MITRE features -> BatchNorm + Dense -> 32-dim
        Concat -> Dense(128) -> Dense(6) -> Softmax
    
    Total parameters: ~370K (less than full model's 706K)
    """
    
    # Class names for interpretability
    CLASS_NAMES = ['Safe', 'Recon', 'Downloader', 'Exploit', 'Destructive', 'ADVANCED_APT']
    NUM_CLASSES = 6
    
    def __init__(
        self,
        # BiLSTM params
        vocab_size: int = 256,
        embed_dim: int = 64,
        lstm_hidden: int = 128,
        lstm_layers: int = 2,
        lstm_dropout: float = 0.3,
        use_attention: bool = True,
        # MITRE encoder params (only 21 dims)
        mitre_dim: int = 21,
        mitre_hidden: int = 64,
        mitre_output: int = 32,
        mitre_dropout: float = 0.3,
        # Fusion params
        fusion_hidden: int = 128,
        fusion_dropout: float = 0.3,
        # Output
        num_classes: int = 6
    ):
        super().__init__()
        
        # Save config for serialization
        self.config = {
            'vocab_size': vocab_size,
            'embed_dim': embed_dim,
            'lstm_hidden': lstm_hidden,
            'lstm_layers': lstm_layers,
            'lstm_dropout': lstm_dropout,
            'use_attention': use_attention,
            'mitre_dim': mitre_dim,
            'mitre_hidden': mitre_hidden,
            'mitre_output': mitre_output,
            'mitre_dropout': mitre_dropout,
            'fusion_hidden': fusion_hidden,
            'fusion_dropout': fusion_dropout,
            'num_classes': num_classes,
            'model_type': 'mitre_only'
        }
        
        # Encoders
        self.text_encoder = BiLSTMEncoder(
            vocab_size=vocab_size,
            embed_dim=embed_dim,
            hidden_dim=lstm_hidden,
            num_layers=lstm_layers,
            dropout=lstm_dropout,
            use_attention=use_attention
        )
        
        self.mitre_encoder = MitreEncoder(
            input_dim=mitre_dim,
            hidden_dim=mitre_hidden,
            output_dim=mitre_output,
            dropout=mitre_dropout
        )
        
        # Fusion dimension: BiLSTM output (256) + MITRE output (32) = 288
        fusion_input_dim = self.text_encoder.output_dim + mitre_output
        
        # Fusion and classification layers
        self.fusion = nn.Sequential(
            nn.Linear(fusion_input_dim, fusion_hidden),
            nn.ReLU(),
            nn.Dropout(fusion_dropout),
            nn.Linear(fusion_hidden, num_classes)
        )
        
        self.num_classes = num_classes
    
    def forward(
        self,
        commands: torch.Tensor,
        mitre: torch.Tensor,
        lengths: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """
        Args:
            commands: Character indices [batch, seq_len]
            mitre: MITRE features [batch, 21]
            lengths: Original command sequence lengths [batch]
        Returns:
            Class logits [batch, num_classes]
        """
        # Encode text
        text_features = self.text_encoder(commands, lengths)
        
        # Encode MITRE features
        mitre_features = self.mitre_encoder(mitre)
        
        # Concatenate and classify
        combined = torch.cat([text_features, mitre_features], dim=1)
        logits = self.fusion(combined)
        
        return logits
    
    def predict(
        self,
        commands: torch.Tensor,
        mitre: torch.Tensor,
        lengths: Optional[torch.Tensor] = None
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Get predictions and probabilities.
        
        Returns:
            predictions: Class indices [batch]
            probabilities: Class probabilities [batch, num_classes]
        """
        logits = self.forward(commands, mitre, lengths)
        probabilities = F.softmax(logits, dim=1)
        predictions = torch.argmax(probabilities, dim=1)
        return predictions, probabilities
    
    def get_attention_weights(
        self,
        commands: torch.Tensor,
        lengths: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """
        Extract attention weights for interpretability.
        
        Returns:
            Attention weights [batch, seq_len]
        """
        if not self.text_encoder.use_attention:
            raise ValueError("Model not using attention")
        
        embedded = self.text_encoder.embedding(commands)
        
        if lengths is not None:
            lengths = lengths.cpu()
            packed = nn.utils.rnn.pack_padded_sequence(
                embedded, lengths, batch_first=True, enforce_sorted=False
            )
            lstm_out, _ = self.text_encoder.lstm(packed)
            lstm_out, _ = nn.utils.rnn.pad_packed_sequence(lstm_out, batch_first=True)
        else:
            lstm_out, _ = self.text_encoder.lstm(embedded)
        
        attn_weights = self.text_encoder.attention(lstm_out)
        attn_weights = F.softmax(attn_weights, dim=1).squeeze(-1)
        
        return attn_weights
