"""
Unit tests for model architecture.

Tests that the UnifiedThreatClassifier:
- Has correct input/output dimensions
- Forward pass produces valid logits
- Modality masking works correctly
- Predict method returns valid probabilities
"""

import torch
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from training.neural.model import (
    UnifiedThreatClassifier,
    BiLSTMEncoder,
    MitreEncoder,
    ChangeEncoder,
    TriageEncoder,
)


class TestEncoderDimensions:
    """Verify each encoder produces correct output shapes."""

    def test_bilstm_output_shape(self):
        enc = BiLSTMEncoder(
            vocab_size=256, embed_dim=64,
            hidden_dim=128, num_layers=2,
            use_attention=True
        )
        enc.eval()
        x = torch.randint(0, 256, (4, 100))
        lengths = torch.tensor([100, 80, 60, 40])
        out = enc(x, lengths)
        assert out.shape == (4, 256), \
            f"Expected (4,256), got {out.shape}"

    def test_mitre_encoder_shape(self):
        enc = MitreEncoder(input_dim=21)
        enc.eval()
        x = torch.randn(4, 21)
        out = enc(x)
        assert out.shape[0] == 4
        assert out.shape[1] == 32 or out.shape[1] == 64

    def test_change_encoder_shape(self):
        enc = ChangeEncoder(input_dim=21)
        enc.eval()
        x = torch.randn(4, 21)
        out = enc(x)
        assert out.shape == (4, 32), \
            f"Expected (4,32), got {out.shape}"

    def test_triage_encoder_shape(self):
        enc = TriageEncoder(input_dim=70)
        enc.eval()
        x = torch.randn(4, 70)
        out = enc(x)
        assert out.shape == (4, 32), \
            f"Expected (4,32), got {out.shape}"


class TestUnifiedClassifier:
    """Test the full UnifiedThreatClassifier."""

    @pytest.fixture
    def classifier(self):
        m = UnifiedThreatClassifier()
        m.eval()
        return m

    def test_forward_output_shape(self, classifier):
        """Forward pass should produce [batch, 6] logits."""
        commands = torch.randint(0, 256, (4, 100))
        mitre = torch.randn(4, 21)
        changes = torch.randn(4, 21)
        triage = torch.randn(4, 70)
        lengths = torch.tensor([100, 80, 60, 40])
        mask = torch.zeros(4, 4, dtype=torch.bool)

        logits = classifier(
            commands, mitre, changes,
            triage, lengths, mask
        )
        assert logits.shape == (4, 6), \
            f"Expected (4,6), got {logits.shape}"

    def test_predict_returns_valid_probs(self, classifier):
        """Predict should return probabilities that sum to 1."""
        commands = torch.randint(0, 256, (2, 50))
        mitre = torch.randn(2, 21)
        changes = torch.randn(2, 21)
        triage = torch.randn(2, 70)
        lengths = torch.tensor([50, 30])
        mask = torch.zeros(2, 4, dtype=torch.bool)

        preds, probs = classifier.predict(
            commands, mitre, changes,
            triage, lengths, mask
        )
        assert preds.shape == (2,)
        assert probs.shape == (2, 6)

        # Each row should sum to ~1.0
        sums = probs.sum(dim=1)
        for s in sums:
            assert abs(s.item() - 1.0) < 1e-4, \
                f"Prob sum {s.item()} != 1.0"

    def test_modality_mask_zeros_output(self, classifier):
        """When all modalities masked, output should differ."""
        commands = torch.randint(0, 256, (2, 50))
        mitre = torch.randn(2, 21)
        changes = torch.randn(2, 21)
        triage = torch.randn(2, 70)
        lengths = torch.tensor([50, 30])

        # No masking
        mask_off = torch.zeros(2, 4, dtype=torch.bool)
        logits_off = classifier(
            commands, mitre, changes,
            triage, lengths, mask_off
        )

        # Mask mitre, changes, triage
        mask_on = torch.tensor([
            [False, True, True, True],
            [False, True, True, True],
        ])
        logits_on = classifier(
            commands, mitre, changes,
            triage, lengths, mask_on
        )

        # Should produce different logits
        assert not torch.allclose(logits_off, logits_on), \
            "Masking had no effect on logits"

    def test_six_class_names(self, classifier):
        """Verify CLASS_NAMES has exactly 6 entries."""
        assert len(classifier.CLASS_NAMES) == 6
        assert classifier.CLASS_NAMES[0] == 'Safe'
        assert classifier.CLASS_NAMES[5] == 'ADVANCED_APT'
