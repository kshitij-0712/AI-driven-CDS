"""
Unit tests for the MITRE annotator.

Verifies that attack_mapping.py regex patterns
correctly detect known attack signatures in both
SSH commands and HTTP request payloads.
"""

import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from core.mitre.session_annotator import (
    annotate_session,
    annotation_to_flat_dict,
    get_mitre_feature_columns,
)


class TestMitreAnnotation:
    """Test MITRE tactic detection on known payloads."""

    def _get_tactics(self, commands):
        """Helper: returns set of detected tactic names."""
        if isinstance(commands, str):
            commands = [commands]
        ann = annotate_session(commands)
        flat = annotation_to_flat_dict(ann)
        cols = get_mitre_feature_columns()
        # Return tactic names where value > 0
        return {
            col for col in cols
            if flat.get(col, 0) > 0
        }

    def test_feature_columns_count(self):
        """Should return exactly 21 feature columns."""
        cols = get_mitre_feature_columns()
        assert len(cols) == 21, \
            f"Expected 21 columns, got {len(cols)}"

    # ── SSH Command Detection ──

    def test_ssh_recon_detection(self):
        """id; whoami; uname should trigger discovery."""
        tactics = self._get_tactics([
            "id", "whoami", "uname -a",
            "cat /etc/passwd"
        ])
        assert any("discovery" in t for t in tactics), \
            f"Expected discovery, got {tactics}"

    def test_ssh_credential_access(self):
        """cat /etc/shadow should trigger credential_access."""
        tactics = self._get_tactics(["cat /etc/shadow"])
        assert any(
            "credential" in t.lower()
            for t in tactics
        ), f"Expected credential_access, got {tactics}"

    def test_ssh_persistence(self):
        """crontab should trigger persistence."""
        tactics = self._get_tactics([
            "crontab -l",
            "echo '* * * * * /tmp/backdoor' | crontab -"
        ])
        assert any(
            "persistence" in t for t in tactics
        ), f"Expected persistence, got {tactics}"

    def test_ssh_defense_evasion(self):
        """Removing logs should trigger defense_evasion."""
        tactics = self._get_tactics([
            "rm -rf /var/log/*",
            "history -c"
        ])
        assert any(
            "defense_evasion" in t for t in tactics
        ), f"Expected defense_evasion, got {tactics}"

    def test_ssh_safe_commands(self):
        """ls and pwd should produce minimal tactics."""
        tactics = self._get_tactics(["ls", "pwd", "exit"])
        # Safe commands may trigger 0 or very few tactics
        assert len(tactics) <= 3, \
            f"Too many tactics for safe cmds: {tactics}"

    # ── HTTP Attack Detection ──

    def test_http_sqli_detection(self):
        """SQL injection pattern should fire."""
        tactics = self._get_tactics([
            "GET /login?user=admin' OR 1=1--"
        ])
        # Should detect at least initial_access
        assert len(tactics) > 0, \
            f"SQLi not detected: {tactics}"

    def test_http_path_traversal(self):
        """Path traversal should fire."""
        tactics = self._get_tactics([
            "GET /../../etc/passwd"
        ])
        assert len(tactics) > 0, \
            f"Path traversal not detected: {tactics}"

    def test_flat_dict_is_numeric(self):
        """All flat dict values should be numeric
        (except string metadata fields)."""
        ann = annotate_session(["id", "whoami"])
        flat = annotation_to_flat_dict(ann)
        # These fields are known to be strings
        string_fields = {"severity_tier", "technique_ids"}
        for key, val in flat.items():
            if any(sf in key for sf in string_fields):
                continue
            assert isinstance(val, (int, float)), \
                f"Non-numeric value for {key}: {val}"
