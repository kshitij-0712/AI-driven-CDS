"""
Unit tests for the dataset clean_payload function
and the CommandTokenizer.
"""

import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from training.neural.dataset import (
    clean_payload,
    CommandTokenizer,
)


class TestCleanPayload:
    """Test HTTP boilerplate stripping."""

    def test_strips_get_method(self):
        result = clean_payload("GET /login HTTP/1.1")
        assert "GET" not in result
        assert "/login" in result

    def test_strips_post_method(self):
        result = clean_payload("POST /api/data HTTP/1.1")
        assert "POST" not in result
        assert "/api/data" in result

    def test_strips_http_version(self):
        result = clean_payload(
            "GET /index.html HTTP/1.1\nHost: example.com"
        )
        assert "HTTP/1.1" not in result
        assert "HTTP/1.0" not in result

    def test_keeps_headers(self):
        result = clean_payload(
            "GET /page HTTP/1.1\n"
            "Host: example.com\n"
            "User-Agent: nikto"
        )
        assert "Host: example.com" in result
        assert "User-Agent: nikto" in result

    def test_keeps_query_params(self):
        result = clean_payload(
            "GET /login?user=admin' OR 1=1-- HTTP/1.1"
        )
        assert "admin' OR 1=1--" in result

    def test_keeps_post_body(self):
        result = clean_payload(
            "POST /login HTTP/1.1\n"
            "Host: target.com\n"
            "\n"
            "username=admin&password=test"
        )
        assert "username=admin" in result

    def test_passthrough_ssh_commands(self):
        """SSH commands should pass through unchanged."""
        cmd = "cat /etc/passwd; whoami; id"
        result = clean_payload(cmd)
        assert result == cmd

    def test_non_string_passthrough(self):
        assert clean_payload(None) is None
        assert clean_payload(42) == 42


class TestCommandTokenizer:
    """Test the character-level tokenizer."""

    def test_encode_basic(self):
        tok = CommandTokenizer(max_length=10)
        indices = tok.encode("abc")
        assert len(indices) == 3
        assert indices[0] == ord('a')
        assert indices[1] == ord('b')
        assert indices[2] == ord('c')

    def test_encode_truncation(self):
        tok = CommandTokenizer(max_length=5)
        indices = tok.encode("abcdefghij")
        assert len(indices) == 5

    def test_encode_special_chars(self):
        tok = CommandTokenizer(max_length=100)
        indices = tok.encode("' OR 1=1--")
        assert indices[0] == ord("'")
        assert all(0 <= i < 256 for i in indices)

    def test_vocab_size(self):
        tok = CommandTokenizer(max_length=512)
        assert tok.vocab_size == 256
