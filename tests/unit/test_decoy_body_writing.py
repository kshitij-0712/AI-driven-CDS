import pytest
import os
import json
from unittest.mock import AsyncMock, MagicMock
from starlette.requests import Request
from starlette.datastructures import Headers, URL
from honeypot.generator import HoneypotGenerator
from interceptor.session_store import SessionStore
from deception.orchestrator import OrchestrationResult
from deception.tactics import DeceptionTactic


@pytest.mark.asyncio
async def test_prepare_decoy_files_writes_endpoint_when_generated_files_empty(tmp_path):
    """
    Ensure that when orchestrator returns generated_files=[],
    the primary route body is still written to html_dir so NGINX can serve it.
    """
    config = {
        "galah_honeypot": {
            "internal_output_path": str(tmp_path / "app_structure.json")
        }
    }
    app_struct = {
        "target_url": "http://127.0.0.1:8090",
        "pages": {
            "/": {"title": "Home", "links": [], "forms": []}
        }
    }
    with open(tmp_path / "app_structure.json", "w") as f:
        json.dump(app_struct, f)

    store = SessionStore(str(tmp_path / "sessions.db"))
    gen = HoneypotGenerator(config=config, store=store, scope="internal")

    # Mock DeceptionOrchestrator to return generated_files=[]
    gen.orchestrator.orchestrate_turn = AsyncMock(return_value=OrchestrationResult(
        tactic=DeceptionTactic.T09_INSIDER_SANDBOX,
        status_code=200,
        headers={"Content-Type": "application/json"},
        body='{"status":"error","message":"Access denied"}',
        canary_seeded=None,
        canaries_compromised=[],
        session_profile={},
        generated_files=[],
        delay_ms=0,
        raw_response="",
        session_updates={}
    ))

    # Mock Request
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/workspace/api/action",
        "headers": [(b"content-type", b"application/json")],
        "query_string": b"",
    }
    req = Request(scope)

    html_dir = str(tmp_path / "html")
    os.makedirs(html_dir, exist_ok=True)

    decision = {
        "label": "Insider Anomaly",
        "class_id": 3,
        "rule": "Unauthorized scope breach",
        "severity_max": 7,
    }

    await gen.prepare_decoy_files(
        session_id="test_sess",
        decision=decision,
        request=req,
        body_str='{"action": "vault_dump"}',
        html_dir=html_dir,
        container_id="",
        decoys_manager=None
    )

    # Verify that /workspace/api/action file was created with the simulated JSON!
    expected_file = os.path.join(html_dir, "workspace", "api", "action")
    assert os.path.exists(expected_file), f"Expected endpoint file {expected_file} was not written!"
    with open(expected_file, "r") as f:
        content = f.read()
    assert '{"status":"error","message":"Access denied"}' in content
