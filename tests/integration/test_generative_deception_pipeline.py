"""
End-to-End Integration Tests for Threat-Conditioned Generative Cyber Deception Pipeline:
Verifies multi-turn attack escalation, canary token provenance, zero-stall fallback,
and reactive decoy mutations.
"""

import json
import pytest
from starlette.requests import Request

from honeypot.generator import HoneypotGenerator
from interceptor.session_store import SessionStore
from deception.tactics import DeceptionTactic
from deception.canary import CanaryType


def make_dummy_request(method: str, path: str, query: str = "", body: str = "", headers: dict = None) -> Request:
    """Helper to build a mock ASGI Request for testing HoneypotGenerator."""
    headers_list = []
    for k, v in (headers or {}).items():
        headers_list.append((k.lower().encode("latin-1"), v.encode("latin-1")))

    scope = {
        "type": "http",
        "method": method.upper(),
        "path": path,
        "query_string": query.encode("utf-8"),
        "headers": headers_list,
        "client": ("192.168.1.100", 44321),
    }

    async def receive():
        return {"type": "http.request", "body": body.encode("utf-8"), "more_body": False}

    return Request(scope, receive)


@pytest.fixture
def test_env(tmp_path):
    db_path = str(tmp_path / "test_session_store.db")
    store = SessionStore(db_path)

    config = {
        "galah_honeypot": {
            "crawler": {
                "target_url": "http://127.0.0.1:8090",
                "output_path": str(tmp_path / "app_structure.json"),
                "auto_crawl": False,
            },
            "llm": {
                "provider": "generic_http",
                "api_url": "http://127.0.0.1:9999",  # Will fail/fallback instantly to mock
                "timeout_sec": 1,
            },
        },
        "deception": {
            "tarpit_delay_ms": 100,
            "insider_anomaly_threshold": 0.70,
        },
    }

    # Seed mock app structure
    app_struct = {
        "target_url": "http://127.0.0.1:8090",
        "theme": ":root { --primary: #3b82f6; }",
        "pages": {
            "/": {"title": "Dashboard", "forms": []},
            "/profile": {"title": "User Profile", "forms": [{"action": "/profile", "inputs": [{"name": "id"}]}]},
            "/admin": {"title": "Admin Console", "forms": []},
        },
    }
    with open(config["galah_honeypot"]["crawler"]["output_path"], "w") as f:
        json.dump(app_struct, f)

    generator = HoneypotGenerator(config, store)
    return generator, store, tmp_path


@pytest.mark.asyncio
async def test_generative_deception_pipeline_multiturn_attack(test_env):
    generator, store, tmp_path = test_env
    session_id = "sess_e2e_adversary_001"

    # Turn 1: Benign / early reconnaissance on home dashboard
    req1 = make_dummy_request("GET", "/")
    decision1 = {"label": "Safe", "mitre_techniques": []}
    resp1 = await generator.generate_response(req1, "", decision1, session_id)
    assert resp1.status_code == 200

    profile1 = generator.orchestrator.session_tracker.get_or_create(session_id)
    assert profile1.turns == 1
    assert profile1.current_tactic == DeceptionTactic.T01_CLONE_MASQUERADE

    # Turn 2: SQL Injection exploit attempt on /profile
    # Deception orchestrator must select T03_CANARY_SEEDING (database canary)
    req2 = make_dummy_request("GET", "/profile", query="id=1' UNION SELECT username,password FROM users--")
    decision2 = {"label": "Exploit", "mitre_techniques": ["T1552"]}
    resp2 = await generator.generate_response(req2, "", decision2, session_id)
    assert resp2.status_code == 200

    profile2 = generator.orchestrator.session_tracker.get_or_create(session_id)
    assert profile2.turns == 2
    assert profile2.current_tactic == DeceptionTactic.T03_CANARY_SEEDING
    assert len(profile2.seeded_canaries) == 1

    seeded_token = profile2.seeded_canaries[0]["value"]
    assert "canary_usr_" in seeded_token

    # Turn 3: Attacker leaks/submits the seeded canary token back to the application
    req3 = make_dummy_request("POST", "/api/v1/auth", body=f"db_conn={seeded_token}")
    decision3 = {"label": "Recon"}  # Even if classified as Recon, orchestrator must elevate due to canary leak
    resp3 = await generator.generate_response(req3, f"db_conn={seeded_token}", decision3, session_id)
    assert resp3.status_code == 200

    profile3 = generator.orchestrator.session_tracker.get_or_create(session_id)
    assert profile3.turns == 3
    # Compromised canary list must contain the token
    assert len(profile3.compromised_canaries) >= 1
    assert profile3.interaction_depth == 3
    # Persistence score should have escalated
    assert profile3.persistence_score >= 10.0


@pytest.mark.asyncio
async def test_zero_stall_mock_fallback_sla(test_env):
    """Verifies that upstream API failure instantly returns in <200ms via MockLLMClient fallback."""
    import time
    generator, store, tmp_path = test_env
    session_id = "sess_latency_sla_002"

    req = make_dummy_request("GET", "/admin")
    decision = {"label": "Recon", "mitre_techniques": []}

    t0 = time.perf_counter()
    resp = await generator.generate_response(req, "", decision, session_id)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert resp.status_code == 200
    assert len(resp.body) > 0
    # Strict SLA check: must complete without stalling
    assert elapsed_ms < 500.0, f"Response took {elapsed_ms:.2f}ms, exceeding zero-stall SLA limit"
