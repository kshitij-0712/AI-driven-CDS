"""
Unit tests for AdaptiveShield Deception Orchestrator & Decoy Mutator:
- DeceptionPromptComposer (Context-rich tactic prompting)
- DeceptionOrchestrator (Turn orchestration, canary coordination, and error fallback)
- DecoyEnvironmentMutator (Safe file writes, Nginx config generation, and binary mutation)
"""

import json
import os
import pytest
from unittest.mock import AsyncMock, MagicMock

from deception.canary import CanaryGenerator, CanaryType
from deception.mutator import DecoyEnvironmentMutator
from deception.orchestrator import (
    DeceptionOrchestrator,
    DeceptionPromptComposer,
    OrchestrationResult,
)
from deception.session_tracker import SessionTracker
from deception.tactics import DeceptionTactic, TacticalDirector


# ============================================================================
# 1. Prompt Composer Unit Tests
# ============================================================================

def test_prompt_composer_strategies():
    # Test strategy prompts for key tactics
    s1 = DeceptionPromptComposer.build_tactic_strategy(DeceptionTactic.T01_CLONE_MASQUERADE)
    assert "T01" in s1
    assert "Authentic Clone" in s1

    s2 = DeceptionPromptComposer.build_tactic_strategy(DeceptionTactic.T02_SYNTHETIC_VULN)
    assert "T02" in s2
    assert "Synthetic Vulnerability" in s2

    cg = CanaryGenerator()
    canary = cg.generate_aws_key("test_session")
    s3 = DeceptionPromptComposer.build_tactic_strategy(DeceptionTactic.T03_CANARY_SEEDING, canary=canary)
    assert "T03" in s3
    assert canary.value in s3

    s5 = DeceptionPromptComposer.build_tactic_strategy(DeceptionTactic.T05_ADAPTIVE_TARPIT)
    assert "T05" in s5
    assert "Tarpit" in s5


def test_prompt_composer_full_context():
    req_ctx = {
        "method": "POST",
        "path": "/api/v1/query",
        "query": "id=1' OR '1'='1",
        "body": "token=xyz",
        "headers": {"User-Agent": "sqlmap/1.7"},
    }
    prompt = DeceptionPromptComposer.compose_prompt(
        request_context=req_ctx,
        tactic=DeceptionTactic.T02_SYNTHETIC_VULN,
        intent_label="Exploit",
        app_structure={"target_url": "http://app.local", "theme": "dark", "pages": {}},
        session_profile={"turns": 2, "interaction_depth": 1},
    )

    assert "Generate the deception honeypot response" in prompt
    assert "T02_SYNTHETIC_VULN" in prompt
    assert "sqlmap" in prompt
    assert "Exploit" in prompt


# ============================================================================
# 2. Deception Orchestrator Unit Tests
# ============================================================================

@pytest.mark.asyncio
async def test_orchestrator_turn_safe_traffic():
    mock_router = MagicMock()
    mock_router.generate = AsyncMock(return_value=json.dumps({
        "status_code": 200,
        "headers": {"Content-Type": "text/html"},
        "body": "<html><body><h1>Dashboard</h1></body></html>",
        "session_updates": {},
    }))

    orchestrator = DeceptionOrchestrator(router=mock_router)
    req_ctx = {"method": "GET", "path": "/", "query": "", "body": "", "headers": {}}
    decision = {"label": "Safe"}

    result = await orchestrator.orchestrate_turn(
        request_context=req_ctx,
        decision=decision,
        session_id="sess_safe_01",
    )

    assert isinstance(result, OrchestrationResult)
    assert result.tactic == DeceptionTactic.T01_CLONE_MASQUERADE
    assert result.status_code == 200
    assert "Dashboard" in result.body
    assert result.canary_seeded is None


@pytest.mark.asyncio
async def test_orchestrator_turn_canary_seeding_and_leak_detection():
    cg = CanaryGenerator()
    tracker = SessionTracker(canary_generator=cg)

    mock_router = MagicMock()
    # Mock LLM generating response that plants the canary
    mock_router.generate = AsyncMock(return_value=json.dumps({
        "status_code": 200,
        "headers": {"Content-Type": "application/json"},
        "body": '{"status": "ok", "env": "staged"}',
        "session_updates": {},
    }))

    orchestrator = DeceptionOrchestrator(
        router=mock_router,
        canary_generator=cg,
        session_tracker=tracker,
    )

    # Turn 1: Exploit targeting sensitive database dump -> should seed canary
    req_ctx_1 = {"method": "GET", "path": "/db/dump", "query": "", "body": "", "headers": {}}
    decision_1 = {"label": "Exploit"}

    res_1 = await orchestrator.orchestrate_turn(
        request_context=req_ctx_1,
        decision=decision_1,
        session_id="sess_leak_audit",
    )

    assert res_1.tactic == DeceptionTactic.T03_CANARY_SEEDING
    assert res_1.canary_seeded is not None
    seeded_token_val = res_1.canary_seeded.value

    # Turn 2: Attacker submits the leaked canary in their request body
    req_ctx_2 = {
        "method": "POST",
        "path": "/api/auth",
        "query": "",
        "body": f"token={seeded_token_val}",
        "headers": {},
    }
    decision_2 = {"label": "Recon"}  # Classifiers might see simple POST, but orchestrator will catch leak

    res_2 = await orchestrator.orchestrate_turn(
        request_context=req_ctx_2,
        decision=decision_2,
        session_id="sess_leak_audit",
    )

    # Canary compromise must be detected and recorded
    assert len(res_2.canaries_compromised) >= 1
    assert res_2.canaries_compromised[0]["matched_value"] == seeded_token_val


@pytest.mark.asyncio
async def test_orchestrator_fallback_on_empty_or_broken_llm():
    mock_router = MagicMock()
    mock_router.generate = AsyncMock(return_value="NOT_VALID_JSON_AT_ALL")

    orchestrator = DeceptionOrchestrator(router=mock_router)
    req_ctx = {"method": "GET", "path": "/admin", "query": "", "body": "", "headers": {}}
    decision = {"label": "Recon"}

    result = await orchestrator.orchestrate_turn(
        request_context=req_ctx,
        decision=decision,
        session_id="sess_fallback_test",
    )

    # Should fall back gracefully without raising an exception
    assert result.status_code == 200
    assert "Access Verification" in result.body


# ============================================================================
# 3. Decoy Environment Mutator Unit Tests
# ============================================================================

def test_mutator_write_single_page(tmp_path):
    mutator = DecoyEnvironmentMutator()
    html_dir = str(tmp_path / "html")

    # Valid write
    target_p = mutator.write_decoy_page(
        html_dir=html_dir,
        rel_path="status",
        body="<html><body>All systems operational</body></html>",
    )

    assert os.path.exists(target_p)
    assert target_p.endswith("status.html")
    with open(target_p, "r") as f:
        assert "All systems operational" in f.read()

    # Rejection of path traversal
    with pytest.raises(ValueError):
        mutator.write_decoy_page(
            html_dir=html_dir,
            rel_path="../../etc/shadow",
            body="malicious content",
        )


def test_mutator_write_generated_files(tmp_path):
    mutator = DecoyEnvironmentMutator()
    html_dir = str(tmp_path / "html")

    gen_files = [
        {"relative_path": "config/app.json", "content": '{"debug": true}'},
        {"relative_path": "robots.txt", "content": "Disallow: /admin"},
    ]

    written = mutator.write_generated_files(html_dir, gen_files)
    assert len(written) == 2
    assert all(os.path.exists(p) for p in written)


def test_mutator_update_metadata_and_nginx_conf(tmp_path):
    mutator = DecoyEnvironmentMutator()
    base_dir = str(tmp_path / "decoy_base")

    conf_path = mutator.update_metadata_and_nginx_conf(
        base_dir=base_dir,
        path="/api/v1/status",
        status_code=200,
        content_type="application/json",
        headers={"X-Server-Id": "node-42"},
    )

    assert os.path.exists(conf_path)
    with open(conf_path, "r") as f:
        conf_text = f.read()
        assert "location = /api/v1/status" in conf_text
        assert "application/json" in conf_text
        assert 'add_header "X-Server-Id" "node-42";' in conf_text


def test_mutator_binary_upload_reaction(tmp_path):
    mutator = DecoyEnvironmentMutator()
    decoy_dir = str(tmp_path / "decoy")

    res = mutator.mutate_on_binary_upload(
        session_id="sess_binary_mutate",
        decoy_dir=decoy_dir,
        filename="dropper.exe",
        triage_info={"family_name": "WannaCry", "is_malicious": True},
    )

    assert res["status"] == "mutated"
    assert res["family_detected"] == "WannaCry"
    assert len(res["created_artifacts"]) >= 1
    assert os.path.exists(res["created_artifacts"][0])
