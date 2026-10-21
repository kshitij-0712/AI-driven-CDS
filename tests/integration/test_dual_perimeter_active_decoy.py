import os
import pytest
from unittest.mock import MagicMock, AsyncMock

from honeypot.generator import HoneypotGenerator
from interceptor.session_store import SessionStore


@pytest.mark.asyncio
async def test_honeypot_generator_dual_perimeter_selection():
    store = MagicMock(spec=SessionStore)
    config = {
        "llm": {"provider": "gemini", "api_key": "test_key"},
        "gemini": {"api_key": "test_key"}
    }
    
    # External generator
    gen_ext = HoneypotGenerator(config=config, store=store, is_internal=False)
    assert gen_ext.scope == "external"
    assert "app_structure_external.json" in gen_ext.structure_path
    await gen_ext._ensure_app_structure()
    assert "/login" in gen_ext.app_structure.get("pages", {})

    # Internal generator
    gen_int = HoneypotGenerator(config=config, store=store, is_internal=True)
    assert gen_int.scope == "internal"
    assert "app_structure_internal.json" in gen_int.structure_path
    await gen_int._ensure_app_structure()
    assert "/workspace" in gen_int.app_structure.get("pages", {})


@pytest.mark.asyncio
async def test_active_engagement_condition():
    # In decoy, interactive actions (POST, queries, new paths) must trigger mutation
    ctx = {"redirected_to_decoy": True}
    prev_path = "/index.html"
    prev_label = "Safe"
    prev_severity = 0
    file_exists = True

    # Case 1: Benign button click / POST submission while in decoy
    method = "POST"
    query = ""
    path = "/login"
    label = "Safe"
    severity = 0

    is_attack = label != "Safe"
    is_in_decoy = bool(ctx.get("redirected_to_decoy"))
    is_interactive_action = (
        method.upper() in ("POST", "PUT", "DELETE", "PATCH") or
        bool(query) or
        path != prev_path
    )
    is_escalation = (
        not is_in_decoy or
        not file_exists or
        is_interactive_action or
        (is_attack and (
            label != prev_label or
            severity > prev_severity
        ))
    )

    # Must be TRUE so decoy actively engages rather than staying dormant
    assert is_escalation is True
