"""
Unit tests for AdaptiveShield Core Deception Engine:
- TacticalDirector (Threat-conditioned deception tactic selection)
- CanaryGenerator (Cryptographic token creation, verification, and leak detection)
- SessionTracker (Stateful adversary session profiling and persistence scoring)
"""

import time
import pytest

from deception.tactics import DeceptionTactic, TacticalDirector, TACTIC_REGISTRY
from deception.canary import CanaryType, CanaryGenerator, CanaryToken
from deception.session_tracker import AdversarySessionProfile, SessionTracker


# ============================================================================
# 1. Tactical Director Unit Tests
# ============================================================================

def test_tactical_director_default_safe():
    director = TacticalDirector()
    tactic = director.select_tactic(intent_label="Safe")
    assert tactic == DeceptionTactic.T01_CLONE_MASQUERADE
    meta = director.get_metadata(tactic)
    assert meta.default_status_code == 200
    assert meta.recommended_delay_ms == 0


def test_tactical_director_recon_and_admin_escalation():
    director = TacticalDirector()
    # Simple reconnaissance on normal page
    tactic = director.select_tactic(intent_label="Recon", path="/about")
    assert tactic == DeceptionTactic.T01_CLONE_MASQUERADE

    # Reconnaissance probing administrative surfaces
    tactic_admin = director.select_tactic(intent_label="Recon", path="/admin/login.php")
    assert tactic_admin == DeceptionTactic.T04_DEPTH_ESCALATION

    # Reconnaissance at depth >= 1 and turn >= 2
    tactic_depth = director.select_tactic(intent_label="Recon", path="/status", session_turn=2, interaction_depth=1)
    assert tactic_depth == DeceptionTactic.T04_DEPTH_ESCALATION


def test_tactical_director_exploit_and_canary_seeding():
    director = TacticalDirector()
    # General exploit without credential dumping
    tactic = director.select_tactic(intent_label="Exploit", path="/api/ping")
    assert tactic == DeceptionTactic.T02_SYNTHETIC_VULN

    # Exploit on database dump / export path -> triggers canary seeding
    tactic_db = director.select_tactic(intent_label="Exploit", path="/db/export", canaries_seeded=0)
    assert tactic_db == DeceptionTactic.T03_CANARY_SEEDING

    # Exploit with MITRE technique for credential theft (T1552)
    tactic_mitre = director.select_tactic(
        intent_label="Exploit",
        mitre_techniques=["T1552"],
        canaries_seeded=0,
    )
    assert tactic_mitre == DeceptionTactic.T03_CANARY_SEEDING


def test_tactical_director_binary_triage_mutation():
    director = TacticalDirector()
    # Downloader intent
    tactic_dl = director.select_tactic(intent_label="Downloader")
    assert tactic_dl == DeceptionTactic.T08_BINARY_MUTATION

    # PE file flagged by in-flight MOTIF distiller
    binary_triage = {"has_binary": True, "is_malicious": True, "family_name": "Emotet"}
    tactic_binary = director.select_tactic(intent_label="Recon", binary_triage=binary_triage)
    assert tactic_binary == DeceptionTactic.T08_BINARY_MUTATION


def test_tactical_director_scanner_tarpitting_and_fault():
    director = TacticalDirector()
    # Turn 1, 2, 3 -> Tarpit
    assert director.select_tactic(intent_label="Scanner", session_turn=1) == DeceptionTactic.T05_ADAPTIVE_TARPIT
    assert director.select_tactic(intent_label="Scanner", session_turn=2) == DeceptionTactic.T05_ADAPTIVE_TARPIT
    assert director.select_tactic(intent_label="Scanner", session_turn=3) == DeceptionTactic.T05_ADAPTIVE_TARPIT

    # Turn 4 -> Transient Fault Injection
    tactic_fault = director.select_tactic(intent_label="Scanner", session_turn=4)
    assert tactic_fault == DeceptionTactic.T07_TRANSIENT_FAULT
    assert director.get_metadata(tactic_fault).default_status_code == 503


def test_tactical_director_apt_progression():
    director = TacticalDirector()
    # APT Turn 1 without canaries -> Canary Seeding
    tactic_apt1 = director.select_tactic(intent_label="ADVANCED_APT", session_turn=1, canaries_seeded=0)
    assert tactic_apt1 == DeceptionTactic.T03_CANARY_SEEDING

    # APT Turn 2 with canaries -> Depth Escalation
    tactic_apt2 = director.select_tactic(intent_label="ADVANCED_APT", session_turn=2, canaries_seeded=1)
    assert tactic_apt2 == DeceptionTactic.T04_DEPTH_ESCALATION

    # APT Turn 3 with canaries -> Breadcrumb Trail
    tactic_apt3 = director.select_tactic(intent_label="ADVANCED_APT", session_turn=3, canaries_seeded=1)
    assert tactic_apt3 == DeceptionTactic.T06_BREADCRUMB_TRAIL


def test_tactical_director_insider_override():
    director = TacticalDirector()
    # High anomaly score on internal request
    insider_ctx = {"is_internal": True, "anomaly_score": 0.85, "risk_level": "CRITICAL"}
    tactic = director.select_tactic(intent_label="Safe", insider_context=insider_ctx)
    assert tactic == DeceptionTactic.T09_INSIDER_SANDBOX


# ============================================================================
# 2. Canary Generator & Verification Tests
# ============================================================================

def test_canary_aws_key_generation_and_verification():
    cg = CanaryGenerator(secret_key="unit_test_canary_secret_123")
    token = cg.generate_aws_key(session_id="sess_alpha_99")

    assert token.token_type == CanaryType.AWS_ACCESS_KEY
    assert token.value.startswith("AKIA")
    assert len(token.value) == 20
    assert len(token.secret_value) == 40

    # Verification with exact session_id
    verified = cg.verify_aws_key(token.value, session_id="sess_alpha_99")
    assert verified is not None
    assert verified["is_valid"] is True

    # Verification with wrong session_id should fail
    assert cg.verify_aws_key(token.value, session_id="wrong_session") is None

    # Verification without session_id returns general validity
    verified_general = cg.verify_aws_key(token.value)
    assert verified_general is not None
    assert verified_general["is_valid"] is True


def test_canary_db_connection_generation():
    cg = CanaryGenerator()
    token = cg.generate_db_connection(session_id="sess_beta_42", db_name="payroll_db")

    assert token.token_type == CanaryType.DB_CONN_STR
    assert "postgresql://canary_usr_" in token.value
    assert "payroll_db" in token.value
    assert token.secret_value is not None


def test_canary_api_bearer_jwt_generation_and_verification():
    cg = CanaryGenerator()
    token = cg.generate_api_bearer_jwt(session_id="sess_gamma_77")

    assert token.token_type == CanaryType.API_BEARER_JWT
    parts = token.value.split(".")
    assert len(parts) == 3

    # Verification
    verified = cg.verify_jwt(token.value)
    assert verified is not None
    assert verified["is_valid"] is True
    assert verified["session_id"] == "sess_gamma_77"
    assert verified["token_type"] == CanaryType.API_BEARER_JWT.value

    # Tampered JWT should fail
    tampered_jwt = token.value[:-5] + "XXXXX"
    assert cg.verify_jwt(tampered_jwt) is None


def test_canary_doc_watermark_generation():
    cg = CanaryGenerator()
    token = cg.generate_doc_watermark(session_id="sess_delta_101")
    assert token.token_type == CanaryType.DOC_WATERMARK
    assert token.value.startswith("ADSHIELD-CANARY-")


def test_canary_leak_detection_in_text():
    cg = CanaryGenerator()
    aws_token = cg.generate_aws_key(session_id="sess_leak_01")
    jwt_token = cg.generate_api_bearer_jwt(session_id="sess_leak_02")

    # Sample intercepted request containing leaked tokens
    intercepted_body = f"""
    POST /api/v1/auth HTTP/1.1
    Authorization: Bearer {jwt_token.value}
    X-AWS-Key: {aws_token.value}
    Host: target.internal
    """

    leaks = cg.find_leaked_canaries(intercepted_body)
    assert len(leaks) >= 2

    types_found = {l["token_type"] for l in leaks}
    assert CanaryType.AWS_ACCESS_KEY.value in types_found
    assert CanaryType.API_BEARER_JWT.value in types_found


# ============================================================================
# 3. Session Tracker Unit Tests
# ============================================================================

def test_session_tracker_lifecycle_and_turn_progression():
    tracker = SessionTracker()
    session_id = "sess_tracked_555"

    profile = tracker.get_or_create(session_id, client_ip="192.168.1.50")
    assert profile.turns == 0
    assert profile.interaction_depth == 0

    # Turn 1: Recon
    tracker.record_turn(
        session_id=session_id,
        method="GET",
        path="/",
        intent_label="Recon",
        tactic_used=DeceptionTactic.T01_CLONE_MASQUERADE,
    )
    assert profile.turns == 1
    assert "Recon" in profile.detected_intents
    assert profile.current_tactic == DeceptionTactic.T01_CLONE_MASQUERADE

    # Turn 2: Exploit with Canary
    cg = CanaryGenerator()
    canary = cg.generate_aws_key(session_id=session_id)
    tracker.record_turn(
        session_id=session_id,
        method="POST",
        path="/db/dump",
        intent_label="Exploit",
        tactic_used=DeceptionTactic.T03_CANARY_SEEDING,
        mitre_techniques=["T1059", "T1552"],
        seeded_canary=canary,
        exposed_vuln="MariaDB SQL Syntax Error",
    )
    assert profile.turns == 2
    assert profile.interaction_depth == 1  # Exposed vuln increases depth
    assert len(profile.seeded_canaries) == 1
    assert "T1552" in profile.mitre_techniques_observed
    assert profile.persistence_score > 0.0


def test_session_tracker_canary_leak_compromise_and_depth_elevation():
    tracker = SessionTracker()
    session_id = "sess_canary_test"

    cg = tracker.canary_generator
    canary = cg.generate_aws_key(session_id=session_id)

    # Seed canary
    tracker.record_turn(
        session_id=session_id,
        method="GET",
        path="/config",
        intent_label="Exploit",
        tactic_used=DeceptionTactic.T03_CANARY_SEEDING,
        seeded_canary=canary,
    )

    # Adversary tries to use the leaked canary in a subsequent request
    leaked_request_payload = f"SELECT * FROM secrets WHERE aws_key = '{canary.value}';"
    findings = tracker.inspect_payload_for_canaries(session_id, leaked_request_payload)

    assert len(findings) == 1
    profile = tracker.get_or_create(session_id)
    assert len(profile.compromised_canaries) == 1
    assert profile.compromised_canaries[0]["matched_value"] == canary.value
    # Depth elevated to maximum (3) upon canary compromise
    assert profile.interaction_depth == 3
    # Persistence score should heavily reflect canary compromise (+10 points)
    assert profile.persistence_score >= 10.0


def test_session_tracker_export_summary():
    tracker = SessionTracker()
    session_id = "sess_summary_test"

    tracker.record_turn(
        session_id=session_id,
        method="GET",
        path="/",
        intent_label="Recon",
        tactic_used=DeceptionTactic.T01_CLONE_MASQUERADE,
    )

    summary = tracker.export_summary(session_id)
    assert summary["session_id"] == session_id
    assert summary["turns"] == 1
    assert summary["current_tactic"] == DeceptionTactic.T01_CLONE_MASQUERADE.value
    assert "dwell_time_seconds" in summary
    assert "persistence_score" in summary
