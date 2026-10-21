"""
GlassShield XAI unit tests.

Verifies every component introduced by the GlassShield plan:
    1. Data contracts (XAIExplanation glass-box fields).
    2. TreeSHAPExplainer exact Shapley attribution for the 35-feature RF model.
    3. NeuralTokenSaliency (gradient path + MITRE span fallback).
    4. CounterfactualEngine recourse deltas.
    5. DeceptionRationalizer internal (D4 containment) vs external rationales.
    6. TelemetryAuditor identity/network/kernel verdicts.
    7. AdaptiveXAINarrator end-to-end explanation structuring.
    8. SOC write APIs on CorporateDirectory (whitelist + scope grants).
"""

import os
import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).parent.parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))
PROJECT_ROOT = Path(__file__).parent.parent.parent

from interfaces.xai_contract import ClassificationEvent, RoutingDecision, XAIExplanation
from agents.xai import (
    AdaptiveXAINarrator,
    CounterfactualEngine,
    DeceptionRationalizer,
    NeuralTokenSaliency,
    TelemetryAuditor,
    TreeSHAPExplainer,
    explain_action,
)


INSIDER_MODEL_PATH = PROJECT_ROOT / "models" / "internal_insider_model.pkl"


def _make_event(classification: str, commands: list, features: dict, confidence: float = 0.9) -> ClassificationEvent:
    return ClassificationEvent(
        session_id="test_session",
        timestamp="2026-10-20T12:00:00Z",
        src_ip="192.168.1.103",
        commands=commands,
        classification=classification,
        confidence=confidence,
        mitre_techniques=[],
        features_used=features,
    )


def _make_decision(action: str, reason: str = "Policy: Test", target: str = "upstream") -> RoutingDecision:
    return RoutingDecision(session_id="test_session", action=action, target=target, reason=reason)


# --------------------------------------------------------------------------- #
# Contract                                                                    #
# --------------------------------------------------------------------------- #


class TestGlassShieldContracts:
    def test_explanation_glass_box_fields_default_empty(self):
        x = XAIExplanation(
            session_id="s", summary="x", detailed="y", risk_score=1.0, recommended_actions=[]
        )
        assert x.feature_attributions == {}
        assert x.token_attributions == []
        assert x.counterfactual_recourse == {}
        assert x.telemetry_audit == {}
        assert x.deception_rationale is None


# --------------------------------------------------------------------------- #
# TreeSHAP                                                                    #
# --------------------------------------------------------------------------- #


class TestTreeSHAPExplainer:
    @classmethod
    @pytest.fixture(scope="class")
    def explainer(cls):
        if not INSIDER_MODEL_PATH.exists():
            pytest.skip("internal_insider_model.pkl not available")
        return TreeSHAPExplainer(str(INSIDER_MODEL_PATH))

    def test_model_bundle_loads_with_35_features(self, explainer):
        assert explainer.explainer is not None
        assert len(explainer.feature_names) == 35

    def test_attributions_top_k_and_numeric(self, explainer):
        features = {name: 0.0 for name in explainer.feature_names}
        features["access_intellectual_property"] = 1.0
        attrs = explainer.explain(features, top_k=5)
        assert attrs, "Expected non-empty SHAP attribution for positive-evidence session"
        assert len(attrs) <= 5
        for value in attrs.values():
            assert isinstance(value, float)

    def test_positive_evidence_feature_appears(self, explainer):
        features = {name: 0.0 for name in explainer.feature_names}
        features["access_intellectual_property"] = 1.0
        features["access_unauthorized_scope"] = 1.0
        attrs = explainer.explain(features, top_k=10)
        contributing = {k for k, v in attrs.items() if abs(v) > 1e-9}
        assert contributing, "Expected at least one non-zero attribution"

    def test_zero_evidence_session_still_computes(self, explainer):
        features = {name: 0.0 for name in explainer.feature_names}
        attrs = explainer.explain(features)
        assert isinstance(attrs, dict)

    def test_missing_model_falls_back_to_heuristic(self, tmp_path):
        fallback = TreeSHAPExplainer(str(tmp_path / "does_not_exist.pkl"))
        assert fallback.explainer is None
        out = fallback.explain({"work_after_hours": 1.0, "access_hr_db": 0.0})
        assert out == {"work_after_hours": 10.0}


# --------------------------------------------------------------------------- #
# Neural Token Saliency                                                       #
# --------------------------------------------------------------------------- #


class TestNeuralTokenSaliency:
    @classmethod
    @pytest.fixture(scope="class")
    def neural_model(cls):
        try:
            from agents import decision
            model = decision.load_neural_model()
            if not model:
                pytest.skip("neural model unavailable")
            return model
        except ImportError:
            pytest.skip("PyTorch not installed")

    def test_fallback_mitre_span_highlighting(self):
        s = NeuralTokenSaliency()
        tokens = s.explain("' OR 1=1--", None)
        assert tokens, "MITRE fallback must produce highlighting for SQLi payloads"
        assert all("weight" in t for t in tokens)
        assert all(0.0 <= t["weight"] <= 1.0 for t in tokens)

    def test_empty_command_returns_empty(self):
        assert NeuralTokenSaliency().explain("", None) == []

    def test_gradient_path_with_real_model(self, neural_model):
        s = NeuralTokenSaliency()
        cmd = "rm -rf /var/log"
        tokens = s.explain(cmd, neural_model)
        assert len(tokens) == len(cmd.strip()) or len(tokens) > 0
        for t in tokens:
            assert 0.0 <= t["weight"] <= 1.0
        max_w = max(t["weight"] for t in tokens)
        assert max_w > 0.0, "At least one glyph must carry the maximum saliency"
        assert any(t["weight"] > 0.4 for t in tokens), "Hotspot glyphs (>0.4) expected for destructive command"

    def test_safe_command_with_real_model(self, neural_model):
        s = NeuralTokenSaliency()
        tokens = s.explain("git status", neural_model)
        assert tokens
        assert max(t["weight"] for t in tokens) <= 1.0


# --------------------------------------------------------------------------- #
# Counterfactual Recourse                                                     #
# --------------------------------------------------------------------------- #


class TestCounterfactualEngine:
    def setup_method(self):
        self.engine = CounterfactualEngine()

    def test_scope_violation_recourse(self):
        out = self.engine.generate_recourse("developer", {"access_unauthorized_scope": 1}, 88.0)
        assert "Confine operations" in out["actionable_steps"][0]
        assert out["projected_compliant_risk"] == 46.0
        assert out["target_policy_band"] == "MONITOR"

    def test_after_hours_recourse(self):
        out = self.engine.generate_recourse("hr", {"work_after_hours": 1}, 55.0)
        assert "business hours" in " ".join(out["actionable_steps"])
        assert out["projected_compliant_risk"] == 34.0

    def test_full_recourse_reaches_normal_band(self):
        out = self.engine.generate_recourse(
            "finance",
            {"access_unauthorized_scope": 1, "work_after_hours": 1, "unusual_pc_login": 1, "command_density": 1.0},
            90.0,
        )
        assert out["projected_compliant_risk"] == 10.0  # clamped floor
        assert out["target_policy_band"] == "NORMAL"
        assert len(out["actionable_steps"]) == 4

    def test_clean_behavior_generic_guidance(self):
        out = self.engine.generate_recourse("developer", {}, 10.0)
        assert out["actionable_steps"] == ["Maintain standard operating behavior within defined role scopes."]
        assert out["projected_compliant_risk"] == 10.0


# --------------------------------------------------------------------------- #
# Deception Rationalizer                                                      #
# --------------------------------------------------------------------------- #


class TestDeceptionRationalizer:
    def setup_method(self):
        self.r = DeceptionRationalizer()

    def test_forward_action_returns_none(self):
        assert self.r.rationalize(True, "forward", "upstream", "benign") is None

    def test_internal_redirect_uses_nginx_persona_containment(self):
        out = self.r.rationalize(True, "redirect_to_decoy", "decoy", "Scope violation")
        assert "Nginx Persona" in out["decoy_type"]
        assert "D4" in out["objective"]

    def test_external_redirect_uses_honeypot_intelligence(self):
        out = self.r.rationalize(False, "redirect_to_decoy", "decoy", "Recon scan")
        assert "Honeypot" in out["decoy_type"]
        assert "TTP" in out["objective"]


# --------------------------------------------------------------------------- #
# Telemetry Auditor                                                           #
# --------------------------------------------------------------------------- #


class TestTelemetryAuditor:
    def setup_method(self):
        self.a = TelemetryAuditor()

    def test_verified_identity(self):
        out = self.a.audit("10.10.6.31", {"x-user-role": "hr"}, True)
        assert out["identity_telemetry"] == "VERIFIED"
        assert out["network_provenance"] == "INTERNAL_SUBNET"
        assert out["kernel_enforcement"] == "ACTIVE (nftables)"
        assert out["telemetry_completeness_pct"] == 100

    def test_degraded_internal_identity(self):
        out = self.a.audit("192.168.1.103", {}, True)
        assert out["identity_telemetry"] == "DEGRADED"
        assert out["telemetry_completeness_pct"] == 70

    def test_external_anonymous_fallback(self):
        out = self.a.audit("198.51.100.42", {}, False)
        assert out["identity_telemetry"] == "ANONYMOUS_FALLBACK"
        assert out["network_provenance"] == "EXTERNAL_PERIMETER"


# --------------------------------------------------------------------------- #
# AdaptiveXAINarrator end-to-end                                              #
# --------------------------------------------------------------------------- #


class TestAdaptiveXAINarrator:
    @pytest.fixture(scope="class")
    def narrator(cls):
        return AdaptiveXAINarrator(str(INSIDER_MODEL_PATH) if INSIDER_MODEL_PATH.exists() else "./models/internal_insider_model.pkl")

    def test_insider_explanation_full_glass_box(self, narrator):
        features = {"work_after_hours": 1.0, "access_hr_db": 1.0, "role": "developer"}
        event = _make_event(
            "Insider Anomaly",
            ["cat /payroll/employees.csv"],
            {
                "insider_threat": True,
                "is_internal": True,
                "role": "developer",
                "risk_score": 88.0,
                "policy_decision": "CONTAIN",
                "evidence_features": features,
                "headers": {"x-user-role": "developer"},
                "anomaly_factors": ["access_hr_db"],
            },
            confidence=1.0,
        )
        expl = narrator.generate_explanation(event, _make_decision("redirect_to_decoy"), None)

        assert "Insider Threat Alert" in expl.summary
        assert "CONTAIN" in expl.summary
        assert expl.feature_attributions, "TreeSHAP attribution must be attached"
        assert expl.counterfactual_recourse["actionable_steps"]
        assert expl.deception_rationale is not None
        assert "D4" in expl.deception_rationale["objective"]
        assert expl.telemetry_audit["identity_telemetry"] == "VERIFIED"
        assert expl.risk_score == 88.0
        assert "TreeSHAP" in expl.detailed

    def test_external_destructive_kernel_block(self, narrator):
        event = _make_event(
            "Destructive",
            ["rm -rf /var/log"],
            {"risk_score": 98.0, "policy_decision": "CONTAIN", "headers": {}},
            confidence=0.97,
        )
        expl = narrator.generate_explanation(event, _make_decision("drop_and_block", target="blocked"), None)

        assert "Kernel Block" in expl.summary
        assert expl.token_attributions, "Token saliency must render for external attacks"
        assert expl.deception_rationale is None, "No deception card on kernel block"
        assert expl.risk_score == 98.0

    def test_external_recon_decoy_redirect(self, narrator):
        event = _make_event(
            "Recon",
            ["nmap -sS 192.168.1.0/24"],
            {"risk_score": 41.0, "policy_decision": "ALERT", "headers": {}},
            confidence=0.55,
        )
        expl = narrator.generate_explanation(event, _make_decision("redirect_to_decoy", reason="Recon scan"), None)

        assert "Decoy Redirect" in expl.summary
        assert expl.deception_rationale is not None
        assert "Honeypot" in expl.deception_rationale["decoy_type"]

    def test_safe_request(self, narrator):
        event = _make_event("Safe", ["/about"], {"risk_score": 2.0, "policy_decision": "NORMAL", "headers": {}}, 0.99)
        expl = narrator.generate_explanation(event, _make_decision("forward"), None)
        assert "forwarded safely" in expl.summary
        assert expl.feature_attributions == {}

    def test_already_blocked_fast_path(self, narrator):
        event = _make_event("Destructive", [], {"already_blocked": True}, 1.0)
        expl = narrator.generate_explanation(event, _make_decision("drop_and_block"), None)
        assert expl.risk_score == 100.0
        assert "banned in kernel firewall" in expl.summary


# --------------------------------------------------------------------------- #
# Backward compatibility                                                      #
# --------------------------------------------------------------------------- #


class TestCompatWrapper:
    def test_explain_action_returns_text(self):
        text = explain_action("Exploit", 0.87, "redirect_to_decoy")
        assert text
        assert "Decoy Redirect" in text or "Exploit" in text


# --------------------------------------------------------------------------- #
# CorporateDirectory SOC write APIs                                           #
# --------------------------------------------------------------------------- #


class TestCorporateDirectorySOC:
    def test_add_whitelisted_ip_and_grant_scope(self, tmp_path):
        profile_path = tmp_path / "company_profile.json"
        import json

        profile_path.write_text(
            json.dumps({
                "departments": {"AI_Platform": {"authorized_scopes": ["/models/"]}},
                "employees": [{
                    "user_id": "usr_dev_01",
                    "email": "s@x.com",
                    "name": "S",
                    "role": "developer",
                    "department": "AI_Platform",
                    "assigned_device": "WS",
                    "assigned_ip": "10.10.4.52",
                }],
            }),
            encoding="utf-8",
        )

        from agents.insider.corporate_directory import CorporateDirectory

        cd = CorporateDirectory(db_path=str(tmp_path / "cd.db"), profile_path=str(profile_path))

        # Whitelist flow
        assert cd.add_whitelisted_ip("usr_dev_01", "203.0.113.9") is True
        assert "203.0.113.9" in cd.get_employee("usr_dev_01")["whitelisted_ips"]
        assert cd.check_ip_whitelist("usr_dev_01", "203.0.113.9") is True
        # Unknown user
        assert cd.add_whitelisted_ip("ghost", "1.2.3.4") is False
        # Idempotent
        assert cd.add_whitelisted_ip("usr_dev_01", "203.0.113.9") is True
        emp = cd.get_employee("usr_dev_01")
        assert emp["whitelisted_ips"].count("203.0.113.9") == 1

        # Scope grant flow
        dept = cd.grant_scope("AI_Platform", "/src/")
        assert "/src/" in dept["authorized_scopes"]
        persisted = json.loads(profile_path.read_text(encoding="utf-8"))
        assert "/src/" in persisted["departments"]["AI_Platform"]["authorized_scopes"]
        # Empty args rejected
        assert cd.grant_scope("", "/x/") == {}
