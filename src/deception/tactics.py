"""
AdaptiveShield — Strategic Deception Tactics & Director
Defines the 9 tactical deception objectives and threat-conditioned selection logic.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class DeceptionTactic(str, Enum):
    """The 9 strategic deception tactics available to the deception director."""
    T01_CLONE_MASQUERADE = "T01_CLONE_MASQUERADE"
    T02_SYNTHETIC_VULN = "T02_SYNTHETIC_VULN"
    T03_CANARY_SEEDING = "T03_CANARY_SEEDING"
    T04_DEPTH_ESCALATION = "T04_DEPTH_ESCALATION"
    T05_ADAPTIVE_TARPIT = "T05_ADAPTIVE_TARPIT"
    T06_BREADCRUMB_TRAIL = "T06_BREADCRUMB_TRAIL"
    T07_TRANSIENT_FAULT = "T07_TRANSIENT_FAULT"
    T08_BINARY_MUTATION = "T08_BINARY_MUTATION"
    T09_INSIDER_SANDBOX = "T09_INSIDER_SANDBOX"


@dataclass
class TacticMetadata:
    """Metadata and operational parameters for a specific deception tactic."""
    tactic: DeceptionTactic
    name: str
    description: str
    default_status_code: int = 200
    recommended_delay_ms: int = 0
    requires_canary: bool = False
    applicable_intents: List[str] = field(default_factory=list)


TACTIC_REGISTRY: Dict[DeceptionTactic, TacticMetadata] = {
    DeceptionTactic.T01_CLONE_MASQUERADE: TacticMetadata(
        tactic=DeceptionTactic.T01_CLONE_MASQUERADE,
        name="Authentic Clone & Masquerade",
        description="Serves an authentic clone of the target application theme with zero obvious vulnerabilities.",
        default_status_code=200,
        recommended_delay_ms=0,
        applicable_intents=["Safe", "Recon"],
    ),
    DeceptionTactic.T02_SYNTHETIC_VULN: TacticMetadata(
        tactic=DeceptionTactic.T02_SYNTHETIC_VULN,
        name="Synthetic Vulnerability Exposure",
        description="Synthesizes realistic error traces (MariaDB syntax, Linux passwd slices, reflected payloads) to confirm exploit success.",
        default_status_code=200,
        recommended_delay_ms=25,
        applicable_intents=["Exploit", "Destructive"],
    ),
    DeceptionTactic.T03_CANARY_SEEDING: TacticMetadata(
        tactic=DeceptionTactic.T03_CANARY_SEEDING,
        name="Honeytoken & Canary Seeding",
        description="Injects cryptographically signed canary credentials (AWS keys, DB tokens, JWTs) into response data or headers.",
        default_status_code=200,
        recommended_delay_ms=20,
        requires_canary=True,
        applicable_intents=["Recon", "Exploit", "ADVANCED_APT"],
    ),
    DeceptionTactic.T04_DEPTH_ESCALATION: TacticMetadata(
        tactic=DeceptionTactic.T04_DEPTH_ESCALATION,
        name="Interactive Depth Escalation",
        description="Unlocks simulated administrative consoles, developer staging panels, or internal debug portals.",
        default_status_code=200,
        recommended_delay_ms=50,
        applicable_intents=["Recon", "Exploit", "ADVANCED_APT"],
    ),
    DeceptionTactic.T05_ADAPTIVE_TARPIT: TacticMetadata(
        tactic=DeceptionTactic.T05_ADAPTIVE_TARPIT,
        name="Adaptive Tarpitting & Delay",
        description="Injects controlled latency (250ms–1500ms) to waste automated scanner bandwidth and rate-limit tools.",
        default_status_code=200,
        recommended_delay_ms=850,
        applicable_intents=["Scanner", "Recon"],
    ),
    DeceptionTactic.T06_BREADCRUMB_TRAIL: TacticMetadata(
        tactic=DeceptionTactic.T06_BREADCRUMB_TRAIL,
        name="Deceptive Breadcrumb Trail",
        description="Injects hidden clues, internal URLs, or backup notes to steer adversaries toward deep Cowrie SSH honeypots.",
        default_status_code=200,
        recommended_delay_ms=30,
        applicable_intents=["ADVANCED_APT", "Recon"],
    ),
    DeceptionTactic.T07_TRANSIENT_FAULT: TacticMetadata(
        tactic=DeceptionTactic.T07_TRANSIENT_FAULT,
        name="Transient Fault Injection",
        description="Emits authentic HTTP 500/503 errors to probe automated tooling retry logic and fault resilience.",
        default_status_code=503,
        recommended_delay_ms=10,
        applicable_intents=["Scanner", "Exploit"],
    ),
    DeceptionTactic.T08_BINARY_MUTATION: TacticMetadata(
        tactic=DeceptionTactic.T08_BINARY_MUTATION,
        name="Reactive Binary Dropper Mutation",
        description="Coordinates with watcher.py upon binary upload to seed fake expected target files in honeypot sandboxes.",
        default_status_code=200,
        recommended_delay_ms=60,
        applicable_intents=["Downloader", "Destructive"],
    ),
    DeceptionTactic.T09_INSIDER_SANDBOX: TacticMetadata(
        tactic=DeceptionTactic.T09_INSIDER_SANDBOX,
        name="Silent Insider Sandbox",
        description="Serves watermarked intranet documents and restricted file decoys without disrupting operational workflows.",
        default_status_code=200,
        recommended_delay_ms=40,
        requires_canary=True,
        applicable_intents=["Safe", "Recon", "Exploit", "ADVANCED_APT"],
    ),
}


class TacticalDirector:
    """
    Threat-Informed Tactical Deception Director.
    Selects the optimal deception objective conditioned on multi-modal threat
    classification, MITRE ATT&CK techniques, binary triage status, insider risk,
    and adversary interaction history.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        deception_cfg = self.config.get("deception", {})
        self.tarpit_delay_ms = deception_cfg.get("tarpit_delay_ms", 850)
        self.insider_anomaly_threshold = deception_cfg.get("insider_anomaly_threshold", 0.70)

    def select_tactic(
        self,
        intent_label: str,
        mitre_techniques: Optional[List[str]] = None,
        binary_triage: Optional[Dict[str, Any]] = None,
        insider_context: Optional[Dict[str, Any]] = None,
        interaction_depth: int = 0,
        session_turn: int = 1,
        canaries_seeded: int = 0,
        path: str = "",
    ) -> DeceptionTactic:
        """
        Deterministic, rule-guided tactical objective selection.
        """
        normalized_intent = (intent_label or "Recon").strip().upper()
        mitre_set = set(t.upper() for t in (mitre_techniques or []))
        lower_path = (path or "").lower()

        # 1. Insider Threat Detection Override
        if insider_context:
            is_internal = insider_context.get("is_internal", False)
            anomaly_score = insider_context.get("anomaly_score", 0.0)
            risk_level = str(insider_context.get("risk_level", "")).upper()
            if is_internal and (anomaly_score >= self.insider_anomaly_threshold or risk_level in ("HIGH", "CRITICAL")):
                return DeceptionTactic.T09_INSIDER_SANDBOX

        # 2. In-Flight Binary Dropper or MOTIF Distiller Notification
        if binary_triage and binary_triage.get("has_binary", False):
            if binary_triage.get("is_malicious", False) or normalized_intent in ("DOWNLOADER", "DESTRUCTIVE"):
                return DeceptionTactic.T08_BINARY_MUTATION

        if normalized_intent == "DOWNLOADER":
            return DeceptionTactic.T08_BINARY_MUTATION

        # 3. Sophisticated Threat Actor / APT Lateral Movement
        if normalized_intent == "ADVANCED_APT":
            if canaries_seeded == 0:
                return DeceptionTactic.T03_CANARY_SEEDING
            if session_turn >= 3:
                return DeceptionTactic.T06_BREADCRUMB_TRAIL
            return DeceptionTactic.T04_DEPTH_ESCALATION

        # 4. Active Exploit (SQLi, Command Injection, Path Traversal)
        if normalized_intent in ("EXPLOIT", "DESTRUCTIVE"):
            # If adversary is querying sensitive database tables or config endpoints, bait with canaries
            sensitive_indicators = {"T1005", "T1552", "T1078", "T1083"}  # Data from local system, Unsecured Creds
            is_credential_recon = bool(mitre_set.intersection(sensitive_indicators))
            is_sensitive_path = any(k in lower_path for k in ("db", "dump", "export", "profile", "user", "secret", "config"))

            if (is_credential_recon or is_sensitive_path) and canaries_seeded == 0:
                return DeceptionTactic.T03_CANARY_SEEDING
            return DeceptionTactic.T02_SYNTHETIC_VULN

        # 5. Automated Scanner / Fuzzer
        if normalized_intent == "SCANNER":
            # Every 4th turn inject transient fault to assess scanner retry handling; otherwise tarpit
            if session_turn > 1 and session_turn % 4 == 0:
                return DeceptionTactic.T07_TRANSIENT_FAULT
            return DeceptionTactic.T05_ADAPTIVE_TARPIT

        # 6. Reconnaissance
        if normalized_intent == "RECON":
            # If path indicates administrative exploration
            admin_indicators = {"/admin", "/dev", "/api/v1/debug", "/staging", "/manager", "/console", "/config"}
            if any(ind in lower_path for ind in admin_indicators) or (session_turn >= 2 and interaction_depth >= 1):
                return DeceptionTactic.T04_DEPTH_ESCALATION
            return DeceptionTactic.T01_CLONE_MASQUERADE

        # 7. Safe / Default Traffic
        return DeceptionTactic.T01_CLONE_MASQUERADE

    def get_metadata(self, tactic: DeceptionTactic) -> TacticMetadata:
        """Retrieve metadata for a given tactic."""
        return TACTIC_REGISTRY.get(tactic, TACTIC_REGISTRY[DeceptionTactic.T01_CLONE_MASQUERADE])
