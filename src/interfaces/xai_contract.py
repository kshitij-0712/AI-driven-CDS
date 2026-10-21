from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ClassificationEvent:
    session_id: str
    timestamp: str
    src_ip: str
    commands: List[str]
    classification: str
    confidence: float
    mitre_techniques: List[str]
    features_used: Dict[str, Any]


@dataclass
class RoutingDecision:
    session_id: str
    action: str
    target: str
    reason: str


@dataclass
class XAIExplanation:
    session_id: str
    summary: str
    detailed: str
    risk_score: float
    recommended_actions: List[str]
    # GlassShield First-Class Additions
    feature_attributions: Dict[str, float] = field(default_factory=dict)
    token_attributions: List[Dict[str, Any]] = field(default_factory=list)
    counterfactual_recourse: Dict[str, Any] = field(default_factory=dict)
    telemetry_audit: Dict[str, Any] = field(default_factory=dict)
    deception_rationale: Optional[Dict[str, Any]] = None
