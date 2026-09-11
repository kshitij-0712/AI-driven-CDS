from dataclasses import dataclass
from typing import Any, Dict, List


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
