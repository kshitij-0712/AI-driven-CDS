from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class UserBehaviorSignal:
    user_id: str
    session_id: str
    timestamp: str
    action_type: str
    action_details: Dict[str, Any]
    source_ip: str
    is_internal: bool


@dataclass
class InsiderThreatScore:
    user_id: str
    risk_score: float
    anomaly_factors: List[str]
    recommendation: str
