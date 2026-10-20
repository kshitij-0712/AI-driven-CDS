"""
AdaptiveShield Autonomous Cyber Deception Module
Provides threat-conditioned strategic deception, dynamic honeytokens, and state tracking.
"""

from deception.tactics import (
    DeceptionTactic,
    TacticMetadata,
    TACTIC_REGISTRY,
    TacticalDirector,
)
from deception.canary import (
    CanaryType,
    CanaryToken,
    CanaryGenerator,
)
from deception.session_tracker import (
    AdversarySessionProfile,
    SessionTracker,
)

__all__ = [
    "DeceptionTactic",
    "TacticMetadata",
    "TACTIC_REGISTRY",
    "TacticalDirector",
    "CanaryType",
    "CanaryToken",
    "CanaryGenerator",
    "AdversarySessionProfile",
    "SessionTracker",
]
