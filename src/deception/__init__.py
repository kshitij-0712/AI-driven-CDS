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
from deception.orchestrator import (
    DeceptionPromptComposer,
    DeceptionOrchestrator,
    OrchestrationResult,
)
from deception.mutator import (
    DecoyEnvironmentMutator,
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
    "DeceptionPromptComposer",
    "DeceptionOrchestrator",
    "OrchestrationResult",
    "DecoyEnvironmentMutator",
]
