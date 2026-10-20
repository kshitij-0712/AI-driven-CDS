"""
AdaptiveShield — Adversary Engagement & Interaction State Machine
Maintains stateful attacker profiles, tracks turns, and scores persistence.
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from deception.canary import CanaryGenerator, CanaryToken
from deception.tactics import DeceptionTactic


@dataclass
class AdversarySessionProfile:
    """Stateful profile of an interacting adversary session."""
    session_id: str
    client_ip: str = "127.0.0.1"
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    turns: int = 0
    detected_intents: List[str] = field(default_factory=list)
    mitre_techniques_observed: Set[str] = field(default_factory=set)
    seeded_canaries: List[Dict[str, Any]] = field(default_factory=list)
    compromised_canaries: List[Dict[str, Any]] = field(default_factory=list)
    exposed_vulnerabilities: List[str] = field(default_factory=list)
    submitted_credentials: List[Dict[str, str]] = field(default_factory=list)
    dropped_binaries: List[str] = field(default_factory=list)
    current_tactic: DeceptionTactic = DeceptionTactic.T01_CLONE_MASQUERADE
    interaction_depth: int = 0  # 0: public, 1: probe/error, 2: auth/staging, 3: privileged/shell
    persistence_score: float = 0.0

    @property
    def dwell_time_seconds(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    def calculate_persistence(self) -> float:
        """
        Computes an empirical adversary persistence score based on turns,
        dwell duration, exploit diversity, and canary compromise attempts.
        """
        score = (
            (self.turns * 1.5)
            + (min(self.dwell_time_seconds, 600.0) / 30.0)
            + (len(self.mitre_techniques_observed) * 2.0)
            + (len(self.submitted_credentials) * 3.0)
            + (len(self.compromised_canaries) * 10.0)
            + (len(self.dropped_binaries) * 5.0)
        )
        self.persistence_score = round(score, 2)
        return self.persistence_score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "client_ip": self.client_ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "dwell_time_seconds": round(self.dwell_time_seconds, 2),
            "turns": self.turns,
            "detected_intents": self.detected_intents,
            "mitre_techniques_observed": sorted(list(self.mitre_techniques_observed)),
            "seeded_canaries_count": len(self.seeded_canaries),
            "compromised_canaries_count": len(self.compromised_canaries),
            "compromised_canaries": self.compromised_canaries,
            "exposed_vulnerabilities": self.exposed_vulnerabilities,
            "submitted_credentials_count": len(self.submitted_credentials),
            "dropped_binaries_count": len(self.dropped_binaries),
            "current_tactic": self.current_tactic.value,
            "interaction_depth": self.interaction_depth,
            "persistence_score": self.persistence_score,
        }


class SessionTracker:
    """
    Thread-safe adversary session tracker and intelligence accumulator.
    """

    def __init__(
        self,
        canary_generator: Optional[CanaryGenerator] = None,
        ttl_seconds: int = 3600,
    ):
        self.canary_generator = canary_generator or CanaryGenerator()
        self.ttl_seconds = ttl_seconds
        self._profiles: Dict[str, AdversarySessionProfile] = {}
        self._lock = threading.Lock()

    def get_or_create(self, session_id: str, client_ip: str = "127.0.0.1") -> AdversarySessionProfile:
        """Retrieve existing adversary session profile or instantiate a new one."""
        with self._lock:
            if session_id not in self._profiles:
                self._profiles[session_id] = AdversarySessionProfile(
                    session_id=session_id,
                    client_ip=client_ip,
                )
            profile = self._profiles[session_id]
            profile.last_seen = time.time()
            return profile

    def record_turn(
        self,
        session_id: str,
        method: str,
        path: str,
        intent_label: str,
        tactic_used: DeceptionTactic,
        mitre_techniques: Optional[List[str]] = None,
        binary_triage: Optional[Dict[str, Any]] = None,
        seeded_canary: Optional[CanaryToken] = None,
        credentials_attempted: Optional[Dict[str, str]] = None,
        exposed_vuln: Optional[str] = None,
    ) -> AdversarySessionProfile:
        """
        Updates session metrics following an interaction turn.
        """
        profile = self.get_or_create(session_id)
        with self._lock:
            profile.turns += 1
            profile.last_seen = time.time()
            profile.current_tactic = tactic_used

            if intent_label and intent_label not in profile.detected_intents:
                profile.detected_intents.append(intent_label)

            if mitre_techniques:
                for tech in mitre_techniques:
                    profile.mitre_techniques_observed.add(tech)

            if seeded_canary:
                profile.seeded_canaries.append(seeded_canary.to_dict())

            if credentials_attempted:
                profile.submitted_credentials.append(credentials_attempted)
                profile.interaction_depth = max(profile.interaction_depth, 2)

            if exposed_vuln and exposed_vuln not in profile.exposed_vulnerabilities:
                profile.exposed_vulnerabilities.append(exposed_vuln)
                profile.interaction_depth = max(profile.interaction_depth, 1)

            if binary_triage and binary_triage.get("has_binary"):
                fam = binary_triage.get("family_name", "unknown_binary")
                profile.dropped_binaries.append(fam)
                profile.interaction_depth = max(profile.interaction_depth, 3)

            profile.calculate_persistence()
            return profile

    def inspect_payload_for_canaries(self, session_id: str, payload_text: str) -> List[Dict[str, Any]]:
        """
        Inspects an incoming request payload or command for previously seeded canary tokens.
        If a match is confirmed, marks the canary as compromised and elevates the session.
        """
        if not payload_text:
            return []

        leaks = self.canary_generator.find_leaked_canaries(payload_text)
        if not leaks:
            return []

        profile = self.get_or_create(session_id)
        with self._lock:
            for leak in leaks:
                leak_record = {
                    "matched_value": leak.get("matched_value"),
                    "token_type": leak.get("token_type"),
                    "detected_at": time.time(),
                    "origin_session": leak.get("session_id") or session_id,
                }
                # Prevent duplicate entries
                if not any(c.get("matched_value") == leak_record["matched_value"] for c in profile.compromised_canaries):
                    profile.compromised_canaries.append(leak_record)

            # Re-calculate persistence and elevate depth
            profile.interaction_depth = 3
            profile.calculate_persistence()

        return leaks

    def export_summary(self, session_id: str) -> Dict[str, Any]:
        """Export session metrics for logging or publication benchmarks."""
        profile = self.get_or_create(session_id)
        return profile.to_dict()

    def cleanup_expired(self) -> int:
        """Purge sessions older than the configured TTL."""
        now = time.time()
        to_purge = []
        with self._lock:
            for sid, p in self._profiles.items():
                if now - p.last_seen > self.ttl_seconds:
                    to_purge.append(sid)
            for sid in to_purge:
                del self._profiles[sid]
        return len(to_purge)
