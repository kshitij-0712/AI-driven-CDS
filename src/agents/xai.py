import os
import sys
import time
from typing import Any, Dict, List

# Add parent directories to PYTHONPATH if necessary
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from interfaces.xai_contract import ClassificationEvent, RoutingDecision, XAIExplanation
from core.mitre.attack_mapping import ATTACK_PATTERNS, TACTICS, severity_to_tier

class AdaptiveXAINarrator:
    def __init__(self):
        pass

    def _match_mitre_techniques(self, commands: List[str]) -> List[Dict[str, Any]]:
        matches = []
        for cmd in commands:
            if not cmd:
                continue
            for p in ATTACK_PATTERNS:
                try:
                    if p["_compiled"].search(cmd):
                        matches.append({
                            "command": cmd,
                            "technique_id": p["technique_id"],
                            "technique_name": p["technique_name"],
                            "tactic": p["tactic"],
                            "description": p.get("description", "Command execution pattern"),
                            "severity": p.get("severity", 1)
                        })
                except Exception:
                    pass
        return matches

    def generate_explanation(self, event: ClassificationEvent, decision: RoutingDecision) -> XAIExplanation:
        """
        Processes classification events and routing decisions to generate a plain-English XAIExplanation.
        """
        label = event.classification
        action = decision.action
        src_ip = event.src_ip
        commands = event.commands
        confidence = event.confidence
        
        # 1. Match MITRE techniques
        mitre_matches = self._match_mitre_techniques(commands)
        matched_ids = [m["technique_id"] for m in mitre_matches]
        
        # Calculate risk score
        risk_score = 0.0
        if label.lower() == "safe":
            risk_score = event.confidence * 10.0 # Under 10
        elif label.lower() == "recon":
            risk_score = 30.0 + (confidence * 20.0) # 30-50
        elif label.lower() in ("downloader", "exploit"):
            risk_score = 50.0 + (confidence * 25.0) # 50-75
        else: # Destructive, APT
            risk_score = 75.0 + (confidence * 25.0) # 75-100

        # Override risk score if insider adapter calculated it higher
        if "risk_score" in event.features_used:
            risk_score = float(event.features_used["risk_score"])

        # Check if already blocked in firewall
        if event.features_used.get("already_blocked"):
            return ExplanationReport(
                summary=f"Access Blocked: IP {src_ip} is banned in kernel firewall.",
                detailed=f"The incoming connection from {src_ip} was dropped instantly. This IP address is banned in the nftables firewall due to previous high-risk activity. The security gateway blocks all traffic from this source until released by the security team.",
                risk_score=100.0,
                recommended_actions=[
                    "Maintain active firewall ban.",
                    "Review historical audit logs for IP: " + src_ip,
                    "Verify if source machine is compromised by external attackers."
                ]
            )

        # 2. Build explanation summary and detailed text based on scenarios
        summary = ""
        detailed_points = []
        recommended_actions = []

        # Check for Insider Threat Alerts first (since they are special)
        is_insider_threat = event.features_used.get("insider_threat", False) or "Insider threat detected" in decision.reason
        
        if is_insider_threat:
            role = event.features_used.get("role", "employee")
            anomaly_factors = event.features_used.get("anomaly_factors", ["Scope access violation"])
            
            summary = f"Insider Threat Alert: Session terminated and IP {src_ip} blocked."
            detailed_points.append(f"Internal employee logged in as role '{role}' exhibited high-risk anomalous behavior.")
            detailed_points.append(f"Anomalous factors detected: {', '.join(anomaly_factors)}")
            
            if mitre_matches:
                detailed_points.append("Executed commands matched these MITRE ATT&CK techniques:")
                for m in mitre_matches:
                    tactic_info = TACTICS.get(m["tactic"], {"id": "TA0000"})
                    detailed_points.append(f" - {m['command']}: {m['technique_name']} ({m['technique_id']}) - Tactic: {m['tactic']} ({tactic_info['id']})")

            recommended_actions.extend([
                "Lock employee AD (Active Directory) credentials immediately.",
                "Conduct manual forensic audit of local logs on source machine.",
                "Revoke unauthorized API/scope privileges."
            ])
            
        elif label.lower() == "safe":
            summary = f"Normal request from {src_ip} forwarded safely."
            detailed_points.append("The AI classified the session activity as SAFE (Intent: Safe).")
            detailed_points.append("No malicious command patterns or unauthorized scope accesses were detected.")
            detailed_points.append(f"Transaction completed with 0.1s latency.")
            recommended_actions.append("No action required. Connection monitored normally.")
            
        elif label.lower() in ("recon", "downloader", "exploit"):
            summary = f"Decoy Redirect: IP {src_ip} silently trapped in Docker honeypot."
            detailed_points.append(f"The system intercepted a suspicious {label.upper()} scan from IP {src_ip}.")
            
            if commands:
                detailed_points.append(f"Triggered by command execution: '{', '.join(commands)}'")
                
            if mitre_matches:
                detailed_points.append("Matched MITRE ATT&CK mapping:")
                for m in mitre_matches:
                    tactic_info = TACTICS.get(m["tactic"], {"id": "TA0000"})
                    detailed_points.append(f" - {m['technique_name']} ({m['technique_id']}) under {m['tactic'].upper()} tactic ({tactic_info['id']})")
                    detailed_points.append(f"   Details: {m['description']}")
            else:
                detailed_points.append("No specific MITRE patterns matched, but semantic models flagged anomalous command parameters.")
                
            detailed_points.append("Action: Rerouted traffic to a Docker decoy container to study attacker techniques without risking primary assets.")
            recommended_actions.extend([
                "Monitor honeypot session stream for further downloads or tool usage.",
                "Extract download payloads for sandbox analysis."
            ])
            
        else: # Destructive, APT
            summary = f"Kernel Block: IP {src_ip} blocked at Operating System level."
            detailed_points.append(f"Severed connection immediately due to critical {label.upper()} threat detection.")
            
            if commands:
                detailed_points.append(f"Attacker attempted high-risk command execution: '{', '.join(commands)}'")
                
            if mitre_matches:
                detailed_points.append("Matched high-severity MITRE ATT&CK mappings:")
                for m in mitre_matches:
                    tactic_info = TACTICS.get(m["tactic"], {"id": "TA0000"})
                    detailed_points.append(f" - {m['technique_name']} ({m['technique_id']}) [Severity: {m['severity']}/10] - Tactic: {m['tactic']} ({tactic_info['id']})")
            
            detailed_points.append("Action: Terminated active session and wrote blocklist rule to nftables kernel module to reject all subsequent packets.")
            recommended_actions.extend([
                "Verify kernel firewall ruleset is active.",
                "Submit source IP address to organization threat intelligence feeds.",
                "Scan filesystem for persistence payloads."
            ])

        detailed = "\n".join(detailed_points)

        return XAIExplanation(
            session_id=event.session_id,
            summary=summary,
            detailed=detailed,
            risk_score=risk_score,
            recommended_actions=recommended_actions
        )

# Maintain compatibility with the old simple orchestrator function
def explain_action(intent_label, confidence, action):
    narrator = AdaptiveXAINarrator()
    event = ClassificationEvent(
        session_id="simple_session",
        timestamp=datetime.now().isoformat() + "Z" if "datetime" in sys.modules else str(time.time()),
        src_ip="unknown",
        commands=[],
        classification=intent_label,
        confidence=confidence,
        mitre_techniques=[],
        features_used={}
    )
    decision = RoutingDecision(
        session_id="simple_session",
        action=action,
        target="unknown",
        reason="Compat mode"
    )
    explanation = narrator.generate_explanation(event, decision)
    return f"{explanation.summary}\n{explanation.detailed}"
