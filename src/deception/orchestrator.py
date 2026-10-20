"""
AdaptiveShield — Strategic Deception Orchestrator & Prompt Composer
Coordinates real-time threat intelligence with LLM generative deception and canary seeding.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from deception.canary import CanaryGenerator, CanaryToken, CanaryType
from deception.session_tracker import AdversarySessionProfile, SessionTracker
from deception.tactics import DeceptionTactic, TacticalDirector

logger = logging.getLogger(__name__)


@dataclass
class OrchestrationResult:
    """Encapsulates the end-to-end output of a deception interaction turn."""
    tactic: DeceptionTactic
    status_code: int
    headers: Dict[str, str]
    body: str
    canary_seeded: Optional[CanaryToken] = None
    canaries_compromised: List[Dict[str, Any]] = field(default_factory=list)
    session_profile: Optional[Dict[str, Any]] = None
    generated_files: Optional[List[Dict[str, str]]] = None
    delay_ms: int = 0
    raw_response: str = ""
    session_updates: Dict[str, Any] = field(default_factory=dict)


class DeceptionPromptComposer:
    """
    Builds structured, contextual prompts for the LLM generative engine
    conditioned on target app theme, threat intelligence, and chosen deception tactic.
    """

    SYSTEM_INSTRUCTION = """You are AdaptiveShield Decoy Engine, an autonomous cyber deception assistant.
Your goal is to convince adversarial actors that they are interacting with genuine production systems.
You will generate realistic HTTP responses dynamically based on the assigned deception tactic.

You must respond ONLY with a valid JSON object matching the following structure:
{
  "status_code": 200,
  "headers": {
    "Content-Type": "text/html"
  },
  "body": "<!DOCTYPE html><html>...</html>",
  "session_updates": {},
  "generated_files": []
}

Guidelines:
1. "status_code": Use realistic HTTP status codes matching the tactic instructions.
2. "headers": Include appropriate headers like Content-Type ("text/html", "application/json", "text/plain").
3. "body": Return high-fidelity visible text content inside the <body> tag or JSON object. NEVER return a blank page or placeholder text like 'content...'.
4. "generated_files": Optional list of up to 5 declarative decoy files (e.g. [{"relative_path": "config.php", "content": "..."}]).
5. "session_updates": Record internal state changes only.
6. Return ONLY the JSON object without markdown formatting or commentary.
"""

    @staticmethod
    def build_tactic_strategy(tactic: DeceptionTactic, canary: Optional[CanaryToken] = None) -> str:
        """Formulates specific strategy instructions for the given tactic."""
        if tactic == DeceptionTactic.T01_CLONE_MASQUERADE:
            return (
                "TACTIC: Authentic Clone & Masquerade (T01). "
                "The visitor appears benign or is performing early reconnaissance. "
                "Serve a high-fidelity clone matching the target application theme. "
                "Do NOT expose any obvious errors, tracebacks, or vulnerabilities. "
                "Return normal HTTP 200 OK."
            )
        elif tactic == DeceptionTactic.T02_SYNTHETIC_VULN:
            return (
                "TACTIC: Synthetic Vulnerability Exposure (T02). "
                "The attacker is attempting an active exploit (SQLi, CMDi, Path Traversal, or XSS). "
                "Make the exploit appear successful to retain attacker engagement: "
                "- If SQL injection: emit authentic MariaDB/MySQL syntax tracebacks or mock database row dumps. "
                "- If path traversal (/etc/passwd): return realistic Linux user account lines (root:x:0:0...). "
                "- If command injection (ping, cat): return command terminal output followed by execution results. "
                "- If XSS: reflect the payload in an unescaped DOM element."
            )
        elif tactic == DeceptionTactic.T03_CANARY_SEEDING:
            canary_desc = (
                f"Plant the following canary credential naturally in the response:\n"
                f"Canary Type: {canary.token_type.value if canary else 'aws_access_key'}\n"
                f"Canary Key/Value: {canary.value if canary else 'AKIAIOSFODNN7EXAMPLE'}\n"
            )
            if canary and canary.secret_value:
                canary_desc += f"Secret Key/Password: {canary.secret_value}\n"
            return (
                f"TACTIC: Honeytoken & Canary Seeding (T03).\n"
                f"The adversary is searching for credentials, database dumps, or configuration keys.\n"
                f"{canary_desc}"
                f"Embed this credential believably into the response body (e.g. inside an environment config file, "
                f"a database query record, or an internal API response) so the adversary exfiltrates it."
            )
        elif tactic == DeceptionTactic.T04_DEPTH_ESCALATION:
            return (
                "TACTIC: Interactive Depth Escalation (T04). "
                "The adversary has probed administrative or staging surfaces. "
                "Unlock a realistic administrative portal or developer maintenance dashboard. "
                "Include functional-looking HTML forms with 'Username' and 'Password' inputs and professional styling."
            )
        elif tactic == DeceptionTactic.T05_ADAPTIVE_TARPIT:
            return (
                "TACTIC: Adaptive Tarpit (T05). "
                "Automated scanner traffic detected. Return a standard, valid response format (HTML or JSON) "
                "while the proxy introduces deliberate micro-latency to exhaust scanner bandwidth."
            )
        elif tactic == DeceptionTactic.T06_BREADCRUMB_TRAIL:
            return (
                "TACTIC: Deceptive Breadcrumb Trail (T06). "
                "Sophisticated threat actor detected. Embed subtle hints into HTML comments or metadata "
                "(e.g., '<!-- Internal SSH staging node at 10.0.12.8:2222 -->' or '/backup/api_staging.json') "
                "to entice the attacker to pivot into secondary Cowrie honeypots."
            )
        elif tactic == DeceptionTactic.T07_TRANSIENT_FAULT:
            return (
                "TACTIC: Transient Fault Injection (T07). "
                "Simulate a temporary upstream service failure (HTTP 503 Service Unavailable or HTTP 500) "
                "with an authentic gateway error message to test whether automated tools adapt or abort."
            )
        elif tactic == DeceptionTactic.T08_BINARY_MUTATION:
            return (
                "TACTIC: Reactive Binary Dropper Mutation (T08). "
                "Malware dropper or binary upload detected. Respond with an authentic HTTP 200 upload confirmation "
                "(e.g., 'File uploaded successfully. Staged to /tmp/upload_cache/ for asynchronous batch processing.')."
            )
        elif tactic == DeceptionTactic.T09_INSIDER_SANDBOX:
            watermark_hint = f"Watermark: {canary.value}" if canary else "Watermark: ADSHIELD-CANARY-AUDIT"
            return (
                f"TACTIC: Silent Insider Sandbox (T09).\n"
                f"Internal anomaly detected. Serve a sanitized internal intranet portal with links to canary corporate files. "
                f"Embed watermark reference '{watermark_hint}' into document headers."
            )
        return "TACTIC: Default Realistic Response."

    @classmethod
    def compose_prompt(
        cls,
        request_context: Dict[str, Any],
        tactic: DeceptionTactic,
        intent_label: str,
        app_structure: Optional[Dict[str, Any]] = None,
        session_profile: Optional[Dict[str, Any]] = None,
        canary: Optional[CanaryToken] = None,
    ) -> str:
        app_struct = app_structure or {}
        clean_pages = {}
        for p, info in app_struct.get("pages", {}).items():
            clean_pages[p] = {"title": info.get("title", ""), "forms": info.get("forms", [])}

        app_info = {
            "target_url": app_struct.get("target_url", ""),
            "theme": app_struct.get("theme", ""),
            "pages": clean_pages,
        }

        strategy = cls.build_tactic_strategy(tactic, canary)

        prompt_dict = {
            "incoming_request": {
                "method": request_context.get("method", "GET"),
                "path": request_context.get("path", "/"),
                "query": request_context.get("query", ""),
                "body": request_context.get("body", ""),
                "headers": request_context.get("headers", {}),
            },
            "threat_intelligence": {
                "intent_label": intent_label,
                "selected_tactic": tactic.value,
                "binary_triage": request_context.get("binary_triage"),
                "insider_context": request_context.get("insider_context"),
            },
            "target_app_knowledge": app_info,
            "adversary_session_memory": session_profile or {},
            "response_strategy": strategy,
        }

        return (
            "Generate the deception honeypot response for the following security context.\n"
            "Return ONLY a parseable JSON object matching the requested schema.\n\n"
            f"Context:\n{json.dumps(prompt_dict, indent=2)}\n"
        )


class DeceptionOrchestrator:
    """
    Central Controller for Threat-Conditioned Cyber Deception.
    Connects TacticalDirector, CanaryGenerator, SessionTracker, and the LLM Router.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        router: Any = None,
        canary_generator: Optional[CanaryGenerator] = None,
        session_tracker: Optional[SessionTracker] = None,
        tactical_director: Optional[TacticalDirector] = None,
    ):
        self.config = config or {}
        self.canary_generator = canary_generator or CanaryGenerator()
        self.session_tracker = session_tracker or SessionTracker(canary_generator=self.canary_generator)
        self.director = tactical_director or TacticalDirector(config=self.config)
        self.router = router

    async def orchestrate_turn(
        self,
        request_context: Dict[str, Any],
        decision: Dict[str, Any],
        session_id: str,
        app_structure: Optional[Dict[str, Any]] = None,
        client_ip: str = "127.0.0.1",
    ) -> OrchestrationResult:
        """
        Executes a single deception turn:
        1. Inspects incoming request payload for previously leaked canaries.
        2. Retrieves session profile & turn count.
        3. Selects optimal deception tactic.
        4. Seeds new canary token if required by tactic.
        5. Composes context-rich LLM prompt.
        6. Generates response via LLM Router (with safe fallback).
        7. Parses JSON and updates session profile.
        """
        method = request_context.get("method", "GET")
        path = request_context.get("path", "/")
        query = request_context.get("query", "")
        body_str = request_context.get("body", "")
        headers = request_context.get("headers", {})
        intent_label = decision.get("label", "Recon")

        # 1. Inspect for leaked canaries in incoming request (query, body, auth header)
        inspection_target = f"{query}\n{body_str}\n{headers.get('authorization', '')}\n{headers.get('x-api-key', '')}"
        compromised = self.session_tracker.inspect_payload_for_canaries(session_id, inspection_target)
        if compromised:
            logger.warning(f"Attacker session {session_id} submitted compromised canary: {compromised}")
            intent_label = "ADVANCED_APT"

        # 2. Retrieve current adversary session profile
        profile = self.session_tracker.get_or_create(session_id, client_ip=client_ip)
        current_turn = profile.turns + 1

        # 3. Select Deception Tactic
        tactic = self.director.select_tactic(
            intent_label=intent_label,
            mitre_techniques=decision.get("mitre_techniques"),
            binary_triage=decision.get("binary_triage"),
            insider_context=decision.get("insider_context"),
            interaction_depth=profile.interaction_depth,
            session_turn=current_turn,
            canaries_seeded=len(profile.seeded_canaries),
            path=path,
        )
        metadata = self.director.get_metadata(tactic)

        # 4. Generate Canary Token if required by tactic
        seeded_canary: Optional[CanaryToken] = None
        if metadata.requires_canary or tactic == DeceptionTactic.T03_CANARY_SEEDING:
            is_sql_intent = any(k in query.lower() for k in ("sql", "select", "union", "dump", "where", "--"))
            if "db" in path.lower() or is_sql_intent:
                seeded_canary = self.canary_generator.generate_db_connection(session_id)
            elif "doc" in path.lower() or tactic == DeceptionTactic.T09_INSIDER_SANDBOX:
                seeded_canary = self.canary_generator.generate_doc_watermark(session_id)
            else:
                seeded_canary = self.canary_generator.generate_aws_key(session_id)

        # 5. Build Prompts
        system_instruction = DeceptionPromptComposer.SYSTEM_INSTRUCTION
        user_prompt = DeceptionPromptComposer.compose_prompt(
            request_context=request_context,
            tactic=tactic,
            intent_label=intent_label,
            app_structure=app_structure,
            session_profile=profile.to_dict(),
            canary=seeded_canary,
        )

        # 6. Call LLM Router
        raw_response = ""
        if self.router:
            try:
                raw_response = await self.router.generate(intent_label, system_instruction, user_prompt)
            except Exception as e:
                logger.error(f"Router generate error in DeceptionOrchestrator: {e}")
                raw_response = ""

        # 7. Parse and Validate Response
        parsed = self._parse_json_response(raw_response, metadata.default_status_code)

        # 8. Update Session Tracker
        self.session_tracker.record_turn(
            session_id=session_id,
            method=method,
            path=path,
            intent_label=intent_label,
            tactic_used=tactic,
            mitre_techniques=decision.get("mitre_techniques"),
            binary_triage=decision.get("binary_triage"),
            seeded_canary=seeded_canary,
            exposed_vuln=tactic.value if tactic == DeceptionTactic.T02_SYNTHETIC_VULN else None,
        )

        return OrchestrationResult(
            tactic=tactic,
            status_code=parsed.get("status_code", metadata.default_status_code),
            headers=parsed.get("headers", {"Content-Type": "text/html"}),
            body=parsed.get("body", ""),
            canary_seeded=seeded_canary,
            canaries_compromised=compromised,
            session_profile=profile.to_dict(),
            generated_files=parsed.get("generated_files"),
            delay_ms=metadata.recommended_delay_ms,
            raw_response=raw_response,
            session_updates=parsed.get("session_updates", {}),
        )

    def _parse_json_response(self, text: str, default_status: int = 200) -> Dict[str, Any]:
        """Tolerant JSON parser with fallback."""
        if not text:
            return {
                "status_code": default_status,
                "headers": {"Content-Type": "text/html"},
                "body": "<html><body><div style='background:#0f172a;color:#f8fafc;padding:30px;'><h2>Access Verification</h2><p>Request processed under audit policy.</p></div></body></html>",
                "session_updates": {},
            }

        text_clean = text.strip()
        try:
            return json.loads(text_clean)
        except json.JSONDecodeError:
            pass

        import re
        match = re.search(r"(\{.*\})", text_clean, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        return {
            "status_code": default_status,
            "headers": {"Content-Type": "text/html"},
            "body": "<html><body><div style='background:#0f172a;color:#f8fafc;padding:30px;'><h2>Access Verification</h2><p>Request processed under audit policy.</p></div></body></html>",
            "session_updates": {},
        }
