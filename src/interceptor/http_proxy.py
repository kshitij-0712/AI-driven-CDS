import json
import os
import time
from contextlib import asynccontextmanager
from typing import Dict

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from agents.decision import build_hybrid_classifier, classify_http_request
from agents.deception import DecoyManager
from interceptor.nftables_manager import NftablesManager
from interceptor.session_store import SessionStore
from agents.insider.insider_adapter import AdaptiveInsiderDetector
from agents.xai import AdaptiveXAINarrator
import ipaddress
from datetime import datetime
import asyncio
from fastapi.responses import StreamingResponse

# Global event queue for the live dashboard
event_queue = asyncio.Queue()


def _is_private_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip.strip())
        return address.is_private or address.is_loopback
    except ValueError:
        return False


def _request_to_context(request: Request, body: str) -> Dict:
    return {
        "method": request.method,
        "path": request.url.path,
        "query": str(request.url.query or ""),
        "body": body,
        "headers": dict(request.headers),
        "source_ip": request.client.host if request.client else "unknown",
    }


def create_http_guard_app(config: Dict) -> FastAPI:

    runtime_cfg = config.get("runtime", {})
    http_cfg = config.get("http_guard", {})
    decoy_cfg = config.get("decoys", {})

    db_path = runtime_cfg.get("db_path", "./runtime/adaptiveshield.db")
    threat_log_path = runtime_cfg.get("threat_log_path", "./runtime/logs/threat_events.jsonl")
    real_host = http_cfg.get("real_service_host", "127.0.0.1")
    real_port = int(http_cfg.get("real_service_port", 8080))
    timeout_sec = int(http_cfg.get("request_timeout_sec", 10))
    brute_force_threshold = int(http_cfg.get("brute_force_threshold", 8))
    block_duration_minutes = int(http_cfg.get("block_duration_minutes", 60))
    fallback_on_error = bool(http_cfg.get("fallback_on_error", True))

    os.makedirs(os.path.dirname(threat_log_path), exist_ok=True)

    store = SessionStore(db_path)
    nft = NftablesManager()
    nft.ensure_base_ruleset()

    classifier = build_hybrid_classifier()
    insider_detector = AdaptiveInsiderDetector()
    xai_detector = AdaptiveXAINarrator()

    decoys = DecoyManager(
        http_image=decoy_cfg.get("http_image", "adaptiveshield/http-decoy:latest"),
        max_instances=int(decoy_cfg.get("max_instances", 5)),
        idle_timeout_sec=int(decoy_cfg.get("idle_timeout_sec", 300)),
        fallback_url=decoy_cfg.get("fallback_url"),
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        decoys.pre_pull_images(decoy_cfg.get("pre_pull_images", []))
        yield
        decoys.shutdown_all_decoys()

    app = FastAPI(title="AdaptiveShield HTTP Guard", version="0.1.0", lifespan=lifespan)
    app.state.store = store
    app.state.nft = nft
    app.state.classifier = classifier
    app.state.decoys = decoys

    async def forward_request(target_base_url: str, request: Request, body: bytes) -> Response:
        target_url = f"{target_base_url}{request.url.path}"
        if request.url.query:
            target_url = f"{target_url}?{request.url.query}"

        headers = dict(request.headers)
        headers.pop("host", None)

        async with httpx.AsyncClient(timeout=timeout_sec) as client:
            upstream = await client.request(
                request.method,
                target_url,
                headers=headers,
                content=body,
            )

        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=dict(upstream.headers),
        )

    @app.get("/health")
    async def health():
        from agents.decision import _neural_model
        return {
            "status": "ok",
            "classifier": "hybrid_v2",
            "neural_model": "active" if _neural_model is not None else "unavailable",
            "docker_available": decoys.docker_available,
            "real_service": f"http://{real_host}:{real_port}",
        }

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    async def guard(path: str, request: Request):
        raw_body = await request.body()
        body_str = raw_body.decode("utf-8", errors="ignore")

        context = _request_to_context(request, body_str)
        src_ip = context["source_ip"]

        blocked_until = store.get_blocked_until(src_ip)
        if blocked_until and blocked_until > time.time():
            return JSONResponse(
                status_code=403,
                content={"error": "blocked", "reason": "temporary_block", "blocked_until": blocked_until},
            )

        session_id = store.get_or_create_session(src_ip)
        ctx = store._get_context(session_id)
        
        # Fetch command history for context-aware classification
        command_history = store.get_command_history(session_id)
        decision = classify_http_request(classifier, context, command_history=command_history)
        
        # Update command history with the current extracted command
        extracted_cmd = decision.get("extracted_command", "")
        if extracted_cmd and extracted_cmd != "/":
            store.append_command_history(session_id, extracted_cmd)

        # Simple brute-force detection for HTTP login endpoints.
        path_lower = request.url.path.lower()
        if request.method.upper() == "POST" and any(k in path_lower for k in ["login", "signin", "auth"]):
            attempts = store.increment_counter(session_id, "login_attempts")
            if attempts >= brute_force_threshold:
                decision = {
                    "class_id": 3,
                    "label": "Exploit",
                    "confidence": 1.0,
                    "action": "drop_and_block",
                    "rule": "HTTP brute-force threshold exceeded",
                    "mitre_tactics": ["credential_access"],
                    "severity_max": 8,
                    "http_findings": ["brute_force"],
                }

        # Check for Insider Threat if source IP is internal/private
        is_internal = _is_private_ip(src_ip)
        if is_internal and not ctx.get("redirected_to_decoy"):
            from interfaces.insider_contract import UserBehaviorSignal
            
            # Extract simulated features from HTTP JSON body if available
            extra_details = {}
            if body_str:
                try:
                    body_json = json.loads(body_str)
                    if isinstance(body_json, dict):
                        extra_details = body_json
                except Exception:
                    pass
            
            action_details = {
                "command": extra_details.get("command", decision.get("extracted_command", "")),
                "file_path": request.url.path,
                "role": request.headers.get("x-user-role", "normal"),
                **extra_details
            }
            
            signal = UserBehaviorSignal(
                user_id=request.headers.get("x-user-id", "unknown_user"),
                session_id=session_id,
                timestamp=datetime.now().isoformat() + "Z",
                action_type=request.method,
                action_details=action_details,
                source_ip=src_ip,
                is_internal=True
            )
            insider_threat = insider_detector.analyze_signal(signal)
            
            # Map insider recommendation to proxy action
            if insider_threat.recommendation in ("TERMINATE_SESSION_AND_BLOCK_IP", "CHALLENGE_WITH_MFA_OR_THROTTLE"):
                decision["action"] = "drop_and_block"
                decision["rule"] = f"Insider threat detected: {', '.join(insider_threat.anomaly_factors)}"
                decision["label"] = "Destructive"
                decision["severity_max"] = 9

        action = decision["action"]
        target = f"http://{real_host}:{real_port}"
        result = None

        if action == "drop_and_block":
            target = "blocked"
            block_seconds = block_duration_minutes * 60
            store.mark_blocked(session_id, block_seconds)
            nft.block_ip(src_ip, reason=decision.get("rule"))
            result = JSONResponse(
                status_code=403,
                content={
                    "error": "request_blocked",
                    "label": decision["label"],
                    "rule": decision.get("rule"),
                },
            )
        elif action == "redirect_to_decoy":
            decoy = decoys.get_or_spawn_http_decoy(session_id)
            if decoy:
                target = decoy.base_url
            
            # Decoy Cold-Start Fix
            max_retries = 10
            for i in range(max_retries):
                try:
                    result = await forward_request(target, request, raw_body)
                    break
                except Exception as e:
                    if i == max_retries - 1:
                        result = JSONResponse(
                            status_code=502,
                            content={"error": "upstream_failure", "target": target},
                        )
                    else:
                        import asyncio
                        await asyncio.sleep(0.1) # Wait 100ms before retrying
        else:
            try:
                result = await forward_request(target, request, raw_body)
            except Exception:
                if fallback_on_error:
                    decoy = decoys.get_or_spawn_http_decoy(session_id)
                    if decoy:
                        target = decoy.base_url
                        try:
                            result = await forward_request(target, request, raw_body)
                        except Exception:
                            result = JSONResponse(
                                status_code=502,
                                content={"error": "upstream_failure", "target": target},
                            )
                    else:
                        result = JSONResponse(
                            status_code=502,
                            content={"error": "real_service_unreachable"},
                        )
                else:
                    result = JSONResponse(
                        status_code=502,
                        content={"error": "real_service_unreachable"},
                    )

        event = {
            "timestamp": time.time(),
            "session_id": session_id,
            "source_ip": src_ip,
            "method": request.method,
            "path": request.url.path,
            "query": str(request.url.query or ""),
            "label": decision["label"],
            "action": action,
            "target": target,
            "rule": decision.get("rule"),
            "mitre_tactics": decision.get("mitre_tactics", []),
            "severity_max": decision.get("severity_max", 0),
            "response_status": result.status_code if result else 500,
            "login_attempts": store.get_counter(session_id, "login_attempts"),
        }

        # Include neural model metadata when available
        if "neural_confidence" in decision:
            event["neural_confidence"] = decision["neural_confidence"]
        if "fallback_reason" in decision:
            event["fallback_reason"] = decision["fallback_reason"]

        # Basic brute-force detector: repeated non-safe attempts from same source.
        if decision["label"] != "Safe" and brute_force_threshold > 0:
            if decision["label"] in ("Recon", "Downloader", "Exploit", "Destructive", "ADVANCED_APT"):
                event["suspicious"] = True

        # Generate XAI Explanation
        from interfaces.xai_contract import ClassificationEvent, RoutingDecision
        insider_threat_obj = locals().get("insider_threat")
        is_insider_active = is_internal and insider_threat_obj is not None
        
        xai_features = {}
        if is_insider_active:
            xai_features = {
                "insider_threat": True if insider_threat_obj.recommendation == "TERMINATE_SESSION_AND_BLOCK_IP" else False,
                "role": request.headers.get("x-user-role", "normal"),
                "anomaly_factors": insider_threat_obj.anomaly_factors,
                "risk_score": insider_threat_obj.risk_score
            }

        xai_event = ClassificationEvent(
            session_id=session_id,
            timestamp=datetime.now().isoformat() + "Z",
            src_ip=src_ip,
            commands=[decision.get("extracted_command", "")] if decision.get("extracted_command") else [],
            classification=decision["label"],
            confidence=decision.get("neural_confidence", 1.0),
            mitre_techniques=decision.get("mitre_tactics", []),
            features_used=xai_features
        )
        xai_decision = RoutingDecision(
            session_id=session_id,
            action=action,
            target=target,
            reason=decision.get("rule", "Classification triggered")
        )
        
        explanation = xai_detector.generate_explanation(xai_event, xai_decision)
        
        event["xai_summary"] = explanation.summary
        event["xai_detailed"] = explanation.detailed
        event["xai_risk_score"] = explanation.risk_score
        event["xai_recommendations"] = explanation.recommended_actions

        # Push to live dashboard stream queue
        try:
            await event_queue.put(event)
        except Exception:
            pass

        store.write_event(session_id, event)
        with open(threat_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
        print(json.dumps(event), flush=True)

        return result

    @app.get("/api/events")
    async def sse_events(request: Request):
        async def event_generator():
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(event_queue.get(), timeout=1.0)
                    yield f"data: {json.dumps(event)}\n\n"
                    event_queue.task_done()
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        return StreamingResponse(event_generator(), media_type="text/event-stream")

    from fastapi.responses import HTMLResponse
    @app.get("/dashboard", response_class=HTMLResponse)
    async def get_dashboard():
        template_path = os.path.join(os.path.dirname(__file__), "..", "orchestrator", "templates", "dashboard.html")
        if os.path.exists(template_path):
            with open(template_path, "r", encoding="utf-8") as f:
                return f.read()
        return "Dashboard template not found."

    return app
