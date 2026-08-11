import asyncio
import json
import logging
import time
from typing import Dict, Tuple

import asyncssh

from agents.decision import classify_ssh_command, build_hybrid_classifier
from agents.deception import DecoyManager
from interceptor.nftables_manager import NftablesManager
from interceptor.session_store import SessionStore

logger = logging.getLogger(__name__)
logging.getLogger("asyncssh").setLevel(logging.DEBUG)

class BackendProxySession(asyncssh.SSHClientSession):
    def __init__(self, frontend_chan):
        self.frontend_chan = frontend_chan

    def data_received(self, data, datatype):
        self.frontend_chan.write(data)

    def connection_lost(self, exc):
        if exc:
            print(f"Backend connection lost with error: {exc}", flush=True)
        if not self.frontend_chan.is_closing():
            self.frontend_chan.exit(0)
            self.frontend_chan.close()

class SSHGuardSession(asyncssh.SSHServerSession):
    def __init__(self, target_host: str, target_port: int, session_id: str, src_ip: str, 
                 store: SessionStore, nft: NftablesManager, classifier, decoy_mgr: DecoyManager, 
                 is_decoy: bool, auth_username: str = None, auth_password: str = None, real_conn = None):
        self.target_host = target_host
        self.target_port = target_port
        self.session_id = session_id
        self.src_ip = src_ip
        self.store = store
        self.nft = nft
        self.classifier = classifier
        self.decoy_mgr = decoy_mgr
        self.is_decoy = is_decoy
        self.auth_username = auth_username
        self.auth_password = auth_password
        
        self.chan = None
        self.backend_conn = real_conn
        self.backend_chan = None
        self.cmd_buffer = ""

    def connection_made(self, chan):
        self.chan = chan

    def pty_requested(self, term_type, term_size, term_modes):
        self._term_type = term_type
        self._term_size = term_size
        self._term_modes = term_modes
        return True

    def shell_requested(self):
        asyncio.create_task(self._proxy_shell())
        return True

    def exec_requested(self, command):
        self.cmd_buffer = command
        asyncio.create_task(self._proxy_exec(command))
        return True

    async def _proxy_exec(self, command):
        try:
            if self.is_decoy:
                self.backend_conn = await asyncssh.connect(
                    self.target_host, port=self.target_port,
                    known_hosts=None, username=self.auth_username or 'root', 
                    password=self.auth_password or 'password'
                )
            # Else: real_conn is already established and passed in self.backend_conn!
            
            # We process the command for threat detection before sending it
            self._process_command(command)
            
            # Since _process_command might have closed the channel if it was an exploit, we check
            if self.chan.is_closing():
                return
                
            self.backend_chan, _ = await self.backend_conn.create_session(
                lambda: BackendProxySession(self.chan), command
            )
        except Exception as e:
            print(f"Failed to connect to backend for exec {self.target_host}:{self.target_port}: {e}", flush=True)
            logger.error(f"Failed to connect to backend for exec {self.target_host}:{self.target_port}: {e}")
            if not self.chan.is_closing():
                self.chan.exit(1)
                self.chan.close()

    async def _proxy_shell(self):
        try:
            if self.is_decoy:
                self.backend_conn = await asyncssh.connect(
                    self.target_host, port=self.target_port,
                    known_hosts=None, username=self.auth_username or 'root', 
                    password=self.auth_password or 'password'
                )
                
            self.backend_chan, _ = await self.backend_conn.create_session(
                lambda: BackendProxySession(self.chan),
                term_type=getattr(self, '_term_type', 'xterm'),
                term_size=getattr(self, '_term_size', (80, 24)),
                term_modes=getattr(self, '_term_modes', {})
            )
        except Exception as e:
            print(f"Failed to connect to backend for shell {self.target_host}:{self.target_port}: {e}", flush=True)
            logger.error(f"Failed to connect to backend {self.target_host}:{self.target_port}: {e}")
            if not self.chan.is_closing():
                self.chan.exit(1)
                self.chan.close()

    def data_received(self, data, datatype):
        # Forward keystrokes to backend
        if self.backend_chan and not self.backend_chan.is_closing():
            if isinstance(data, str):
                self.backend_chan.write(data.replace('\r', '\r\n'))
            else:
                self.backend_chan.write(data.replace(b'\r', b'\r\n'))

        # Buffer for command reconstruction
        if isinstance(data, bytes):
            # Sometimes data is bytes depending on asyncssh version
            data = data.decode('utf-8', 'ignore')

        for char in data:
            if char == '\r' or char == '\n':
                if self.cmd_buffer.strip():
                    self._process_command(self.cmd_buffer.strip())
                self.cmd_buffer = ""
            elif char == '\x08' or char == '\x7f':  # Backspace
                self.cmd_buffer = self.cmd_buffer[:-1]
            elif char.isprintable():
                self.cmd_buffer += char

    def _process_command(self, cmd: str):
        if not self.is_decoy:
            return  # Deferred real server monitoring

        # Save to history
        history = self.store.get_command_history(self.session_id)
        self.store.append_command_history(self.session_id, cmd)
        
        context = {
            "source_ip": self.src_ip,
            "session_id": self.session_id,
            "protocol": "ssh"
        }
        
        full_command = f"{history}; {cmd}".strip("; ") if history else cmd
        
        decision = classify_ssh_command(self.classifier, full_command, context)
        
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
        import ipaddress
        is_insider = False
        try:
            addr = ipaddress.ip_address(self.src_ip.strip())
            is_insider = addr.is_private or addr.is_loopback
        except ValueError:
            pass

        risk_score = base_risk_score
        insider_threat = None

        if is_insider:
            from interfaces.insider_contract import UserBehaviorSignal
            from agents.insider.insider_adapter import AdaptiveInsiderDetector
            from datetime import datetime
            
            action_details = {
                "command": cmd,
                "file_path": f"ssh://{self.src_ip}",
                "role": "sys_admin",
            }
            signal = UserBehaviorSignal(
                user_id=self.auth_username or "ssh_user",
                session_id=self.session_id,
                timestamp=datetime.now().isoformat() + "Z",
                action_type="EXEC",
                action_details=action_details,
                source_ip=self.src_ip,
                is_internal=True
            )
            insider_detector = AdaptiveInsiderDetector()
            insider_threat = insider_detector.analyze_signal(signal)
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

        event = {
            "timestamp": time.time(),
            "session_id": self.session_id,
            "source_ip": self.src_ip,
            "protocol": "ssh",
            "command": cmd,
            "label": decision["label"],
            "action": action,
            "rule": decision.get("rule"),
            "mitre_tactics": decision.get("mitre_tactics", []),
            "severity_max": decision.get("severity_max", 0),
            "is_insider": is_insider,
            "risk_score": risk_score,
            "policy_decision": policy_decision,
        }
        
        if is_insider and insider_threat:
            event["evidence_features"] = {k: v for k, v in insider_threat.features.items() if v > 0} if insider_threat.features else {}

        if "neural_confidence" in decision:
            event["neural_confidence"] = decision["neural_confidence"]

        # Generate XAI Explanation
        try:
            from agents.xai import AdaptiveXAINarrator
            from interfaces.xai_contract import ClassificationEvent, RoutingDecision
            from datetime import datetime
            
            xai_detector = AdaptiveXAINarrator()
            
            xai_features = {
                "risk_score": risk_score,
                "policy_decision": policy_decision,
                "protocol": "ssh"
            }
            if is_insider and insider_threat:
                xai_features.update({
                    "insider_threat": True if action == "drop_and_block" else False,
                    "role": "sys_admin",
                    "anomaly_factors": insider_threat.anomaly_factors,
                    "evidence_features": insider_threat.features
                })

            xai_event = ClassificationEvent(
                session_id=self.session_id,
                timestamp=datetime.now().isoformat() + "Z",
                src_ip=self.src_ip,
                commands=[cmd] if cmd else [],
                classification=decision["label"],
                confidence=decision.get("neural_confidence", 1.0),
                mitre_techniques=decision.get("mitre_tactics", []),
                features_used=xai_features
            )
            xai_decision = RoutingDecision(
                session_id=self.session_id,
                action=action,
                target="decoy" if action == "redirect_to_decoy" else ("blocked" if action == "drop_and_block" else "real_ssh"),
                reason=decision.get("rule", "SSH command classification")
            )
            
            explanation = xai_detector.generate_explanation(xai_event, xai_decision)
            
            event["xai_summary"] = explanation.summary
            event["xai_detailed"] = explanation.detailed
            event["xai_risk_score"] = explanation.risk_score
            event["xai_recommendations"] = explanation.recommended_actions
            
            # Push to the dashboard event queue asynchronously
            from interceptor.http_proxy import active_event_queue
            if active_event_queue is not None:
                asyncio.create_task(active_event_queue.put(event))
        except Exception as e:
            logger.error(f"XAI parsing failed for SSH: {e}")

        self.store.write_event(self.session_id, event)
        with open("./runtime/logs/threat_events.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

        if decision["action"] == "drop_and_block":
            self.nft.block_ip(self.src_ip, reason=decision.get("rule"))
            self.chan.close()


class AdaptiveSSHServer(asyncssh.SSHServer):
    def __init__(self, store: SessionStore, nft: NftablesManager, classifier, decoy_mgr: DecoyManager, config: Dict):
        self.store = store
        self.nft = nft
        self.classifier = classifier
        self.decoy_mgr = decoy_mgr
        self.config = config
        
        self.brute_force_threshold = int(config.get("brute_force_threshold", 20))
        self.real_host = config.get("real_service_host", "127.0.0.1")
        self.real_port = int(config.get("real_service_port", 2200))

    def connection_made(self, conn):
        self.conn = conn
        self.src_ip = conn.get_extra_info('peername')[0]
        self.session_id = self.store.get_or_create_session(self.src_ip)
        
        # Check if already blocked at L7
        blocked_until = self.store.get_blocked_until(self.src_ip)
        if blocked_until and blocked_until > time.time():
            self.conn.close()

    def password_auth_supported(self):
        return True
        
    def kbdint_auth_supported(self):
        return False

    async def validate_password(self, username, password):
        print(f"validate_password called for {username}")
        # 1. Check if IP is permanently flagged for Cowrie
        ctx = self.store._get_context(self.session_id)
        if ctx.get("ssh_flagged_for_decoy"):
            locked_password = ctx.get("ssh_locked_password")
            if locked_password == password:
                self.route_to_decoy = True
                self.auth_username = username
                self.auth_password = password
                print("Accepting password (routed to decoy)")
                return True
            else:
                print("Rejecting password (wrong locked password)")
                return False
                
        # 2. Try real backend
        try:
            self.real_conn = await asyncssh.connect(
                self.real_host, port=self.real_port,
                known_hosts=None, username=username, password=password
            )
            self.route_to_decoy = False
            self.auth_username = username
            self.auth_password = password
            print("Backend password auth succeeded!")
            
            # Reset failure count since auth succeeded
            ctx["ssh_login_attempts"] = 0
            self.store.conn.execute("UPDATE sessions SET context_json = ? WHERE id = ?", (json.dumps(ctx), self.session_id))
            self.store.conn.commit()
            
            return True
        except Exception as e:
            print(f"Backend password auth failed: {e}")
            attempts = self.store.increment_counter(self.session_id, "ssh_login_attempts")
            if attempts >= self.brute_force_threshold:
                print("Threshold reached, flagging IP for decoy")
                ctx["ssh_flagged_for_decoy"] = True
                ctx["ssh_locked_password"] = password
                self.store.conn.execute("UPDATE sessions SET context_json = ? WHERE id = ?", (json.dumps(ctx), self.session_id))
                self.store.conn.commit()
                
                # Trap the attacker by accepting the password that triggered the threshold!
                self.route_to_decoy = True
                self.auth_username = username
                self.auth_password = password
                return True
            return False

    def public_key_auth_supported(self):
        return True

    async def validate_public_key(self, username, key):
        print(f"validate_public_key called for {username}")
        ctx = self.store._get_context(self.session_id)
        if ctx.get("ssh_flagged_for_decoy"):
            self.route_to_decoy = True
            self.auth_username = username
            self.auth_password = "password" # Cowrie default
            return True
            
        allowed_keys_path = self.config.get("allowed_keys_path", "./config/authorized_keys")
        try:
            import os
            if os.path.exists(allowed_keys_path):
                with open(allowed_keys_path, "r") as f:
                    for line in f:
                        if not line.strip() or line.startswith('#'): continue
                        imported_key = asyncssh.import_public_key(line)
                        if key == imported_key:
                            # Valid key! Let's connect to real backend using proxy's key
                            try:
                                self.real_conn = await asyncssh.connect(
                                    self.real_host, port=self.real_port,
                                    known_hosts=None, username=username,
                                    client_keys=[self.config.get("server_key_path", "./config/ssh_host_rsa_key.key")]
                                )
                                self.route_to_decoy = False
                                self.auth_username = username
                                print("Backend key auth succeeded!")
                                
                                # Reset failure count since auth succeeded
                                ctx["ssh_login_attempts"] = 0
                                self.store.conn.execute("UPDATE sessions SET context_json = ? WHERE id = ?", (json.dumps(ctx), self.session_id))
                                self.store.conn.commit()
                                
                                return True
                            except Exception as e:
                                print(f"Proxy failed to auth to backend with its own key: {e}")
                                return False
        except Exception as e:
            print(f"Error checking public keys: {e}")

        # Failure
        attempts = self.store.increment_counter(self.session_id, "ssh_login_attempts")
        if attempts >= self.brute_force_threshold:
            ctx["ssh_flagged_for_decoy"] = True
            ctx["ssh_locked_password"] = "password"
            self.store.conn.execute("UPDATE sessions SET context_json = ? WHERE id = ?", (json.dumps(ctx), self.session_id))
            self.store.conn.commit()
            
            # Trap the attacker by accepting the key that triggered the threshold!
            self.route_to_decoy = True
            self.auth_username = username
            self.auth_password = "password"
            return True
        return False

    def session_requested(self):
        print(f"session_requested called, route_to_decoy: {getattr(self, 'route_to_decoy', False)}", flush=True)
        if hasattr(self, 'route_to_decoy'):
            if self.route_to_decoy:
                decoy = self.decoy_mgr.get_or_spawn_ssh_decoy(self.session_id)
                print(f"Decoy spawned: {decoy}", flush=True)
                if decoy:
                    return SSHGuardSession(
                        target_host="127.0.0.1", target_port=int(decoy.base_url),
                        session_id=self.session_id, src_ip=self.src_ip,
                        store=self.store, nft=self.nft, classifier=self.classifier,
                        decoy_mgr=self.decoy_mgr, is_decoy=True,
                        auth_username=getattr(self, 'auth_username', 'root'),
                        auth_password=getattr(self, 'auth_password', 'password')
                    )
            else:
                return SSHGuardSession(
                    target_host=self.real_host, target_port=self.real_port,
                    session_id=self.session_id, src_ip=self.src_ip,
                    store=self.store, nft=self.nft, classifier=self.classifier,
                    decoy_mgr=self.decoy_mgr, is_decoy=False,
                    auth_username=getattr(self, 'auth_username', 'root'),
                    auth_password=getattr(self, 'auth_password', 'password'),
                    real_conn=getattr(self, 'real_conn', None)
                )
        
        print("Rejecting session request because route_to_decoy is not set or decoy is None")
        self.conn.close()
        return None

async def start_ssh_proxy(config: Dict, store: SessionStore, nft: NftablesManager, classifier, decoy_mgr: DecoyManager):
    ssh_cfg = config.get("ssh_guard", {})
    if not ssh_cfg.get("enabled", False):
        return
        
    port = int(ssh_cfg.get("listen_port", 22))
    server_key = ssh_cfg.get("server_key_path", "./config/ssh_host_rsa_key.key")
    
    def server_factory():
        return AdaptiveSSHServer(store, nft, classifier, decoy_mgr, ssh_cfg)

    await asyncssh.create_server(
        server_factory, '', port,
        server_host_keys=[server_key]
    )
    logger.info(f"SSH Guard listening on port {port}")
