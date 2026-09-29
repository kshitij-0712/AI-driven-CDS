"""
Triage Watcher — monitors decoy download directories for dropped binaries.

When an attacker downloads a file inside a decoy container (e.g., Cowrie),
this watcher detects it, runs static analysis, updates the session's neural
features, and re-triggers the Deception Agent (LLM) to dynamically regenerate
the decoy environment based on the new malware intelligence.
"""

import asyncio
import json
import logging
import os
import threading
import time
from typing import Dict, Optional, Any

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from interceptor.session_store import SessionStore
from core.malware.static_analyzer import analyze_binary
from agents.decision import classify_ssh_command

logger = logging.getLogger(__name__)


def map_to_triage_features(result: dict) -> list[float]:
    """Map static_analyzer output dict to the 12 neural features."""
    fi = result.get("format_info", {})
    cl = result.get("classification", {})
    scores = cl.get("scores", {})

    features = [
        float(result.get("file_size", 0)),
        float(result.get("overall_entropy", 0.0)),
        float(result.get("analysis_priority", 0)),
        1.0 if fi.get("is_go_binary") else 0.0,
        1.0 if fi.get("is_upx_packed") else 0.0,
        1.0 if fi.get("is_stripped", True) else 0.0,
        1.0 if fi.get("is_dll") else 0.0,
        1.0 if fi.get("linkage") == "static" else 0.0,
        float(scores.get("miner", 0)),
        float(scores.get("botnet_dropper", 0)),
        float(scores.get("recon_scanner", 0)),
        float(scores.get("destructive", 0)),
    ]
    return features


class DecoyDownloadHandler(FileSystemEventHandler):
    def __init__(
        self,
        store: SessionStore,
        classifier: Any,
        builder: Any,
        decoy_mgr: Any
    ):
        self.store = store
        self.classifier = classifier
        self.builder = builder
        self.decoy_mgr = decoy_mgr
        self._loop = asyncio.new_event_loop()
        
        # Start background event loop for async builder calls
        def run_loop():
            asyncio.set_event_loop(self._loop)
            self._loop.run_forever()
            
        t = threading.Thread(target=run_loop, daemon=True)
        t.start()

    def on_created(self, event):
        print(f"[TRIAGE WATCHER] FileCreatedEvent detected: {event.src_path}", flush=True)
        if event.is_directory:
            return
        
        filepath = event.src_path
        # Expected path format: .../runtime/decoy_ssh/<session_id>/downloads/<file>
        parts = filepath.split(os.sep)
        if "downloads" not in parts:
            return
            
        try:
            dl_idx = parts.index("downloads")
            dir_session = parts[dl_idx - 1]
        except ValueError:
            return

        # Resolve the actual session_id in case this is a claimed prewarm container
        session_id = dir_session
        base_dir = os.sep.join(parts[:dl_idx])
        sid_file = os.path.join(base_dir, "session_id.txt")
        if os.path.exists(sid_file):
            try:
                with open(sid_file, "r") as f:
                    content = f.read().strip()
                    if content:
                        session_id = content
            except Exception:
                pass

        logger.info(f"New binary dropped in decoy (session: {session_id}): {filepath}")
        
        # Wait a moment for the download to finish writing
        time.sleep(1.0)
        
        try:
            self._process_binary(session_id, filepath)
        except Exception:
            logger.exception(f"Failed to process dropped binary: {filepath}")

    def _process_binary(self, session_id: str, filepath: str):
        # 1. Analyze
        result = analyze_binary(filepath)
        features = map_to_triage_features(result)
        logger.info(f"Triage features extracted for {session_id}: entropy={features[1]:.2f}")

        # 2. Update session store
        self.store.update_context(session_id, {"triage_features": features})

        # 3. Re-classify the session history using the new triage features
        history = self.store.get_command_history(session_id)
        if not history:
            return

        # Fetch IP from session store to build context
        cur = self.store.conn.cursor()
        cur.execute("SELECT src_ip FROM sessions WHERE id = ?", (session_id,))
        row = cur.fetchone()
        src_ip = row[0] if row else "unknown"

        context = {
            "source_ip": src_ip,
            "session_id": session_id,
            "protocol": "ssh",
        }

        decision = classify_ssh_command(
            self.classifier,
            history,
            context,
            triage_features=features
        )
        decision["triage_enriched"] = True

        logger.info(
            f"Session {session_id} re-classified with malware features: "
            f"{decision['label']} (Conf: {decision.get('confidence', 1.0):.2f})"
        )

        event = {
            "timestamp": time.time(),
            "session_id": session_id,
            "source_ip": src_ip,
            "protocol": "ssh",
            "command": "TRIAGE_RECLASSIFICATION",
            "label": decision["label"],
            "action": decision["action"],
            "rule": decision.get("rule"),
            "mitre_tactics": decision.get("mitre_tactics", []),
            "severity_max": decision.get("severity_max", 0),
            "is_reclassification": True,
            "triage_features": features
        }
        if "neural_confidence" in decision:
            event["neural_confidence"] = decision["neural_confidence"]
            
        self.store.write_event(session_id, event)
        with open("./runtime/logs/threat_events.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")


        # 4. Trigger the LLM Deception Agent to regenerate the environment
        # We need the cowrie_base_dir and container_id
        decoy = self.decoy_mgr.get_or_spawn_ssh_decoy(session_id)
        if decoy:
            logger.info(f"Regenerating decoy files for {session_id} using LLM...")
            # We schedule this into our dedicated event loop
            asyncio.run_coroutine_threadsafe(
                self.builder.prepare_decoy_files(
                    session_id,
                    decision,
                    decoy.host_dir,
                    decoy.container_id,
                    self.decoy_mgr
                ),
                self._loop
            )


class TriageWatcher:
    def __init__(
        self,
        watch_dir: str,
        store: SessionStore,
        classifier: Any,
        builder: Any,
        decoy_mgr: Any
    ):
        self.watch_dir = watch_dir
        self.observer = Observer()
        self.handler = DecoyDownloadHandler(store, classifier, builder, decoy_mgr)
        
    def start(self):
        os.makedirs(self.watch_dir, exist_ok=True)
        self.observer.schedule(self.handler, self.watch_dir, recursive=True)
        self.observer.start()
        logger.info(f"Triage watcher started on {self.watch_dir}")

    def stop(self):
        self.observer.stop()
        self.observer.join()
