import logging
import pickle
import re
from pathlib import Path
from urllib.parse import unquote_plus as unquote

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CLASS_NAMES = ['Safe', 'Recon', 'Downloader', 'Exploit', 'Destructive', 'ADVANCED_APT']
CLASS_DESCRIPTIONS = {
    0: "Normal/benign session",
    1: "Reconnaissance - scanning/enum",
    2: "Downloader - malware dropper",
    3: "Exploit - credential theft, RAT",
    4: "Destructive - data wipe, ransomware",
    5: "ADVANCED_APT - multi-stage persistent threat",
}

CONFIDENCE_THRESHOLD = 0.55  # Below this, fall back to MITRE rules

MITRE_FEATURE_COLS = [
    'mitre_tactic_reconnaissance', 'mitre_tactic_resource_development',
    'mitre_tactic_initial_access', 'mitre_tactic_execution',
    'mitre_tactic_persistence', 'mitre_tactic_privilege_escalation',
    'mitre_tactic_defense_evasion', 'mitre_tactic_credential_access',
    'mitre_tactic_discovery', 'mitre_tactic_lateral_movement',
    'mitre_tactic_collection', 'mitre_tactic_command_and_control',
    'mitre_tactic_exfiltration', 'mitre_tactic_impact',
    'mitre_severity_max', 'mitre_severity_mean', 'mitre_severity_weighted',
    'mitre_kill_chain_score', 'mitre_unique_technique_count',
    'mitre_total_commands', 'mitre_matched_commands'
]

# ---------------------------------------------------------------------------
# HTTP attack pre-filter patterns (fast regex check before neural model)
# ---------------------------------------------------------------------------

HTTP_ATTACK_PATTERNS = {
    "xss": [
        r"<script[^>]*>",
        r"javascript:",
        r"on\w+\s*=",
        r"<img[^>]+onerror",
        r"<svg[^>]+onload",
        r"alert\s*\(",
        r"document\.cookie",
    ],
    "sqli": [
        r"'\s*(or|and)\s+['\d\w]+\s*=\s*['\d\w]+",
        r"union\s+select",
        r"select\s+.+\s+from",
        r"drop\s+table",
        r"--\s*$",
        r"/\*.*\*/",
    ],
    "path_traversal": [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"/etc/passwd",
        r"windows/system32",
    ],
    "command_injection": [
        r"[;&|`]\s*(whoami|id|uname|cat|ls|bash|sh)",
        r"\$\([^)]+\)",
        r"`[^`]+`",
    ],
    "scanner": [
        r"sqlmap",
        r"nikto",
        r"nmap",
        r"dirbuster",
        r"gobuster",
        r"wfuzz",
        r"burp",
    ],
}


def _match_http_patterns(payload):
    findings = []
    text = (payload or "").lower()
    for category, patterns in HTTP_ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text):
                findings.append(category)
                break
    return findings


# ---------------------------------------------------------------------------
# Legacy sklearn model helpers (DEPRECATED - kept for reference only)
# ---------------------------------------------------------------------------

# These functions are deprecated and not used in the current pipeline.
# The modern pipeline uses UnifiedThreatClassifier (BiLSTM + structured features).
# Kept for historical reference only.

def load_model(model_path, vectorizer_path):
    """DEPRECATED: Load legacy sklearn model."""
    import warnings
    warnings.warn("load_model() is deprecated. Use UnifiedThreatClassifier instead.", DeprecationWarning)
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    with open(vectorizer_path, 'rb') as f:
        vectorizer = pickle.load(f)
    return model, vectorizer


def predict_intent(model, vectorizer, commands, class_labels):
    """DEPRECATED: Predict with legacy sklearn model."""
    import warnings
    warnings.warn("predict_intent() is deprecated. Use UnifiedThreatClassifier instead.", DeprecationWarning)
    if not commands:
        return {
            "label": "Safe",
            "confidence": 0.0,
        }
    X = vectorizer.transform(commands)
    probs = model.predict_proba(X)
    mean_probs = probs.mean(axis=0)
    idx = int(mean_probs.argmax())
    label = class_labels[idx]
    confidence = float(mean_probs[idx])
    return {
        "label": label,
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
# Neural model loading
# ---------------------------------------------------------------------------

# Removed global model state - now managed via FastAPI app.state
# See src/interceptor/http_proxy.py create_http_guard_app() for initialization


def _encode_batch(texts, max_length=512):
    """Inline character-level tokenizer (same logic as CommandTokenizer)."""
    encoded = []
    for text in texts:
        indices = []
        for char in text[:max_length]:
            code = ord(char)
            indices.append(code if code < 256 else 1)  # 1 = UNK
        encoded.append(indices)

    lengths = [len(seq) for seq in encoded]
    max_len = min(max(lengths) if lengths else 1, max_length)
    padded = []
    for seq in encoded:
        if len(seq) < max_len:
            seq = seq + [0] * (max_len - len(seq))
        padded.append(seq[:max_len])

    import torch
    return (
        torch.tensor(padded, dtype=torch.long),
        torch.tensor([min(l, max_len) for l in lengths], dtype=torch.long),
    )


def load_neural_model():
    """Load the neural model from .pt state dict.

    We reconstruct the model architecture and load the weights.

    Returns the loaded model if successful, None otherwise.
    """
    try:
        import torch
        from training.neural.model import UnifiedThreatClassifier
    except ImportError as exc:
        logger.warning("PyTorch or model module not available: %s", exc)
        return None

    # Load config to get the dynamically set model path
    import yaml
    config_path = Path(__file__).parent.parent.parent / "config" / "settings.yaml"
    model_path_str = "models/brain_v6_unified.pt" # Fallback
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
            model_path_str = config.get("ml", {}).get("neural_v6_model_path", model_path_str)
    except Exception as e:
        logger.warning("Could not read settings.yaml, using default neural model path. Error: %s", e)

    # Locate the model file
    model_path = Path(__file__).parent.parent.parent / model_path_str.strip("./")

    if not model_path.exists():
        logger.warning("Neural model not found at %s", model_path)
        return None

    try:
        device = "cuda" if torch.cuda.is_available() else "cpu"
        checkpoint = torch.load(model_path, map_location=device, weights_only=False)
        model = UnifiedThreatClassifier()
        model.load_state_dict(checkpoint["model_state_dict"])
        model.eval()
        model.to(device)

        param_count = sum(p.numel() for p in model.parameters())
        logger.info(
            "Neural model loaded: UnifiedThreatClassifier (%s params)", f"{param_count:,}"
        )
        return model
    except Exception:
        logger.exception("Failed to load neural model")
        return None


def get_neural_model():
    """Backward compatibility - returns the globally loaded model if available.
    
    NOTE: This is deprecated. Use app.state.neural_model instead.
    """
    # We don't maintain global state anymore - return None to signal
    # that the caller should use app.state.neural_model
    return None


# ---------------------------------------------------------------------------
# MITRE feature extraction for neural model
# ---------------------------------------------------------------------------

def _extract_mitre_features(commands: str):
    """Extract 21-dim MITRE feature vector from a command string.

    This mirrors the feature extraction used during model training.
    """
    from core.mitre.session_annotator import annotate_session, annotation_to_flat_dict

    cmd_list = [c.strip() for c in commands.replace("&&", ";").replace("||", ";").replace("\\n", ";").split(";") if c.strip()]
    if not cmd_list:
        cmd_list = [commands]

    annotation = annotate_session(cmd_list)
    flat = annotation_to_flat_dict(annotation)

    return [flat.get(col, 0.0) for col in MITRE_FEATURE_COLS]


def _classify_neural(
    commands: str,
    neural_model,
    is_http: bool = False,
    triage_features: list = None,
):
    """Run neural inference using UnifiedThreatClassifier.

    Args:
        commands: The command/payload string to classify.
        neural_model: The loaded UnifiedThreatClassifier model (from app.state).
        is_http: Whether this is an HTTP request.
        triage_features: Optional list of 12 floats from
            static_analyzer. When provided, the triage
            modality is unmasked so the model can use
            binary analysis features for re-classification.
    """
    if neural_model is None:
        return None

    import torch

    # Tokenize
    encoded, lengths = _encode_batch([commands])

    # 1. MITRE features
    mitre_features = _extract_mitre_features(commands)
    mitre = torch.tensor(
        [mitre_features], dtype=torch.float32
    )

    # 2. Changes (21 dim: 20 system + 1 protocol flag)
    changes = torch.zeros((1, 21), dtype=torch.float32)
    changes[0, 20] = 1.0 if is_http else 0.0

    # 3. Triage (70 dim)
    triage = torch.zeros((1, 70), dtype=torch.float32)
    triage_masked = True
    if triage_features is not None and len(triage_features) >= 12:
        triage[0, :12] = torch.tensor(
            triage_features[:12], dtype=torch.float32
        )
        triage_masked = False

    # 4. Modality Mask (True = missing/masked)
    # [cmd, mitre, changes, triage]
    modality_mask = torch.tensor(
        [[False, False, not is_http, triage_masked]],
        dtype=torch.bool,
    )

    # Inference
    with torch.no_grad():
        predictions, probabilities = neural_model.predict(
            encoded, mitre, changes,
            triage, lengths, modality_mask,
        )

    pred_class = predictions[0].item()
    probs = probabilities[0].cpu().numpy()
    confidence = float(probs[pred_class])

    return (
        pred_class,
        CLASS_NAMES[pred_class],
        confidence,
        {
            CLASS_NAMES[i]: float(probs[i])
            for i in range(len(CLASS_NAMES))
        },
    )


# ---------------------------------------------------------------------------
# Main HTTP classification entry point
# ---------------------------------------------------------------------------

def classify_http_request(
    hybrid_classifier,
    request_context,
    command_history: str = "",
    neural_model=None,
    triage_features: list = None,
):
    """Classify an HTTP request using multi-stage pipeline.

    Pipeline:
    1. Fast regex pre-filter for obvious attacks
    2. Neural BiLSTM model (if loaded) with confidence
    3. MITRE rule-based HybridClassifierV2 fallback

    Args:
        triage_features: Optional 12 floats from
            static_analyzer for binary-enriched
            re-classification.

    request_context keys:
      - method, path, query, body, headers, source_ip

    Returns a dict with threat label, action, explanation.
    """
    method = (request_context.get("method") or "GET").upper()
    path = request_context.get("path") or "/"
    query = request_context.get("query") or ""
    body = request_context.get("body") or ""
    headers = request_context.get("headers") or {}
    source_ip = request_context.get("source_ip") or "unknown"

    user_agent = str(headers.get("user-agent", ""))

    # --- Build the synthetic command (Raw HTTP Format) ---
    # The neural model was trained on full HTTP requests in synthetic_batches.csv,
    # so we must reconstruct the raw HTTP envelope (Method + Path + Headers + Body).
    
    full_path = path
    if query:
        full_path += f"?{query}"
        
    raw_request = f"{method} {full_path} HTTP/1.1\n"
    
    # Append headers
    for k, v in headers.items():
        # Title-case the header keys for standard formatting (e.g., user-agent -> User-Agent)
        raw_request += f"{k.title()}: {v}\n"
        
    # Append body if present
    if body:
        raw_request += f"\n{unquote(body)}"
        
    synthetic_cmd = raw_request.strip()

    # Clean HTTP boilerplate to isolate the context
    import re
    synthetic_cmd = re.sub(r'^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+', '', synthetic_cmd)
    synthetic_cmd = re.sub(r'\s+HTTP/1\.[01]', '', synthetic_cmd)

    # Combine history with current command for context-aware classification
    full_command = f"{command_history}\n\n{synthetic_cmd}".strip() if command_history else synthetic_cmd

    # Run MITRE rules classification first to get rule_id, rule_label, and explanation
    rule_id, rule_label, explanation = hybrid_classifier.classify(full_command)
    http_findings = [] # Regex removed

    # --- Stage 2: Neural model with confidence thresholding ---
    neural_result = _classify_neural(
        full_command,
        neural_model,
        is_http=True,
        triage_features=triage_features,
    ) if neural_model is not None else None

    if neural_result is not None:
        pred_id, label, confidence, probs = neural_result

        if confidence >= CONFIDENCE_THRESHOLD:
            # Check for safeguard override
            if rule_id > pred_id:
                logger.info(
                    "Safeguard override: Neural predicted '%s' (conf=%.2f%%) but rules detected '%s'. Overriding to rules.",
                    label, confidence * 100, rule_label
                )
                pred_id, label, confidence = rule_id, rule_label, 1.0
                rule_name = explanation.get("rule_matched")
            else:
                rule_name = f"neural_model (confidence={confidence:.2%})"

            if label == "Safe":
                action = "forward"
            elif label == "Recon":
                action = "forward_and_log"
            elif label in ("Downloader", "Exploit"):
                action = "redirect_to_decoy"
            else:
                action = "drop_and_block"

            result = {
                "class_id": pred_id,
                "label": label,
                "confidence": confidence,
                "action": action,
                "rule": rule_name,
                "mitre_tactics": explanation.get("mitre_tactics", []),
                "severity_max": explanation.get("severity_max", 0),
                "http_findings": http_findings,
                "neural_confidence": neural_result[2],
                "neural_probs": probs,
                "extracted_command": synthetic_cmd,
            }
            
            # Deep XAI Integration
            from agents.xai import AdaptiveXAINarrator
            from interfaces.xai_contract import ClassificationEvent, RoutingDecision
            
            xai_event = ClassificationEvent(
                session_id=request_context.get("session_id", "unknown"),
                timestamp="now",
                src_ip=source_ip,
                commands=[synthetic_cmd],
                classification=label,
                confidence=confidence,
                mitre_techniques=result["mitre_tactics"],
                features_used={"rule": rule_name}
            )
            xai_decision = RoutingDecision(
                session_id=request_context.get("session_id", "unknown"),
                action=action,
                target="decoy" if action == "redirect_to_decoy" else ("drop" if action == "drop_and_block" else "upstream"),
                reason=rule_name
            )
            narrator = AdaptiveXAINarrator()
            xai_explanation = narrator.generate_explanation(xai_event, xai_decision)
            
            result["xai_summary"] = xai_explanation.summary
            result["xai_detailed"] = xai_explanation.detailed
            result["xai_risk_score"] = xai_explanation.risk_score
            result["xai_recommendations"] = xai_explanation.recommended_actions
            
            return result
        else:
            # Low confidence — fall through to MITRE rules
            logger.debug(
                "Neural confidence %.2f%% < threshold %.0f%%, falling back to MITRE rules",
                confidence * 100, CONFIDENCE_THRESHOLD * 100
            )

    # --- Stage 3: MITRE rule-based fallback ---
    if rule_label == "Safe":
        action = "forward"
    elif rule_label == "Recon":
        action = "forward_and_log"
    elif rule_label in ("Downloader", "Exploit"):
        action = "redirect_to_decoy"
    else:
        action = "drop_and_block"

    result = {
        "class_id": rule_id,
        "label": rule_label,
        "confidence": 1.0,
        "action": action,
        "rule": explanation.get("rule_matched"),
        "mitre_tactics": explanation.get("mitre_tactics", []),
        "severity_max": explanation.get("severity_max", 0),
        "http_findings": http_findings,
    }

    # Annotate with neural fallback info if neural model was attempted but low-confidence
    if neural_result is not None:
        _, _, neural_conf, neural_probs = neural_result
        result["neural_confidence"] = neural_conf
        result["neural_probs"] = neural_probs
        result["fallback_reason"] = f"Neural confidence {neural_conf:.1%} < threshold {CONFIDENCE_THRESHOLD:.0%}"

    result["extracted_command"] = synthetic_cmd
    
    # Deep XAI Integration for Fallback
    from agents.xai import AdaptiveXAINarrator
    from interfaces.xai_contract import ClassificationEvent, RoutingDecision
    
    xai_event = ClassificationEvent(
        session_id=request_context.get("session_id", "unknown"),
        timestamp="now",
        src_ip=source_ip,
        commands=[synthetic_cmd],
        classification=rule_label,
        confidence=1.0,
        mitre_techniques=result["mitre_tactics"],
        features_used={"rule": result["rule"]}
    )
    xai_decision = RoutingDecision(
        session_id=request_context.get("session_id", "unknown"),
        action=action,
        target="decoy" if action == "redirect_to_decoy" else ("drop" if action == "drop_and_block" else "upstream"),
        reason=result["rule"]
    )
    narrator = AdaptiveXAINarrator()
    xai_explanation = narrator.generate_explanation(xai_event, xai_decision)
    
    result["xai_summary"] = xai_explanation.summary
    result["xai_detailed"] = xai_explanation.detailed
    result["xai_risk_score"] = xai_explanation.risk_score
    result["xai_recommendations"] = xai_explanation.recommended_actions
    
    return result


# ---------------------------------------------------------------------------
# SSH Guard Integration
# ---------------------------------------------------------------------------

def classify_ssh_command(
    hybrid_classifier,
    command: str,
    context: dict,
    neural_model=None,
    triage_features: list = None,
) -> dict:
    """Evaluate an SSH command for threats.

    Args:
        triage_features: Optional 12 floats from
            static_analyzer for binary-enriched
            re-classification.
    """
    if not command.strip():
        return {
            "class_id": 0,
            "label": "Safe",
            "confidence": 1.0,
            "action": "forward",
            "rule": "Empty command",
            "mitre_tactics": [],
            "severity_max": 0,
        }

    # Run MITRE rules classification
    rule_id, rule_label, explanation = (
        hybrid_classifier.classify(command)
    )

    # Stage 2: Neural Inference
    neural_result = _classify_neural(
        command,
        neural_model,
        triage_features=triage_features,
    ) if neural_model is not None else None

    if neural_result is not None:
        pred_id, label, confidence, probs = neural_result
        if confidence >= CONFIDENCE_THRESHOLD:
            # Check for safeguard override
            if rule_id > pred_id:
                logger.info(
                    "Safeguard override (SSH): Neural predicted '%s' (conf=%.2f%%) but rules detected '%s'. Overriding to rules.",
                    label, confidence * 100, rule_label
                )
                pred_id, label, confidence = rule_id, rule_label, 1.0
                rule_name = explanation.get("rule_matched")
            else:
                rule_name = f"neural_model (confidence={confidence:.2%})"

            # Mirror HTTP behavior: let Exploit/Downloader continue inside the decoy
            if label == "Safe":
                action = "forward"
            elif label == "Recon":
                action = "forward_and_log"
            elif label in ("Exploit", "Downloader"):
                action = "redirect_to_decoy"
            else:
                action = "drop_and_block"

            result = {
                "class_id": pred_id,
                "label": label,
                "confidence": confidence,
                "action": action,
                "rule": rule_name,
                "mitre_tactics": explanation.get("mitre_tactics", []),
                "severity_max": explanation.get("severity_max", 0),
                "neural_confidence": neural_result[2],
                "neural_probs": probs,
            }
            
            # Deep XAI Integration
            from agents.xai import AdaptiveXAINarrator
            from interfaces.xai_contract import ClassificationEvent, RoutingDecision
            
            xai_event = ClassificationEvent(
                session_id=context.get("session_id", "unknown"),
                timestamp="now",
                src_ip=context.get("source_ip", "unknown"),
                commands=[command],
                classification=label,
                confidence=confidence,
                mitre_techniques=result["mitre_tactics"],
                features_used={"rule": rule_name}
            )
            xai_decision = RoutingDecision(
                session_id=context.get("session_id", "unknown"),
                action=action,
                target="decoy" if action == "redirect_to_decoy" else ("drop" if action == "drop_and_block" else "upstream"),
                reason=rule_name
            )
            narrator = AdaptiveXAINarrator()
            xai_explanation = narrator.generate_explanation(xai_event, xai_decision)
            
            result["xai_summary"] = xai_explanation.summary
            result["xai_detailed"] = xai_explanation.detailed
            result["xai_risk_score"] = xai_explanation.risk_score
            result["xai_recommendations"] = xai_explanation.recommended_actions
            
            return result

    # Stage 3: MITRE Fallback
    if rule_label == "Safe":
        action = "forward"
    elif rule_label == "Recon":
        action = "forward_and_log"
    elif rule_label in ("Exploit", "Downloader"):
        action = "redirect_to_decoy"
    else:
        action = "drop_and_block"

    result = {
        "class_id": rule_id,
        "label": rule_label,
        "confidence": 1.0,
        "action": action,
        "rule": explanation.get("rule_matched"),
        "mitre_tactics": explanation.get("mitre_tactics", []),
        "severity_max": explanation.get("severity_max", 0),
    }

    if neural_result is not None:
        _, _, neural_conf, neural_probs = neural_result
        result["neural_confidence"] = neural_conf
        result["neural_probs"] = neural_probs
        result["fallback_reason"] = f"Neural confidence {neural_conf:.1%} < threshold {CONFIDENCE_THRESHOLD:.0%}"

    # Deep XAI Integration for Fallback
    from agents.xai import AdaptiveXAINarrator
    from interfaces.xai_contract import ClassificationEvent, RoutingDecision
    
    xai_event = ClassificationEvent(
        session_id=context.get("session_id", "unknown"),
        timestamp="now",
        src_ip=context.get("source_ip", "unknown"),
        commands=[command],
        classification=rule_label,
        confidence=1.0,
        mitre_techniques=result["mitre_tactics"],
        features_used={"rule": result["rule"]}
    )
    xai_decision = RoutingDecision(
        session_id=context.get("session_id", "unknown"),
        action=action,
        target="decoy" if action == "redirect_to_decoy" else ("drop" if action == "drop_and_block" else "upstream"),
        reason=result["rule"]
    )
    narrator = AdaptiveXAINarrator()
    xai_explanation = narrator.generate_explanation(xai_event, xai_decision)
    
    result["xai_summary"] = xai_explanation.summary
    result["xai_detailed"] = xai_explanation.detailed
    result["xai_risk_score"] = xai_explanation.risk_score
    result["xai_recommendations"] = xai_explanation.recommended_actions

    return result

# ---------------------------------------------------------------------------
# Factory: build classifiers at startup
# ---------------------------------------------------------------------------

def build_hybrid_classifier():
    """Factory to build HybridClassifierV2.

    Keeps setup in one place so orchestrator/API can use it directly.
    Neural model loading is now handled at FastAPI app startup via lifespan.
    """
    try:
        from training.neural.hybrid_classifier_v2 import HybridClassifierV2

        return HybridClassifierV2()
    except Exception:
        logger.warning("HybridClassifierV2 unavailable — using fallback classifier")
        return _FallbackHybridClassifier()


class _FallbackHybridClassifier:
    """Fallback classifier when full HybridClassifierV2 dependencies are unavailable."""

    def classify(self, commands):
        text = (commands or "").lower()

        if "rm -rf /" in text:
            return 4, "Destructive", {"rule_matched": "fallback destructive", "mitre_tactics": ["impact"], "severity_max": 9}
        if "wget" in text or "curl" in text:
            return 2, "Downloader", {"rule_matched": "fallback downloader", "mitre_tactics": ["command_and_control"], "severity_max": 7}
        if "nmap" in text or "netstat" in text:
            return 1, "Recon", {"rule_matched": "fallback recon", "mitre_tactics": ["discovery"], "severity_max": 5}

        return 0, "Safe", {"rule_matched": "fallback safe", "mitre_tactics": [], "severity_max": 1}
