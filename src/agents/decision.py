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
# Legacy sklearn model helpers (kept for backward compatibility)
# ---------------------------------------------------------------------------

def load_model(model_path, vectorizer_path):
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    with open(vectorizer_path, 'rb') as f:
        vectorizer = pickle.load(f)
    return model, vectorizer


def predict_intent(model, vectorizer, commands, class_labels):
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

_neural_model = None
_neural_tokenizer = None
_neural_device = "cpu"
_neural_loaded = False


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
    """Load the ThreatClassifierMitreOnly neural model from .pt state dict.

    The model was trained on the train_1 branch and saved as a state_dict + config.
    We reconstruct the model architecture and load the weights.

    Returns True if successfully loaded, False otherwise.
    """
    global _neural_model, _neural_tokenizer, _neural_device, _neural_loaded

    if _neural_loaded:
        return _neural_model is not None

    _neural_loaded = True  # Mark as attempted regardless of outcome

    try:
        import torch
        from training.neural.model import ThreatClassifierMitreOnly
    except ImportError as exc:
        logger.warning("PyTorch or model module not available: %s", exc)
        return False

    # Locate the model file
    model_dir = Path(__file__).parent.parent.parent / "models"
    model_path = model_dir / "brain_v5_mitre_only_semantic_balanced_v2.pt"

    if not model_path.exists():
        logger.warning("Neural model not found at %s", model_path)
        return False

    try:
        checkpoint = torch.load(model_path, map_location="cpu", weights_only=False)
        config = checkpoint["model_config"]

        # Remove 'model_type' key — it's metadata, not a constructor arg
        constructor_args = {k: v for k, v in config.items() if k != "model_type"}
        model = ThreatClassifierMitreOnly(**constructor_args)
        model.load_state_dict(checkpoint["model_state_dict"])
        model.eval()

        _neural_model = model
        _neural_device = "cpu"

        param_count = sum(p.numel() for p in model.parameters())
        logger.info(
            "Neural model loaded: ThreatClassifierMitreOnly (%s params)", f"{param_count:,}"
        )
        return True
    except Exception:
        logger.exception("Failed to load neural model")
        return False


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


def _classify_neural(commands: str):
    """Run neural inference on a command string.

    Returns (class_id, label, confidence, probabilities) or None if model unavailable.
    """
    if _neural_model is None:
        return None

    import torch

    # Tokenize
    encoded, lengths = _encode_batch([commands])

    # MITRE features
    mitre_features = _extract_mitre_features(commands)
    structured = torch.tensor([mitre_features], dtype=torch.float32)

    # Inference
    with torch.no_grad():
        predictions, probabilities = _neural_model.predict(encoded, structured, lengths)

    pred_class = predictions[0].item()
    probs = probabilities[0].cpu().numpy()
    confidence = float(probs[pred_class])

    return pred_class, CLASS_NAMES[pred_class], confidence, {CLASS_NAMES[i]: float(probs[i]) for i in range(len(CLASS_NAMES))}


# ---------------------------------------------------------------------------
# Main HTTP classification entry point
# ---------------------------------------------------------------------------

def classify_http_request(hybrid_classifier, request_context, command_history: str = "", neural_model_loaded=None):
    """Classify an HTTP request context using a multi-stage pipeline.

    Pipeline:
    1. Fast regex pre-filter for obvious attacks (XSS, SQLi, etc.)
    2. Neural BiLSTM model (if loaded) with confidence thresholding
    3. MITRE rule-based HybridClassifierV2 fallback

    request_context keys:
      - method, path, query, body, headers (dict), source_ip

    Returns a dict with threat label, action, and explanation.
    """
    method = (request_context.get("method") or "GET").upper()
    path = request_context.get("path") or "/"
    query = request_context.get("query") or ""
    body = request_context.get("body") or ""
    headers = request_context.get("headers") or {}
    source_ip = request_context.get("source_ip") or "unknown"

    user_agent = str(headers.get("user-agent", ""))

    # --- Build the synthetic command (URL-decoded) ---
    # Extract just the values from query/body params (strip keys like cmd=, q=, file=)
    # The neural model was trained on raw commands, not HTTP query strings.
    extracted_values = []
    
    for payload in (query, body):
        if not payload:
            continue
        decoded = unquote(payload)
        for param in decoded.split("&"):
            if "=" in param:
                extracted_values.append(param.split("=", 1)[1])
            else:
                if param.strip():
                    extracted_values.append(param)
                    
    synthetic_cmd = " ".join(extracted_values).strip()
    if not synthetic_cmd:
        synthetic_cmd = unquote(path)

    # Combine history with current command for context-aware classification
    full_command = f"{command_history}; {synthetic_cmd}".strip("; ") if command_history else synthetic_cmd

    # Run MITRE rules classification first to get rule_id, rule_label, and explanation
    rule_id, rule_label, explanation = hybrid_classifier.classify(full_command)

    # --- Stage 1: Fast regex pre-filter ---
    joined_payload = " ".join([path, query, body, user_agent])
    joined_payload = unquote(joined_payload)
    http_findings = _match_http_patterns(joined_payload)

    # Check path specifically for scanner and sensitive file discovery patterns
    decoded_path = unquote(path).lower()
    if re.search(r"^/(admin|dev-admin|config|setup|backup|wp-)", decoded_path):
        http_findings.append("scanner")
    if re.search(r"(\.env|\.git)", decoded_path):
        http_findings.append("sensitive_file_discovery")

    stage1_id = None
    if "xss" in http_findings or "sqli" in http_findings or "command_injection" in http_findings:
        stage1_id, stage1_label, stage1_action = 3, "Exploit", "redirect_to_decoy"
        stage1_rule = "HTTP exploit pattern matched"
        stage1_tactics = ["execution", "initial_access"]
        stage1_severity = 9
    elif "path_traversal" in http_findings or "scanner" in http_findings or "sensitive_file_discovery" in http_findings:
        stage1_id, stage1_label, stage1_action = 1, "Recon", "forward_and_log"
        stage1_rule = "HTTP reconnaissance pattern matched"
        stage1_tactics = ["reconnaissance", "discovery"]
        stage1_severity = 6

    if stage1_id is not None:
        # Check if rules found a higher severity threat than Stage 1 pre-filter
        if rule_id > stage1_id:
            logger.info(
                "Safeguard override (Stage 1): Stage 1 matched '%s' but rules detected '%s'. Overriding to rules.",
                stage1_label, rule_label
            )
            # Fall through to rules result
        else:
            return {
                "class_id": stage1_id,
                "label": stage1_label,
                "confidence": 1.0,
                "action": stage1_action,
                "rule": stage1_rule,
                "mitre_tactics": stage1_tactics,
                "severity_max": stage1_severity,
                "http_findings": http_findings,
                "extracted_command": synthetic_cmd,
            }

    # --- Stage 2: Neural model with confidence thresholding ---
    neural_result = _classify_neural(full_command) if _neural_model is not None else None

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

            return {
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
    return result


# ---------------------------------------------------------------------------
# SSH Guard Integration
# ---------------------------------------------------------------------------

def classify_ssh_command(hybrid_classifier, command: str, context: dict) -> dict:
    """Evaluate an SSH command for threats.
    Expects `command` to be the full session context if available.
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

    # Run MITRE rules classification first to get rule_id, rule_label, and explanation
    rule_id, rule_label, explanation = hybrid_classifier.classify(command)

    # Stage 2: Neural Inference
    neural_result = _classify_neural(command) if _neural_model is not None else None

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

            # We don't have redirect_to_decoy mid-session for SSH, so we drop_and_block for exploits too.
            if label == "Safe":
                action = "forward"
            elif label == "Recon":
                action = "forward_and_log"
            else:
                action = "drop_and_block"

            return {
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

    # Stage 3: MITRE Fallback
    if rule_label == "Safe":
        action = "forward"
    elif rule_label == "Recon":
        action = "forward_and_log"
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

    return result

# ---------------------------------------------------------------------------
# Factory: build classifiers at startup
# ---------------------------------------------------------------------------

def build_hybrid_classifier():
    """Factory to build HybridClassifierV2.

    Keeps setup in one place so orchestrator/API can use it directly.
    Also attempts to load the neural model as a side-effect.
    """
    # Attempt to load neural model
    neural_ok = load_neural_model()
    if neural_ok:
        logger.info("Neural model ready — will use neural + MITRE hybrid pipeline")
    else:
        logger.warning("Neural model unavailable — using MITRE rules only")

    try:
        from training.neural.hybrid_classifier_v2 import HybridClassifierV2

        return HybridClassifierV2()
    except Exception:
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
