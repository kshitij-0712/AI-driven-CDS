import pickle
import re
from urllib.parse import unquote


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


def classify_http_request(hybrid_classifier, request_context):
    """Classify an HTTP request context using the hybrid classifier.

    request_context keys:
      - method
      - path
      - query
      - body
      - headers (dict)
      - source_ip

    Returns a dict with threat label and action intent.
    """
    method = (request_context.get("method") or "GET").upper()
    path = request_context.get("path") or "/"
    query = request_context.get("query") or ""
    body = request_context.get("body") or ""
    headers = request_context.get("headers") or {}
    source_ip = request_context.get("source_ip") or "unknown"

    user_agent = str(headers.get("user-agent", ""))

    joined_payload = " ".join([path, query, body, user_agent])
    joined_payload = unquote(joined_payload)
    http_findings = _match_http_patterns(joined_payload)

    if "xss" in http_findings or "sqli" in http_findings or "command_injection" in http_findings:
        return {
            "class_id": 3,
            "label": "Exploit",
            "confidence": 1.0,
            "action": "redirect_to_decoy",
            "rule": "HTTP exploit pattern matched",
            "mitre_tactics": ["execution", "initial_access"],
            "severity_max": 9,
            "http_findings": http_findings,
        }

    if "path_traversal" in http_findings or "scanner" in http_findings:
        return {
            "class_id": 1,
            "label": "Recon",
            "confidence": 1.0,
            "action": "forward_and_log",
            "rule": "HTTP reconnaissance pattern matched",
            "mitre_tactics": ["reconnaissance", "discovery"],
            "severity_max": 6,
            "http_findings": http_findings,
        }

    synthetic_cmd = f"http_{method.lower()} {path} {query} {body} src={source_ip}"

    pred_id, label, explanation = hybrid_classifier.classify(synthetic_cmd)

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
        "confidence": 1.0,
        "action": action,
        "rule": explanation.get("rule_matched"),
        "mitre_tactics": explanation.get("mitre_tactics", []),
        "severity_max": explanation.get("severity_max", 0),
        "http_findings": http_findings,
    }


def build_hybrid_classifier():
    """Factory to build HybridClassifierV2.

    Keeps setup in one place so orchestrator/API can use it directly.
    """
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
