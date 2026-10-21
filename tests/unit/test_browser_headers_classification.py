import pytest
from agents.decision import classify_http_request
from training.neural.hybrid_classifier import HybridClassifier


@pytest.fixture
def classifier():
    return HybridClassifier()


def test_browser_favicon_request_classified_safe(classifier):
    """Ensure standard browser requests for /favicon.ico with image MIME headers are safe."""
    context = {
        "method": "GET",
        "path": "/favicon.ico",
        "query": "",
        "body": "",
        "headers": {
            "host": "127.0.0.1:8000",
            "user-agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:157.0) Gecko/20100101 Firefox/157.0",
            "accept": "image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5",
            "accept-language": "en-US,en;q=0.9",
            "referer": "http://127.0.0.1:8000/",
        }
    }
    decision = classify_http_request(classifier, context)
    assert decision["label"] == "Safe"
    assert decision["action"] == "forward"
    assert decision["risk_score"] == 0.0


def test_browser_headers_do_not_trigger_false_sqli(classifier):
    """Ensure MIME type Accept headers like image/*;q=0.8,*/* are never matched as SQLi comments."""
    context = {
        "method": "GET",
        "path": "/",
        "query": "",
        "body": "",
        "headers": {
            "host": "127.0.0.1:8000",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/*,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.5",
            "priority": "u=0, i",
        }
    }
    decision = classify_http_request(classifier, context)
    assert decision["label"] == "Safe"
    assert decision["action"] == "forward"


def test_actual_sqli_attack_still_detected(classifier):
    """Ensure actual SQL injection in query parameters is detected and routed to decoy."""
    context = {
        "method": "GET",
        "path": "/login",
        "query": "user=admin' OR 1=1--",
        "body": "",
        "headers": {
            "host": "127.0.0.1:8000",
            "user-agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)",
            "accept": "text/html,application/xhtml+xml,image/*,*/*",
        }
    }
    decision = classify_http_request(classifier, context)
    assert decision["label"] == "Exploit"
    assert decision["action"] == "redirect_to_decoy"
