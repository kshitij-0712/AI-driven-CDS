"""
Unit tests for binary triage distillation integration into decision.py.
"""

from agents.decision import (
    build_hybrid_classifier,
    classify_http_request,
    classify_ssh_command,
)


def test_http_request_with_destructive_binary_payload():
    """Verify an HTTP upload with a destructive binary triage triggers Destructive/drop_and_block."""
    classifier = build_hybrid_classifier()
    context = {
        "method": "POST",
        "path": "/upload",
        "query": "",
        "body": "payload_binary_data",
        "headers": {"content-type": "application/octet-stream"},
        "source_ip": "192.168.1.100",
        "session_id": "test-http-bin-1",
    }
    # High destructive triage vector
    destr_triage = [2000000.0, 7.8, 95.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0]

    result = classify_http_request(
        hybrid_classifier=classifier,
        request_context=context,
        triage_features=destr_triage,
    )

    assert result["label"] == "Destructive"
    assert result["action"] == "drop_and_block"
    assert "binary_triage" in result
    assert result["binary_triage"]["label"] == "Destructive"


def test_ssh_command_with_downloader_binary_payload():
    """Verify an SSH command with downloader triage vector triggers Downloader/redirect_to_decoy."""
    classifier = build_hybrid_classifier()
    context = {"source_ip": "10.0.0.50", "session_id": "test-ssh-bin-2"}

    # Benign-looking command text, but associated with a dropped downloader binary
    command = "./downloaded_helper"
    downloader_triage = [50000.0, 6.0, 70.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0]

    result = classify_ssh_command(
        hybrid_classifier=classifier,
        command=command,
        context=context,
        triage_features=downloader_triage,
    )

    assert result["label"] == "Downloader"
    assert result["action"] == "redirect_to_decoy"
    assert "binary_triage" in result
    assert result["binary_triage"]["label"] == "Downloader"
