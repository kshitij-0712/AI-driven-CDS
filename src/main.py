import os
import json
import yaml

from agents.discovery import run_discovery, write_report
from agents.analysis import correlate_downloads_to_sessions
from agents.decision import load_model, predict_intent
from agents.deception import decide_decoy_action
from agents.xai import explain_action


def load_config(config_path):
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def main():
    config = load_config("./config/settings.yaml")

    # ===== Discovery =====
    discovery_report = run_discovery("127.0.0.1")
    write_report(discovery_report, "./data/processed/discovery_report.json")

    # ===== Correlation =====
    raw_logs_dir = config["paths"]["raw_logs_dir"]
    cowrie_path = os.path.join(raw_logs_dir, "raw_cowrie_all.json")

    correlation = correlate_downloads_to_sessions(
        config["paths"]["binaries_dir"],
        cowrie_path,
        config["analysis"]["session_link_time_window_sec"],
    )

    with open("./data/processed/session_binary_map.json", "w") as f:
        json.dump(correlation, f, indent=2)

    # ===== Load ML =====
    model_path = config["ml"]["model_path"]
    vectorizer_path = config["ml"]["vectorizer_path"]
    classes = config["ml"]["classes"]

    # ===== Use session (real or dummy) =====
    sessions = correlation.get("sessions", [])

    if sessions:
        session = sessions[0]
    else:
        session = {
            "commands": [],
            "first_ts": 1,
            "last_ts": 2,
            "download_shas": []
        }

    # ===== Run prediction =====
    if os.path.exists(model_path) and os.path.exists(vectorizer_path):
        model, vectorizer = load_model(model_path, vectorizer_path)
    else:
        model, vectorizer = None, None

    result = predict_intent(model, vectorizer, session, classes)

    # ===== Save output (IMPORTANT) =====
    with open("./data/processed/insider_results.json", "w") as f:
        json.dump(result, f, indent=2)

    # ===== Decision + XAI =====
    action = decide_decoy_action(result["label"])
    explanation = explain_action(result["label"], result["confidence"], action)

    with open("./data/processed/xai_audit_log.txt", "a") as f:
        f.write(explanation + "\n")

    # ===== Clean Output =====
    print("\n=== FINAL DECISION ===")
    print(f"Threat Label: {result.get('label')}")
    print(f"Confidence: {result.get('confidence')}")
    print(f"Insider Flag: {result.get('insider_flag')}")
    print(f"Risk Score: {result.get('risk_score')}")
    print(f"CERT Risk: {result.get('cert_risk')}")
    print(f"Explanation: {result.get('insider_explanation')}")
    print(f"Action: {action}")


if __name__ == "__main__":
    main()