import argparse
import json
import os
import pickle
import yaml


def load_config(config_path):
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def load_model(model_path, vectorizer_path):
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    with open(vectorizer_path, 'rb') as f:
        vectorizer = pickle.load(f)
    return model, vectorizer


def load_session_binary_map(processed_dir, verbose=False):
    map_path = os.path.join(processed_dir, "session_binary_map.json")
    if not os.path.exists(map_path):
        if verbose:
            print("session_binary_map.json not found; binaries will be empty.")
        return {}
    with open(map_path, 'r') as f:
        data = json.load(f)
    downloads = data.get("downloads", [])
    session_map = {}
    for item in downloads:
        session_id = item.get("session_id")
        if not session_id:
            continue
        session_map.setdefault(session_id, []).append({
            "file": item.get("file"),
            "sha256": item.get("sha256"),
            "mtime": item.get("mtime"),
        })
    return session_map


def predict_intent(model, vectorizer, commands, class_labels):
    if not commands:
        return {"label": "Safe", "confidence": 0.0}
    X = vectorizer.transform(commands)
    probs = model.predict_proba(X)
    mean_probs = probs.mean(axis=0)
    idx = int(mean_probs.argmax())
    return {
        "label": class_labels[idx],
        "confidence": float(mean_probs[idx]),
    }


def _parse_timestamp(value):
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            return float(value)
        return float(str(value))
    except Exception:
        return None


def load_cowrie_sessions(
    cowrie_raw_path,
    max_sessions=None,
    max_lines=None,
    max_commands_per_session=None,
    verbose=False,
    progress_every=50000,
):
    sessions = {}
    with open(cowrie_raw_path, 'r') as f:
        for line_idx, line in enumerate(f, start=1):
            if max_lines and line_idx > max_lines:
                if verbose:
                    print(f"Reached max lines limit: {max_lines}")
                break
            try:
                entry = json.loads(line)
            except Exception:
                continue
            if entry.get('eventid') != 'cowrie.command.input':
                continue
            session = entry.get('session') or entry.get('sessionid')
            if not session:
                continue
            ts = _parse_timestamp(entry.get('timestamp'))
            src_ip = entry.get('src_ip')
            cmd = entry.get('input')

            if session not in sessions:
                sessions[session] = {
                    "session_id": session,
                    "src_ip": src_ip,
                    "first_ts": ts,
                    "last_ts": ts,
                    "commands": [],
                }

            item = sessions[session]
            if ts is not None:
                if item["first_ts"] is None or ts < item["first_ts"]:
                    item["first_ts"] = ts
                if item["last_ts"] is None or ts > item["last_ts"]:
                    item["last_ts"] = ts
            if cmd:
                if max_commands_per_session and len(item["commands"]) >= max_commands_per_session:
                    continue
                item["commands"].append(cmd)

            if max_sessions and len(sessions) >= max_sessions:
                if verbose:
                    print(f"Reached max sessions limit: {max_sessions}")
                break

            if verbose and progress_every and line_idx % progress_every == 0:
                print(f"Parsed {line_idx} lines, {len(sessions)} sessions...")

    return list(sessions.values())


def main():
    parser = argparse.ArgumentParser(description="Test AdaptiveShield model on Cowrie sessions")
    parser.add_argument("--max-lines", type=int, default=None, help="Limit log lines for quick tests")
    parser.add_argument("--max-sessions", type=int, default=None, help="Limit number of sessions")
    parser.add_argument("--max-commands", type=int, default=None, help="Limit commands per session")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--progress-every", type=int, default=50000, help="Verbose progress interval")
    parser.add_argument("--no-commands", dest="include_commands", action="store_false", help="Exclude command lists from report")
    parser.add_argument("--no-binaries", dest="include_binaries", action="store_false", help="Exclude binary lists from report")
    parser.set_defaults(include_commands=True, include_binaries=True)
    args = parser.parse_args()

    config = load_config("./config/settings.yaml")
    model_path = config["ml"]["model_path"]
    vectorizer_path = config["ml"]["vectorizer_path"]
    class_labels = config["ml"]["classes"]

    cowrie_raw_path = os.path.join(config["paths"]["raw_logs_dir"], "raw_cowrie_all.json")
    if not os.path.exists(cowrie_raw_path):
        raise FileNotFoundError("raw_cowrie_all.json not found in data/raw_logs")

    model, vectorizer = load_model(model_path, vectorizer_path)
    if args.verbose:
        print("Loading sessions from Cowrie logs...")
    sessions = load_cowrie_sessions(
        cowrie_raw_path,
        max_sessions=args.max_sessions,
        max_lines=args.max_lines,
        max_commands_per_session=args.max_commands,
        verbose=args.verbose,
        progress_every=args.progress_every,
    )
    if args.verbose:
        print(f"Loaded {len(sessions)} sessions. Starting inference...")

    session_binary_map = load_session_binary_map(config["paths"]["processed_dir"], verbose=args.verbose)

    predictions = []
    label_counts = {}
    for idx, session in enumerate(sessions, start=1):
        result = predict_intent(model, vectorizer, session["commands"], class_labels)
        label = result["label"]
        label_counts[label] = label_counts.get(label, 0) + 1
        entry = {
            "session_id": session["session_id"],
            "src_ip": session["src_ip"],
            "command_count": len(session["commands"]),
            "label": label,
            "confidence": result["confidence"],
        }
        if args.include_commands:
            entry["commands"] = session["commands"]
        if args.include_binaries:
            entry["binaries"] = session_binary_map.get(session["session_id"], [])
        predictions.append(entry)
        if args.verbose and args.progress_every and idx % args.progress_every == 0:
            print(f"Processed {idx} sessions...")

    output_path = os.path.join(config["paths"]["processed_dir"], "session_predictions.json")
    with open(output_path, 'w') as f:
        json.dump({
            "total_sessions": len(predictions),
            "label_counts": label_counts,
            "predictions": predictions,
        }, f, indent=2)

    print(f"Wrote predictions to {output_path}")
    print(f"Session counts: {label_counts}")


if __name__ == "__main__":
    main()
