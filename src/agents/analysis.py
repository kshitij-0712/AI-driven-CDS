import json
import os
import hashlib
from datetime import datetime

from core.ingestors.log_parsers import ingest_cowrie, ingest_zeek, ingest_dionaea_bistreams


def _sha256(path):
    hasher = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def _parse_timestamp(value):
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            return float(value)
        return float(str(value))
    except Exception:
        return None


def _extract_session_commands(cowrie_raw_path):
    sessions = {}
    if not os.path.exists(cowrie_raw_path):
        return sessions

    with open(cowrie_raw_path, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)
            except Exception:
                continue
            session = entry.get('session') or entry.get('sessionid')
            if not session:
                continue
            ts = _parse_timestamp(entry.get('timestamp'))
            event_id = entry.get('eventid')
            cmd = entry.get('input') if event_id == 'cowrie.command.input' else None
            src_ip = entry.get('src_ip')

            if session not in sessions:
                sessions[session] = {
                    "session_id": session,
                    "src_ip": src_ip,
                    "first_ts": ts,
                    "last_ts": ts,
                    "commands": [],
                }

            session_entry = sessions[session]
            if ts is not None:
                if session_entry["first_ts"] is None or ts < session_entry["first_ts"]:
                    session_entry["first_ts"] = ts
                if session_entry["last_ts"] is None or ts > session_entry["last_ts"]:
                    session_entry["last_ts"] = ts
            if cmd:
                session_entry["commands"].append(cmd)
    return sessions


def _match_file_to_session(file_mtime, sessions, time_window_sec):
    best_session = None
    best_delta = None
    for session_id, details in sessions.items():
        if details["first_ts"] is None or details["last_ts"] is None:
            continue
        if details["first_ts"] - time_window_sec <= file_mtime <= details["last_ts"] + time_window_sec:
            delta = min(abs(file_mtime - details["first_ts"]), abs(file_mtime - details["last_ts"]))
            if best_delta is None or delta < best_delta:
                best_delta = delta
                best_session = session_id
    return best_session


def correlate_downloads_to_sessions(download_dir, cowrie_raw_path, time_window_sec=300):
    sessions = _extract_session_commands(cowrie_raw_path)
    correlated = []
    for root, _, files in os.walk(download_dir):
        for filename in files:
            full_path = os.path.join(root, filename)
            try:
                file_mtime = os.path.getmtime(full_path)
            except Exception:
                continue
            session_id = _match_file_to_session(file_mtime, sessions, time_window_sec)
            correlated.append({
                "file": full_path,
                "sha256": _sha256(full_path),
                "session_id": session_id,
                "mtime": datetime.utcfromtimestamp(file_mtime).isoformat() + "Z",
            })
    return {
        "sessions": list(sessions.values()),
        "downloads": correlated,
    }


def run_ingestors(config):
    raw_dir = config["paths"]["raw_logs_dir"]
    cowrie_out = os.path.join(raw_dir, "raw_cowrie_all.json")
    zeek_out = os.path.join(raw_dir, "raw_zeek_universal.json")
    dionaea_out = os.path.join(raw_dir, "raw_dionaea_streams.json")

    cowrie_count = ingest_cowrie(config["ingestors"]["cowrie_input_dir"], cowrie_out)
    zeek_count = ingest_zeek(
        [config["ingestors"]["zeek_history_dir"], config["ingestors"]["zeek_spool_dir"]],
        zeek_out,
        ["conn", "dns", "http", "ssh", "ftp", "ssl", "weird", "files", "known_services"],
    )
    dionaea_count = ingest_dionaea_bistreams(config["ingestors"]["dionaea_bistream_dir"], dionaea_out)
    return {
        "cowrie": cowrie_count,
        "zeek": zeek_count,
        "dionaea": dionaea_count,
    }


def write_processed_sessions(processed, output_path):
    with open(output_path, 'w') as f:
        json.dump(processed, f, indent=2)
