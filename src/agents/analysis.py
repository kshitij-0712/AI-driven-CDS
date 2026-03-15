import json
import os
import hashlib
from datetime import datetime

from core.ingestors.log_parsers import ingest_cowrie, ingest_zeek, ingest_dionaea_bistreams


# ===================================================================
# Default path for Phase 1 triage results
# ===================================================================
DEFAULT_TRIAGE_PATH = "data/processed/binary_triage/all_triage_results.json"


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
        s = str(value)
        # Try parsing as float first (Unix epoch)
        try:
            return float(s)
        except ValueError:
            pass
        # Try ISO-8601 format (e.g. "2025-11-29T00:01:23.456789Z")
        # Strip trailing 'Z' and parse
        s = s.rstrip("Z")
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
        return dt.timestamp()
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
    """Legacy mtime-based correlation. See correlate_downloads_from_logs() instead."""
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


def correlate_downloads_from_logs(cowrie_log_paths, download_dir=None):
    """
    Correlate binary downloads to attacker sessions using Cowrie log events.

    This is the correct correlation method. It uses the
    `cowrie.session.file_download` events in the logs which directly link
    session IDs to SHA256 hashes — no timestamp heuristics needed.

    Also extracts `cowrie.session.file_upload` events.

    Parameters
    ----------
    cowrie_log_paths : list[str]
        List of paths to Cowrie JSON log files.
    download_dir : str, optional
        Path to the downloads directory. Used to verify files exist
        and get file paths. If None, only SHA256s are recorded.

    Returns
    -------
    dict
        {
            "sessions": list of session dicts (with commands, downloads),
            "downloads": list of {sha256, session_id, url, event_type} dicts,
            "stats": summary statistics
        }
    """
    sessions = {}         # session_id -> session dict
    download_events = []  # all download/upload events

    # Set of sha256s that exist on disk
    on_disk = set()
    sha_to_path = {}
    if download_dir and os.path.isdir(download_dir):
        for fname in os.listdir(download_dir):
            full = os.path.join(download_dir, fname)
            if os.path.isfile(full):
                # Cowrie names files by sha256
                on_disk.add(fname)
                sha_to_path[fname] = full

    for log_path in cowrie_log_paths:
        if not os.path.isfile(log_path):
            continue
        with open(log_path, "r") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except Exception:
                    continue

                session_id = entry.get("session") or entry.get("sessionid")
                if not session_id:
                    continue

                ts = _parse_timestamp(entry.get("timestamp"))
                event_id = entry.get("eventid", "")
                src_ip = entry.get("src_ip")

                # Initialize session if new
                if session_id not in sessions:
                    sessions[session_id] = {
                        "session_id": session_id,
                        "src_ip": src_ip,
                        "first_ts": ts,
                        "last_ts": ts,
                        "commands": [],
                        "download_shas": [],  # SHA256s downloaded in this session
                    }

                s = sessions[session_id]
                if ts is not None:
                    if s["first_ts"] is None or ts < s["first_ts"]:
                        s["first_ts"] = ts
                    if s["last_ts"] is None or ts > s["last_ts"]:
                        s["last_ts"] = ts

                # Record commands
                if event_id == "cowrie.command.input":
                    cmd = entry.get("input")
                    if cmd:
                        s["commands"].append(cmd)

                # Record file downloads
                elif event_id == "cowrie.session.file_download":
                    sha = entry.get("shasum")
                    if sha:
                        s["download_shas"].append(sha)
                        download_events.append({
                            "sha256": sha,
                            "session_id": session_id,
                            "url": entry.get("url"),
                            "outfile": entry.get("outfile"),
                            "event_type": "download",
                            "timestamp": entry.get("timestamp"),
                            "file_on_disk": sha in on_disk,
                            "file_path": sha_to_path.get(sha),
                        })

                # Record file uploads
                elif event_id == "cowrie.session.file_upload":
                    sha = entry.get("shasum")
                    if sha:
                        s["download_shas"].append(sha)
                        download_events.append({
                            "sha256": sha,
                            "session_id": session_id,
                            "event_type": "upload",
                            "timestamp": entry.get("timestamp"),
                            "file_on_disk": sha in on_disk,
                            "file_path": sha_to_path.get(sha),
                        })

    # Deduplicate download_shas per session
    for s in sessions.values():
        s["download_shas"] = sorted(set(s["download_shas"]))

    # Stats
    sessions_with_commands = sum(1 for s in sessions.values() if s["commands"])
    sessions_with_downloads = sum(1 for s in sessions.values() if s["download_shas"])
    unique_shas = set(d["sha256"] for d in download_events)
    shas_on_disk = unique_shas & on_disk

    stats = {
        "total_sessions": len(sessions),
        "sessions_with_commands": sessions_with_commands,
        "sessions_with_downloads": sessions_with_downloads,
        "total_download_events": len(download_events),
        "unique_sha256s": len(unique_shas),
        "sha256s_on_disk": len(shas_on_disk),
    }

    return {
        "sessions": list(sessions.values()),
        "downloads": download_events,
        "stats": stats,
    }


# ===================================================================
# Phase 1: Binary triage integration
# ===================================================================

def _load_triage_index(triage_path=DEFAULT_TRIAGE_PATH):
    """
    Load the Phase 1 triage results and build a SHA256 -> features lookup.

    The triage JSON has structure: { "stats": {...}, "results": [...] }
    Each result has "sha256", "classification", "format_info", etc.

    Returns a dict keyed by sha256 with the relevant features extracted
    for training pipeline consumption.
    """
    if not os.path.isfile(triage_path):
        return {}

    with open(triage_path, "r") as f:
        data = json.load(f)

    index = {}
    for result in data.get("results", []):
        sha = result.get("sha256")
        if not sha:
            continue

        classification = result.get("classification", {})
        format_info = result.get("format_info", {})

        # Extract the features most useful for the ML pipeline
        index[sha] = {
            "file_type": result.get("file_type", "unknown"),
            "file_size": result.get("file_size", 0),
            "overall_entropy": result.get("overall_entropy", 0.0),
            "analysis_priority": result.get("analysis_priority", 0),
            # Classification
            "primary_label": classification.get("primary_label", "unknown"),
            "confidence": classification.get("confidence", "low"),
            "tags": classification.get("tags", []),
            "behavior_scores": classification.get("scores", {}),
            # Format-specific
            "arch": format_info.get("arch"),
            "linkage": format_info.get("linkage"),
            "is_go_binary": format_info.get("is_go_binary", False),
            "is_packed": format_info.get("is_upx_packed", False),
            "is_dll": format_info.get("is_dll", False),
            "shared_libraries": format_info.get("shared_libraries", []),
            "imphash": format_info.get("imphash"),
        }

    return index


def enrich_sessions_with_binary_features(
    correlated,
    triage_path=DEFAULT_TRIAGE_PATH,
):
    """
    Enrich session data with binary analysis features from Phase 1 triage.

    Works with output from either:
      - correlate_downloads_from_logs() (preferred — sessions have download_shas)
      - correlate_downloads_to_sessions() (legacy — uses downloads list)

    For each session that has associated downloads, this function:
      1. Looks up the triage result for each downloaded binary by SHA256
      2. Computes per-session aggregated binary features:
         - binary_labels: set of all primary_label values from downloads
         - binary_tags: union of all tags from downloads
         - max_priority: highest analysis_priority among downloads
         - has_miner, has_botnet, has_downloader, etc. (boolean flags)

    These aggregated features become the enriched training labels that
    replace the weak synthetic-only labels in the vectorizer.

    Parameters
    ----------
    correlated : dict
        Output of correlate_downloads_from_logs() or
        correlate_downloads_to_sessions().
    triage_path : str
        Path to the all_triage_results.json from Phase 1 triage.

    Returns
    -------
    dict
        Same structure as input, but with enriched fields added to both
        downloads and sessions.
    """
    triage_index = _load_triage_index(triage_path)
    if not triage_index:
        return correlated  # No triage data available, return as-is

    # --- Enrich individual downloads ---
    for dl in correlated.get("downloads", []):
        sha = dl.get("sha256")
        if sha and sha in triage_index:
            dl["binary_features"] = triage_index[sha]
        else:
            dl["binary_features"] = None

    # --- Build session -> SHA256 list mapping ---
    # Support both new format (download_shas on session) and old format
    # (separate downloads list with session_id)
    session_shas = {}
    for session in correlated.get("sessions", []):
        sid = session.get("session_id")
        shas = session.get("download_shas", [])
        if shas:
            session_shas[sid] = shas

    # Fallback: if sessions don't have download_shas, build from downloads list
    if not session_shas:
        for dl in correlated.get("downloads", []):
            sid = dl.get("session_id")
            sha = dl.get("sha256")
            if sid and sha:
                session_shas.setdefault(sid, []).append(sha)

    # --- Enrich sessions with aggregated binary features ---
    _empty_features = {
        "num_downloads": 0,
        "binary_labels": [],
        "binary_tags": [],
        "max_priority": 0,
        "has_miner": False,
        "has_botnet": False,
        "has_downloader": False,
        "has_destructive": False,
        "has_recon": False,
        "has_credential_access": False,
        "has_rat": False,
        "has_go_binary": False,
        "has_packed": False,
    }

    for session in correlated.get("sessions", []):
        sid = session.get("session_id")
        shas = session_shas.get(sid, [])

        if not shas:
            session["binary_features"] = dict(_empty_features)
            continue

        all_labels = set()
        all_tags = set()
        max_priority = 0
        matched_count = 0

        for sha in shas:
            bf = triage_index.get(sha)
            if not bf:
                continue
            matched_count += 1
            label = bf.get("primary_label", "unknown")
            if label not in ("unknown", "empty", "unknown_script", "unknown_binary"):
                all_labels.add(label)
            all_tags.update(bf.get("tags", []))
            max_priority = max(max_priority, bf.get("analysis_priority", 0))

        session["binary_features"] = {
            "num_downloads": len(shas),
            "binary_labels": sorted(all_labels),
            "binary_tags": sorted(all_tags),
            "max_priority": max_priority,
            # Boolean convenience flags for vectorizer
            "has_miner": "mining" in all_tags or "miner" in all_labels,
            "has_botnet": "botnet" in all_tags or "botnet_dropper" in all_labels,
            "has_downloader": "downloader" in all_tags or "downloader" in all_labels,
            "has_destructive": "destructive" in all_tags or "destructive" in all_labels,
            "has_recon": "recon" in all_tags or "recon_scanner" in all_labels,
            "has_credential_access": "credential_access" in all_tags or "credential_stealer" in all_labels,
            "has_rat": "rat" in all_labels,
            "has_go_binary": "go_binary" in all_tags,
            "has_packed": "upx_packed" in all_tags or "high_entropy" in all_tags,
        }

    return correlated


# ===================================================================
# Phase 4: Deep binary feature enrichment
# ===================================================================

def enrich_sessions_with_deep_features(
    correlated,
    triage_path=DEFAULT_TRIAGE_PATH,
):
    """
    Enrich session data with DEEP binary analysis features from all phases.

    This is the Phase 4 upgrade to enrich_sessions_with_binary_features().
    Instead of only using Phase 1 triage data, it uses the feature_merger
    to pull in Ghidra (Phase 2), angr (Phase 3), and script analysis
    results alongside triage.

    The result per session includes:
      - All the original Phase 1 fields (has_miner, has_botnet, etc.)
      - A "deep_feature_vector" list: the 79-column numeric vector from
        the feature merger, aggregated across all binaries the session
        downloaded (using max/sum aggregation as appropriate)

    Parameters
    ----------
    correlated : dict
        Output of correlate_downloads_from_logs().
    triage_path : str
        Path to triage results (passed through to Phase 1 enrichment).

    Returns
    -------
    dict
        Same structure as input, with enriched fields on sessions.
    """
    from core.malware.feature_merger import (
        merge_all_features, DEEP_FEATURE_COLUMNS, get_feature_vector,
    )

    # First, run the Phase 1 enrichment to get labels and boolean flags
    correlated = enrich_sessions_with_binary_features(correlated, triage_path)

    # Load the merged deep features
    merged = merge_all_features(verbose=True)

    # Build session -> SHA256 list mapping (same as Phase 1)
    session_shas = {}
    for session in correlated.get("sessions", []):
        sid = session.get("session_id")
        shas = session.get("download_shas", [])
        if shas:
            session_shas[sid] = shas
    if not session_shas:
        for dl in correlated.get("downloads", []):
            sid = dl.get("session_id")
            sha = dl.get("sha256")
            if sid and sha:
                session_shas.setdefault(sid, []).append(sha)

    # Aggregate deep features per session
    # Strategy: for each numeric column, take the MAX across all binaries
    # the session downloaded. This captures the "most dangerous" binary's
    # features. Boolean flags use OR (max). Counts use SUM.
    #
    # Rationale: A session that downloads a miner AND a recon scanner
    # should have both signals. Sum for counts, max for boolean/complexity.

    # Columns where we want SUM instead of MAX (count-like features)
    SUM_COLUMNS = {
        "ghidra_mining_pool_count", "ghidra_crypto_wallet_count",
        "ghidra_ip_count", "ghidra_url_count", "ghidra_shell_cmd_count",
        "angr_ip_count", "angr_url_count", "angr_mining_indicator_count",
        "angr_shell_cmd_count", "script_url_count", "script_download_count",
        "deep_mining_signal_count", "deep_total_network_indicators",
        "deep_total_crypto_indicators", "deep_total_evasion_indicators",
    }

    # Build a set mapping column name -> index for fast lookup
    sum_indices = set()
    for i, col in enumerate(DEEP_FEATURE_COLUMNS):
        if col in SUM_COLUMNS:
            sum_indices.add(i)

    n_cols = len(DEEP_FEATURE_COLUMNS)
    zero_vector = [0.0] * n_cols

    sessions_with_deep = 0
    sessions_with_any_deep_tool = 0

    for session in correlated.get("sessions", []):
        sid = session.get("session_id")
        shas = session_shas.get(sid, [])

        if not shas:
            session["deep_feature_vector"] = list(zero_vector)
            session["deep_feature_columns"] = DEEP_FEATURE_COLUMNS
            continue

        # Collect feature vectors for all binaries in this session
        vectors = []
        has_deep = False
        for sha in shas:
            entry = merged.get(sha)
            if entry:
                vec = get_feature_vector(entry)
                vectors.append(vec)
                if entry.get("has_ghidra_results", 0) > 0 or entry.get("has_angr_results", 0) > 0:
                    has_deep = True

        if not vectors:
            session["deep_feature_vector"] = list(zero_vector)
            session["deep_feature_columns"] = DEEP_FEATURE_COLUMNS
            continue

        # Aggregate: MAX for most columns, SUM for count columns
        aggregated = list(zero_vector)
        for i in range(n_cols):
            values = [v[i] for v in vectors]
            if i in sum_indices:
                aggregated[i] = sum(values)
            else:
                aggregated[i] = max(values)

        session["deep_feature_vector"] = aggregated
        session["deep_feature_columns"] = DEEP_FEATURE_COLUMNS
        sessions_with_deep += 1
        if has_deep:
            sessions_with_any_deep_tool += 1

    print("Deep feature enrichment: %d sessions got deep features, "
          "%d have Ghidra/angr data" % (sessions_with_deep, sessions_with_any_deep_tool))

    return correlated


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
