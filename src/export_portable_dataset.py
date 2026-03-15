"""
Portable Dataset Export for AdaptiveShield.

This script produces a complete, self-contained export of ALL processed data
from the VM environment so that the full ML pipeline can be rebuilt on the
host machine (RTX 3050, 16GB RAM) without ever needing the original binaries
or Cowrie log files again.

WHAT IT EXPORTS:
  1. sessions.csv           - All 78,504 sessions with commands
  2. downloads.csv          - All 50,520 download events (session -> SHA256)
  3. binary_features.csv    - All 185 SHA256s with full feature vectors
  4. session_labels.csv     - Per-session binary-derived labels
  5. sessions_mitre.csv     - Per-session MITRE ATT&CK annotations (21 features)
  6. sessions_complete.csv  - THE BIG ONE: everything joined, ready for training
  7. mitre_knowledge_base.json - Portable ATT&CK pattern definitions
  8. export_manifest.json   - Metadata, schemas, generation timestamp

USAGE:
  cd /home/me/data/AdaptiveShield
  PYTHONPATH=src .venv/bin/python src/export_portable_dataset.py

OUTPUT: data/exports/  (all files)
"""

import csv
import json
import os
import pickle
import sys
import time
from datetime import datetime, timezone
from glob import glob

# Project imports
from agents.analysis import correlate_downloads_from_logs, enrich_sessions_with_binary_features
from core.malware.feature_merger import (
    merge_all_features, DEEP_FEATURE_COLUMNS, get_feature_vector,
)
from core.mitre.attack_mapping import (
    ATTACK_PATTERNS, TACTICS, TACTIC_NAMES,
    BINARY_TAG_TO_TECHNIQUE, get_knowledge_base_stats,
)
from core.mitre.session_annotator import (
    annotate_session, annotation_to_flat_dict, get_mitre_feature_columns,
)

# ===================================================================
# Configuration
# ===================================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COWRIE_LOG_DIR = os.path.join(BASE_DIR, "data", "cowrie", "log", "cowrie")
COWRIE_DOWNLOAD_DIR = os.path.join(BASE_DIR, "data", "cowrie", "lib", "cowrie", "downloads")
TRIAGE_PATH = os.path.join(BASE_DIR, "data", "processed", "binary_triage", "all_triage_results.json")
EXPORT_DIR = os.path.join(BASE_DIR, "data", "exports")


def _ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def _write_csv(path, rows, fieldnames):
    """Write a list of dicts to CSV."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print("  -> %s (%d rows, %d cols)" % (os.path.basename(path), len(rows), len(fieldnames)))


# ===================================================================
# Step 1: Correlate sessions from raw logs
# ===================================================================

def step1_correlate():
    """Re-run correlation from raw Cowrie logs."""
    print("\n=== Step 1: Correlating sessions from Cowrie logs ===")

    log_files = sorted(glob(os.path.join(COWRIE_LOG_DIR, "cowrie.json*")))
    print("  Found %d log files" % len(log_files))

    if not log_files:
        print("ERROR: No Cowrie log files found at %s" % COWRIE_LOG_DIR)
        sys.exit(1)

    correlated = correlate_downloads_from_logs(log_files, COWRIE_DOWNLOAD_DIR)

    stats = correlated["stats"]
    print("  Total sessions: %d" % stats["total_sessions"])
    print("  Sessions with commands: %d" % stats["sessions_with_commands"])
    print("  Sessions with downloads: %d" % stats["sessions_with_downloads"])
    print("  Total download events: %d" % stats["total_download_events"])
    print("  Unique SHA256s: %d" % stats["unique_sha256s"])

    return correlated


# ===================================================================
# Step 2: Enrich with binary features + labels
# ===================================================================

def step2_enrich(correlated):
    """Add Phase 1 binary features and labels to sessions."""
    print("\n=== Step 2: Enriching sessions with binary features ===")

    enriched = enrich_sessions_with_binary_features(correlated, TRIAGE_PATH)

    # Count labeled sessions
    labeled = 0
    for s in enriched["sessions"]:
        bf = s.get("binary_features", {})
        if bf and any(bf.get(k) for k in [
            "has_miner", "has_botnet", "has_downloader", "has_destructive",
            "has_recon", "has_credential_access", "has_rat",
        ]):
            labeled += 1

    print("  Sessions with binary-derived labels: %d" % labeled)
    return enriched


# ===================================================================
# Step 3: Load deep binary features
# ===================================================================

def step3_load_deep_features():
    """Load the merged deep features from all analysis phases."""
    print("\n=== Step 3: Loading merged binary features ===")

    merged = merge_all_features(verbose=True)
    print("  Loaded %d binary feature entries" % len(merged))
    return merged


# ===================================================================
# Step 4: MITRE annotate all sessions
# ===================================================================

def step4_mitre_annotate(sessions):
    """Run MITRE ATT&CK annotation on all sessions."""
    print("\n=== Step 4: MITRE ATT&CK annotation ===")

    total = len(sessions)
    matched_count = 0
    high_severity_count = 0

    for i, session in enumerate(sessions):
        commands = session.get("commands", [])
        bf = session.get("binary_features", {})
        binary_tags = bf.get("binary_tags", []) if isinstance(bf, dict) else []

        annotation = annotate_session(commands, binary_tags=binary_tags)
        session["mitre_annotation"] = annotation

        if annotation["matched_commands"] > 0:
            matched_count += 1
        if annotation["severity_max"] >= 7:
            high_severity_count += 1

        if (i + 1) % 10000 == 0:
            print("  Annotated %d / %d sessions..." % (i + 1, total))

    print("  Sessions with MITRE matches: %d / %d (%.1f%%)" % (
        matched_count, total, 100.0 * matched_count / total if total else 0))
    print("  High-severity sessions (>=7): %d" % high_severity_count)

    return sessions


# ===================================================================
# Step 5: Assign labels
# ===================================================================

def _assign_label(session):
    """
    Assign training label based on binary features + MITRE severity.

    Priority hierarchy (same as vectorizer.py _label_from_binary_features):
      Go binary with 4+ capability tags -> 5 (APT)
      has_destructive -> 4
      has_credential_access or has_rat or has_packed -> 3
      has_miner or has_botnet or has_downloader -> 2
      has_recon -> 1
      default -> 0 (Safe)
    """
    bf = session.get("binary_features", {})
    if not isinstance(bf, dict):
        return 0, "Safe"

    tags = bf.get("binary_tags", [])
    num_capability_tags = sum(1 for t in tags if t in (
        "mining", "botnet", "credential_access", "persistence",
        "recon", "destructive", "downloader"))

    if bf.get("has_go_binary") and num_capability_tags >= 4:
        return 5, "ADVANCED_APT"
    if bf.get("has_destructive"):
        return 4, "Destructive"
    if bf.get("has_credential_access") or bf.get("has_rat") or bf.get("has_packed"):
        return 3, "Exploit"
    if bf.get("has_miner") or bf.get("has_botnet") or bf.get("has_downloader"):
        return 2, "Downloader"
    if bf.get("has_recon"):
        return 1, "Recon"
    return 0, "Safe"


# ===================================================================
# Step 6: Export all files
# ===================================================================

def step6_export(sessions, downloads, merged_features):
    """Write all export CSV/JSON files."""
    print("\n=== Step 6: Exporting portable dataset ===")
    _ensure_dir(EXPORT_DIR)

    # --- Filter to sessions with commands only ---
    sessions_with_cmds = [s for s in sessions if s.get("commands")]
    print("  Sessions with commands: %d (of %d total)" % (len(sessions_with_cmds), len(sessions)))

    # ------------------------------------------------------------------
    # 1. sessions.csv — All sessions with commands
    # ------------------------------------------------------------------
    print("\n  [1/8] sessions.csv")
    session_rows = []
    for s in sessions_with_cmds:
        cmds = s.get("commands", [])
        session_rows.append({
            "session_id": s["session_id"],
            "src_ip": s.get("src_ip", ""),
            "first_ts": s.get("first_ts", ""),
            "last_ts": s.get("last_ts", ""),
            "num_commands": len(cmds),
            "commands": " ;; ".join(cmds),  # Join with separator
            "duration_sec": round(
                (s.get("last_ts") or 0) - (s.get("first_ts") or 0), 1
            ) if s.get("first_ts") and s.get("last_ts") else 0,
            "num_downloads": len(s.get("download_shas", [])),
            "download_shas": "|".join(s.get("download_shas", [])),
        })

    _write_csv(
        os.path.join(EXPORT_DIR, "sessions.csv"),
        session_rows,
        ["session_id", "src_ip", "first_ts", "last_ts", "num_commands",
         "duration_sec", "num_downloads", "download_shas", "commands"],
    )

    # ------------------------------------------------------------------
    # 2. downloads.csv — All download events
    # ------------------------------------------------------------------
    print("  [2/8] downloads.csv")
    dl_rows = []
    for dl in downloads:
        dl_rows.append({
            "session_id": dl.get("session_id", ""),
            "sha256": dl.get("sha256", ""),
            "url": dl.get("url", ""),
            "timestamp": dl.get("timestamp", ""),
            "event_type": dl.get("event_type", ""),
            "file_on_disk": dl.get("file_on_disk", False),
        })

    _write_csv(
        os.path.join(EXPORT_DIR, "downloads.csv"),
        dl_rows,
        ["session_id", "sha256", "url", "timestamp", "event_type", "file_on_disk"],
    )

    # ------------------------------------------------------------------
    # 3. binary_features.csv — All SHA256s with full feature vectors
    # ------------------------------------------------------------------
    print("  [3/8] binary_features.csv")

    # Collect all columns across all entries
    all_cols = set()
    for entry in merged_features.values():
        all_cols.update(entry.keys())

    # Separate string vs numeric columns
    string_cols = {"sha256", "triage_file_type", "triage_label", "triage_confidence",
                   "triage_arch", "triage_linkage", "triage_tags"}
    # Keep triage_tags as pipe-separated for portability
    numeric_cols = sorted(all_cols - string_cols - {"triage_tags"})
    csv_cols = ["sha256", "triage_file_type", "triage_label", "triage_confidence",
                "triage_arch", "triage_linkage", "triage_tags_str"] + numeric_cols

    bf_rows = []
    for sha, entry in sorted(merged_features.items()):
        row = dict(entry)
        row["sha256"] = sha
        # Convert tags list to pipe-separated string
        tags = row.pop("triage_tags", [])
        row["triage_tags_str"] = "|".join(tags) if isinstance(tags, list) else str(tags)
        bf_rows.append(row)

    _write_csv(
        os.path.join(EXPORT_DIR, "binary_features.csv"),
        bf_rows,
        csv_cols,
    )

    # ------------------------------------------------------------------
    # 4. session_labels.csv — Per-session labels derived from binary features
    # ------------------------------------------------------------------
    print("  [4/8] session_labels.csv")
    label_rows = []
    label_dist = {}
    for s in sessions_with_cmds:
        label_id, label_name = _assign_label(s)
        label_dist[label_name] = label_dist.get(label_name, 0) + 1
        bf = s.get("binary_features", {})
        label_rows.append({
            "session_id": s["session_id"],
            "label_id": label_id,
            "label_name": label_name,
            "num_downloads": bf.get("num_downloads", 0) if isinstance(bf, dict) else 0,
            "has_miner": int(bf.get("has_miner", False)) if isinstance(bf, dict) else 0,
            "has_botnet": int(bf.get("has_botnet", False)) if isinstance(bf, dict) else 0,
            "has_downloader": int(bf.get("has_downloader", False)) if isinstance(bf, dict) else 0,
            "has_destructive": int(bf.get("has_destructive", False)) if isinstance(bf, dict) else 0,
            "has_recon": int(bf.get("has_recon", False)) if isinstance(bf, dict) else 0,
            "has_credential_access": int(bf.get("has_credential_access", False)) if isinstance(bf, dict) else 0,
            "has_rat": int(bf.get("has_rat", False)) if isinstance(bf, dict) else 0,
            "has_go_binary": int(bf.get("has_go_binary", False)) if isinstance(bf, dict) else 0,
            "has_packed": int(bf.get("has_packed", False)) if isinstance(bf, dict) else 0,
            "max_priority": bf.get("max_priority", 0) if isinstance(bf, dict) else 0,
            "binary_labels": "|".join(bf.get("binary_labels", [])) if isinstance(bf, dict) else "",
            "binary_tags": "|".join(bf.get("binary_tags", [])) if isinstance(bf, dict) else "",
        })

    _write_csv(
        os.path.join(EXPORT_DIR, "session_labels.csv"),
        label_rows,
        ["session_id", "label_id", "label_name", "num_downloads",
         "has_miner", "has_botnet", "has_downloader", "has_destructive",
         "has_recon", "has_credential_access", "has_rat", "has_go_binary",
         "has_packed", "max_priority", "binary_labels", "binary_tags"],
    )

    print("    Label distribution:")
    for name, count in sorted(label_dist.items(), key=lambda x: x[1], reverse=True):
        print("      %s: %d" % (name, count))

    # ------------------------------------------------------------------
    # 5. sessions_mitre.csv — MITRE ATT&CK annotations per session
    # ------------------------------------------------------------------
    print("  [5/8] sessions_mitre.csv")
    mitre_cols = ["session_id"] + get_mitre_feature_columns() + ["mitre_severity_tier", "mitre_technique_ids"]
    mitre_rows = []
    for s in sessions_with_cmds:
        annotation = s.get("mitre_annotation", {})
        flat = annotation_to_flat_dict(annotation)
        flat["session_id"] = s["session_id"]
        mitre_rows.append(flat)

    _write_csv(
        os.path.join(EXPORT_DIR, "sessions_mitre.csv"),
        mitre_rows,
        mitre_cols,
    )

    # ------------------------------------------------------------------
    # 6. sessions_complete.csv — EVERYTHING joined, ready for training
    # ------------------------------------------------------------------
    print("  [6/8] sessions_complete.csv")

    # Build deep feature lookup
    deep_lookup = {}
    for sha, entry in merged_features.items():
        deep_lookup[sha] = get_feature_vector(entry)

    # Build the complete rows
    complete_cols = (
        ["session_id", "src_ip", "num_commands", "duration_sec", "commands"]
        + get_mitre_feature_columns()
        + ["mitre_severity_tier", "mitre_technique_ids"]
        + ["num_downloads", "download_shas"]
        + DEEP_FEATURE_COLUMNS
        + ["label_id", "label_name"]
    )

    complete_rows = []
    for s in sessions_with_cmds:
        label_id, label_name = _assign_label(s)
        cmds = s.get("commands", [])
        annotation = s.get("mitre_annotation", {})
        mitre_flat = annotation_to_flat_dict(annotation)

        # Aggregate deep features across all binaries in session
        shas = s.get("download_shas", [])
        agg_deep = [0.0] * len(DEEP_FEATURE_COLUMNS)
        for sha in shas:
            vec = deep_lookup.get(sha)
            if vec:
                for j in range(len(agg_deep)):
                    agg_deep[j] = max(agg_deep[j], vec[j])

        row = {
            "session_id": s["session_id"],
            "src_ip": s.get("src_ip", ""),
            "num_commands": len(cmds),
            "duration_sec": round(
                (s.get("last_ts") or 0) - (s.get("first_ts") or 0), 1
            ) if s.get("first_ts") and s.get("last_ts") else 0,
            "commands": " ;; ".join(cmds),
            "num_downloads": len(shas),
            "download_shas": "|".join(shas),
            "label_id": label_id,
            "label_name": label_name,
        }

        # Add MITRE features
        row.update(mitre_flat)

        # Add deep binary features
        for j, col in enumerate(DEEP_FEATURE_COLUMNS):
            row[col] = agg_deep[j]

        complete_rows.append(row)

    _write_csv(
        os.path.join(EXPORT_DIR, "sessions_complete.csv"),
        complete_rows,
        complete_cols,
    )

    # ------------------------------------------------------------------
    # 7. mitre_knowledge_base.json — Portable ATT&CK pattern definitions
    # ------------------------------------------------------------------
    print("  [7/8] mitre_knowledge_base.json")
    kb = {
        "description": "MITRE ATT&CK command-to-technique mapping for SSH honeypot analysis",
        "version": "1.0",
        "generated": datetime.now(timezone.utc).isoformat(),
        "tactics": TACTICS,
        "tactic_order": TACTIC_NAMES,
        "command_patterns": [
            {k: v for k, v in p.items() if k != "_compiled"}
            for p in ATTACK_PATTERNS
        ],
        "binary_tag_mappings": BINARY_TAG_TO_TECHNIQUE,
        "stats": get_knowledge_base_stats(),
    }

    kb_path = os.path.join(EXPORT_DIR, "mitre_knowledge_base.json")
    with open(kb_path, "w") as f:
        json.dump(kb, f, indent=2)
    print("  -> mitre_knowledge_base.json (%d patterns)" % len(ATTACK_PATTERNS))

    # ------------------------------------------------------------------
    # 8. export_manifest.json — Metadata
    # ------------------------------------------------------------------
    print("  [8/8] export_manifest.json")

    # Collect MITRE stats
    severity_dist = {}
    kill_chain_dist = {}
    for s in sessions_with_cmds:
        ann = s.get("mitre_annotation", {})
        tier = ann.get("severity_tier", "none")
        severity_dist[tier] = severity_dist.get(tier, 0) + 1
        kc = ann.get("kill_chain_score", 0)
        kill_chain_dist[str(kc)] = kill_chain_dist.get(str(kc), 0) + 1

    manifest = {
        "description": "AdaptiveShield portable dataset export",
        "generated": datetime.now(timezone.utc).isoformat(),
        "source": "VM binary analysis environment (VirtualBox)",
        "target": "Host machine for neural model training (RTX 3050, 16GB RAM)",
        "files": {
            "sessions.csv": {
                "rows": len(session_rows),
                "description": "All sessions with commands, timestamps, IPs",
                "key_column": "session_id",
            },
            "downloads.csv": {
                "rows": len(dl_rows),
                "description": "All Cowrie download/upload events linking sessions to SHA256s",
                "key_columns": ["session_id", "sha256"],
            },
            "binary_features.csv": {
                "rows": len(bf_rows),
                "columns": len(csv_cols),
                "description": "All binary SHA256s with triage+Ghidra+angr+script features",
                "key_column": "sha256",
                "feature_groups": {
                    "triage": "Phase 1 lightweight static analysis",
                    "ghidra": "Phase 2 deep static analysis (Ghidra headless)",
                    "angr": "Phase 3 symbolic execution",
                    "script": "Shell script behavioral analysis",
                    "deep/has": "Derived cross-source features",
                },
            },
            "session_labels.csv": {
                "rows": len(label_rows),
                "description": "Per-session labels derived from binary analysis",
                "label_distribution": label_dist,
                "label_scheme": {
                    "0": "Safe - no malware indicators",
                    "1": "Recon - reconnaissance/scanning",
                    "2": "Downloader - malware download/dropper/miner",
                    "3": "Exploit - credential theft/RAT/packed",
                    "4": "Destructive - ransomware/data destruction",
                    "5": "ADVANCED_APT - multi-capability Go binary APT",
                },
            },
            "sessions_mitre.csv": {
                "rows": len(mitre_rows),
                "columns": len(mitre_cols),
                "description": "MITRE ATT&CK annotations per session (21 numeric features + metadata)",
                "feature_columns": get_mitre_feature_columns(),
                "severity_distribution": severity_dist,
                "kill_chain_distribution": kill_chain_dist,
            },
            "sessions_complete.csv": {
                "rows": len(complete_rows),
                "columns": len(complete_cols),
                "description": "COMPLETE training-ready dataset: commands + MITRE features + binary features + labels",
                "column_groups": {
                    "session_meta": ["session_id", "src_ip", "num_commands", "duration_sec"],
                    "raw_text": ["commands"],
                    "mitre_features": get_mitre_feature_columns(),
                    "binary_deep_features": DEEP_FEATURE_COLUMNS,
                    "labels": ["label_id", "label_name"],
                },
            },
            "mitre_knowledge_base.json": {
                "patterns": len(ATTACK_PATTERNS),
                "description": "Portable MITRE ATT&CK pattern-to-technique mapping",
            },
        },
        "data_provenance": {
            "honeypot_duration_days": 63,
            "cowrie_log_files": len(glob(os.path.join(COWRIE_LOG_DIR, "cowrie.json*"))),
            "total_sessions": len(sessions),
            "sessions_with_commands": len(sessions_with_cmds),
            "total_download_events": len(downloads),
            "unique_binaries": len(merged_features),
            "binaries_with_ghidra": sum(1 for e in merged_features.values() if e.get("has_ghidra_results")),
            "binaries_with_angr": sum(1 for e in merged_features.values() if e.get("has_angr_results")),
        },
        "recommended_next_steps": [
            "Load sessions_complete.csv on host machine",
            "Build character/token embedding -> BiLSTM for command text",
            "Concatenate MITRE tactic vector (14d) + binary features (79d) as structured input",
            "Use cost-sensitive loss: higher penalty for missing APT/Destructive classes",
            "Train with PyTorch on RTX 3050 (CUDA available)",
            "Consider class 0 (Safe) downsampling or focal loss to handle 95% class imbalance",
        ],
    }

    manifest_path = os.path.join(EXPORT_DIR, "export_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2, default=str)
    print("  -> export_manifest.json")

    return manifest


# ===================================================================
# Main
# ===================================================================

def main():
    print("=" * 70)
    print("AdaptiveShield — Portable Dataset Export")
    print("=" * 70)
    t0 = time.time()

    # Step 1: Correlate
    correlated = step1_correlate()

    # Step 2: Enrich with binary features
    enriched = step2_enrich(correlated)

    # Step 3: Load deep features
    merged = step3_load_deep_features()

    # Step 4: MITRE annotate
    sessions = enriched["sessions"]
    # Filter to sessions with commands for annotation
    sessions_with_cmds = [s for s in sessions if s.get("commands")]
    sessions_with_cmds = step4_mitre_annotate(sessions_with_cmds)

    # Step 5: Labels are assigned inline during export

    # Step 6: Export everything
    manifest = step6_export(
        sessions_with_cmds,
        enriched["downloads"],
        merged,
    )

    elapsed = time.time() - t0
    print("\n" + "=" * 70)
    print("Export complete in %.1f seconds" % elapsed)
    print("Output directory: %s" % EXPORT_DIR)
    print("=" * 70)

    # Print file sizes
    print("\nFile sizes:")
    for fname in sorted(os.listdir(EXPORT_DIR)):
        fpath = os.path.join(EXPORT_DIR, fname)
        size = os.path.getsize(fpath)
        if size > 1024 * 1024:
            print("  %s: %.1f MB" % (fname, size / 1024 / 1024))
        elif size > 1024:
            print("  %s: %.1f KB" % (fname, size / 1024))
        else:
            print("  %s: %d bytes" % (fname, size))


if __name__ == "__main__":
    main()
