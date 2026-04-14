from typing import Dict, List, Optional

from .dataset import (
    DEFAULT_FEATURE_COLUMNS,
    _count_patterns,
    _is_private_ip,
    _normalize_commands,
    _parse_list,
    _safe_float,
    _safe_int,
    CREDENTIAL_PATTERNS,
    PERSISTENCE_PATTERNS,
    PRIVILEGED_PATTERNS,
    SUSPICIOUS_PATTERNS,
)
from .model import load_insider_model


def build_insider_feature_vector(session: Dict[str, any], feature_names: Optional[List[str]] = None) -> List[float]:
    if feature_names is None:
        feature_names = DEFAULT_FEATURE_COLUMNS

    num_commands = 0
    duration_sec = 0.0
    num_downloads = 0
    has_downloads = 0

    commands = session.get("commands", [])
    if isinstance(commands, str):
        commands = [commands] if commands else []
    if isinstance(commands, list):
        num_commands = len(commands)

    if "num_commands" in session:
        num_commands = _safe_int(session.get("num_commands"))

    first_ts = _safe_float(session.get("first_ts"))
    last_ts = _safe_float(session.get("last_ts"))
    if first_ts and last_ts and last_ts >= first_ts:
        duration_sec = float(last_ts - first_ts)
    elif "duration_sec" in session:
        duration_sec = _safe_float(session.get("duration_sec"))

    if "num_downloads" in session:
        num_downloads = _safe_int(session.get("num_downloads"))
    elif "download_shas" in session:
        downloads = session.get("download_shas")
        if isinstance(downloads, list):
            num_downloads = len(downloads)
        else:
            num_downloads = len(_parse_list(str(downloads)))

    has_downloads = 1 if num_downloads > 0 else 0
    command_density = num_commands / max(duration_sec, 1.0)
    normalized_commands = _normalize_commands(session.get("commands"))
    privileged_count = _count_patterns(normalized_commands, PRIVILEGED_PATTERNS)
    persistence_count = _count_patterns(normalized_commands, PERSISTENCE_PATTERNS)
    credential_count = _count_patterns(normalized_commands, CREDENTIAL_PATTERNS)
    suspicious_count = _count_patterns(normalized_commands, SUSPICIOUS_PATTERNS)
    src_ip_internal = float(1 if _is_private_ip(session.get("src_ip")) else 0)
    short_session = float(1 if duration_sec <= 5.0 else 0)
    low_noise_session = float(1 if num_downloads == 0 and num_commands <= 3 else 0)

    raw_values = {
        "num_commands": float(num_commands),
        "duration_sec": float(duration_sec),
        "command_density": float(command_density),
        "num_downloads": float(num_downloads),
        "has_downloads": float(has_downloads),
        "src_ip_internal": src_ip_internal,
        "short_session": short_session,
        "low_noise_session": low_noise_session,
        "privileged_command_count": float(privileged_count),
        "persistence_command_count": float(persistence_count),
        "credential_command_count": float(credential_count),
        "suspicious_command_count": float(suspicious_count),
        "triage_priority": _safe_float(session.get("triage_priority")),
        "triage_is_go": float(1 if _safe_float(session.get("triage_is_go")) else 0),
        "triage_is_packed": float(1 if _safe_float(session.get("triage_is_packed")) else 0),
        "triage_is_stripped": float(1 if _safe_float(session.get("triage_is_stripped")) else 0),
        "triage_is_dll": float(1 if _safe_float(session.get("triage_is_dll")) else 0),
        "triage_is_static": float(1 if _safe_float(session.get("triage_is_static")) else 0),
        "triage_score_mining": _safe_float(session.get("triage_score_mining")),
        "triage_score_botnet": _safe_float(session.get("triage_score_botnet")),
        "triage_score_recon": _safe_float(session.get("triage_score_recon")),
        "triage_score_destructive": _safe_float(session.get("triage_score_destructive")),
        "mitre_severity_max": _safe_float(session.get("mitre_severity_max")),
        "mitre_severity_weighted": _safe_float(session.get("mitre_severity_weighted")),
        "mitre_kill_chain_score": _safe_float(session.get("mitre_kill_chain_score")),
        "mitre_matched_commands": float(_safe_int(session.get("mitre_matched_commands"))),
        "has_ghidra_results": float(1 if _safe_int(session.get("has_ghidra_results")) else 0),
        "has_angr_results": float(1 if _safe_int(session.get("has_angr_results")) else 0),
        "has_script_results": float(1 if _safe_int(session.get("has_script_results")) else 0),
    }

    return [raw_values[col] for col in feature_names]


def predict_insider(model_bundle: Dict[str, any], session: Dict[str, any], threshold: float = 0.5) -> Dict[str, any]:
    feature_vector = build_insider_feature_vector(session, model_bundle["feature_names"])
    scaler = model_bundle["scaler"]
    model = model_bundle["model"]
    X = scaler.transform([feature_vector])
    probs = model.predict_proba(X)
    score = float(probs[0][1] if probs.shape[1] > 1 else probs[0][0])
    label = "INSIDER_LIKE" if score >= threshold else "NORMAL"
    return {
        "label": label,
        "score": score,
        "threshold": threshold,
        "raw_vector": feature_vector,
    }


def load_and_predict(model_path: str, session: Dict[str, any], threshold: float = 0.5) -> Dict[str, any]:
    model_bundle = load_insider_model(model_path)
    return predict_insider(model_bundle, session, threshold)
