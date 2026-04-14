import csv
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

CERT_LOGIN_FEATURES = "login_features.csv"
CERT_INSIDER_LOGIN_ALERTS = "insider_login_alerts.csv"
CERT_FINAL_INSIDER_RISK = "final_insider_risk.csv"
CERT_DEVICE_ALERTS = "insider_device_alerts.csv"
CERT_EMAIL_ALERTS = "insider_email_alerts.csv"
CERT_FILE_ALERTS = "insider_file_alerts.csv"
CERT_HTTP_ALERTS = "insider_http_alerts.csv"

CERT_LOGON_CSV = "logon.csv"
CERT_DEVICE_CSV = "device.csv"
CERT_EMAIL_CSV = "email.csv"
CERT_FILE_CSV = "file.csv"
CERT_PSYCHOMETRIC_CSV = "psychometric.csv"

START_ACTIONS = {"logon", "connect"}
STOP_ACTIONS = {"logoff", "disconnect"}


def _safe_int(value: Optional[str]) -> int:
    try:
        return int(float(value))
    except Exception:
        return 0


def _safe_float(value: Optional[str]) -> float:
    try:
        return float(value)
    except Exception:
        return 0.0


def _safe_str(value: Optional[str]) -> str:
    return "" if value is None else str(value).strip()


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip()
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S.%f",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _load_csv(path: str, max_rows: Optional[int] = None) -> List[Dict[str, str]]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"CERT CSV file not found: {path}")

    rows = []
    with open(path, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for index, row in enumerate(reader):
            rows.append({k: _safe_str(v) for k, v in row.items()})
            if max_rows is not None and index + 1 >= max_rows:
                break
    return rows


def parse_login_features(path: str, max_rows: Optional[int] = None) -> List[Dict[str, Any]]:
    rows = _load_csv(path, max_rows)
    parsed = []
    for row in rows:
        parsed.append({
            "user": row.get("user", ""),
            "datetime": row.get("datetime", ""),
            "hour": _safe_int(row.get("hour")),
            "login_count": _safe_int(row.get("login_count")),
            "pc_variety": _safe_int(row.get("pc_variety")),
            "label": row.get("label", ""),
            "risk_score": _safe_float(row.get("risk_score")),
            "explanation": row.get("explanation", ""),
        })
    return parsed


def parse_alert_rows(path: str, max_rows: Optional[int] = None) -> List[Dict[str, Any]]:
    rows = _load_csv(path, max_rows)
    parsed = []
    for row in rows:
        parsed.append({
            "user": row.get("user", ""),
            "datetime": row.get("datetime", ""),
            "label": row.get("label", ""),
            "risk_score": _safe_float(row.get("risk_score")),
            "explanation": row.get("explanation", ""),
        })
    return parsed


def parse_psychometric(path: str) -> Dict[str, Dict[str, Any]]:
    rows = _load_csv(path)
    output: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        user_id = row.get("user_id", "")
        if not user_id:
            continue
        output[user_id] = {
            "psych_O": _safe_int(row.get("O")),
            "psych_C": _safe_int(row.get("C")),
            "psych_E": _safe_int(row.get("E")),
            "psych_A": _safe_int(row.get("A")),
            "psych_N": _safe_int(row.get("N")),
        }
    return output


def _build_sessions_from_events(
    path: str,
    source: str,
    max_rows: Optional[int] = None,
) -> List[Dict[str, Any]]:
    rows = _load_csv(path, max_rows)
    events = []
    for row in rows:
        dt = _parse_datetime(row.get("date"))
        if dt is None:
            continue
        user_id = row.get("user", "") or row.get("user_id", "")
        if not user_id:
            continue
        pc = row.get("pc", "")
        activity = row.get("activity", "").strip()
        if not activity:
            continue
        events.append({
            "user_id": user_id,
            "pc": pc,
            "activity": activity,
            "datetime": dt,
            "raw": row,
        })

    events.sort(key=lambda item: (item["user_id"], item["pc"], item["datetime"]))
    active_sessions: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    output: List[Dict[str, Any]] = []

    for event in events:
        key = (event["user_id"], event["pc"])
        action = event["activity"].strip().lower()
        if action in START_ACTIONS:
            active_sessions.setdefault(key, []).append(event)
            continue

        if action in STOP_ACTIONS:
            if active_sessions.get(key):
                start_event = active_sessions[key].pop(0)
                start_dt = start_event["datetime"]
                end_dt = event["datetime"]
                duration = max(0.0, (end_dt - start_dt).total_seconds())
                session_id = f"{source}_{event['user_id']}_{event['pc']}_{start_dt.strftime('%Y%m%d%H%M%S')}"
                output.append({
                    "session_id": session_id,
                    "source": source,
                    "user_id": event["user_id"],
                    "pc": event["pc"],
                    "start_time": start_dt.isoformat(),
                    "end_time": end_dt.isoformat(),
                    "duration_sec": duration,
                    "start_hour": float(start_dt.hour),
                    "start_weekday": float(start_dt.weekday()),
                    "event_count": 2.0,
                    "activity_type": f"{start_event['activity'].lower()}_to_{action}",
                    "internal_source": 1.0,
                    "label": 0,
                    "baseline_type": "internal_user",
                })
            continue

    return output


def build_cert_internal_baseline_sessions(
    cert_dir: str,
    max_rows: Optional[int] = None,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    logon_path = os.path.join(cert_dir, CERT_LOGON_CSV)
    device_path = os.path.join(cert_dir, CERT_DEVICE_CSV)
    psych_path = os.path.join(cert_dir, CERT_PSYCHOMETRIC_CSV)

    if not os.path.exists(logon_path) and not os.path.exists(device_path):
        raise FileNotFoundError(
            f"No internal baseline files found in {cert_dir}. Expected {CERT_LOGON_CSV} or {CERT_DEVICE_CSV}."
        )

    psychometric = parse_psychometric(psych_path) if os.path.exists(psych_path) else {}
    sessions: List[Dict[str, Any]] = []

    if os.path.exists(logon_path):
        sessions.extend(_build_sessions_from_events(logon_path, "logon", max_rows))
    if os.path.exists(device_path):
        sessions.extend(_build_sessions_from_events(device_path, "device", max_rows))

    user_pcs: Dict[str, set] = {}
    for session in sessions:
        user_pcs.setdefault(session["user_id"], set()).add(session["pc"])

    for session in sessions:
        user_id = session["user_id"]
        session["pc_variety"] = float(len(user_pcs.get(user_id, set())))
        traits = psychometric.get(user_id, {})
        session.update(traits)
        session["session_label"] = "normal"

    feature_names = [
        "session_id",
        "source",
        "user_id",
        "pc",
        "start_time",
        "end_time",
        "duration_sec",
        "start_hour",
        "start_weekday",
        "event_count",
        "activity_type",
        "internal_source",
        "label",
        "baseline_type",
        "pc_variety",
        "psych_O",
        "psych_C",
        "psych_E",
        "psych_A",
        "psych_N",
        "session_label",
    ]
    return sessions, feature_names


def build_cert_baseline_dataset(
    cert_dir: str,
    max_rows: Optional[int] = None,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    internal_path = os.path.join(cert_dir, CERT_LOGON_CSV)
    if os.path.exists(internal_path):
        return build_cert_internal_baseline_sessions(cert_dir, max_rows)

    login_path = os.path.join(cert_dir, CERT_LOGIN_FEATURES)
    login_rows = parse_login_features(login_path, max_rows)

    alert_paths = {
        "login": os.path.join(cert_dir, CERT_INSIDER_LOGIN_ALERTS),
        "device": os.path.join(cert_dir, CERT_DEVICE_ALERTS),
        "email": os.path.join(cert_dir, CERT_EMAIL_ALERTS),
        "file": os.path.join(cert_dir, CERT_FILE_ALERTS),
        "http": os.path.join(cert_dir, CERT_HTTP_ALERTS),
    }

    alert_indices = {}
    for alert_type, path in alert_paths.items():
        if os.path.exists(path):
            alert_rows = parse_alert_rows(path, max_rows)
            alert_indices[alert_type] = _index_rows(alert_rows, ["user", "datetime"])
        else:
            alert_indices[alert_type] = {}

    final_risk_path = os.path.join(cert_dir, CERT_FINAL_INSIDER_RISK)
    final_risk_rows = []
    if os.path.exists(final_risk_path):
        final_risk_rows = _load_csv(final_risk_path, max_rows)
    final_risk_index = _index_rows(final_risk_rows, ["user"])

    output_rows: List[Dict[str, Any]] = []
    feature_names = [
        "user",
        "datetime",
        "hour",
        "login_count",
        "pc_variety",
        "login_risk_score",
        "login_label",
        "final_insider_risk",
        "final_risk_level",
        "device_alerts_count",
        "email_alerts_count",
        "file_alerts_count",
        "http_alerts_count",
        "device_risk_score",
        "email_risk_score",
        "file_risk_score",
        "http_risk_score",
        "combined_risk_score",
        "baseline_label",
    ]

    for row in login_rows:
        user = row["user"]
        dt = row["datetime"]
        record = {
            "user": user,
            "datetime": dt,
            "hour": row["hour"],
            "login_count": row["login_count"],
            "pc_variety": row["pc_variety"],
            "login_risk_score": row["risk_score"],
            "login_label": row["label"],
            "final_insider_risk": None,
            "final_risk_level": None,
            "device_alerts_count": 0,
            "email_alerts_count": 0,
            "file_alerts_count": 0,
            "http_alerts_count": 0,
            "device_risk_score": 0.0,
            "email_risk_score": 0.0,
            "file_risk_score": 0.0,
            "http_risk_score": 0.0,
            "combined_risk_score": row["risk_score"],
            "baseline_label": 0,
        }

        for alert_type, index in alert_indices.items():
            key = (user, dt)
            matches = index.get(key, []) if index else []
            if matches:
                count = len(matches)
                total_risk = sum(m.get("risk_score", 0.0) for m in matches)
                record[f"{alert_type}_alerts_count"] = count
                record[f"{alert_type}_risk_score"] = total_risk
                record["combined_risk_score"] += total_risk

        final_matches = final_risk_index.get((user,), [])
        if final_matches:
            final_match = final_matches[0]
            record["final_insider_risk"] = final_match.get("final_risk")
            record["final_risk_level"] = final_match.get("risk_level")
            record["combined_risk_score"] += _safe_float(final_match.get("final_risk"))

        if row["label"].lower() != "normal" or record["combined_risk_score"] > 0.0:
            record["baseline_label"] = 1

        output_rows.append(record)

    return output_rows, feature_names


def _index_rows(rows: List[Dict[str, Any]], key_fields: List[str]) -> Dict[Tuple[str, ...], List[Dict[str, Any]]]:
    index: Dict[Tuple[str, ...], List[Dict[str, Any]]] = {}
    for row in rows:
        key = tuple(row.get(field, "") for field in key_fields)
        index.setdefault(key, []).append(row)
    return index


def save_cert_dataset(rows: List[Dict[str, Any]], output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    if not rows:
        raise ValueError("No CERT rows available to save.")

    fieldnames = list(rows[0].keys())
    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
