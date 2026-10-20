"""
External Corpus Builder — the single canonical builder for public datasets.

One pass: parse sources -> classify with the shared engine
(relabel_sessions.classify) -> dedup -> write. Supersedes the v1/v2 builders
(kept as reference in verify/relabeling/).

Sources (under data/external/, the shared-folder symlink):
  csic2010/    CSIC 2010 v02 CSVs (HTTP normal/anomalous)
  ssh_shell_attacks/  ML4Net 230K (ssh_attacks.csv converted on Windows host)
  shell_attack_evolution/  zyw-286 SRDS-2025 Cowrie session JSONLs
  nl2bash/     NL2Bash real benign commands

Label policy:
  csic2010:     static probe -> Recon; dynamic payload -> Exploit;
                native-anom quiet rows floor to Recon; native-norm -> Safe
  nl2bash:      Safe (curated benign)
  zyw + ml4net: shared content-signal engine

Hostnames: raw source text is preserved (no localhost rewriting). Host tokens
are constant within CSIC across BOTH classes (zero discriminative power),
runtime envelopes are reconstructed from the live request where paths and
payloads carry the signal, and clean_payload() already strips HTTP
method/version boilerplate at train time.

Output: data/exports/unified_external_corpus.csv (+ stats JSON).
"""
import ast
import csv
import json
import re
import sys
from pathlib import Path
from collections import Counter

try:
    csv.field_size_limit(64 * 1024 * 1024)
except OverflowError:
    csv.field_size_limit(2 ** 31 - 1)

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from relabel_sessions import (  # shared engine — single source of truth
    SIG_APT, SIG_DOWNLOADER, SIG_EXPLOIT, SIG_RECON, SIG_DESTRUCTIVE,
    INFECTION_CHAIN, first_match, CLASS_NAMES,
)

ROOT = Path(__file__).resolve().parents[3]
EXT_BASE = ROOT / "data" / "external"
OUT_DIR = ROOT / "data" / "exports"
OUT_CSV = OUT_DIR / "unified_external_corpus.csv"
STATS_JSON = OUT_DIR / "unified_external_corpus_stats.json"

# ------------------------------------------------------------------ classification
SQLI_MARKERS = re.compile(
    r"union\s+select|or\s+1=1|'\s*or\s*'|drop\s+table|insert\s+into|"
    r"select\s+[\w*%\s]+\s+from|%27|--\s*$|/\*.*\*/", re.I)
STATIC_PROBE_HINTS = re.compile(
    r"\.(bak|old|Inc|nsf|java|jsp\.\w+)$|/\d{6,}(\.\w+)*$|"
    r"robots\.txt|\.git|\.svn|phpinfo|server-status|wp-admin|wp-login|"
    r"web\.config|/admin|manager/|backup|changelog|\.rar$|\.zip$|\.tgz$", re.I)


def url_decode(text):
    from urllib.parse import unquote_plus
    try:
        return unquote_plus(str(text))
    except Exception:
        return str(text)


# ------------------------------------------------------------------ classification
def classify_shared(commands_text):
    """Same priority engine as the Azure relabeler."""
    hit = first_match(SIG_APT, commands_text)
    if hit:
        return 5, f"apt:{hit}"
    if SIG_DOWNLOADER[3][1].search(commands_text):  # devtcp_stager
        return 2, "downloader:devtcp_stager"
    hit = first_match(SIG_EXPLOIT, commands_text)
    if hit:
        return 3, f"exploit:{hit}"
    hit = first_match(SIG_DOWNLOADER, commands_text)
    if hit:
        return 2, f"downloader:{hit}"
    if not INFECTION_CHAIN.search(commands_text):
        hit = first_match(SIG_DESTRUCTIVE, commands_text)
        if hit:
            return 4, f"destructive:{hit}"
    hit = first_match(SIG_RECON, commands_text)
    if hit:
        return 1, f"recon:{hit}"
    return 0, "quiet:safe"


def classify_http(url, body, commands_full):
    """CSIC split rule: static probe -> Recon; dynamic payload -> Exploit."""
    target = url_decode(f"{url} {body}")
    if STATIC_PROBE_HINTS.search(url) and not SQLI_MARKERS.search(target):
        return 1, "http_static_probe"
    if SQLI_MARKERS.search(target):
        return 3, "http_dynamic_payload"
    return classify_shared(commands_full)


# ------------------------------------------------------------------ row emission
rows_written = 0
per_source = {}

FIELDS = ["session_id", "source", "commands", "native_label",
          "mapped_label_id", "mapped_label_name", "label_source",
          "is_http", "attack_techniques"]


def emit(writer, session_id, source, commands, native_label, mapped_id,
         label_source, is_http=False, techniques=""):
    global rows_written
    if mapped_id is None:
        return False
    cmd_str = commands if isinstance(commands, str) else "; ".join(commands)
    if not cmd_str or not cmd_str.strip():
        return False
    writer.writerow({
        "session_id": session_id,
        "source": source,
        "commands": cmd_str,
        "native_label": native_label,
        "mapped_label_id": mapped_id,
        "mapped_label_name": CLASS_NAMES[mapped_id],
        "label_source": label_source,
        "is_http": int(is_http),
        "attack_techniques": techniques,
    })
    rows_written += 1
    per_source.setdefault(source, Counter())[CLASS_NAMES[mapped_id]] += 1
    return True


# ------------------------------------------------------------------ loaders
def load_csic(writer):
    base = EXT_BASE / "csic2010"
    files = [
        ("output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_anom.csv", "anom"),
        ("output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_norm.csv", "norm"),
    ]
    n = 0
    for fname, kind in files:
        path = base / fname
        if not path.exists():
            print(f"  [csic] MISSING: {fname}")
            continue
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f, quotechar='"', escapechar='\\')
            for i, row in enumerate(reader):
                method = (row.get("method") or "GET").strip()
                url = (row.get("url") or "/").strip()
                proto = (row.get("protocol") or "HTTP/1.1").strip()
                headers = []
                for h, key in [("Host", "host"), ("User-Agent", "userAgent"),
                               ("Accept", "accept"), ("Connection", "connection"),
                               ("Content-Type", "contentType")]:
                    v = row.get(key)
                    if v and str(v).lower() != "null":
                        headers.append(f"{h}: {v}")
                payload = row.get("payload")
                raw = f"{method} {url} {proto}"
                if headers:
                    raw += "; " + "; ".join(headers)
                if payload and str(payload).lower() != "null":
                    raw += "; " + str(payload)
                raw = raw.strip()

                if kind == "anom":
                    segs = [s for s in raw.split("; ") if "=" in s]
                    body = segs[-1] if segs else ""
                    lab, why = classify_http(url, body, raw)
                    if lab == 0:
                        lab, why = 1, "csic_anom_floor:recon"
                else:
                    lab, why = 0, "csic_native_norm"
                emit(writer, f"csic_{kind}_{i}", "csic2010", raw, kind, lab,
                     f"v2engine:{why}", is_http=True)
                n += 1
    print(f"  [csic] rows written: {n}")


def load_zyw286(writer):
    base = EXT_BASE / "shell_attack_evolution" / "sessions"
    kept = 0
    for fname in ["2021_2022.jsonl", "2024.jsonl"]:
        path = base / fname
        if not path.exists():
            print(f"  [zyw286] MISSING: {fname}")
            continue
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                cmds = r.get("commands") or []
                if not cmds:
                    continue
                text = "; ".join(cmds)
                lab, why = classify_shared(text)
                techs = "|".join(r.get("attack_techniques") or [])
                emit(writer, f"zyw_{r.get('session_id', kept)}",
                     "shell_attack_evolution", text, techs, lab,
                     f"v2engine:{why}", techniques=techs)
                kept += 1
    print(f"  [zyw286] sessions written: {kept}")


def _parse_fingerprint(fp_raw):
    """CSV round-trip gives numpy-style repr like \"['A' 'B']\" — valid Python
    via implicit string concatenation, so literal_eval would yield ['AB'].
    Insert commas first, then sanity-check against known intents."""
    if not isinstance(fp_raw, str):
        return fp_raw if isinstance(fp_raw, (list, tuple)) else []
    s = fp_raw.strip()
    if s.startswith("[") and s.endswith("]") and "," not in s:
        s = re.sub(r"'\s+'", "', '", s)
    try:
        fp = ast.literal_eval(s)
        if not isinstance(fp, (list, tuple)):
            fp = [fp_raw]
        known = {"Harmless", "Discovery", "Execution", "Defense Evasion",
                 "Persistence", "Impact", "Other"}
        if not all(str(x).strip() in known for x in fp):
            inner = fp_raw.strip().strip("[]")
            fp = [p.strip().strip("'\"") for p in inner.split() if p.strip()]
    except (ValueError, SyntaxError):
        inner = fp_raw.strip().strip("[]")
        fp = [p.strip().strip("'\"") for p in inner.split() if p.strip()] or [fp_raw]
    return fp


def load_ml4net(writer):
    base = EXT_BASE / "ssh_shell_attacks" / "data" / "raw"
    csv_path = base / "ssh_attacks.csv"
    parquet_path = base / "ssh_attacks.parquet"
    df = None
    if csv_path.exists():
        import pandas as pd
        df = pd.read_csv(csv_path)
    elif parquet_path.exists():
        try:
            import pandas as pd
            df = pd.read_parquet(parquet_path)
        except Exception as e:
            print(f"  [ml4net] parquet unreadable here ({type(e).__name__}); convert on Windows host.")
            return 0
    else:
        print("  [ml4net] MISSING both csv and parquet")
        return 0
    if df is None:
        return 0

    ML4NET_HINTS = {
        "Harmless": "harmless native", "Discovery": "discovery native",
        "Execution": "execution native", "Defense Evasion": "evasion native",
        "Impact": "impact native", "Persistence": "persistence native",
    }
    kept = 0
    for r in df.to_dict("records"):
        fp = _parse_fingerprint(r.get("Set_Fingerprint") or [])
        if not fp:
            continue
        session = str(r.get("full_session") or "")
        if not session.strip():
            continue
        lab, why = classify_shared(session)
        hint = next((ML4NET_HINTS.get(str(x).strip()) for x in fp
                     if str(x).strip() in ML4NET_HINTS), "mixed")
        emit(writer, f"ml4net_{r.get('session_id', kept)}", "ssh_shell_attacks",
             session, "|".join(str(x) for x in fp), lab,
             f"v2engine:{why}; native={hint}")
        kept += 1
    print(f"  [ml4net] sessions written: {kept}")


def load_nl2bash(writer):
    path = EXT_BASE / "nl2bash" / "repo" / "data" / "bash" / "all.cm"
    if not path.exists():
        print("  [nl2bash] MISSING")
        return 0
    kept = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            cmd = line.strip()
            if not cmd or len(cmd) < 3:
                continue
            emit(writer, f"nl2bash_{i}", "nl2bash", cmd, "benign", 0, "nl2bash_benign")
            kept += 1
    print(f"  [nl2bash] commands written: {kept}")


# ------------------------------------------------------------------ main
def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print("Building unified external corpus (canonical v2 policy)...")
    tmp = OUT_CSV.with_suffix(".tmp")
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        load_csic(writer)
        load_zyw286(writer)
        load_ml4net(writer)
        load_nl2bash(writer)

    print("Deduplicating exact duplicates within source...")
    seen = set()
    dedup = OUT_CSV.with_suffix(".dedup")
    n_out = 0
    with open(tmp, newline="", encoding="utf-8") as f, \
         open(dedup, "w", newline="", encoding="utf-8") as out:
        reader = csv.DictReader(f)
        w = csv.DictWriter(out, fieldnames=FIELDS)
        w.writeheader()
        for row in reader:
            key = (row["source"], row["commands"][:512])
            if key in seen:
                continue
            seen.add(key)
            w.writerow(row)
            n_out += 1
    dedup.replace(OUT_CSV)
    tmp.unlink(missing_ok=True)

    with open(STATS_JSON, "w") as f:
        json.dump({
            "total_rows": n_out,
            "per_source_class": {s: dict(d) for s, d in per_source.items()},
        }, f, indent=2)

    print(f"\nUnified corpus: {OUT_CSV}")
    print(f"Total rows (deduped): {n_out}")
    print("\nPer-source class distribution:")
    for src, dist in per_source.items():
        total = sum(dist.values())
        print(f"  {src} (total {total}):")
        for name in CLASS_NAMES:
            if name in dist:
                print(f"    {name:14s} {dist[name]:7d}  ({100*dist[name]/total:.1f}%)")


if __name__ == "__main__":
    main()