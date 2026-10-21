"""
Training Corpus Assembly — builds the final stratified training splits.

Merges:
  - data/exports/sessions_complete_v3.csv   (Azure, engine-labeled + binary truth)
  - data/exports/unified_external_corpus.csv (CSIC + zyw-286 + ML4Net + NL2Bash)
  - HttpParamsDataset payloads (sqli/xss/cmdi/path-traversal -> Exploit;
    wrapped in a minimal HTTP envelope since runtime sees envelopes)
  - data/processed/synthetic_batches.csv    (LLM synthetic minority edge cases)
  - data/exports/tier0_annotation_sheet_LABELED.csv (SOC-adjudicated Gold Ground Truth)

Architecture:
  - Azure deduplication: per-IP unique command sessions (no cap).
  - Template downsampling: identical signatures within (source, label) capped at 200.
  - Composite Validation Set (val.csv):
      * 100% of Tier-0 Gold (357 rows) — human/SOC verified ground truth.
      * Balanced Azure honeypot slice (~120 rows).
      * Balanced Synthetic slice (~480 rows).
      * Balanced Public slice (~1,075 rows).
      * Total val.csv ~2,030 rows, balanced across all 6 classes and all 4 domains.
  - Training Set (train.csv):
      * Reclaims all remaining data (~285,000+ rows).
      * STRICT ZERO LEAKAGE: val command strings are 100% disjoint from train.
      * Tier-0 is 100% excluded from train.
  - Sub-eval compatibility:
      * test_azure.csv (Azure val slice) and test_public.csv (Public val slice)
        exported for downstream domain-specific evaluation without stealing from train.
  - MITRE ATT&CK Targets:
      * All 21 MITRE feature columns (14 tactics + 7 metrics) computed on-the-fly
        and exported to all CSVs.

Outputs under data/exports/training/:
  train.csv, val.csv, test_azure.csv, test_public.csv, assembly_manifest.json
"""
import csv
import json
import math
import re
import sys
import random
from pathlib import Path
from collections import Counter, defaultdict

try:
    csv.field_size_limit(64 * 1024 * 1024)
except OverflowError:
    csv.field_size_limit(2 ** 31 - 1)

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from training.neural.dataset import ThreatDataset
from core.mitre.session_annotator import annotate_session, annotation_to_flat_dict

ROOT = Path(__file__).resolve().parents[3]
EXPORTS = ROOT / "data" / "exports"
OUT_DIR = EXPORTS / "training"
HTTPPARAMS = ROOT / "data" / "external" / "httpparams" / "payload_full.csv"
SYNTHETIC_CSV = ROOT / "data" / "processed" / "synthetic_batches.csv"
TIER0 = EXPORTS / "tier0_annotation_sheet_LABELED.csv"

CLASS_NAMES = ["Safe", "Recon", "Downloader", "Exploit", "Destructive", "ADVANCED_APT"]
SEED = 42
TEMPLATE_CAP = 200        # max rows per (source, label, signature)
SAFE_CAP = 40000          # global cap on Safe rows in TRAIN

# HttpParams attack_type -> class
HTTPPARAMS_MAP = {
    "sqli": 3,
    "xss": 3,
    "cmdi": 3,
    "path-traversal": 3,
    "norm": 0,
}


def norm_signature(text):
    s = str(text).lower()
    s = re.sub(r"[0-9a-f]{8,}", "HASH", s)
    s = re.sub(r"[0-9]{2,}", "N", s)
    s = re.sub(r"\s+", "", s)
    return s[:256]


def get_val_quota(origin, label_id, count):
    """Determine balanced validation slice quota per stratum."""
    if origin == "azure":
        if count <= 2:
            return 0
        return min(50, max(1, count // 10))
    elif origin == "synthetic":
        return min(80, max(1, count // 4))
    elif origin == "public":
        # For public minority classes (Downloader=2, Destructive=4)
        if label_id == 2:
            return min(25, count // 4)
        elif label_id == 4:
            return min(50, count // 4)
        else:
            return min(250, count // 10)
    return 0


def main():
    rng = random.Random(SEED)
    rows = []

    # ---------- 1. Tier-0 Gold Ground Truth ----------
    tier0_rows = []
    if TIER0.exists():
        with open(TIER0, newline="", encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                cmds = (r.get("commands") or "").strip()
                label_str = (r.get("your_label") or "").strip()
                if not cmds or label_str not in CLASS_NAMES:
                    continue
                tier0_rows.append({
                    "session_id": r.get("row_id") or r.get("session_id", f"tier0_{len(tier0_rows)}"),
                    "source": "soc_gold",
                    "commands": cmds,
                    "label_id": CLASS_NAMES.index(label_str),
                    "label_source": "tier0_soc_adjudicated",
                    "origin": "tier0",
                })
        print(f"tier-0 gold rows: {len(tier0_rows)}")
    else:
        print("tier-0 gold sheet: MISSING (skipped)")

    # ---------- 2. Azure (Per-IP unique sessions, no cap) ----------
    n0 = len(rows)
    seen_azure = set()
    with open(EXPORTS / "sessions_complete_v3.csv", newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            cmds = (r.get("commands") or "").strip()
            if not cmds:
                continue
            ip = (r.get("src_ip") or "unknown").strip()
            key = (ip, cmds)
            if key in seen_azure:
                continue
            seen_azure.add(key)
            rows.append({
                "session_id": r["session_id"],
                "source": "azure_cowrie",
                "commands": cmds,
                "label_id": int(float(r["label_v3_id"])),
                "label_source": r.get("label_v3_source", ""),
                "origin": "azure",
            })
    print(f"azure rows (per-IP unique): {len(rows) - n0}")

    # ---------- 3. External (deduped within public corpora) ----------
    n0 = len(rows)
    seen_ext = set()
    with open(EXPORTS / "unified_external_corpus.csv", newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            cmds = (r.get("commands") or "").strip()
            if not cmds or cmds in seen_ext:
                continue
            seen_ext.add(cmds)
            rows.append({
                "session_id": r["session_id"],
                "source": r["source"],
                "commands": cmds,
                "label_id": int(float(r["mapped_label_id"])),
                "label_source": r.get("label_source", ""),
                "origin": "public",
            })
    print(f"external rows: {len(rows) - n0}")

    # ---------- 4. HttpParams payloads ----------
    n0 = len(rows)
    if HTTPPARAMS.exists():
        with open(HTTPPARAMS, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for i, r in enumerate(reader):
                payload = (r.get("payload") or "").strip()
                atype = (r.get("attack_type") or "norm").strip()
                if not payload or len(payload) < 3:
                    continue
                lab = HTTPPARAMS_MAP.get(atype)
                if lab is None:
                    continue
                envelope = f"POST /param HTTP/1.1; Host: host.internal; payload={payload}"
                rows.append({
                    "session_id": f"httpparams_{i}",
                    "source": "httpparams",
                    "commands": envelope,
                    "label_id": lab,
                    "label_source": f"httpparams:{atype}",
                    "origin": "public",
                })
        print(f"httpparams rows: {len(rows) - n0}")
    else:
        print("httpparams: MISSING (skipped)")

    # ---------- 5. Synthetic batches (minority class balancing) ----------
    n0 = len(rows)
    if SYNTHETIC_CSV.exists():
        seen_syn = set()
        real_commands = {r["commands"] for r in rows}
        with open(SYNTHETIC_CSV, newline="", encoding="utf-8", errors="ignore") as f:
            for r in csv.DictReader(f):
                cmds = (r.get("commands") or "").strip()
                if not cmds or cmds in seen_syn or cmds in real_commands:
                    continue
                seen_syn.add(cmds)
                try:
                    lid = int(float(r.get("label_id", -1)))
                except (ValueError, TypeError):
                    continue
                if 0 <= lid <= 5:
                    rows.append({
                        "session_id": r.get("session_id", f"syn_{len(rows)}"),
                        "source": "synthetic_llm",
                        "commands": cmds,
                        "label_id": lid,
                        "label_source": "synthetic_batch",
                        "origin": "synthetic",
                    })
        print(f"synthetic rows: {len(rows) - n0}")
    else:
        print("synthetic batches: MISSING (skipped)")

    # ---------- 6. Template downsampling ----------
    groups = defaultdict(list)
    for r in rows:
        groups[(r["source"], r["label_id"], norm_signature(r["commands"]))].append(r)
    kept = []
    dropped = 0
    for (src, lab, _sig), grp in groups.items():
        if len(grp) > TEMPLATE_CAP:
            kept.extend(grp[:TEMPLATE_CAP])
            dropped += len(grp) - TEMPLATE_CAP
        else:
            kept.extend(grp)
    print(f"template downsampling: dropped {dropped} rows (cap {TEMPLATE_CAP}/signature)")
    rows = kept

    # ---------- 7. Stratified Sampling for Composite Validation Set ----------
    by_stratum = defaultdict(list)
    for r in rows:
        by_stratum[(r["origin"], r["label_id"])].append(r)
    for key in by_stratum:
        rng.shuffle(by_stratum[key])

    val_tier0 = list(tier0_rows)
    val_azure = []
    val_synthetic = []
    val_public = []

    for (origin, lab), grp in sorted(by_stratum.items()):
        n = len(grp)
        quota = get_val_quota(origin, lab, n)
        val_slice = grp[:quota]
        if origin == "azure":
            val_azure.extend(val_slice)
        elif origin == "synthetic":
            val_synthetic.extend(val_slice)
        elif origin == "public":
            val_public.extend(val_slice)

    val = val_tier0 + val_azure + val_synthetic + val_public
    val_commands = set(r["commands"] for r in val)
    print(f"\ncomposite val rows: {len(val)} (tier0={len(val_tier0)}, azure={len(val_azure)}, syn={len(val_synthetic)}, pub={len(val_public)})")

    # ---------- 8. Train Assembly (Strict Zero Leakage) ----------
    val_ids = set(r["session_id"] for r in val)
    train = [r for r in rows if r["commands"] not in val_commands and r["session_id"] not in val_ids and r["origin"] != "tier0"]

    # Safe-cap on TRAIN only
    safe_train = [r for r in train if r["label_id"] == 0]
    if len(safe_train) > SAFE_CAP:
        rng.shuffle(safe_train)
        survivors = {id(r) for r in safe_train[:SAFE_CAP]}
        train = [r for r in train if r["label_id"] != 0 or id(r) in survivors]
        print(f"safe-cap: train Safe reduced to {SAFE_CAP}")

    rng.shuffle(train)
    rng.shuffle(val)

    # Hard leakage checks
    train_commands = set(r["commands"] for r in train)
    assert train_commands.isdisjoint(val_commands), "ERROR: Validation leakage detected in train set!"
    assert all(r["origin"] != "tier0" for r in train), "ERROR: Tier-0 leaked into train set!"
    print("leakage assertions passed: train and val commands are strictly disjoint (0 overlap).")

    # Compatibility subsets
    test_azure = val_azure
    test_public = val_public

    # ---------- 9. Feature Annotation & CSV Writing ----------
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    FIELDS = [
        "session_id", "source", "commands", "label_id", "label_name",
        "label_source", "origin"
    ] + ThreatDataset.MITRE_COLS

    def write_dataset(path, data):
        print(f"annotating and writing {path.name} ({len(data)} rows)...")
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS)
            w.writeheader()
            for r in data:
                cmds_list = [c.strip() for c in r["commands"].split('\n') if c.strip()] or [r["commands"]]
                ann = annotate_session(cmds_list)
                flat = annotation_to_flat_dict(ann)
                out_row = {
                    "session_id": r["session_id"],
                    "source": r["source"],
                    "commands": r["commands"],
                    "label_id": r["label_id"],
                    "label_name": CLASS_NAMES[r["label_id"]],
                    "label_source": r["label_source"],
                    "origin": r["origin"],
                }
                for col in ThreatDataset.MITRE_COLS:
                    out_row[col] = flat.get(col, 0)
                w.writerow(out_row)
        print(f"  wrote {path} successfully.")

    write_dataset(OUT_DIR / "train.csv", train)
    write_dataset(OUT_DIR / "val.csv", val)
    write_dataset(OUT_DIR / "test_azure.csv", test_azure)
    write_dataset(OUT_DIR / "test_public.csv", test_public)

    # ---------- 10. Manifest with Class Weights ----------
    train_dist = Counter(r["label_id"] for r in train)
    total = sum(train_dist.values())
    weights = {}
    for c in range(6):
        cnt = max(train_dist.get(c, 0), 1)
        weights[c] = round(math.sqrt(total / (6 * cnt)), 4)

    val_dist = Counter(r["label_id"] for r in val)
    manifest = {
        "class_names": CLASS_NAMES,
        "counts": {
            "train": {CLASS_NAMES[c]: train_dist.get(c, 0) for c in range(6)},
            "val": {CLASS_NAMES[c]: val_dist.get(c, 0) for c in range(6)},
            "test_azure": {CLASS_NAMES[c]: Counter(r['label_id'] for r in test_azure).get(c, 0) for c in range(6)},
            "test_public": {CLASS_NAMES[c]: Counter(r['label_id'] for r in test_public).get(c, 0) for c in range(6)},
        },
        "inverse_sqrt_class_weights": {CLASS_NAMES[c]: weights[c] for c in range(6)},
        "danger_costs": {"Safe": 1.0, "Recon": 1.0, "Downloader": 12.0,
                          "Exploit": 14.0, "Destructive": 18.0, "ADVANCED_APT": 18.0},
        "template_cap": TEMPLATE_CAP,
        "safe_cap_train": SAFE_CAP,
        "tier0_eval_file": str(TIER0),
    }
    with open(OUT_DIR / "assembly_manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    print("\n=== TRAIN DISTRIBUTION ===")
    for c in range(6):
        print(f"  {CLASS_NAMES[c]:14s} {train_dist.get(c, 0):7d}")
    print("\n=== VAL DISTRIBUTION ===")
    for c in range(6):
        print(f"  {CLASS_NAMES[c]:14s} {val_dist.get(c, 0):7d}")
    print("\n=== INVERSE-SQRT WEIGHTS ===")
    for c in range(6):
        print(f"  {CLASS_NAMES[c]:14s} {weights[c]}")
    print(f"\nManifest: {OUT_DIR / 'assembly_manifest.json'}")


if __name__ == "__main__":
    main()