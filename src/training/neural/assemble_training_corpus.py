"""
Training Corpus Assembly — builds the final stratified training splits.

Merges:
  - data/exports/sessions_complete_v3.csv   (Azure, engine-labeled + binary truth)
  - data/exports/unified_external_corpus.csv (CSIC + zyw-286 + ML4Net + NL2Bash)
  - HttpParamsDataset payloads (sqli/xss/cmdi/path-traversal -> Exploit;
    wrapped in a minimal HTTP envelope since runtime sees envelopes)

Then:
  - Template downsampling: command signatures repeating >N times are capped
    (the busybox/authorized_keys families must not dominate gradients)
  - Stratified split 70/15/15 with THREE disjoint eval sets:
      * test_azure   : held-out Azure rows only (deployment-domain eval,
                      triage masked at scoring time by the eval harness)
      * test_public  : held-out external rows only (cross-domain eval)
      * tier0        : the 257-row LLM-annotated sheet (human-verifiable eval)
  - Class weights computed from the FINAL training distribution and saved
    for the training script (train_neural consumes this manifest).

Outputs under data/exports/:
  training/train.csv, training/val.csv,
  training/test_azure.csv, training/test_public.csv
  training/assembly_manifest.json (distributions + weights)
"""
import csv
import json
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

ROOT = Path(__file__).resolve().parents[3]
EXPORTS = ROOT / "data" / "exports"
OUT_DIR = EXPORTS / "training"
HTTPPARAMS = ROOT / "data" / "external" / "httpparams" / "payload_full.csv"
TIER0 = EXPORTS / "tier0_annotation_sheet_LABELED.csv"

CLASS_NAMES = ["Safe", "Recon", "Downloader", "Exploit", "Destructive", "ADVANCED_APT"]
SEED = 42
TEMPLATE_CAP = 200        # max rows per (source, label, signature)
SAFE_CAP = 40000          # global cap on Safe rows in TRAIN (diversify emphasis)
VAL_FRAC = 0.15
TEST_FRAC = 0.15

# HttpParams attack_type -> class (cmdi is shell injection over HTTP ->
# Exploit, consistent with runtime where HTTP reaches a Linux host)
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


def main():
    rng = random.Random(SEED)
    rows = []   # unified schema: session_id, source, commands, label_id, label_source

    # ---------- Azure ----------
    with open(EXPORTS / "sessions_complete_v3.csv", newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append({
                "session_id": r["session_id"],
                "source": "azure_cowrie",
                "commands": r.get("commands", ""),
                "label_id": int(float(r["label_v3_id"])),
                "label_source": r.get("label_v3_source", ""),
                "origin": "azure",
            })
    print(f"azure rows: {len(rows)}")

    # ---------- External ----------
    n0 = len(rows)
    with open(EXPORTS / "unified_external_corpus.csv", newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append({
                "session_id": r["session_id"],
                "source": r["source"],
                "commands": r.get("commands", ""),
                "label_id": int(float(r["mapped_label_id"])),
                "label_source": r.get("label_source", ""),
                "origin": "public",
            })
    print(f"external rows: {len(rows) - n0}")

    # ---------- HttpParams payloads ----------
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
                # minimal envelope: runtime feeds reconstructed requests;
                # param values ride in the query/body position
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

    # ---------- Global exact-command dedup across sources ----------
    seen = set()
    deduped = []
    for r in rows:
        key = r["commands"][:512]
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)
    print(f"after global exact dedup: {len(deduped)} (was {len(rows)})")
    rows = deduped

    # ---------- Template downsampling ----------
    # Cap identical normalized signatures within (source, label)
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

    # ---------- Split: stratified by (origin, label) ----------
    # Azure rows are the deployment domain: eval representation matters more
    # than exact 15%. Per-azure-class: min 10 rows (or all if fewer) to eval,
    # 10% to val, rest to train. Public rows use the standard 15/15 split.
    by_stratum = defaultdict(list)
    for r in rows:
        by_stratum[(r["origin"], r["label_id"])].append(r)
    for key in by_stratum:
        rng.shuffle(by_stratum[key])

    AZURE_EVAL_FLOOR = 10

    train, val = [], []
    test_azure, test_public = [], []
    for (origin, lab), grp in sorted(by_stratum.items()):
        n = len(grp)
        if origin == "azure":
            n_test = min(max(AZURE_EVAL_FLOOR, n // 10), n // 2 if n > 1 else n)
            n_test = min(n_test, n)
        else:
            n_test = int(n * TEST_FRAC)
        n_val = int((n - n_test) * VAL_FRAC) if origin == "azure" else int(n * VAL_FRAC)
        test = grp[:n_test]
        val_ = grp[n_test:n_test + n_val]
        tr_ = grp[n_test + n_val:]
        train.extend(tr_)
        val.extend(val_)
        if origin == "azure":
            test_azure.extend(test)
        else:
            test_public.extend(test)

    # Safe-cap on TRAIN only (keeps val/test distributions honest)
    safe_train = [r for r in train if r["label_id"] == 0]
    if len(safe_train) > SAFE_CAP:
        rng.shuffle(safe_train)
        survivors = {id(r) for r in safe_train[:SAFE_CAP]}
        train = [r for r in train if r["label_id"] != 0 or id(r) in survivors]
        print(f"safe-cap: train Safe reduced to {SAFE_CAP}")

    rng.shuffle(train)
    rng.shuffle(val)

    # ---------- Write ----------
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    FIELDS = ["session_id", "source", "commands", "label_id", "label_name",
              "label_source", "origin"]

    def write(path, data):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS)
            w.writeheader()
            for r in data:
                w.writerow({
                    "session_id": r["session_id"], "source": r["source"],
                    "commands": r["commands"], "label_id": r["label_id"],
                    "label_name": CLASS_NAMES[r["label_id"]],
                    "label_source": r["label_source"], "origin": r["origin"],
                })
        print(f"wrote {path} ({len(data)} rows)")

    write(OUT_DIR / "train.csv", train)
    write(OUT_DIR / "val.csv", val)
    write(OUT_DIR / "test_azure.csv", test_azure)
    write(OUT_DIR / "test_public.csv", test_public)

    # ---------- Manifest with class weights ----------
    train_dist = Counter(r["label_id"] for r in train)
    total = sum(train_dist.values())
    # inverse-sqrt weights (stable under extreme imbalance)
    import math
    weights = {}
    for c in range(6):
        cnt = max(train_dist.get(c, 0), 1)
        weights[c] = round(math.sqrt(total / (6 * cnt)), 4)

    manifest = {
        "class_names": CLASS_NAMES,
        "counts": {
            "train": {CLASS_NAMES[c]: train_dist.get(c, 0) for c in range(6)},
            "val": {CLASS_NAMES[c]: Counter(r['label_id'] for r in val).get(c, 0) for c in range(6)},
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
    print("\n=== INVERSE-SQRT WEIGHTS ===")
    for c in range(6):
        print(f"  {CLASS_NAMES[c]:14s} {weights[c]}")
    print(f"\nManifest: {OUT_DIR / 'assembly_manifest.json'}")


if __name__ == "__main__":
    main()