#!/usr/bin/env python3
"""
Manual Single-Binary Deep Analysis Runner
==========================================

Analyzes ONE binary at a time with both Ghidra and angr, prints a human-readable
summary of what the binary is doing, and tracks progress in a persistent tracker
file. Designed for manual execution so you can understand each binary individually
and recover from crashes without losing progress.

Usage:
    # List all targets with done/pending status:
    python src/analyze_single.py --list

    # Analyze a specific binary by SHA256 (prefix match):
    python src/analyze_single.py 94f2e4d8

    # Analyze by full path:
    python src/analyze_single.py data/cowrie/lib/cowrie/downloads/94f2e4d8d443...

    # Run only Ghidra on a binary:
    python src/analyze_single.py --ghidra-only 94f2e4d8

    # Run only angr on a binary:
    python src/analyze_single.py --angr-only 94f2e4d8

    # Re-analyze (force overwrite existing results):
    python src/analyze_single.py --force 94f2e4d8

    # Set custom timeouts (seconds):
    python src/analyze_single.py --ghidra-timeout 3600 --angr-timeout 1800 94f2e4d8

Tracker file: data/processed/analysis_tracker.txt
  - Appended after every binary analysis (even failures)
  - Used by --list to show done/pending status
  - Human-readable, one line per binary per tool
"""

import argparse
import json
import os
import sys
import time

# Ensure src/ is on the path
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SRC_DIR)

BASE_DIR = os.path.dirname(SRC_DIR)

# Paths
TRIAGE_RESULTS = os.path.join(BASE_DIR, "data", "processed", "binary_triage", "all_triage_results.json")
GHIDRA_OUTPUT_DIR = os.path.join(BASE_DIR, "data", "processed", "ghidra_features")
ANGR_OUTPUT_DIR = os.path.join(BASE_DIR, "data", "processed", "angr_features")
TRACKER_FILE = os.path.join(BASE_DIR, "data", "processed", "analysis_tracker.txt")


# ==========================================================================
# Target list management
# ==========================================================================

def load_all_targets():
    """
    Load the 41 binary targets (39 ELF + 2 PE representatives) from triage results.
    Returns a list of dicts with sha256, path, file_type, classification, priority, file_size.
    """
    with open(TRIAGE_RESULTS) as f:
        data = json.load(f)

    targets = []
    pe_imphashes_seen = set()

    for r in data["results"]:
        ft = r["file_type"]

        # Classification extraction
        cls = r.get("classification", {})
        label = cls.get("primary_label", "unknown") if isinstance(cls, dict) else str(cls)

        if ft == "elf":
            targets.append({
                "sha256": r["sha256"],
                "path": os.path.join(BASE_DIR, r["path"]),
                "file_type": "elf",
                "classification": label,
                "priority": r.get("analysis_priority", 0),
                "file_size": r.get("file_size", 0),
            })
        elif ft == "pe":
            # Deduplicate PEs by imphash — only keep first representative per group
            fi = r.get("format_info", {})
            imphash = fi.get("imphash", "none")
            if imphash in pe_imphashes_seen:
                continue
            pe_imphashes_seen.add(imphash)
            targets.append({
                "sha256": r["sha256"],
                "path": os.path.join(BASE_DIR, r["path"]),
                "file_type": "pe",
                "classification": label,
                "priority": r.get("analysis_priority", 0),
                "file_size": r.get("file_size", 0),
                "imphash": imphash,
            })

    # Sort by priority descending, then size ascending
    targets.sort(key=lambda t: (-t["priority"], t["file_size"]))
    return targets


def load_tracker():
    """
    Load the tracker file and return a dict: sha256 -> {ghidra: status, angr: status}.
    """
    tracker = {}
    if not os.path.isfile(TRACKER_FILE):
        return tracker

    with open(TRACKER_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(" | ")
            if len(parts) < 4:
                continue
            sha = parts[0].strip()
            tool = parts[1].strip()
            status = parts[2].strip()
            if sha not in tracker:
                tracker[sha] = {}
            tracker[sha][tool] = status
    return tracker


def append_tracker(sha256, tool, status, elapsed, details=""):
    """Append one line to the tracker file."""
    os.makedirs(os.path.dirname(TRACKER_FILE), exist_ok=True)

    # Create header if file doesn't exist
    if not os.path.isfile(TRACKER_FILE):
        with open(TRACKER_FILE, "w") as f:
            f.write("# AdaptiveShield Deep Analysis Tracker\n")
            f.write("# Format: SHA256 | tool | status | elapsed | timestamp | details\n")
            f.write("# ---------------------------------------------------------------\n")

    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(TRACKER_FILE, "a") as f:
        f.write("{} | {} | {} | {:.1f}s | {} | {}\n".format(
            sha256, tool, status, elapsed, timestamp, details))


def find_target(identifier, targets):
    """
    Find a target by SHA256 prefix or file path.
    Returns the target dict or None.
    """
    identifier = identifier.strip()

    # Try as SHA256 prefix
    matches = [t for t in targets if t["sha256"].startswith(identifier)]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print("ERROR: Ambiguous SHA256 prefix '{}' matches {} targets:".format(
            identifier, len(matches)))
        for m in matches:
            print("  {} ({})".format(m["sha256"][:32], m["classification"]))
        return None

    # Try as file path
    abs_path = os.path.abspath(identifier)
    for t in targets:
        if os.path.abspath(t["path"]) == abs_path:
            return t

    # Try as relative path from BASE_DIR
    rel_path = os.path.join(BASE_DIR, identifier)
    for t in targets:
        if os.path.abspath(t["path"]) == os.path.abspath(rel_path):
            return t

    print("ERROR: No target found matching '{}'".format(identifier))
    print("Use --list to see all available targets.")
    return None


# ==========================================================================
# Analysis execution
# ==========================================================================

def run_ghidra_single(target, timeout=1800, force=False):
    """
    Run Ghidra analysis on a single binary.
    Returns (status, elapsed_seconds, details_string).
    """
    from core.malware.ghidra_extract import run_ghidra_analysis

    sha = target["sha256"]
    out_json = os.path.join(GHIDRA_OUTPUT_DIR, sha + ".json")

    if os.path.isfile(out_json) and not force:
        print("  [Ghidra] SKIP — already analyzed (use --force to re-run)")
        return "skipped", 0.0, "already exists"

    if force and os.path.isfile(out_json):
        os.remove(out_json)
        print("  [Ghidra] Removed existing output, re-analyzing...")

    print("  [Ghidra] Starting analysis (timeout: {}s)...".format(timeout))
    t0 = time.time()

    try:
        summary = run_ghidra_analysis(
            binary_paths=[target["path"]],
            output_dir=GHIDRA_OUTPUT_DIR,
            timeout_per_binary=timeout,
            verbose=True,
        )
        elapsed = time.time() - t0

        if summary["stats"]["success"] > 0:
            return "ok", elapsed, "success"
        elif summary["stats"].get("timeout", 0) > 0:
            return "timeout", elapsed, "exceeded {}s".format(timeout)
        else:
            err = summary["errors"][0]["error"] if summary["errors"] else "unknown"
            return "failed", elapsed, str(err)[:200]

    except Exception as e:
        elapsed = time.time() - t0
        return "error", elapsed, str(e)[:200]


def run_angr_single(target, timeout=900, force=False):
    """
    Run angr analysis on a single binary.
    Returns (status, elapsed_seconds, details_string).
    """
    from core.malware.symbolic import analyze_binary, _sha256_file

    sha = target["sha256"]
    out_json = os.path.join(ANGR_OUTPUT_DIR, sha + ".json")

    if os.path.isfile(out_json) and not force:
        print("  [angr] SKIP — already analyzed (use --force to re-run)")
        return "skipped", 0.0, "already exists"

    if force and os.path.isfile(out_json):
        os.remove(out_json)
        print("  [angr] Removed existing output, re-analyzing...")

    # Size-based timeout adjustment
    file_size_mb = target["file_size"] / (1024 * 1024)
    adjusted_timeout = timeout
    if file_size_mb > 20:
        adjusted_timeout = max(timeout, timeout * 3)
    elif file_size_mb > 10:
        adjusted_timeout = max(timeout, timeout * 2)
    elif file_size_mb > 1:
        adjusted_timeout = max(timeout, int(timeout * 1.5))

    print("  [angr] Starting analysis (timeout: {}s, adjusted for {:.1f}MB)...".format(
        adjusted_timeout, file_size_mb))

    os.makedirs(ANGR_OUTPUT_DIR, exist_ok=True)
    t0 = time.time()

    try:
        analysis = analyze_binary(target["path"], timeout=adjusted_timeout)
        elapsed = time.time() - t0

        # Write output (even partial)
        with open(out_json, "w") as f:
            json.dump(analysis, f, indent=2, default=str)

        if "error" in analysis:
            if analysis.get("partial"):
                return "partial", elapsed, analysis["error"]
            return "error", elapsed, analysis["error"]
        return "ok", elapsed, "success"

    except Exception as e:
        elapsed = time.time() - t0
        return "error", elapsed, str(e)[:200]


# ==========================================================================
# Result summary printer
# ==========================================================================

def print_analysis_summary(target):
    """
    Load and print a human-readable summary of the analysis results for a binary.
    Combines triage, Ghidra, and angr results into one view.
    """
    sha = target["sha256"]
    print("\n" + "=" * 70)
    print("ANALYSIS SUMMARY: {}".format(sha[:32]))
    print("=" * 70)
    print("Classification: {}  |  Priority: {}  |  Size: {:.1f} MB  |  Type: {}".format(
        target["classification"], target["priority"],
        target["file_size"] / (1024 * 1024), target["file_type"]))
    print("Path: {}".format(target["path"]))

    # --- Ghidra results ---
    ghidra_json = os.path.join(GHIDRA_OUTPUT_DIR, sha + ".json")
    if os.path.isfile(ghidra_json):
        print("\n--- Ghidra Results ---")
        try:
            with open(ghidra_json) as f:
                gdata = json.load(f)

            basic = gdata.get("basic", {})
            print("  Architecture: {}".format(basic.get("architecture", "?")))
            print("  Compiler: {}".format(basic.get("compiler", "?")))
            print("  Format: {}".format(basic.get("executable_format", "?")))

            funcs = gdata.get("functions", {})
            print("  Functions: {} total".format(funcs.get("function_count", "?")))
            if "runtime_functions_filtered" in funcs:
                print("    Go runtime filtered: {}".format(funcs["runtime_functions_filtered"]))
                print("    User functions listed: {}".format(funcs.get("user_functions_listed", "?")))

            go = gdata.get("go_info", {})
            if gdata.get("is_go_binary"):
                print("  Go binary: YES")
                if go.get("go_version"):
                    print("    Go version: {}".format(go["go_version"]))
                print("    User functions: {}".format(go.get("user_function_count", 0)))
                print("    Runtime functions: {}".format(go.get("runtime_function_count", 0)))
                uf = go.get("user_functions", [])
                if uf:
                    print("    Notable user functions:")
                    for fn in uf[:20]:
                        print("      - {}".format(fn))
                    if len(uf) > 20:
                        print("      ... and {} more".format(len(uf) - 20))

            si = gdata.get("string_indicators", {})
            if si.get("mining_pools"):
                print("  Mining pools: {}".format(si["mining_pools"][:3]))
            if si.get("crypto_wallets"):
                print("  Crypto wallets: {}".format(si["crypto_wallets"][:3]))
            if si.get("ip_addresses"):
                print("  IP addresses: {}".format(si["ip_addresses"][:10]))
            if si.get("urls"):
                print("  URLs: {}".format(si["urls"][:5]))
            if si.get("shell_commands"):
                print("  Shell commands: {}".format(si["shell_commands"][:5]))
            if si.get("file_paths"):
                print("  File paths: {}".format(si["file_paths"][:10]))

            ic = gdata.get("import_categories", {})
            for cat, funcs_list in ic.items():
                if funcs_list:
                    print("  Import category '{}': {}".format(cat, funcs_list[:10]))

            dp = gdata.get("data_patterns", {})
            if dp.get("has_aes_sbox"):
                print("  [!] AES S-box detected (encryption capability)")
            if dp.get("has_sha256_constants"):
                print("  [!] SHA-256 constants detected (hashing capability)")

        except Exception as e:
            print("  Error reading Ghidra results: {}".format(e))
    else:
        print("\n--- Ghidra: NOT YET ANALYZED ---")

    # --- angr results ---
    angr_json = os.path.join(ANGR_OUTPUT_DIR, sha + ".json")
    if os.path.isfile(angr_json):
        print("\n--- angr Results ---")
        try:
            with open(angr_json) as f:
                adata = json.load(f)

            basic = adata.get("basic", {})
            print("  Architecture: {} ({}bit)".format(basic.get("arch", "?"), basic.get("bits", "?")))

            cfg = adata.get("cfg_metrics", {})
            if "error" not in cfg:
                print("  CFG: {} blocks, {} edges, {} functions".format(
                    cfg.get("basic_blocks", "?"), cfg.get("edges", "?"),
                    cfg.get("functions_recovered", "?")))
                print("  Cyclomatic complexity: {}".format(cfg.get("cyclomatic_complexity", "?")))
                print("  CFG recovery time: {}s".format(cfg.get("cfg_time", "?")))
            else:
                print("  CFG error: {}".format(cfg["error"][:100]))

            funcs = adata.get("functions", {})
            if "error" not in funcs:
                print("  Functions: {} total, {} user listed".format(
                    funcs.get("total_count", "?"), funcs.get("user_functions_listed", "?")))
                if "runtime_filtered" in funcs:
                    print("    Runtime filtered: {}".format(funcs["runtime_filtered"]))

            go = adata.get("go_info", {})
            if go.get("is_go"):
                print("  Go binary: YES")
                print("    User functions: {}".format(go.get("user_function_count", 0)))
                print("    Runtime filtered: {}".format(go.get("runtime_function_count", 0)))
                uf = go.get("user_functions", [])
                if uf:
                    print("    Notable user functions:")
                    for fn in uf[:20]:
                        print("      - {}".format(fn))
                    if len(uf) > 20:
                        print("      ... and {} more".format(len(uf) - 20))

            sc = adata.get("syscalls", {})
            for cat, calls in sc.items():
                if calls:
                    print("  Syscall category '{}': {}".format(cat, calls[:10]))

            strings = adata.get("strings", {})
            if strings.get("ip_addresses"):
                print("  IP addresses: {}".format(strings["ip_addresses"][:10]))
            if strings.get("urls"):
                print("  URLs: {}".format(strings["urls"][:5]))
            if strings.get("mining_indicators"):
                print("  Mining indicators: {}".format(strings["mining_indicators"][:3]))
            if strings.get("shell_commands"):
                print("  Shell commands: {}".format(strings["shell_commands"][:5]))

            beh = adata.get("behavioral_summary", {})
            active = [k.replace("has_", "").replace("_", " ") for k, v in beh.items()
                      if v is True]
            if active:
                print("  Behavioral flags: {}".format(", ".join(active)))
            print("  Complexity tier: {}".format(beh.get("complexity_tier", "?")))

            if adata.get("partial"):
                print("  [!] PARTIAL RESULTS — analysis timed out")
            if adata.get("error"):
                print("  [!] Error: {}".format(adata["error"][:100]))

            print("  Total analysis time: {:.1f}s".format(adata.get("total_time", 0)))

        except Exception as e:
            print("  Error reading angr results: {}".format(e))
    else:
        print("\n--- angr: NOT YET ANALYZED ---")

    print("=" * 70)


# ==========================================================================
# --list command
# ==========================================================================

def print_target_list():
    """Print all targets with their analysis status."""
    targets = load_all_targets()
    tracker = load_tracker()

    # Also check for existing output files (may have been analyzed without tracker)
    ghidra_done = set()
    angr_done = set()
    if os.path.isdir(GHIDRA_OUTPUT_DIR):
        for f in os.listdir(GHIDRA_OUTPUT_DIR):
            if f.endswith(".json") and not f.startswith("_"):
                ghidra_done.add(f.replace(".json", ""))
    if os.path.isdir(ANGR_OUTPUT_DIR):
        for f in os.listdir(ANGR_OUTPUT_DIR):
            if f.endswith(".json") and not f.startswith("_"):
                angr_done.add(f.replace(".json", ""))

    print("=" * 90)
    print("DEEP ANALYSIS TARGET LIST ({} binaries)".format(len(targets)))
    print("=" * 90)
    print("{:<4} {:<16} {:>8} {:<20} {:>4} {:<8} {:<8}".format(
        "#", "SHA256", "Size", "Classification", "Pri", "Ghidra", "angr"))
    print("-" * 90)

    ghidra_complete = 0
    angr_complete = 0

    for i, t in enumerate(targets):
        sha = t["sha256"]
        sha_short = sha[:16]
        size_str = "{:.1f}MB".format(t["file_size"] / (1024 * 1024))

        # Determine Ghidra status
        g_status = "PENDING"
        if sha in ghidra_done:
            g_status = "DONE"
            ghidra_complete += 1
        tr = tracker.get(sha, {})
        if tr.get("ghidra") in ("ok", "success"):
            g_status = "DONE"
        elif tr.get("ghidra") in ("failed", "error", "timeout"):
            g_status = tr["ghidra"].upper()

        # Determine angr status
        a_status = "PENDING"
        if sha in angr_done:
            a_status = "DONE"
            angr_complete += 1
        if tr.get("angr") in ("ok", "success"):
            a_status = "DONE"
        elif tr.get("angr") in ("partial",):
            a_status = "PARTIAL"
        elif tr.get("angr") in ("failed", "error", "timeout"):
            a_status = tr["angr"].upper()

        print("{:<4} {} {:>8} {:<20} {:>4} {:<8} {:<8}".format(
            i + 1, sha_short, size_str, t["classification"][:20],
            t["priority"], g_status, a_status))

    print("-" * 90)
    print("Ghidra: {}/{} complete  |  angr: {}/{} complete".format(
        ghidra_complete, len(targets), angr_complete, len(targets)))
    print()
    print("To analyze a binary:")
    print("  python src/analyze_single.py <sha256_prefix>")
    print("  python src/analyze_single.py --ghidra-only <sha256_prefix>")
    print("  python src/analyze_single.py --angr-only <sha256_prefix>")


# ==========================================================================
# Main
# ==========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Manual single-binary deep analysis runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python src/analyze_single.py --list              # Show all targets
  python src/analyze_single.py 94f2e4d8            # Analyze by SHA prefix
  python src/analyze_single.py --ghidra-only 9e5b  # Ghidra only
  python src/analyze_single.py --angr-only 9e5b    # angr only
  python src/analyze_single.py --force 9e5b        # Force re-analysis
        """,
    )
    parser.add_argument("target", nargs="?", help="SHA256 prefix or file path of binary to analyze")
    parser.add_argument("--list", action="store_true", help="List all targets with status")
    parser.add_argument("--ghidra-only", action="store_true", help="Run only Ghidra analysis")
    parser.add_argument("--angr-only", action="store_true", help="Run only angr analysis")
    parser.add_argument("--force", action="store_true", help="Force re-analysis even if already done")
    parser.add_argument("--ghidra-timeout", type=int, default=1800,
                        help="Ghidra timeout per binary in seconds (default: 1800 = 30min)")
    parser.add_argument("--angr-timeout", type=int, default=900,
                        help="angr base timeout per binary in seconds (default: 900 = 15min, auto-adjusted for size)")
    parser.add_argument("--summary-only", action="store_true",
                        help="Only print existing analysis summary, don't run analysis")

    args = parser.parse_args()

    if args.list:
        print_target_list()
        return

    if not args.target:
        parser.print_help()
        print("\nERROR: Specify a target (SHA256 prefix or path), or use --list")
        sys.exit(1)

    # Load targets and find the requested one
    targets = load_all_targets()
    target = find_target(args.target, targets)
    if not target:
        sys.exit(1)

    sha = target["sha256"]
    print()
    print("=" * 70)
    print("ANALYZING: {} ...".format(sha[:32]))
    print("=" * 70)
    print("Classification: {}  |  Priority: {}  |  Size: {:.1f} MB".format(
        target["classification"], target["priority"],
        target["file_size"] / (1024 * 1024)))
    print("Type: {}  |  Path: {}".format(target["file_type"], target["path"]))
    print()

    if args.summary_only:
        print_analysis_summary(target)
        return

    run_ghidra = not args.angr_only
    run_angr = not args.ghidra_only

    # --- Ghidra ---
    if run_ghidra:
        print("[1/2] GHIDRA ANALYSIS")
        print("-" * 40)
        g_status, g_elapsed, g_details = run_ghidra_single(
            target, timeout=args.ghidra_timeout, force=args.force)
        append_tracker(sha, "ghidra", g_status, g_elapsed, g_details)
        print("  Result: {} ({:.1f}s)".format(g_status, g_elapsed))
        if g_details and g_status not in ("ok", "skipped"):
            print("  Details: {}".format(g_details[:200]))
        print()

    # --- angr ---
    if run_angr:
        step = "2/2" if run_ghidra else "1/1"
        print("[{}] ANGR ANALYSIS".format(step))
        print("-" * 40)
        a_status, a_elapsed, a_details = run_angr_single(
            target, timeout=args.angr_timeout, force=args.force)
        append_tracker(sha, "angr", a_status, a_elapsed, a_details)
        print("  Result: {} ({:.1f}s)".format(a_status, a_elapsed))
        if a_details and a_status not in ("ok", "skipped"):
            print("  Details: {}".format(a_details[:200]))
        print()

    # --- Print combined summary ---
    print_analysis_summary(target)


if __name__ == "__main__":
    main()
