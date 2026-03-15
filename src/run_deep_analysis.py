#!/usr/bin/env python3
"""
Phase 2+3 Deep Binary Analysis Runner
======================================

Orchestrates Ghidra (Phase 2) and angr (Phase 3) analysis on the honeypot
malware binaries. Handles:

  1. Loading Phase 1 triage results to build the target list
  2. Deduplicating identical binaries (e.g., the 23 Dionaea PEs with same imphash)
  3. Running Ghidra headless analysis on all ELF + representative PE binaries
  4. Running angr analysis on priority targets (Go, packed, stripped binaries)
  5. Saving results and a combined summary

Target selection logic:
  - ALL 39 ELF binaries go through Ghidra (disassembly, function analysis, strings)
  - For the 23 identical PE DLLs, only 1 representative is analyzed
  - The 1 outlier PE DLL is analyzed separately
  - angr targets: Go binaries (highest value), packed_unknown, botnet_droppers,
    and optionally stripped miners

Usage:
    python src/run_deep_analysis.py [--phase 2|3|both] [--ghidra-timeout 600]
                                    [--angr-timeout 300] [--dry-run] [--verbose]

    # Run only Ghidra (Phase 2):
    python src/run_deep_analysis.py --phase 2

    # Run only angr (Phase 3):
    python src/run_deep_analysis.py --phase 3

    # Run both (default):
    python src/run_deep_analysis.py

    # Dry run (shows targets without running analysis):
    python src/run_deep_analysis.py --dry-run
"""

import argparse
import json
import os
import sys
import time
from collections import Counter

# Ensure src/ is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ==========================================================================
# Configuration
# ==========================================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TRIAGE_RESULTS_FILE = os.path.join(
    BASE_DIR, "data", "processed", "binary_triage", "all_triage_results.json"
)
GHIDRA_OUTPUT_DIR = os.path.join(BASE_DIR, "data", "processed", "ghidra_features")
ANGR_OUTPUT_DIR = os.path.join(BASE_DIR, "data", "processed", "angr_features")


def load_triage_results():
    """Load Phase 1 triage results and return the list of per-binary dicts."""
    with open(TRIAGE_RESULTS_FILE) as f:
        data = json.load(f)
    return data["results"]


def build_target_lists(triage_results):
    """
    From the triage results, build the target lists for Ghidra and angr.

    Returns
    -------
    ghidra_targets : list[dict]
        Each dict has: sha256, path, file_type, classification, priority,
        file_size, tag (Go/stripped/normal/pe), reason.
    angr_targets : list[dict]
        Same structure, subset of binaries that benefit from angr analysis.
    pe_dedup_info : dict
        Info about PE deduplication for logging.
    """
    elf_bins = []
    pe_bins = []

    for r in triage_results:
        ft = r["file_type"]
        if ft == "elf":
            fi = r.get("format_info", {})
            secs = fi.get("sections", [])
            is_go = ".gopclntab" in secs
            has_shstrtab = ".shstrtab" in secs
            stripped = not has_shstrtab

            cls_info = r.get("classification", {})
            if isinstance(cls_info, dict):
                label = cls_info.get("primary_label", "unknown")
            else:
                label = str(cls_info)

            elf_bins.append({
                "sha256": r["sha256"],
                "path": r["path"],
                "file_type": "elf",
                "classification": label,
                "priority": r.get("analysis_priority", 0),
                "file_size": r.get("file_size", 0),
                "arch": fi.get("arch", "unknown"),
                "linkage": fi.get("linkage", "unknown"),
                "is_go": is_go,
                "stripped": stripped,
                "tag": "Go" if is_go else ("stripped" if stripped else "normal"),
            })

        elif ft == "pe":
            fi = r.get("format_info", {})
            cls_info = r.get("classification", {})
            if isinstance(cls_info, dict):
                label = cls_info.get("primary_label", "unknown")
            else:
                label = str(cls_info)

            pe_bins.append({
                "sha256": r["sha256"],
                "path": r["path"],
                "file_type": "pe",
                "classification": label,
                "priority": r.get("analysis_priority", 0),
                "file_size": r.get("file_size", 0),
                "imphash": fi.get("imphash", "none"),
                "tag": "pe",
            })

    # --- Deduplicate PE binaries ---
    # Group by imphash and pick one representative per group
    pe_by_imphash = {}
    for p in pe_bins:
        ih = p["imphash"]
        pe_by_imphash.setdefault(ih, []).append(p)

    pe_representatives = []
    pe_dedup_info = {}
    for ih, group in pe_by_imphash.items():
        # Pick the first one as representative
        rep = group[0]
        rep["reason"] = "PE representative (imphash %s, %d identical)" % (ih, len(group))
        pe_representatives.append(rep)
        pe_dedup_info[ih] = {
            "count": len(group),
            "representative": rep["sha256"],
            "classification": rep["classification"],
        }

    # --- Build Ghidra target list ---
    # All ELFs + PE representatives, sorted by priority descending
    ghidra_targets = []
    for e in elf_bins:
        e["reason"] = "ELF %s (%s, %s)" % (e["tag"], e["classification"], e["arch"])
        ghidra_targets.append(e)
    for p in pe_representatives:
        ghidra_targets.append(p)

    ghidra_targets.sort(key=lambda x: -x["priority"])

    # --- Build angr target list ---
    # Priority order:
    #   1. Go binaries (highest value — Ghidra alone struggles with Go)
    #   2. packed_unknown (high entropy, need CFG recovery)
    #   3. botnet_droppers (static, small, interesting)
    #   4. stripped miners (large but CFG recovery can reveal structure)
    #   5. recon_scanners (if time permits)
    angr_targets = []

    # Go binaries first
    for e in elf_bins:
        if e["is_go"]:
            e_copy = dict(e)
            e_copy["reason"] = "Go binary — angr CFG recovery for goroutine analysis"
            angr_targets.append(e_copy)

    # packed_unknown
    for e in elf_bins:
        if e["classification"] == "packed_unknown":
            e_copy = dict(e)
            e_copy["reason"] = "Packed/encrypted — angr CFG heuristics may reveal hidden code"
            angr_targets.append(e_copy)

    # botnet_droppers
    for e in elf_bins:
        if e["classification"] == "botnet_dropper":
            e_copy = dict(e)
            e_copy["reason"] = "Static botnet dropper — angr syscall identification"
            angr_targets.append(e_copy)

    # stripped miners (only the smaller ones to avoid multi-hour analysis)
    for e in sorted(elf_bins, key=lambda x: x["file_size"]):
        if (e["classification"] == "miner" and e["stripped"]
                and not e["is_go"]
                and e["file_size"] < 20 * 1024 * 1024):  # < 20MB
            e_copy = dict(e)
            e_copy["reason"] = "Stripped miner — angr function recovery"
            angr_targets.append(e_copy)

    # Recon scanners (small, fast to analyze)
    for e in sorted(elf_bins, key=lambda x: x["file_size"]):
        if e["classification"] == "recon_scanner":
            e_copy = dict(e)
            e_copy["reason"] = "Recon scanner — angr for hidden capabilities"
            angr_targets.append(e_copy)

    return ghidra_targets, angr_targets, pe_dedup_info


def print_target_summary(ghidra_targets, angr_targets, pe_dedup_info):
    """Print a human-readable summary of what will be analyzed."""
    print("=" * 70)
    print("DEEP ANALYSIS TARGET SUMMARY")
    print("=" * 70)

    print("\n--- Ghidra Targets (%d binaries) ---" % len(ghidra_targets))
    total_size = sum(t["file_size"] for t in ghidra_targets)
    print("Total size: %.1f MB" % (total_size / (1024 * 1024)))

    tag_counts = Counter(t["tag"] for t in ghidra_targets)
    for tag, cnt in tag_counts.most_common():
        print("  %s: %d" % (tag, cnt))

    print("\nTop 10 by priority:")
    for t in ghidra_targets[:10]:
        print("  %s | %-20s | pri=%3d | %6.1f MB | %s" % (
            t["sha256"][:16], t["classification"],
            t["priority"], t["file_size"] / (1024 * 1024), t["tag"]))

    if pe_dedup_info:
        print("\nPE deduplication:")
        for ih, info in pe_dedup_info.items():
            print("  imphash %s: %d -> 1 representative (%s)" % (
                ih[:16], info["count"], info["classification"]))

    print("\n--- angr Targets (%d binaries) ---" % len(angr_targets))
    total_size = sum(t["file_size"] for t in angr_targets)
    print("Total size: %.1f MB" % (total_size / (1024 * 1024)))

    for t in angr_targets:
        print("  %s | %-20s | %6.1f MB | %s" % (
            t["sha256"][:16], t["classification"],
            t["file_size"] / (1024 * 1024), t["reason"]))


def resolve_path(rel_path):
    """Convert a relative path from triage results to absolute."""
    abs_path = os.path.join(BASE_DIR, rel_path)
    if os.path.isfile(abs_path):
        return abs_path
    # Try as-is
    if os.path.isfile(rel_path):
        return rel_path
    raise FileNotFoundError("Binary not found: %s (tried %s)" % (rel_path, abs_path))


def run_phase2(ghidra_targets, timeout_per_binary=600, verbose=True):
    """
    Run Ghidra headless analysis (Phase 2) on all targets.

    We process binaries in priority order but with a twist: we do smaller
    binaries first within each priority tier, because Ghidra is faster on them
    and we get more coverage quickly.
    """
    from core.malware.ghidra_extract import run_ghidra_analysis

    print("\n" + "=" * 70)
    print("PHASE 2: Ghidra Headless Analysis")
    print("=" * 70)

    # Sort: priority desc, then size asc within same priority
    sorted_targets = sorted(
        ghidra_targets,
        key=lambda t: (-t["priority"], t["file_size"]),
    )

    # Resolve all paths
    binary_paths = []
    for t in sorted_targets:
        try:
            path = resolve_path(t["path"])
            binary_paths.append(path)
        except FileNotFoundError as e:
            print("WARNING: %s" % e)

    print("\nAnalyzing %d binaries with Ghidra..." % len(binary_paths))
    print("Output directory: %s" % GHIDRA_OUTPUT_DIR)
    print("Timeout per binary: %ds" % timeout_per_binary)
    print()

    t0 = time.time()
    summary = run_ghidra_analysis(
        binary_paths=binary_paths,
        output_dir=GHIDRA_OUTPUT_DIR,
        timeout_per_binary=timeout_per_binary,
        verbose=verbose,
    )
    elapsed = time.time() - t0

    stats = summary["stats"]
    print("\n--- Ghidra Phase 2 Complete ---")
    print("Total: %d | Success: %d | Skipped: %d | Failed: %d | Timeout: %d" % (
        stats["total"], stats["success"], stats["skipped"],
        stats["failed"], stats.get("timeout", 0)))
    print("Elapsed: %.1f seconds (%.1f min)" % (elapsed, elapsed / 60))

    if summary["errors"]:
        print("\nErrors:")
        for err in summary["errors"][:10]:
            print("  %s: %s" % (err["sha256"][:16], str(err["error"])[:80]))

    return summary


def run_phase3(angr_targets, timeout_per_binary=300, max_memory_gb=4, verbose=True):
    """
    Run angr analysis (Phase 3) on priority targets.

    angr runs in-process, so we need to be careful about memory. For large
    binaries (>20MB), we increase the timeout but also accept that analysis
    may be partial.
    """
    from core.malware.symbolic import run_angr_analysis

    print("\n" + "=" * 70)
    print("PHASE 3: angr Static Analysis")
    print("=" * 70)

    # Sort by file size ascending (analyze small ones first for quick wins)
    sorted_targets = sorted(angr_targets, key=lambda t: t["file_size"])

    binary_paths = []
    for t in sorted_targets:
        try:
            path = resolve_path(t["path"])
            binary_paths.append(path)
        except FileNotFoundError as e:
            print("WARNING: %s" % e)

    print("\nAnalyzing %d binaries with angr..." % len(binary_paths))
    print("Output directory: %s" % ANGR_OUTPUT_DIR)
    print("Timeout per binary: %ds (auto-adjusted for large files)" % timeout_per_binary)
    print("Memory limit: %d GB per binary" % max_memory_gb)
    print()

    t0 = time.time()
    summary = run_angr_analysis(
        binary_paths=binary_paths,
        output_dir=ANGR_OUTPUT_DIR,
        timeout_per_binary=timeout_per_binary,
        max_memory_gb=max_memory_gb,
        verbose=verbose,
    )
    elapsed = time.time() - t0

    stats = summary["stats"]
    print("\n--- angr Phase 3 Complete ---")
    print("Total: %d | Success: %d | Skipped: %d | Failed: %d" % (
        stats["total"], stats["success"], stats["skipped"], stats["failed"]))
    print("Elapsed: %.1f seconds (%.1f min)" % (elapsed, elapsed / 60))

    if summary["errors"]:
        print("\nErrors:")
        for err in summary["errors"][:10]:
            print("  %s: %s" % (err["sha256"][:16], str(err["error"])[:80]))

    return summary


def main():
    parser = argparse.ArgumentParser(
        description="Phase 2+3 Deep Binary Analysis Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--phase", choices=["2", "3", "both"], default="both",
        help="Which phase to run: 2 (Ghidra), 3 (angr), or both (default)",
    )
    parser.add_argument(
        "--ghidra-timeout", type=int, default=600,
        help="Timeout per binary for Ghidra analysis in seconds (default: 600)",
    )
    parser.add_argument(
        "--angr-timeout", type=int, default=300,
        help="Timeout per binary for angr analysis in seconds (default: 300)",
    )
    parser.add_argument(
        "--angr-memory", type=int, default=4,
        help="Memory limit for angr in GB (default: 4)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show targets without running analysis",
    )
    parser.add_argument(
        "--verbose", action="store_true", default=True,
        help="Print progress (default: True)",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Minimal output",
    )

    args = parser.parse_args()
    if args.quiet:
        args.verbose = False

    print("=" * 70)
    print("AdaptiveShield — Deep Binary Analysis Pipeline")
    print("=" * 70)
    print()

    # 1. Load triage results
    print("Loading Phase 1 triage results from:")
    print("  %s" % TRIAGE_RESULTS_FILE)
    triage_results = load_triage_results()
    print("  -> %d files in triage" % len(triage_results))

    # 2. Build target lists
    ghidra_targets, angr_targets, pe_dedup_info = build_target_lists(triage_results)

    # 3. Print summary
    print_target_summary(ghidra_targets, angr_targets, pe_dedup_info)

    if args.dry_run:
        print("\n[DRY RUN] Exiting without running analysis.")
        return

    # 4. Run analyses
    ghidra_summary = None
    angr_summary = None

    if args.phase in ("2", "both"):
        ghidra_summary = run_phase2(
            ghidra_targets,
            timeout_per_binary=args.ghidra_timeout,
            verbose=args.verbose,
        )

    if args.phase in ("3", "both"):
        angr_summary = run_phase3(
            angr_targets,
            timeout_per_binary=args.angr_timeout,
            max_memory_gb=args.angr_memory,
            verbose=args.verbose,
        )

    # 5. Combined summary
    print("\n" + "=" * 70)
    print("DEEP ANALYSIS COMPLETE")
    print("=" * 70)

    combined = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ghidra": ghidra_summary["stats"] if ghidra_summary else None,
        "angr": angr_summary["stats"] if angr_summary else None,
    }

    summary_path = os.path.join(BASE_DIR, "data", "processed", "deep_analysis_summary.json")
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)
    with open(summary_path, "w") as f:
        json.dump(combined, f, indent=2)
    print("\nCombined summary written to: %s" % summary_path)


if __name__ == "__main__":
    main()
