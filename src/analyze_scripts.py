#!/usr/bin/env python3
"""
Shell Script Malware Analyzer
==============================

Analyzes the 5 interesting shell scripts captured by the Cowrie honeypot that
Ghidra/angr cannot process (they're text, not compiled binaries). Extracts:

  - Downloaded URLs (wget/curl targets)
  - C2 / payload server IPs and ports
  - Commands executed (chmod, crontab, kill, etc.)
  - File paths written to or read from
  - Persistence mechanisms (crontab, systemd, /etc/init.d, rc.local)
  - Anti-forensics (rm, history clearing, log deletion)
  - Target architectures (multi-arch dropper detection)
  - Mining configuration (wallet addresses, pool URLs, worker names)
  - Self-deletion behavior

Outputs JSON feature files to data/processed/script_features/ for integration
with the ML pipeline (Phase 4).

Usage:
    python src/analyze_scripts.py              # Analyze all 5 scripts
    python src/analyze_scripts.py --verbose    # With full details
"""

import json
import os
import re
import sys
import time
import hashlib

SRC_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SRC_DIR)
sys.path.insert(0, SRC_DIR)

TRIAGE_RESULTS = os.path.join(BASE_DIR, "data", "processed", "binary_triage", "all_triage_results.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "data", "processed", "script_features")


def sha256_of_content(content):
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def analyze_script(file_path, sha256=None):
    """
    Analyze a shell script and extract behavioral features.

    Returns a dict with all extracted features.
    """
    with open(file_path, "r", errors="replace") as f:
        content = f.read()

    lines = content.split("\n")
    result = {
        "sha256": sha256 or sha256_of_content(content),
        "file_path": file_path,
        "file_size": os.path.getsize(file_path),
        "line_count": len(lines),
        "analyzer": "script_analyzer",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    # ---- Shebang detection ----
    shebang = None
    if lines and lines[0].startswith("#!"):
        shebang = lines[0].strip()
    result["shebang"] = shebang

    # ---- URL extraction ----
    # wget/curl download URLs
    url_re = re.compile(r'https?://[^\s;"\'<>|&]+')
    all_urls = list(set(url_re.findall(content)))

    # Separate download commands from general URLs
    download_cmds = []
    wget_re = re.compile(r'wget\s+(?:-[^\s]*\s+)*([^\s;"\'|&]+)')
    curl_re = re.compile(r'curl\s+(?:-[^\s]*\s+)*(?:-O\s+)?([^\s;"\'|&]+)')
    for m in wget_re.finditer(content):
        url = m.group(1)
        if url.startswith("http"):
            download_cmds.append({"tool": "wget", "url": url})
    for m in curl_re.finditer(content):
        url = m.group(1)
        if url.startswith("http"):
            download_cmds.append({"tool": "curl", "url": url})

    result["urls"] = all_urls
    result["download_commands"] = download_cmds

    # ---- IP address extraction ----
    ip_re = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    ips = list(set(ip_re.findall(content)))
    # Filter out common non-C2 IPs
    ips = [ip for ip in ips if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255")]
    result["ip_addresses"] = ips

    # ---- Port extraction from URLs ----
    port_re = re.compile(r':(\d{2,5})/')
    ports = list(set(port_re.findall(content)))
    result["ports"] = ports

    # ---- Target architectures (multi-arch dropper detection) ----
    arch_keywords = [
        "x86_64", "x86", "i586", "i686", "arm", "arm5", "arm6", "arm7",
        "arm8", "aarch64", "armv8", "mips", "mpsl", "mipsel", "ppc",
        "sh4", "spc", "m68k", "arc",
    ]
    detected_archs = []
    for arch in arch_keywords:
        # Look for arch in download URLs or binary names
        if re.search(r'[./]' + re.escape(arch) + r'[\s;"\']', content) or \
           re.search(r'\b' + re.escape(arch) + r'\b', content):
            detected_archs.append(arch)
    result["target_architectures"] = list(set(detected_archs))
    result["is_multi_arch_dropper"] = len(set(detected_archs)) > 2

    # ---- Command extraction ----
    dangerous_cmds = {
        "chmod": re.compile(r'chmod\s+\S+\s+\S+'),
        "chown": re.compile(r'chown\s+\S+'),
        "kill": re.compile(r'kill\s+[-\d]+'),
        "killall": re.compile(r'killall\s+\S+'),
        "pkill": re.compile(r'pkill\s+\S+'),
        "rm": re.compile(r'rm\s+[-rf]*\s*\S+'),
        "mv": re.compile(r'mv\s+\S+\s+\S+'),
        "cp": re.compile(r'cp\s+\S+\s+\S+'),
        "mkdir": re.compile(r'mkdir\s+[-p]*\s*\S+'),
        "crontab": re.compile(r'crontab\s+\S+'),
        "nohup": re.compile(r'nohup\s+\S+'),
        "setsid": re.compile(r'setsid\s+\S+'),
        "disown": re.compile(r'disown'),
    }
    found_cmds = {}
    for cmd_name, pattern in dangerous_cmds.items():
        matches = pattern.findall(content)
        if matches:
            found_cmds[cmd_name] = matches[:20]  # cap at 20 per cmd
    result["dangerous_commands"] = found_cmds

    # ---- Persistence mechanisms ----
    persistence = []
    if "crontab" in content or "cron" in content.lower():
        # Extract cron entries
        cron_re = re.compile(r'["\']([*/\d]+\s+[*/\d]+\s+[*/\d]+\s+[*/\d]+\s+[*/\d]+\s+.+?)["\']')
        cron_entries = cron_re.findall(content)
        persistence.append({
            "type": "crontab",
            "entries": cron_entries[:10],
        })
    if "/etc/init.d" in content or "update-rc.d" in content:
        persistence.append({"type": "init.d"})
    if "systemctl" in content or ".service" in content:
        persistence.append({"type": "systemd"})
    if "/etc/rc.local" in content:
        persistence.append({"type": "rc.local"})
    if ".bashrc" in content or ".profile" in content or ".bash_profile" in content:
        persistence.append({"type": "shell_profile"})
    if "chkconfig" in content:
        persistence.append({"type": "chkconfig"})
    result["persistence_mechanisms"] = persistence

    # ---- Anti-forensics ----
    anti_forensics = []
    if "rm $0" in content or "rm -f $0" in content:
        anti_forensics.append("self_deletion")
    if "history" in content.lower() and ("clear" in content.lower() or "-c" in content):
        anti_forensics.append("history_clearing")
    if "/var/log" in content and ("rm" in content or ">" in content):
        anti_forensics.append("log_deletion")
    if "unset HISTFILE" in content or "HISTSIZE=0" in content:
        anti_forensics.append("history_disable")
    result["anti_forensics"] = anti_forensics

    # ---- Mining configuration ----
    mining = {}

    # Monero wallet addresses (95 or 106 chars, starts with 4)
    monero_re = re.compile(r'\b(4[0-9A-Za-z]{94,105})\b')
    wallets = monero_re.findall(content)
    if wallets:
        mining["monero_wallets"] = list(set(wallets))

    # Mining pool URLs
    pool_re = re.compile(r'((?:stratum\+tcp|stratum\+ssl)://[^\s;"\']+)')
    pools = pool_re.findall(content)
    if not pools:
        # Try plain pool hostnames
        pool_kw_re = re.compile(r'((?:pool|mine|mining)\.[^\s;"\']+)')
        pools = pool_kw_re.findall(content)
    if pools:
        mining["pool_urls"] = list(set(pools))

    # Worker names
    if "moneroocean" in content.lower():
        mining["pool_service"] = "MoneroOcean"
    if "xmrig" in content.lower():
        mining["miner_software"] = "XMRig"

    # Mining-related variables/configs
    if "WALLET" in content:
        mining["has_wallet_variable"] = True
    if "hashrate" in content.lower():
        mining["references_hashrate"] = True

    result["mining_config"] = mining
    result["is_miner"] = bool(mining)

    # ---- File paths written/referenced ----
    paths = []
    path_re = re.compile(r'(/(?:tmp|var|home|root|opt|usr|etc|dev|proc|sys|mnt|run)[/\w.-]+)')
    for m in path_re.finditer(content):
        p = m.group(1)
        if p not in paths:
            paths.append(p)
    result["referenced_paths"] = paths[:50]

    # ---- Behavioral summary ----
    behavioral = {
        "is_downloader": len(download_cmds) > 0,
        "is_multi_arch_dropper": result["is_multi_arch_dropper"],
        "is_miner": result["is_miner"],
        "has_persistence": len(persistence) > 0,
        "has_anti_forensics": len(anti_forensics) > 0,
        "has_self_deletion": "self_deletion" in anti_forensics,
        "downloads_count": len(download_cmds),
        "unique_c2_ips": len(ips),
        "target_arch_count": len(set(detected_archs)),
    }
    result["behavioral_summary"] = behavioral

    return result


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Shell script malware analyzer")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print full details")
    args = parser.parse_args()

    print("=" * 70)
    print("AdaptiveShield — Shell Script Malware Analyzer")
    print("=" * 70)

    # Load triage results to find the interesting scripts
    with open(TRIAGE_RESULTS) as f:
        data = json.load(f)

    interesting_labels = {"downloader", "destructive", "miner"}
    script_targets = []
    for r in data["results"]:
        if r["file_type"] != "script":
            continue
        cls = r.get("classification", {})
        label = cls.get("primary_label", "unknown") if isinstance(cls, dict) else str(cls)
        if label in interesting_labels:
            script_targets.append({
                "sha256": r["sha256"],
                "path": os.path.join(BASE_DIR, r["path"]),
                "label": label,
                "tags": cls.get("tags", []) if isinstance(cls, dict) else [],
            })

    print("Found {} interesting scripts to analyze\n".format(len(script_targets)))
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    all_results = []

    for i, st in enumerate(script_targets):
        print("[{}/{}] Analyzing {} ({})...".format(
            i + 1, len(script_targets), st["sha256"][:16], st["label"]))

        result = analyze_script(st["path"], sha256=st["sha256"])
        result["triage_label"] = st["label"]
        result["triage_tags"] = st["tags"]

        # Save individual JSON
        out_path = os.path.join(OUTPUT_DIR, st["sha256"] + ".json")
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)

        all_results.append(result)

        # Print summary
        beh = result["behavioral_summary"]
        print("  Lines: {} | URLs: {} | IPs: {} | Downloads: {}".format(
            result["line_count"], len(result["urls"]), len(result["ip_addresses"]),
            beh["downloads_count"]))
        if result["target_architectures"]:
            print("  Target archs: {} ({})".format(
                len(result["target_architectures"]),
                ", ".join(result["target_architectures"][:6])))
        if result["mining_config"]:
            print("  Mining: {}".format(
                ", ".join(k for k in result["mining_config"] if result["mining_config"][k])))
        if result["persistence_mechanisms"]:
            print("  Persistence: {}".format(
                ", ".join(p["type"] for p in result["persistence_mechanisms"])))
        if result["anti_forensics"]:
            print("  Anti-forensics: {}".format(", ".join(result["anti_forensics"])))

        flags = [k.replace("is_", "").replace("has_", "")
                 for k, v in beh.items() if v is True]
        if flags:
            print("  Behavioral flags: {}".format(", ".join(flags)))

        if args.verbose:
            print("  Download URLs:")
            for dc in result["download_commands"][:10]:
                print("    {} -> {}".format(dc["tool"], dc["url"]))
            if result["ip_addresses"]:
                print("  C2 IPs: {}".format(result["ip_addresses"]))
            if result["referenced_paths"]:
                print("  File paths: {}".format(result["referenced_paths"][:10]))

        print()

    # Save combined summary
    summary_path = os.path.join(OUTPUT_DIR, "_script_analysis_summary.json")
    summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_scripts": len(all_results),
        "results": all_results,
        "stats": {
            "downloaders": sum(1 for r in all_results if r["behavioral_summary"]["is_downloader"]),
            "miners": sum(1 for r in all_results if r["behavioral_summary"]["is_miner"]),
            "multi_arch": sum(1 for r in all_results if r["behavioral_summary"]["is_multi_arch_dropper"]),
            "with_persistence": sum(1 for r in all_results if r["behavioral_summary"]["has_persistence"]),
            "with_anti_forensics": sum(1 for r in all_results if r["behavioral_summary"]["has_anti_forensics"]),
            "total_unique_ips": len(set(ip for r in all_results for ip in r["ip_addresses"])),
            "total_unique_urls": len(set(u for r in all_results for u in r["urls"])),
        },
    }
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    print("=" * 70)
    print("SCRIPT ANALYSIS COMPLETE")
    print("=" * 70)
    print("Results saved to: {}".format(OUTPUT_DIR))
    print("Summary: {}".format(summary_path))
    s = summary["stats"]
    print("  {} downloaders, {} miners, {} multi-arch".format(
        s["downloaders"], s["miners"], s["multi_arch"]))
    print("  {} unique C2 IPs, {} unique URLs".format(
        s["total_unique_ips"], s["total_unique_urls"]))
    print("  {} with persistence, {} with anti-forensics".format(
        s["with_persistence"], s["with_anti_forensics"]))


if __name__ == "__main__":
    main()
