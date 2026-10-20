"""
Session Relabeler — the single canonical labeling engine for AdaptiveShield.

Supersedes the earlier relabel_azure.py (v2, regex-only overrides) and
relabel_v3.py (kept as reference in verify/). Implements the LLM-audited
content-signal priority engine (Tier-0 acceptance: 85.6% family-level
agreement with independent annotation, up from 48.6% for the v2 rules).

Pipeline: data/exports/sessions_complete.csv (original binary-labeled
export) -> data/exports/sessions_complete_v3.csv

Label policy (priority order, first match wins):
  0. Binary ground truth: original label_id > 0 (malware landed & triaged)
     is NEVER overridden. [LLM agreement on these rows: 92%]
  1. Takeover/persistence -> ADVANCED_APT  (authorized_keys, useradd/
     chpasswd backdoor, chattr+ssh, cron/systemd install, hidden nohup)
     [LLM-validated: T1098.004 chains are persistence, not destruction]
  2. Fileless /dev/tcp ELF stager -> Downloader (fetch bytes + chmod + exec;
     checked BEFORE exploit so stagers don't read as reverse shells)
  3. Exploit tier -> Exploit (shadow reads, ssh key theft, history mining,
     cracking tools, SQLi/XSS/traversal, pure reverse shells)
  4. Downloader tier -> Downloader (wget|sh, fetch+chmod chains, b64|exec)
  5. Destructive tier -> Destructive (system-dir wipes, dd/mkfs, fork bomb,
     ransomware encrypt; 'history -c' inside a fetch-run chain is bot
     cleanup and does NOT count [LLM-validated])
  6. Recon tier -> Recon (uname/whoami/id enum, free/uptime/mount/df/env,
     nmap/netstat, passwd listing, fs sweeps, HTTP static probes)
  7. Severity floor: still-quiet session with MITRE severity >= 6 -> Recon
  8. Otherwise Safe.

Output columns appended (all original columns preserved):
  label_v3_id / label_v3_name / label_v3_source / mitre_severity_max

Usage:
    PYTHONPATH=src .venv/bin/python src/training/neural/relabel_sessions.py
"""
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

from core.mitre.session_annotator import annotate_session

ROOT = Path(__file__).resolve().parents[3]
IN_CSV = ROOT / "data" / "exports" / "sessions_complete.csv"
OUT_CSV = ROOT / "data" / "exports" / "sessions_complete_v3.csv"
STATS = ROOT / "data" / "exports" / "relabel_v3_stats.json"

CLASS_NAMES = ["Safe", "Recon", "Downloader", "Exploit", "Destructive", "ADVANCED_APT"]

# ------------------------------------------------------------------ signal tiers
SIG_APT = [
    ("authorized_keys", re.compile(r"authorized_keys|ssh-rsa\s+AAAA", re.I)),
    ("chattr_ssh", re.compile(r"chattr\s+[+-]i[ai]?\s+\S*\.?\s*ssh|lockr\s+-ia\s+\.?\s*ssh", re.I)),
    ("passwd_takeover", re.compile(r"chpasswd|passwd\s*\|?\s*bash|echo\s+root:[^|]{2,}\|", re.I)),
    ("useradd_backdoor", re.compile(r"useradd\s|usermod\s+-aG", re.I)),
    ("ssh_dir_setup", re.compile(r"mkdir\s+-p\s+~?/?\.?\s*ssh", re.I)),
    ("cron_install", re.compile(r"(echo|>>|>)\s*[^;]*(/etc/cron|crontab|@reboot)", re.I)),
    ("service_install", re.compile(r"systemctl\s+(enable|daemon-reload)", re.I)),
    ("hidden_launch", re.compile(r"nohup\s+\./", re.I)),
]
SIG_DESTRUCTIVE = [
    ("system_wipe", re.compile(r"rm\s+-rf\s+/(etc|var|usr|boot|home|root)(\s|/|$)|rm\s+-rf\s+/\s*$", re.I)),
    ("disk_wipe", re.compile(r"dd\s+[^;]*of=/dev/(sd|hd|nvme|vd)|\bmkfs\b", re.I)),
    ("fork_bomb", re.compile(r":\(\)\s*\{", re.I)),
    ("ransom_encrypt", re.compile(r"openssl\s+enc\s+[^;]*(-aes|-des)", re.I)),
    ("log_coverup", re.compile(r"history\s+-c|HISTFILE|rm\s+-rf\s+/var/log|shred\s", re.I)),
]
SIG_EXPLOIT = [
    ("shadow_read", re.compile(r"cat\s+(\/etc\/)?shadow|\/etc\/shadow", re.I)),
    ("ssh_key_theft", re.compile(r"id_(rsa|dsa|ecdsa|ed25519)", re.I)),
    ("history_mining", re.compile(r"(bash|mysql)_history", re.I)),
    ("cracking_tools", re.compile(r"mimikatz|unshadow|hashcat|\bjohn\s|\bhydra\s|medusa", re.I)),
    ("sqli_dynamic", re.compile(r"union\s+select|or\s+1=1|'\s*or\s*'|drop\s+table|select\s+[\w*%\s]+\s+from", re.I)),
    ("xss", re.compile(r"<script|javascript:|onerror\s*=|onload\s*=", re.I)),
    ("traversal", re.compile(r"\.\./|%2e%2e|GET[^;]*etc/passwd", re.I)),
    ("reverse_shell", re.compile(r"bash\s+-i\s+>&|/dev/tcp/|nc\s+[^;]*\s-e\s|socat", re.I)),
]
SIG_DOWNLOADER = [
    ("pipe_to_shell", re.compile(r"(wget|curl|tftp)[^;|]*\|\s*(ba)?sh", re.I)),
    ("b64_exec", re.compile(r"base64\s+(-d|--decode)\s*\|", re.I)),
    ("fetch_exec_chain", re.compile(r"(wget|curl|tftp)[^;]{0,200}(chmod\s+\+x|\./\S+)", re.I)),
    # fileless ELF stager via /dev/tcp: fetch bytes to /tmp + chmod + exec
    ("devtcp_stager", re.compile(
        r"/dev/tcp/[^;]{0,250}(cat\s+0<&6|>\s*/tmp/\S+).{0,200}(chmod\s+\+x|\./)", re.I | re.S)),
]
SIG_RECON = [
    ("enumeration", re.compile(
        r"\buname\b|\bwhoami\b|\bid\b|\bhostname\b|\blscpu\b|\barch\b|"
        r"/proc/(cpuinfo|mounts|version|meminfo|net/)|ifconfig|netstat|"
        r"\bnmap\b|masscan|\bps\s+aux\b", re.I)),
    ("sysinfo_lite", re.compile(
        r"\bfree\s+(-\w+\s+)?-h\b|\buptime\b|\bmount\b\s*[;|]|\benv\b\s*[;|]\s*head|"
        r"\bdf\s+-h\b|\bdmesg\b|ipinfo\.io|ifconfig\.me|icanhazip|checkip\.amazonaws", re.I)),
    ("passwd_listing", re.compile(r"cat\s+(\/etc\/)?passwd\b", re.I)),
    ("fs_sweep", re.compile(r"(ls\s*;|cd\s+/\s*;|cd\s+etc\s*;)", re.I)),
    ("http_static_probe", re.compile(
        r"robots\.txt|\.git\b|\.svn|\.bak\b|\.old\b|\.Inc\b|phpinfo|server-status|"
        r"wp-admin|wp-login|web\.config|/admin|manager/|backup|changelog|/\d{8,}\.", re.I)),
]

# Infection-chain cleanup context: 'history -c' / rm of the dropper itself
# right after a fetch-run chain is bot cleanup, NOT anti-forensic destruction.
INFECTION_CHAIN = re.compile(
    r"(wget|curl|tftp)[^;]{0,300}(chmod|\./|sh\s|bash\s)", re.I)


def first_match(sigs, text):
    for name, rx in sigs:
        if rx.search(text):
            return name
    return None


def classify(commands_text):
    """Content-signal priority engine. Returns (class_id, reason).

    Tier order: binary > APT > devtcp-stager > Exploit > Downloader >
    Destructive > Recon > severity-floor > Safe. The devtcp_stager check
    runs before the exploit tier so fetch-and-execute /dev/tcp chains
    classify as Downloader (LLM-validated), while pure reverse shells stay
    Exploit.
    """
    t = str(commands_text)
    hit = first_match(SIG_APT, t)
    if hit:
        return 5, f"apt:{hit}"
    if SIG_DOWNLOADER[3][1].search(t):  # devtcp_stager
        return 2, "downloader:devtcp_stager"
    hit = first_match(SIG_EXPLOIT, t)
    if hit:
        return 3, f"exploit:{hit}"
    hit = first_match(SIG_DOWNLOADER, t)
    if hit:
        return 2, f"downloader:{hit}"
    # destructive suppressed inside infection chains (bot cleanup)
    if not INFECTION_CHAIN.search(t):
        hit = first_match(SIG_DESTRUCTIVE, t)
        if hit:
            return 4, f"destructive:{hit}"
    hit = first_match(SIG_RECON, t)
    if hit:
        return 1, f"recon:{hit}"
    return 0, "quiet:safe"


def mitre_severity(commands_text):
    if not isinstance(commands_text, str) or not commands_text.strip():
        return 0
    parts = [c.strip() for c in commands_text.replace("&&", ";").replace("||", ";").split(";") if c.strip()]
    if not parts:
        return 0
    try:
        return annotate_session(parts)["severity_max"]
    except Exception:
        return 0


def main():
    print(f"Reading {IN_CSV} ...")
    with open(IN_CSV, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fields_in = list(reader.fieldnames or [])
        rows = list(reader)
    print(f"Loaded {len(rows)} sessions")

    label_v3, src_v3, sev_col = [], [], []
    trans = Counter()
    sev_floor = 0
    for i, row in enumerate(rows):
        orig_id = int(float(row.get("label_id", 0) or 0))
        cmds = row.get("commands", "")

        if orig_id > 0:
            lab, why = orig_id, "kept_binary"
        else:
            lab, why = classify(cmds)
            sev = mitre_severity(cmds)
            if lab == 0 and sev >= 6:
                lab, why = 1, f"recon_floor:sev>={sev}"
                sev_floor += 1
        sev_col.append(mitre_severity(cmds) if orig_id == 0 else -1)

        label_v3.append(lab)
        src_v3.append(why)
        trans[(row.get("label_name", "?"), CLASS_NAMES[lab])] += 1
        if (i + 1) % 10000 == 0:
            print(f"  classified {i+1}/{len(rows)}")

    out_fields = fields_in + ["label_v3_id", "label_v3_name", "label_v3_source",
                              "mitre_severity_max"]
    print(f"Writing {OUT_CSV} ...")
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=out_fields)
        w.writeheader()
        for row, lab, why, sev in zip(rows, label_v3, src_v3, sev_col):
            row["label_v3_id"] = lab
            row["label_v3_name"] = CLASS_NAMES[lab]
            row["label_v3_source"] = why
            row["mitre_severity_max"] = sev
            w.writerow(row)

    dist = Counter(label_v3)
    print("\n=== LABEL V3 DISTRIBUTION ===")
    for cid in range(6):
        print(f"  {CLASS_NAMES[cid]:14s} {dist.get(cid, 0):7d}")
    print(f"\nseverity-floor promotions: {sev_floor}")

    print("\n=== TRANSITIONS original -> v3 (top 20) ===")
    for (a, b), n in trans.most_common(20):
        print(f"  {n:7d}  {a:14s} -> {b}")

    with open(STATS, "w") as f:
        json.dump({
            "distribution": {CLASS_NAMES[c]: dist.get(c, 0) for c in range(6)},
            "transitions": {f"{a}->{b}": n for (a, b), n in trans.items()},
            "severity_floor_promotions": sev_floor,
            "total": len(rows),
        }, f, indent=2)
    print(f"\nStats: {STATS}")


if __name__ == "__main__":
    main()