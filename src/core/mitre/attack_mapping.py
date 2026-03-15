"""
MITRE ATT&CK Sub-Technique Knowledge Base for SSH Honeypot Analysis.

This module provides the domain knowledge that the ML model lacks: a structured
mapping from observable command patterns to MITRE ATT&CK sub-techniques, with
tactic classification and severity scoring.

WHY THIS EXISTS:
The previous model used character-level TF-IDF (2-5 char n-grams) which treats
commands as opaque strings. It has zero concept of what commands DO. This module
bridges that gap by encoding expert knowledge:
  - "cat /etc/shadow" -> T1552.001 (Credentials in Files) -> credential_access -> severity 8
  - "wget http://x/bot" -> T1105 (Ingress Tool Transfer) -> command_and_control -> severity 7

The session_annotator.py uses this knowledge base to produce per-session feature
vectors (14-dimensional tactic vectors, severity scores, kill chain metrics)
that capture WHAT an attacker is doing, not just WHAT they typed.

DESIGN DECISIONS:
1. Sub-technique level (T1059.004 not T1059) for maximum granularity.
   The host-side neural model can always aggregate up to tactic level.
2. Severity 1-10 scale calibrated for SSH honeypot context:
   - 1-3: Benign/low-signal (ls, pwd, uname)
   - 4-5: Reconnaissance (port scanning, system enumeration)
   - 6-7: Active exploitation prep (downloading tools, setting permissions)
   - 8-9: Direct exploitation (credential theft, C2, persistence)
   - 10: Destructive/critical (wiping, ransomware, APT multi-stage)
3. Patterns are regex-based for flexibility. Order matters — first match wins
   per command, but a command can match multiple patterns across different
   techniques (e.g., "wget http://x/bot && chmod +x bot" matches both T1105
   and T1222.002).
4. Binary analysis tags also map to ATT&CK via BINARY_TAG_TO_TECHNIQUE,
   allowing the model to combine command-level and binary-level intelligence.

MAINTENANCE:
Add new patterns as new attack behaviors are observed. The patterns are
intentionally broad (e.g., r"wget|curl" not r"wget\s+-O") to catch variants.
Specificity comes from combining multiple low-confidence matches into a
high-confidence session profile.

REFERENCE: https://attack.mitre.org/
"""

import re

# ===================================================================
# The 14 ATT&CK Tactics (Enterprise Matrix)
# ===================================================================

TACTICS = {
    "reconnaissance":       {"id": "TA0043", "order": 1,  "description": "Gathering information to plan operations"},
    "resource_development":  {"id": "TA0042", "order": 2,  "description": "Establishing resources for operations"},
    "initial_access":       {"id": "TA0001", "order": 3,  "description": "Getting into the network"},
    "execution":            {"id": "TA0002", "order": 4,  "description": "Running malicious code"},
    "persistence":          {"id": "TA0003", "order": 5,  "description": "Maintaining foothold"},
    "privilege_escalation": {"id": "TA0004", "order": 6,  "description": "Gaining higher permissions"},
    "defense_evasion":      {"id": "TA0005", "order": 7,  "description": "Avoiding detection"},
    "credential_access":    {"id": "TA0006", "order": 8,  "description": "Stealing credentials"},
    "discovery":            {"id": "TA0007", "order": 9,  "description": "Learning about the environment"},
    "lateral_movement":     {"id": "TA0008", "order": 10, "description": "Moving through the network"},
    "collection":           {"id": "TA0009", "order": 11, "description": "Gathering data of interest"},
    "command_and_control":  {"id": "TA0011", "order": 12, "description": "Communicating with compromised systems"},
    "exfiltration":         {"id": "TA0010", "order": 13, "description": "Stealing data"},
    "impact":               {"id": "TA0040", "order": 14, "description": "Manipulate, interrupt, or destroy systems"},
}

TACTIC_NAMES = sorted(TACTICS.keys(), key=lambda t: TACTICS[t]["order"])


# ===================================================================
# ATT&CK Command Patterns — Sub-Technique Level
# ===================================================================
# Each pattern is a dict with:
#   pattern      : compiled regex to match against a single command string
#   technique_id : MITRE ATT&CK technique/sub-technique ID
#   technique_name: human-readable name
#   tactic       : one of the 14 tactic keys above
#   severity     : 1-10 integer (see scale in module docstring)
#   description  : brief explanation of why this pattern matters
#
# IMPORTANT: Patterns are tested case-insensitively against each command.
# A single command can match multiple patterns (multi-technique detection).

_RAW_PATTERNS = [
    # =================================================================
    # EXECUTION (TA0002)
    # =================================================================
    {
        "pattern": r"(^|[;&|]\s*)(bash|sh|dash|zsh|ksh|csh)\s+(-[a-z]*i|.*>\s*&\s*/dev/tcp/)",
        "technique_id": "T1059.004",
        "technique_name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "execution",
        "severity": 8,
        "description": "Interactive shell or reverse shell via /dev/tcp",
    },
    {
        "pattern": r"python[23]?\s+(-c\s+|.*\.(py|pyw))",
        "technique_id": "T1059.006",
        "technique_name": "Command and Scripting Interpreter: Python",
        "tactic": "execution",
        "severity": 6,
        "description": "Python script execution",
    },
    {
        "pattern": r"perl\s+(-e\s+|.*\.pl)",
        "technique_id": "T1059.006",
        "technique_name": "Command and Scripting Interpreter: Python",
        "tactic": "execution",
        "severity": 6,
        "description": "Perl script execution (mapped to scripting interpreter)",
    },
    {
        "pattern": r"\./[a-zA-Z0-9_\-\.]+",
        "technique_id": "T1204.002",
        "technique_name": "User Execution: Malicious File",
        "tactic": "execution",
        "severity": 7,
        "description": "Executing a file from current directory (common malware pattern)",
    },
    {
        "pattern": r"(chmod\s+\+x|chmod\s+[0-7]*[1357][0-7]*)\s+.*&&.*\./",
        "technique_id": "T1204.002",
        "technique_name": "User Execution: Malicious File",
        "tactic": "execution",
        "severity": 9,
        "description": "chmod+execute chain — classic malware deployment",
    },
    {
        "pattern": r"nohup\s+\./",
        "technique_id": "T1204.002",
        "technique_name": "User Execution: Malicious File",
        "tactic": "execution",
        "severity": 8,
        "description": "Background execution with nohup (persist beyond session)",
    },
    {
        "pattern": r"\|\s*(bash|sh|dash|zsh)",
        "technique_id": "T1059.004",
        "technique_name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "execution",
        "severity": 8,
        "description": "Piping content to shell (download-and-execute pattern)",
    },
    {
        "pattern": r"base64\s+(-d|--decode)",
        "technique_id": "T1140",
        "technique_name": "Deobfuscate/Decode Files or Information",
        "tactic": "defense_evasion",
        "severity": 7,
        "description": "Base64 decoding — common obfuscation technique",
    },

    # =================================================================
    # PERSISTENCE (TA0003)
    # =================================================================
    {
        "pattern": r"crontab\s+(-[erl]|.*\s)",
        "technique_id": "T1053.003",
        "technique_name": "Scheduled Task/Job: Cron",
        "tactic": "persistence",
        "severity": 8,
        "description": "Crontab manipulation for persistence",
    },
    {
        "pattern": r"(echo|cat|printf|tee).*(/etc/cron|crontab|@reboot|\*/\d+\s+\*)",
        "technique_id": "T1053.003",
        "technique_name": "Scheduled Task/Job: Cron",
        "tactic": "persistence",
        "severity": 8,
        "description": "Writing cron entries for persistence",
    },
    {
        "pattern": r"(echo|cat|printf|tee).*/etc/(rc\.local|rc\.d|init\.d/)",
        "technique_id": "T1037.004",
        "technique_name": "Boot or Logon Initialization Scripts: RC Scripts",
        "tactic": "persistence",
        "severity": 8,
        "description": "Modifying boot scripts for persistence",
    },
    {
        "pattern": r"systemctl\s+(enable|daemon-reload|start)",
        "technique_id": "T1543.002",
        "technique_name": "Create or Modify System Process: Systemd Service",
        "tactic": "persistence",
        "severity": 8,
        "description": "Systemd service manipulation for persistence",
    },
    {
        "pattern": r"(echo|cat|printf|tee).*\.ssh/authorized_keys",
        "technique_id": "T1098.004",
        "technique_name": "Account Manipulation: SSH Authorized Keys",
        "tactic": "persistence",
        "severity": 9,
        "description": "Adding SSH keys for persistent access",
    },
    {
        "pattern": r"(echo|cat|printf|tee).*/etc/(profile|bashrc|\.bashrc|\.profile|environment)",
        "technique_id": "T1546.004",
        "technique_name": "Event Triggered Execution: Unix Shell Configuration Modification",
        "tactic": "persistence",
        "severity": 7,
        "description": "Modifying shell profile for persistence",
    },
    {
        "pattern": r"chattr\s+\+i",
        "technique_id": "T1222.002",
        "technique_name": "File and Directory Permissions Modification: Linux and Mac",
        "tactic": "persistence",
        "severity": 7,
        "description": "Making files immutable to prevent removal",
    },

    # =================================================================
    # PRIVILEGE ESCALATION (TA0004)
    # =================================================================
    {
        "pattern": r"sudo\s+",
        "technique_id": "T1548.003",
        "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "privilege_escalation",
        "severity": 6,
        "description": "Attempting sudo elevation",
    },
    {
        "pattern": r"(chmod\s+[u+]*s\s|chmod\s+[0-7]*[4-7][0-7]{2}\s)",
        "technique_id": "T1548.001",
        "technique_name": "Abuse Elevation Control Mechanism: Setuid and Setgid",
        "tactic": "privilege_escalation",
        "severity": 8,
        "description": "Setting SUID/SGID bits for privilege escalation",
    },
    {
        "pattern": r"/etc/sudoers",
        "technique_id": "T1548.003",
        "technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "privilege_escalation",
        "severity": 9,
        "description": "Accessing/modifying sudoers file",
    },

    # =================================================================
    # DEFENSE EVASION (TA0005)
    # =================================================================
    {
        "pattern": r"(history\s+-c|unset\s+HISTFILE|HISTSIZE=0|HISTFILESIZE=0|export\s+HISTFILE=/dev/null)",
        "technique_id": "T1070.003",
        "technique_name": "Indicator Removal: Clear Command History",
        "tactic": "defense_evasion",
        "severity": 7,
        "description": "Clearing or disabling command history",
    },
    {
        "pattern": r"(rm\s+(-[rf]*\s+)*/var/log|>/var/log/|truncate.*log|echo\s*>.*\.log)",
        "technique_id": "T1070.002",
        "technique_name": "Indicator Removal: Clear Linux or Mac System Logs",
        "tactic": "defense_evasion",
        "severity": 8,
        "description": "Clearing system logs to cover tracks",
    },
    {
        "pattern": r"(iptables|ufw|firewalld|nft)\s+.*(-A|-I|add|insert).*DROP",
        "technique_id": "T1562.004",
        "technique_name": "Impair Defenses: Disable or Modify System Firewall",
        "tactic": "defense_evasion",
        "severity": 7,
        "description": "Modifying firewall rules",
    },
    {
        "pattern": r"(kill|killall|pkill)\s+.*(syslog|rsyslog|auditd|ossec|aide|tripwire|clamd|falcon|crowdstrike)",
        "technique_id": "T1562.001",
        "technique_name": "Impair Defenses: Disable or Modify Tools",
        "tactic": "defense_evasion",
        "severity": 9,
        "description": "Killing security monitoring tools",
    },
    {
        "pattern": r"chmod\s+[0-7]*[0-7]{3}\s+",
        "technique_id": "T1222.002",
        "technique_name": "File and Directory Permissions Modification: Linux and Mac",
        "tactic": "defense_evasion",
        "severity": 4,
        "description": "Changing file permissions",
    },
    {
        "pattern": r"(mv|cp|ln\s+-s).*/(bin|sbin|usr)/",
        "technique_id": "T1036.003",
        "technique_name": "Masquerading: Rename System Utilities",
        "tactic": "defense_evasion",
        "severity": 7,
        "description": "Replacing or masquerading as system binaries",
    },
    {
        "pattern": r"(ulimit|prlimit|sysctl).*",
        "technique_id": "T1489",
        "technique_name": "Service Stop",
        "tactic": "defense_evasion",
        "severity": 4,
        "description": "Modifying system resource limits",
    },

    # =================================================================
    # CREDENTIAL ACCESS (TA0006)
    # =================================================================
    {
        "pattern": r"cat\s+/etc/(passwd|shadow|group|gshadow|master\.passwd)",
        "technique_id": "T1552.001",
        "technique_name": "Unsecured Credentials: Credentials in Files",
        "tactic": "credential_access",
        "severity": 8,
        "description": "Reading system credential files",
    },
    {
        "pattern": r"(cat|cp|scp|rsync).*\.ssh/(id_rsa|id_dsa|id_ecdsa|id_ed25519|known_hosts)",
        "technique_id": "T1552.004",
        "technique_name": "Unsecured Credentials: Private Keys",
        "tactic": "credential_access",
        "severity": 9,
        "description": "Stealing SSH private keys",
    },
    {
        "pattern": r"(cat|strings|grep).*\.(bash_history|mysql_history|psql_history|history)",
        "technique_id": "T1552.003",
        "technique_name": "Unsecured Credentials: Bash History",
        "tactic": "credential_access",
        "severity": 7,
        "description": "Mining credentials from shell history",
    },
    {
        "pattern": r"(cat|grep|find).*(\.env|config\.(json|yml|yaml|ini|xml)|credentials|secrets|password|token)",
        "technique_id": "T1552.001",
        "technique_name": "Unsecured Credentials: Credentials in Files",
        "tactic": "credential_access",
        "severity": 7,
        "description": "Searching for credentials in config files",
    },
    {
        "pattern": r"(unshadow|john|hashcat|hydra|medusa|crackmapexec)",
        "technique_id": "T1110.002",
        "technique_name": "Brute Force: Password Cracking",
        "tactic": "credential_access",
        "severity": 9,
        "description": "Password cracking tools",
    },
    {
        "pattern": r"(mimikatz|LaZagne|credumpv?|pypykatz|secretsdump)",
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactic": "credential_access",
        "severity": 10,
        "description": "Credential dumping tools",
    },

    # =================================================================
    # DISCOVERY (TA0007)
    # =================================================================
    {
        "pattern": r"(uname\s+-[a-z]*|cat\s+/etc/(issue|os-release|lsb-release|redhat-release)|lsb_release|hostnamectl)",
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "severity": 3,
        "description": "Gathering system information (OS, kernel, hostname)",
    },
    {
        "pattern": r"(cat\s+/proc/(cpuinfo|meminfo|version)|free\s+(-[a-z]*)?|lscpu|dmidecode|lshw)",
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "severity": 3,
        "description": "Gathering hardware information (CPU, memory)",
    },
    {
        "pattern": r"(ifconfig|ip\s+(addr|link|route)|cat\s+/etc/(resolv\.conf|hosts|network)|networkctl|nmcli)",
        "technique_id": "T1016",
        "technique_name": "System Network Configuration Discovery",
        "tactic": "discovery",
        "severity": 4,
        "description": "Network configuration enumeration",
    },
    {
        "pattern": r"(netstat|ss)\s+(-[a-z]*)?",
        "technique_id": "T1049",
        "technique_name": "System Network Connections Discovery",
        "tactic": "discovery",
        "severity": 4,
        "description": "Listing active network connections",
    },
    {
        "pattern": r"(whoami|id|w\b|who\b|users\b|last\b|lastlog)",
        "technique_id": "T1033",
        "technique_name": "System Owner/User Discovery",
        "tactic": "discovery",
        "severity": 3,
        "description": "Identifying current user and other users",
    },
    {
        "pattern": r"(ps\s+(-[a-z]*)?|top\s|htop|pgrep|pidof)",
        "technique_id": "T1057",
        "technique_name": "Process Discovery",
        "tactic": "discovery",
        "severity": 3,
        "description": "Process enumeration",
    },
    {
        "pattern": r"(ls\s+(-[a-z]*)?\s*(/|/root|/home|/tmp|/var|/opt|/etc)|find\s+/|locate\s+|tree\s+/)",
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "discovery",
        "severity": 3,
        "description": "File system enumeration",
    },
    {
        "pattern": r"(df\s|du\s|mount\b|fdisk\s+-l|lsblk|blkid)",
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "severity": 2,
        "description": "Disk and storage enumeration",
    },
    {
        "pattern": r"(dpkg|rpm|apt|yum|pacman|pip)\s+(list|-l|--list|-qa)",
        "technique_id": "T1518",
        "technique_name": "Software Discovery",
        "tactic": "discovery",
        "severity": 3,
        "description": "Installed software enumeration",
    },
    {
        "pattern": r"(nmap|masscan|zmap|unicornscan|rustscan)\s+",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "discovery",
        "severity": 6,
        "description": "Active network/port scanning",
    },
    {
        "pattern": r"(arp\s+(-[a-z]*)?|cat\s+/proc/net/(arp|tcp|udp))",
        "technique_id": "T1016.001",
        "technique_name": "System Network Configuration Discovery: Internet Connection Discovery",
        "tactic": "discovery",
        "severity": 4,
        "description": "ARP table / network neighbor discovery",
    },
    {
        "pattern": r"(curl|wget)\s+.*(checkip|ipinfo|myip|ifconfig\.me|icanhazip|ident\.me|ipify|seeip|ipgrab)",
        "technique_id": "T1016.001",
        "technique_name": "System Network Configuration Discovery: Internet Connection Discovery",
        "tactic": "discovery",
        "severity": 5,
        "description": "External IP address discovery",
    },
    {
        "pattern": r"(cat\s+/etc/crontab|crontab\s+-l|systemctl\s+list|service\s+--status-all|chkconfig)",
        "technique_id": "T1007",
        "technique_name": "System Service Discovery",
        "tactic": "discovery",
        "severity": 4,
        "description": "Enumerating running services and scheduled tasks",
    },
    {
        "pattern": r"(getent|cat\s+/etc/(passwd|group)|compgen\s+-u|awk.*/(passwd|group))",
        "technique_id": "T1087.001",
        "technique_name": "Account Discovery: Local Account",
        "tactic": "discovery",
        "severity": 4,
        "description": "Enumerating local user accounts",
    },

    # =================================================================
    # LATERAL MOVEMENT (TA0008)
    # =================================================================
    {
        "pattern": r"ssh\s+.*@",
        "technique_id": "T1021.004",
        "technique_name": "Remote Services: SSH",
        "tactic": "lateral_movement",
        "severity": 7,
        "description": "SSH to another host (lateral movement)",
    },
    {
        "pattern": r"scp\s+.*:",
        "technique_id": "T1021.004",
        "technique_name": "Remote Services: SSH",
        "tactic": "lateral_movement",
        "severity": 7,
        "description": "SCP file transfer to another host",
    },
    {
        "pattern": r"(ansible|puppet|salt|psexec|wmiexec|smbexec)",
        "technique_id": "T1021.006",
        "technique_name": "Remote Services: Windows Remote Management",
        "tactic": "lateral_movement",
        "severity": 8,
        "description": "Remote management / execution tools",
    },

    # =================================================================
    # COMMAND AND CONTROL (TA0011)
    # =================================================================
    {
        "pattern": r"(wget|curl|fetch|lwp-download)\s+https?://",
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "command_and_control",
        "severity": 7,
        "description": "Downloading files from remote server",
    },
    {
        "pattern": r"(wget|curl|fetch)\s+.*\|\s*(bash|sh)",
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "command_and_control",
        "severity": 9,
        "description": "Download-and-execute pattern (highest risk C2)",
    },
    {
        "pattern": r"(tftp|ftpget|ftp\s+)\s+",
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "command_and_control",
        "severity": 7,
        "description": "File transfer via TFTP/FTP",
    },
    {
        "pattern": r"/dev/tcp/[0-9]",
        "technique_id": "T1095",
        "technique_name": "Non-Application Layer Protocol",
        "tactic": "command_and_control",
        "severity": 9,
        "description": "Raw TCP connection via bash /dev/tcp",
    },
    {
        "pattern": r"(nc|ncat|netcat|socat)\s+.*(-[a-z]*l|-[a-z]*p|LISTEN|EXEC)",
        "technique_id": "T1095",
        "technique_name": "Non-Application Layer Protocol",
        "tactic": "command_and_control",
        "severity": 8,
        "description": "Netcat listener or reverse shell",
    },
    {
        "pattern": r"(nc|ncat|netcat)\s+[0-9]+\.[0-9]+",
        "technique_id": "T1095",
        "technique_name": "Non-Application Layer Protocol",
        "tactic": "command_and_control",
        "severity": 7,
        "description": "Netcat connection to IP address",
    },
    {
        "pattern": r"(curl|wget).*discord(app)?\.com/(api/webhooks|attachments)",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "command_and_control",
        "severity": 8,
        "description": "Discord webhook C2 communication",
    },
    {
        "pattern": r"(curl|wget).*pastebin\.com|hastebin|paste\.",
        "technique_id": "T1102.002",
        "technique_name": "Web Service: Bidirectional Communication",
        "tactic": "command_and_control",
        "severity": 7,
        "description": "Using paste services for C2",
    },
    {
        "pattern": r"(irc|IRC|PRIVMSG|JOIN\s+#)",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "command_and_control",
        "severity": 7,
        "description": "IRC-based C2 communication",
    },

    # =================================================================
    # COLLECTION (TA0009)
    # =================================================================
    {
        "pattern": r"(tar\s+[a-z]*[cz]|zip\s+|gzip\s+|7z\s+a).*(/etc|/home|/root|/var)",
        "technique_id": "T1560.001",
        "technique_name": "Archive Collected Data: Archive via Utility",
        "tactic": "collection",
        "severity": 7,
        "description": "Archiving sensitive directories for exfiltration",
    },
    {
        "pattern": r"(cat|strings|grep|less|more)\s+.*(database|db\.|sql|\.sqlite|\.mdb)",
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "collection",
        "severity": 7,
        "description": "Reading database files",
    },

    # =================================================================
    # EXFILTRATION (TA0010)
    # =================================================================
    {
        "pattern": r"(curl|wget)\s+.*(-X\s+POST|--data|--upload-file|-T\s+|-F\s+)",
        "technique_id": "T1048.003",
        "technique_name": "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol",
        "tactic": "exfiltration",
        "severity": 8,
        "description": "HTTP POST data exfiltration",
    },
    {
        "pattern": r"(scp|rsync|sftp)\s+.*@[0-9a-zA-Z]",
        "technique_id": "T1048.002",
        "technique_name": "Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
        "tactic": "exfiltration",
        "severity": 7,
        "description": "Data exfiltration via SCP/rsync/SFTP",
    },

    # =================================================================
    # IMPACT (TA0040)
    # =================================================================
    {
        "pattern": r"rm\s+(-[rf]*\s+)?/($|\s|;|&&)",
        "technique_id": "T1485",
        "technique_name": "Data Destruction",
        "tactic": "impact",
        "severity": 10,
        "description": "Recursive deletion of root filesystem",
    },
    {
        "pattern": r"rm\s+-[rf]*\s+(/etc|/var|/home|/boot|/usr)",
        "technique_id": "T1485",
        "technique_name": "Data Destruction",
        "tactic": "impact",
        "severity": 9,
        "description": "Deletion of critical system directories",
    },
    {
        "pattern": r"dd\s+if=/dev/(zero|urandom|random)\s+of=/dev/(sd|hd|nvme|vd)",
        "technique_id": "T1561.001",
        "technique_name": "Disk Wipe: Disk Content Wipe",
        "tactic": "impact",
        "severity": 10,
        "description": "Disk wiping with dd",
    },
    {
        "pattern": r"(mkfs|mke2fs|mkfs\.ext[234]|mkfs\.xfs)",
        "technique_id": "T1561.002",
        "technique_name": "Disk Wipe: Disk Structure Wipe",
        "tactic": "impact",
        "severity": 10,
        "description": "Reformatting filesystems",
    },
    {
        "pattern": r":\(\)\{\s*:\|:&\s*\};:",
        "technique_id": "T1499.004",
        "technique_name": "Endpoint Denial of Service: Application or System Exploitation",
        "tactic": "impact",
        "severity": 8,
        "description": "Fork bomb denial of service",
    },
    {
        "pattern": r"(openssl|gpg)\s+(enc|encrypt|-e).*(-aes|-des|-chacha)",
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "impact",
        "severity": 10,
        "description": "Encrypting files (ransomware behavior)",
    },
    {
        "pattern": r"(kill|killall|pkill)\s+(-9\s+)?-?\d*",
        "technique_id": "T1489",
        "technique_name": "Service Stop",
        "tactic": "impact",
        "severity": 5,
        "description": "Killing processes (may target competing malware or services)",
    },
    {
        "pattern": r"(xmrig|minerd|cpuminer|ethminer|stratum\+tcp://|pool\.|nicehash|nanopool|f2pool)",
        "technique_id": "T1496",
        "technique_name": "Resource Hijacking",
        "tactic": "impact",
        "severity": 7,
        "description": "Cryptocurrency mining (resource hijacking)",
    },
    {
        "pattern": r"(bitcoin|monero|ethereum|zcash|litecoin).*wallet",
        "technique_id": "T1496",
        "technique_name": "Resource Hijacking",
        "tactic": "impact",
        "severity": 7,
        "description": "Cryptocurrency wallet references",
    },

    # =================================================================
    # LOW-SIGNAL COMMANDS (severity 1-2, still categorized for completeness)
    # =================================================================
    {
        "pattern": r"^(ls|dir|pwd|cd|echo|cat|head|tail|wc|sort|uniq|cut|tr|tee)\s",
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "discovery",
        "severity": 1,
        "description": "Basic filesystem navigation (benign in isolation)",
    },
    {
        "pattern": r"^(date|uptime|hostname|env|printenv|set|export|alias|type|which|whereis)\b",
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "severity": 1,
        "description": "Basic system info commands (benign in isolation)",
    },
    {
        "pattern": r"^(apt|yum|dnf|pip|npm|gem|cargo)\s+(install|update|upgrade)",
        "technique_id": "T1072",
        "technique_name": "Software Deployment Tools",
        "tactic": "execution",
        "severity": 4,
        "description": "Package installation (could be tool staging)",
    },
    {
        "pattern": r"^(git|svn|hg)\s+(clone|pull|checkout)",
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "command_and_control",
        "severity": 4,
        "description": "Source code retrieval from repositories",
    },
    {
        "pattern": r"^(docker|podman|lxc|kubectl)\s+",
        "technique_id": "T1610",
        "technique_name": "Deploy Container",
        "tactic": "execution",
        "severity": 6,
        "description": "Container deployment (potential escape vector)",
    },
    {
        "pattern": r"(cat|less|more|vi|vim|nano|emacs)\s+/etc/(ssh/sshd_config|pam\.d/|security/)",
        "technique_id": "T1556",
        "technique_name": "Modify Authentication Process",
        "tactic": "credential_access",
        "severity": 7,
        "description": "Accessing authentication configuration",
    },
]


# ===================================================================
# Compile patterns for performance
# ===================================================================

ATTACK_PATTERNS = []
for raw in _RAW_PATTERNS:
    compiled = dict(raw)
    compiled["_compiled"] = re.compile(raw["pattern"], re.IGNORECASE)
    ATTACK_PATTERNS.append(compiled)


# ===================================================================
# Binary analysis tag -> ATT&CK technique mapping
# ===================================================================
# Maps the behavioral tags from static_analyzer.py to ATT&CK techniques.
# Used to add ATT&CK context to binary-level features.

BINARY_TAG_TO_TECHNIQUE = {
    "mining": [
        {"technique_id": "T1496", "technique_name": "Resource Hijacking",
         "tactic": "impact", "severity": 7},
    ],
    "botnet": [
        {"technique_id": "T1583.005", "technique_name": "Acquire Infrastructure: Botnet",
         "tactic": "resource_development", "severity": 8},
        {"technique_id": "T1071.001", "technique_name": "Application Layer Protocol: Web Protocols",
         "tactic": "command_and_control", "severity": 7},
    ],
    "credential_access": [
        {"technique_id": "T1552.001", "technique_name": "Unsecured Credentials: Credentials in Files",
         "tactic": "credential_access", "severity": 8},
    ],
    "persistence": [
        {"technique_id": "T1053.003", "technique_name": "Scheduled Task/Job: Cron",
         "tactic": "persistence", "severity": 8},
    ],
    "destructive": [
        {"technique_id": "T1485", "technique_name": "Data Destruction",
         "tactic": "impact", "severity": 10},
    ],
    "recon": [
        {"technique_id": "T1046", "technique_name": "Network Service Discovery",
         "tactic": "discovery", "severity": 6},
    ],
    "downloader": [
        {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer",
         "tactic": "command_and_control", "severity": 7},
    ],
    "upx_packed": [
        {"technique_id": "T1027.002", "technique_name": "Obfuscated Files or Information: Software Packing",
         "tactic": "defense_evasion", "severity": 6},
    ],
    "high_entropy": [
        {"technique_id": "T1027", "technique_name": "Obfuscated Files or Information",
         "tactic": "defense_evasion", "severity": 5},
    ],
    "go_binary": [
        {"technique_id": "T1027.002", "technique_name": "Obfuscated Files or Information: Software Packing",
         "tactic": "defense_evasion", "severity": 4},
    ],
    "statically_linked": [
        {"technique_id": "T1027", "technique_name": "Obfuscated Files or Information",
         "tactic": "defense_evasion", "severity": 3},
    ],
}


# ===================================================================
# Severity tier labels (for human readability and cost-sensitive training)
# ===================================================================

SEVERITY_TIERS = {
    (1, 3):  "low",        # Benign / low-signal
    (4, 5):  "medium",     # Reconnaissance / enumeration
    (6, 7):  "high",       # Active exploitation prep
    (8, 9):  "critical",   # Direct exploitation
    (10, 10): "emergency", # Destructive / APT
}


def severity_to_tier(severity):
    """Convert numeric severity (1-10) to tier label."""
    for (lo, hi), tier in SEVERITY_TIERS.items():
        if lo <= severity <= hi:
            return tier
    return "unknown"


# ===================================================================
# Convenience: get all unique technique IDs in the knowledge base
# ===================================================================

def get_all_techniques():
    """Return sorted list of unique technique IDs."""
    techniques = set()
    for p in ATTACK_PATTERNS:
        techniques.add(p["technique_id"])
    for tag_techniques in BINARY_TAG_TO_TECHNIQUE.values():
        for t in tag_techniques:
            techniques.add(t["technique_id"])
    return sorted(techniques)


def get_all_tactics():
    """Return ordered list of tactic names."""
    return list(TACTIC_NAMES)


def get_knowledge_base_stats():
    """Return summary statistics about the knowledge base."""
    techniques = set()
    tactics = set()
    for p in ATTACK_PATTERNS:
        techniques.add(p["technique_id"])
        tactics.add(p["tactic"])
    return {
        "total_patterns": len(ATTACK_PATTERNS),
        "unique_techniques": len(techniques),
        "unique_tactics": len(tactics),
        "technique_ids": sorted(techniques),
        "tactic_names": sorted(tactics),
        "binary_tag_mappings": len(BINARY_TAG_TO_TECHNIQUE),
    }


if __name__ == "__main__":
    stats = get_knowledge_base_stats()
    print("MITRE ATT&CK Knowledge Base Statistics:")
    print("  Total command patterns: %d" % stats["total_patterns"])
    print("  Unique techniques: %d" % stats["unique_techniques"])
    print("  Unique tactics: %d" % stats["unique_tactics"])
    print("  Binary tag mappings: %d" % stats["binary_tag_mappings"])
    print("\nTechniques covered:")
    for tid in stats["technique_ids"]:
        print("  %s" % tid)
    print("\nTactics covered:")
    for t in stats["tactic_names"]:
        print("  %s (%s)" % (t, TACTICS[t]["id"]))
