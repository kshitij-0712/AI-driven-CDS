"""
SSH Decoy Builder — Dynamic Environment Mutation Engine
=======================================================

Dynamically bakes and updates simulated filesystem content, simulated commands,
and lure breadcrumbs inside Cowrie SSH honeypots.

Supports:
- Initial decoy baseline configuration
- Dynamic mutation upon malware/binary triage detection:
  * Downloader / Botnet Dropper: seeds fake stagers, download histories, and C2 hosts.
  * Destructive / Wiper: seeds fake high-value database backups, full partitions.
  * ADVANCED_APT: seeds fake AWS credentials, SSH keys, and internal cluster routes.
  * Exploit: seeds vulnerable kernel banners and web service processes.
- LLM generation via LLMRouter with intent-tailored fallbacks if offline.
"""

import os
import json
import logging
from typing import Dict, Any

from honeypot.router import LLMRouter
from interceptor.session_store import SessionStore

logger = logging.getLogger(__name__)


# ===================================================================
# Malware-Specialized Decoy Mutation Fallbacks
# ===================================================================

FALLBACK_PROFILES = {
    "Downloader": {
        "whoami": "root\n",
        "id": "uid=0(root) gid=0(root) groups=0(root)\n",
        "uname": "Linux worker-node-04 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n",
        "ps": (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.1 168432 11200 ?        Ss   10:00   0:01 /sbin/init\n"
            "root       412  0.0  0.1  28412  6420 ?        Ss   10:00   0:00 /usr/sbin/cron -f\n"
            "www-data   890  0.0  0.2 115200 18200 ?        S    10:05   0:00 nginx: worker process\n"
            "root      1204  0.0  0.1  72100  8400 ?        S    10:12   0:00 /usr/bin/python3 -m http.server 8080\n"
        ),
        "df": (
            "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
            "/dev/sda1       41151600 12840200  26201400  33% /\n"
            "tmpfs            2024100        0   2024100   0% /dev/shm\n"
        ),
        "netstat": (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN\n"
        ),
        "passwd": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "admin:x:1000:1000:Admin,,,:/home/admin:/bin/bash\n"
            "deploy:x:1001:1001:Deploy,,,:/home/deploy:/bin/bash\n"
        ),
        "shadow": (
            "root:$6$rounds=5000$saltsalt$xyz...:19000:0:99999:7:::\n"
            "admin:$6$rounds=5000$saltsalt$abc...:19000:0:99999:7:::\n"
        ),
        "hosts": (
            "127.0.0.1 localhost worker-node-04\n"
            "10.0.4.15 internal-update.corp\n"
            "10.0.4.20 c2-relay.local\n"
        ),
        "bash_history": (
            "curl -s -O http://10.0.4.15/agent.sh\n"
            "chmod +x agent.sh\n"
            "./agent.sh --install\n"
            "wget http://10.0.4.20/payload.tar.gz\n"
            "tar -xzf payload.tar.gz\n"
        ),
    },
    "Destructive": {
        "whoami": "root\n",
        "id": "uid=0(root) gid=0(root) groups=0(root)\n",
        "uname": "Linux prod-db-primary 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n",
        "ps": (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.1 168432 11200 ?        Ss   10:00   0:01 /sbin/init\n"
            "mysql      720  0.2  4.5 1840200 450100 ?      Sl   10:01   0:15 /usr/sbin/mysqld\n"
            "root      1100  0.0  0.1  45200  8100 ?        S    10:10   0:00 /usr/bin/rsync --daemon\n"
        ),
        "df": (
            "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
            "/dev/sda1       41151600 39240200    801400  98% /\n"
            "/dev/sdb1      102400000 91200000  11200000  89% /var/lib/mysql\n"
        ),
        "netstat": (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:873             0.0.0.0:*               LISTEN\n"
        ),
        "passwd": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "admin:x:1000:1000:Admin,,,:/home/admin:/bin/bash\n"
            "mysql:x:111:115:MySQL Server,,,:/nonexistent:/bin/false\n"
        ),
        "shadow": (
            "root:$6$rounds=5000$saltsalt$xyz...:19000:0:99999:7:::\n"
            "admin:$6$rounds=5000$saltsalt$abc...:19000:0:99999:7:::\n"
        ),
        "hosts": (
            "127.0.0.1 localhost prod-db-primary\n"
            "10.0.2.5 prod-db-replica.corp\n"
            "10.0.2.6 backup-nas.corp\n"
        ),
        "bash_history": (
            "tar -czf /var/backups/db_backup.tar.gz /var/lib/mysql\n"
            "rsync -avz /var/backups/ backup-nas.corp:/mnt/backups/\n"
            "ls -la /var/lib/mysql\n"
            "systemctl restart mysql\n"
        ),
    },
    "ADVANCED_APT": {
        "whoami": "root\n",
        "id": "uid=0(root) gid=0(root) groups=0(root)\n",
        "uname": "Linux corp-bastion-01 5.15.0-101-generic #111-Ubuntu SMP x86_64 GNU/Linux\n",
        "ps": (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.1 168432 11200 ?        Ss   09:00   0:01 /sbin/init\n"
            "root       502  0.0  0.2  89100 16200 ?        Ss   09:01   0:02 /usr/sbin/sssd -i --logger=files\n"
            "root      1200  0.0  0.3 210400 24800 ?        Sl   09:15   0:03 /usr/local/bin/aws-vault-proxy\n"
        ),
        "df": (
            "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
            "/dev/nvme0n1p1  82303200 32140200  50163000  40% /\n"
        ),
        "netstat": (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 127.0.0.1:8200          0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:6443            0.0.0.0:*               LISTEN\n"
        ),
        "passwd": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "admin:x:1000:1000:Admin,,,:/home/admin:/bin/bash\n"
            "secops:x:1002:1002:SecOps Lead,,,:/home/secops:/bin/bash\n"
        ),
        "shadow": (
            "root:$6$rounds=5000$saltsalt$xyz...:19000:0:99999:7:::\n"
            "admin:$6$rounds=5000$saltsalt$abc...:19000:0:99999:7:::\n"
        ),
        "hosts": (
            "127.0.0.1 localhost corp-bastion-01\n"
            "10.10.1.10 dc01.internal.corp\n"
            "10.10.2.5 vault.internal.corp\n"
            "10.10.3.15 gitlab.internal.corp\n"
        ),
        "bash_history": (
            "ssh secops@vault.internal.corp\n"
            "aws s3 ls s3://corp-cloud-backups-2026/\n"
            "kubectl get pods -n production\n"
            "cat ~/.aws/credentials\n"
            "ssh admin@10.10.1.10\n"
        ),
    },
    "Exploit": {
        "whoami": "root\n",
        "id": "uid=0(root) gid=0(root) groups=0(root)\n",
        "uname": "Linux ubuntu-srv 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 GNU/Linux\n",
        "ps": (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.1 168432 11200 ?        Ss   10:00   0:01 /sbin/init\n"
            "root       612  0.0  0.1  32100  7800 ?        Ss   10:01   0:00 /usr/sbin/apache2 -k start\n"
            "www-data   615  0.0  0.2  85400 19200 ?        S    10:01   0:01 /usr/sbin/apache2 -k start\n"
        ),
        "df": (
            "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
            "/dev/sda1       41151600 18240200  20801400  47% /\n"
        ),
        "netstat": (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
        ),
        "passwd": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "admin:x:1000:1000:Admin,,,:/home/admin:/bin/bash\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        ),
        "shadow": (
            "root:$6$rounds=5000$saltsalt$xyz...:19000:0:99999:7:::\n"
            "admin:$6$rounds=5000$saltsalt$abc...:19000:0:99999:7:::\n"
        ),
        "hosts": (
            "127.0.0.1 localhost ubuntu-srv\n"
            "10.0.1.20 web-backend.local\n"
        ),
        "bash_history": (
            "sudo -l\n"
            "cat /etc/issue\n"
            "sudo apt-get update\n"
            "cat /var/www/html/wp-config.php\n"
        ),
    },
    "Recon": {
        "whoami": "root\n",
        "id": "uid=0(root) gid=0(root) groups=0(root)\n",
        "uname": "Linux ubuntu-prod-01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 GNU/Linux\n",
        "ps": (
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.1 168432 11200 ?        Ss   10:00   0:01 /sbin/init\n"
            "root       450  0.0  0.1  28412  6420 ?        Ss   10:00   0:00 /usr/sbin/cron -f\n"
        ),
        "df": (
            "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
            "/dev/sda1       41151600 14240200  24801400  36% /\n"
        ),
        "netstat": (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
        ),
        "passwd": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "admin:x:1000:1000:Admin,,,:/home/admin:/bin/bash\n"
        ),
        "shadow": (
            "root:$6$rounds=5000$saltsalt$xyz...:19000:0:99999:7:::\n"
            "admin:$6$rounds=5000$saltsalt$abc...:19000:0:99999:7:::\n"
        ),
        "hosts": (
            "127.0.0.1 localhost ubuntu-prod-01\n"
        ),
        "bash_history": (
            "sudo apt update\n"
            "sudo apt upgrade -y\n"
            "uptime\n"
        ),
    },
}


class SSHDecoyBuilder:
    def __init__(self, config: Dict, store: SessionStore):
        self.config = config
        self.store = store
        self.router = LLMRouter(config)
        self.base_dir = "./runtime/decoy_ssh"

    async def prepare_decoy_files(
        self,
        session_id: str,
        decision: Dict[str, Any],
        cowrie_base_dir: str,
        container_id: str,
        decoys_manager: Any
    ):
        """Bakes/updates static content in the decoy container's volumes."""
        txtcmds_dir = os.path.join(cowrie_base_dir, "txtcmds", "bin")
        honeyfs_etc = os.path.join(cowrie_base_dir, "honeyfs", "etc")
        honeyfs_home = os.path.join(cowrie_base_dir, "honeyfs", "home", "admin")
        cowrie_cfg_path = os.path.join(cowrie_base_dir, "cowrie.cfg")

        os.makedirs(txtcmds_dir, exist_ok=True)
        os.makedirs(honeyfs_etc, exist_ok=True)
        os.makedirs(honeyfs_home, exist_ok=True)

        baseline_flag = os.path.join(cowrie_base_dir, ".baseline_written")
        is_triage = decision.get("triage_enriched", False)
        
        if not os.path.exists(baseline_flag) or is_triage:
            if is_triage:
                logger.info(
                    f"Triage enriched - bypassing baseline check to dynamically mutate decoy files for {session_id}"
                )
            
            await self._generate_and_write_content(
                txtcmds_dir, honeyfs_etc, honeyfs_home, cowrie_cfg_path, session_id, decision, cowrie_base_dir
            )
            with open(baseline_flag, "w") as f:
                f.write("true")

    async def _generate_and_write_content(
        self,
        txtcmds_dir: str,
        honeyfs_etc: str,
        honeyfs_home: str,
        cowrie_cfg_path: str,
        session_id: str,
        decision: Dict[str, Any],
        cowrie_base_dir: str = "",
    ):
        # Determine threat intent from binary intelligence or high-level label
        b_res = decision.get("binary_triage", {})
        intent = b_res.get("label") or decision.get("label", "Exploit")
        b_conf = b_res.get("confidence", decision.get("confidence", 1.0))

        # Select matching fallback template
        fallback_data = FALLBACK_PROFILES.get(intent, FALLBACK_PROFILES.get("Exploit", {}))

        # Prompt for dynamic LLM generation with explicit binary intelligence
        prompt = f"""
You are an autonomous cyber deception engine adapting an active SSH honeypot.
A binary payload was dropped or an attack was classified with:
  Threat Class: {intent}
  Confidence: {b_conf:.1%}

Generate a dynamic mutation profile for the decoy to engage and contain this specific malware threat.
Return ONLY a valid JSON object.
JSON schema:
{{
    "whoami": "output of whoami command",
    "id": "output of id command",
    "uname": "output of uname -a",
    "ps": "output of ps aux command (tailored to {intent})",
    "df": "output of df -h command",
    "netstat": "output of netstat -tuln command",
    "passwd": "content of /etc/passwd",
    "shadow": "content of /etc/shadow",
    "hosts": "content of /etc/hosts (include fake internal IPs)",
    "bash_history": "content of /home/admin/.bash_history (tailored breadcrumbs for {intent})"
}}
"""

        data = None
        try:
            raw_response = await self.router.generate(
                intent_label=intent,
                system_instruction="You are a honeypot configuration generator. Output strictly JSON.",
                prompt=prompt
            )
            
            import re
            match = re.search(r"(\{.*\})", raw_response.strip(), re.DOTALL)
            if match:
                data = json.loads(match.group(1))
            else:
                data = json.loads(raw_response.strip())
        except Exception as e:
            logger.warning(
                f"LLM decoy generation failed or timed out ({e}). Using malware-specialized fallback for {intent}."
            )
            data = fallback_data

        if not isinstance(data, dict):
            data = fallback_data

        # Merge with fallback defaults to ensure no missing keys
        merged = dict(fallback_data)
        merged.update({k: v for k, v in data.items() if v})

        # 1. Write txtcmds (dynamic simulated commands in Cowrie across all command prefixes)
        txtcmd_map = {
            "whoami": merged.get("whoami", "root\n"),
            "id": merged.get("id", "uid=0(root) gid=0(root) groups=0(root)\n"),
            "uname": merged.get("uname", "Linux corp-bastion-01 5.15.0-105-generic #115-Ubuntu SMP x86_64 GNU/Linux\n"),
            "ps": merged.get("ps", ""),
            "df": merged.get("df", ""),
            "netstat": merged.get("netstat", ""),
            "hostname": merged.get("hostname", "corp-bastion-01\n"),
        }
        for sub in ["", "bin", "usr/bin", "sbin", "usr/sbin"]:
            target_sub = os.path.join(cowrie_base_dir, "txtcmds", sub) if sub else os.path.join(cowrie_base_dir, "txtcmds")
            os.makedirs(target_sub, exist_ok=True)
            for cmd_name, cmd_content in txtcmd_map.items():
                if cmd_content:
                    with open(os.path.join(target_sub, cmd_name), "w", encoding="utf-8") as f:
                        f.write(str(cmd_content).strip() + "\n")

        # 2. Write honeyfs files (/etc, /home/admin, /root)
        with open(os.path.join(honeyfs_etc, "passwd"), "w", encoding="utf-8") as f:
            f.write(merged.get("passwd", "").strip() + "\n")
        with open(os.path.join(honeyfs_etc, "shadow"), "w", encoding="utf-8") as f:
            f.write(merged.get("shadow", "").strip() + "\n")
        with open(os.path.join(honeyfs_etc, "hostname"), "w", encoding="utf-8") as f:
            hostname = "corp-bastion-01"
            if intent == "Destructive":
                hostname = "prod-db-primary"
            elif intent == "Downloader":
                hostname = "worker-node-04"
            f.write(f"{hostname}\n")
        with open(os.path.join(honeyfs_etc, "hosts"), "w", encoding="utf-8") as f:
            f.write(merged.get("hosts", "").strip() + "\n")

        # Write bash history across operator and root homes
        bash_hist = merged.get("bash_history", "").strip() + "\n"
        with open(os.path.join(honeyfs_home, ".bash_history"), "w", encoding="utf-8") as f:
            f.write(bash_hist)
        root_home = os.path.join(cowrie_base_dir, "honeyfs", "root")
        os.makedirs(root_home, exist_ok=True)
        with open(os.path.join(root_home, ".bash_history"), "w", encoding="utf-8") as f:
            f.write(bash_hist)

        # 3. Seed threat-specific lure files in honeyfs
        if cowrie_base_dir:
            if intent == "ADVANCED_APT":
                # Plant fake cloud credentials and SSH keys for APT actors
                aws_dir = os.path.join(honeyfs_home, ".aws")
                ssh_dir = os.path.join(honeyfs_home, ".ssh")
                os.makedirs(aws_dir, exist_ok=True)
                os.makedirs(ssh_dir, exist_ok=True)
                with open(os.path.join(aws_dir, "credentials"), "w") as f:
                    f.write(
                        "[default]\n"
                        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
                        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                    )
                with open(os.path.join(ssh_dir, "authorized_keys"), "w") as f:
                    f.write("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... secops@internal.corp\n")

            elif intent == "Destructive":
                # Plant fake database backup target for wipers/ransomware
                backup_dir = os.path.join(cowrie_base_dir, "honeyfs", "var", "backups")
                os.makedirs(backup_dir, exist_ok=True)
                with open(os.path.join(backup_dir, "db_backup_2026.sql"), "w") as f:
                    f.write("-- Production Database Dump 2026\n-- Table structure for table `users`\n")

        # 4. Write cowrie.cfg with aligned hostname
        cfg_hostname = "ubuntu-prod-01"
        if intent == "Destructive":
            cfg_hostname = "prod-db-primary"
        elif intent == "ADVANCED_APT":
            cfg_hostname = "corp-bastion-01"
        elif intent == "Downloader":
            cfg_hostname = "worker-node-04"

        cfg_content = f"""
[honeypot]
hostname = {cfg_hostname}
sensor_name = {cfg_hostname}

[ssh]
version = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
"""
        with open(cowrie_cfg_path, "w") as f:
            f.write(cfg_content)
