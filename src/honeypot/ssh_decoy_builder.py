import os
import json
import logging
from typing import Dict, Any

from honeypot.router import LLMRouter
from interceptor.session_store import SessionStore

logger = logging.getLogger(__name__)

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
        if not os.path.exists(baseline_flag):
            await self._generate_and_write_content(
                txtcmds_dir, honeyfs_etc, honeyfs_home, cowrie_cfg_path, session_id, decision
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
        decision: Dict[str, Any]
    ):
        intent = decision.get("label", "Exploit")

        # 1. Generate Fake Files using LLM
        prompt = f"""
        You are configuring a realistic SSH honeypot. The attacker has been classified with intent: {intent}.
        Generate the contents for the following simulated files on a Ubuntu Linux server. Return ONLY a valid JSON object.
        JSON schema:
        {{
            "whoami": "output of whoami command",
            "id": "output of id command",
            "uname": "output of uname -a",
            "passwd": "content of /etc/passwd (include a few realistic fake users like 'admin' and 'db_user')",
            "shadow": "content of /etc/shadow (include weak bcrypt hashes that can be cracked to keep attacker busy)",
            "bash_history": "content of /home/admin/.bash_history (include breadcrumbs based on intent, e.g. mysql logins or curl commands)"
        }}
        """

        try:
            # We don't have a prompt builder for SSH yet, so just using a raw prompt string.
            raw_response = await self.router.generate(
                intent_label=intent,
                system_instruction="You are a honeypot configuration generator. Output strictly JSON.",
                user_prompt=prompt
            )
            
            # Simple JSON parsing
            import re
            match = re.search(r"(\{.*\})", raw_response.strip(), re.DOTALL)
            if match:
                data = json.loads(match.group(1))
            else:
                data = json.loads(raw_response.strip())
        except Exception as e:
            logger.error(f"Failed to generate SSH decoy content via LLM: {e}")
            # Fallback content
            data = {
                "whoami": "root\n",
                "id": "uid=0(root) gid=0(root) groups=0(root)\n",
                "uname": "Linux ubuntu-prod-01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n",
                "passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin,,,:/home/admin:/bin/bash\n",
                "shadow": "root:$2a$12$xyz...:18000:0:99999:7:::\nadmin:$2a$12$abc...:18000:0:99999:7:::\n",
                "bash_history": "sudo apt update\nsudo apt upgrade -y\nmysql -u root -p\ncd /var/www/html\n"
            }

        # Write txtcmds
        with open(os.path.join(txtcmds_dir, "whoami"), "w") as f:
            f.write(data.get("whoami", "root\n").strip() + "\n")
        with open(os.path.join(txtcmds_dir, "id"), "w") as f:
            f.write(data.get("id", "uid=0(root) gid=0(root) groups=0(root)\n").strip() + "\n")
        with open(os.path.join(txtcmds_dir, "uname"), "w") as f:
            f.write(data.get("uname", "Linux ubuntu-prod-01 5.15.0-91-generic\n").strip() + "\n")

        # Write honeyfs files
        with open(os.path.join(honeyfs_etc, "passwd"), "w") as f:
            f.write(data.get("passwd", "").strip() + "\n")
        with open(os.path.join(honeyfs_etc, "shadow"), "w") as f:
            f.write(data.get("shadow", "").strip() + "\n")
        with open(os.path.join(honeyfs_etc, "hostname"), "w") as f:
            f.write("ubuntu-prod-01\n")
        with open(os.path.join(honeyfs_home, ".bash_history"), "w") as f:
            f.write(data.get("bash_history", "").strip() + "\n")

        # Write cowrie.cfg
        cfg_content = """
[honeypot]
hostname = ubuntu-prod-01
sensor_name = ubuntu-prod-01

[ssh]
version = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
"""
        with open(cowrie_cfg_path, "w") as f:
            f.write(cfg_content)
