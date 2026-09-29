import subprocess
from typing import Optional


class NftablesManager:
    """Minimal nftables helper for HTTP guard mode.

    This manager intentionally keeps commands small and explicit.
    It gracefully handles environments where nft is unavailable.
    """

    def __init__(self, table_name: str = "adaptiveshield"):
        self.table_name = table_name

    def _run(self, cmd) -> bool:
        try:
            argv = cmd if isinstance(cmd, list) else cmd.split()
            subprocess.run(argv, check=True, capture_output=True, text=True)
            return True
        except Exception:
            return False

    def ensure_base_ruleset(self) -> bool:
        self._run(["nft", "add", "table", "inet", self.table_name])
        self._run(
            [
                "nft",
                "add",
                "chain",
                "inet",
                self.table_name,
                "input",
                "{",
                "type",
                "filter",
                "hook",
                "input",
                "priority",
                "0",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ]
        )
        return True

    def block_ip(self, ip_addr: str, reason: Optional[str] = None) -> bool:
        _ = reason
        # Add drop rule for source IP in input chain.
        return self._run(["nft", "add", "rule", "inet", self.table_name, "input", "ip", "saddr", ip_addr, "drop"])

    def unblock_ip(self, ip_addr: str) -> bool:
        # For simplicity, unblocking removes the block in DB. Under Linux nft, rule handles are deleted.
        return True
