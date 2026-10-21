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
        # Exemption commented out per user request so local test IP can be verified getting blocked in nftables:
        # if not ip_addr or ip_addr in ("127.0.0.1", "::1", "localhost", "unknown"):
        #     return False
        if not ip_addr or ip_addr == "unknown":
            return False
        # Add drop rule for source IP in input chain.
        return self._run(["nft", "add", "rule", "inet", self.table_name, "input", "ip", "saddr", ip_addr, "drop"])

    def unblock_ip(self, ip_addr: str) -> bool:
        # Delete matching rule handles or flush table
        return self._run(f"nft flush table inet {self.table_name}")

    def flush_all(self) -> bool:
        """Clear all firewall blocks in adaptiveshield table."""
        return self._run(["nft", "flush", "table", "inet", self.table_name])
