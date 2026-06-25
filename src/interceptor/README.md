# HTTP Guard Runtime

This package contains the HTTP-first runtime interception layer used for same-host deployment.

## Components

- `http_proxy.py`: FastAPI-based HTTP guard that classifies and routes requests.
- `session_store.py`: SQLite-backed session and event store.
- `nftables_manager.py`: minimal helper for IP block rules.

## Flow

1. Request arrives at AdaptiveShield on port `80`.
2. Session is created/updated using source IP.
3. Request payload is classified (`Safe`, `Recon`, `Exploit`, etc.).
4. Action is chosen:
   - `forward` -> real service
   - `forward_and_log` -> real service with detailed log
   - `redirect_to_decoy` -> decoy container endpoint
   - `drop_and_block` -> 403 + nftables block rule
5. Structured event is written to `runtime/logs/threat_events.jsonl`.
