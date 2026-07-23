# AdaptiveShield

AdaptiveShield is a portable, multi-agent cyber deception and analysis system. It discovers exposed services, deploys decoys, learns attacker behavior, and explains every decision with XAI.

## One-Shot Deployment (HTTP Guard, Kernel-Aware)

AdaptiveShield now supports HTTP-first runtime deployment on the same host as your real service.

- Incoming traffic on port `80` is inspected in real time using a **3-stage dynamic pipeline**:
  1. Regex pre-filtering for fast attack matching.
  2. Neural inference using the `brain_v5_mitre_only` BiLSTM model.
  3. MITRE rule heuristic fallback (if neural confidence < 55%).
- Safe traffic is forwarded to your real app (`127.0.0.1:8080` by default).
- Suspicious and malicious traffic is logged or redirected to decoy containers.
- High-risk traffic can be blocked with nftables-based IP rules.

### Prerequisites

- Docker + Docker Compose
- Permission to run container with `NET_ADMIN` and Docker socket access
- Real HTTP service running on the same host (`127.0.0.1:8080` by default)

### Start

```bash
docker compose up -d --build
```

### Verify

```bash
docker compose ps
docker compose logs -f adaptiveshield
curl http://127.0.0.1/health
```

If your real service is currently bound to `80`, move it to `8080` (or update `http_guard.real_service_port` in `config/settings.yaml`) so AdaptiveShield can sit in front as the guard.

Threat events are written to `runtime/logs/threat_events.jsonl` and runtime state to `runtime/adaptiveshield.db`.

### Runtime Config (HTTP First)

See `config/settings.yaml` sections:

- `deployment`
- `http_guard`
- `decoys`
- `runtime`

Default behavior:

- Listen: `0.0.0.0:80`
- Forward safe requests to: `127.0.0.1:8080`
- Pre-pull decoys: `nginx:alpine`, `cowrie/cowrie:latest`, `dinotools/dionaea:latest`

## What This Repository Contains
- Agents: Discovery, Deception, Analysis, Decision, XAI
- Core processing: log ingest, vectorization, malware analysis
- Data pipeline: raw logs -> processed features -> model inference

## Quick Start
1. Install dependencies (Python, scikit-learn, optional nmap, optional angr/ghidra).
2. Place input logs under `./data/input/`:
   - Cowrie logs: `./data/input/cowrie/`
   - Dionaea bistreams: `./data/input/dionaea_bistreams/`
   - Zeek logs: `./data/input/zeek/logs/` and `./data/input/zeek/spool/`
3. Run the orchestrator:
   ```bash
   python ./src/main.py
   ```

### Training
- Ensure processed data exists in `./data/processed/ai_ready/` (already migrated).
- Train a fresh model:
  ```bash
  python ./src/training/train_model.py
  ```
  Outputs:
  - Model: `./models/brain_v5_mitre_only_semantic_balanced_v2.pt` (and `.pkl` bundle)
  - Report: `./models/brain_v5_mitre_only_semantic_balanced_v2_results.json`

### Testing
- Run inference on real Cowrie sessions:
  ```bash
  python ./src/training/test_model.py
  ```
  Outputs:
  - Predictions: `./data/processed/session_predictions.json`

### Report Contents
- The report now includes full command lists and any correlated binaries by default.
- Use `--no-commands` or `--no-binaries` to keep reports smaller.

### Quick Tests (Faster)
- Limit lines, sessions, and commands with verbose progress:
  ```bash
  python ./src/training/test_model.py --max-lines 20000 --max-sessions 200 --max-commands 20 --verbose --progress-every 5000
  ```

## Portability
This project is self-contained. Copy the entire `AdaptiveShield/` directory to another machine and it will run from the same layout.

## Key Files
- `Agents.md`: system architecture and agent roles
- `config/settings.yaml`: all paths and thresholds
- `src/main.py`: orchestration entry point
- `data/raw_logs/`: ingested raw logs
- `data/processed/`: processed outputs, session-binary map
- `models/`: trained ML models
