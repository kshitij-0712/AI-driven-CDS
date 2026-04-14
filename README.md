# AdaptiveShield

AdaptiveShield is a portable, multi-agent cyber deception and analysis system. It discovers exposed services, deploys decoys, learns attacker behavior, and explains every decision with XAI.

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
  - Model: `./models/brain_v2_deep.pkl`
  - Report: `./data/processed/training_report.json`
- Train the insider-resilient detection module with the exported session dataset:
  ```bash
  python ./src/train_insider.py
  ```
  Outputs:
  - Model: `./models/insider_model.pkl`
  - Dataset: `./data/exports/insider_dataset.csv`
- Generate a CERT baseline dataset from CERT output files:
  ```bash
  python ./src/train_insider.py --cert-dir ./data/cert-outputs --cert-output ./data/exports/cert_baseline_dataset.csv
  ```
  Outputs:
  - CERT baseline dataset: `./data/exports/cert_baseline_dataset.csv`
  - Uses files such as `login_features.csv`, `insider_login_alerts.csv`, and `final_insider_risk.csv`

### Insider-resilient detection notes
This module currently detects stealthy malicious sessions using the exported session dataset.
The current export dataset contains no internal source IPs, so this model is still a proxy for suspicious insider-like behavior rather than a true internal user compromise detector.
To move it closer to true malicious insider detection, refine the dataset and features with:
- internal access / source indicators
- unusual command patterns for privileged access
- persistence / credential misuse signals
- low-noise file or download activity
- strange timing relative to normal sessions

These refinements help the system approximate a malicious insider attacking its own environment instead of only generic external attacker behavior.
If additional data is available, use Cowrie logs for session extraction and CERT logs as a normal behavior baseline.

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
