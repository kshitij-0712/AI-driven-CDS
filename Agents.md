# AdaptiveShield: Multi-Agent Deception & Analysis Architecture

## 1. System Overview
AdaptiveShield is an autonomous cyber-deception system that proactively detects, traps, and analyzes threats. It uses a cycle of Discovery -> Deception -> Analysis -> Decision -> Explanation. The project is self-contained and portable, with all runtime artifacts stored under ./data.

## 2. Agent Definitions

### Discovery Agent ("The Scout")
- Goal: Map the true attack surface of the host machine.
- Responsibilities:
  - Periodically scan the host (or network range) using nmap or masscan.
  - Identify real services (what is genuinely reachable).
  - Identify candidate decoy ports (closed but plausible services).
- Output: discovery_report.json (list of open ports, services, and candidate decoy ports).

### Deception Agent ("The Trapmaker")
- Goal: Manage honeypot instances to trap attackers.
- Responsibilities:
  - Deploy Cowrie (SSH/Telnet) or Dionaea (SMB/HTTP/FTP) on candidate ports.
  - Adapt configuration dynamically (banner rotation, port mapping, fake services) based on Decision Agent commands.
  - Monitor health and log availability for each decoy.
- Output: live decoys and raw log streams.

### Analysis Agent ("The Detective")
- Goal: Transform raw telemetry into actionable intelligence.
- Sub-modules:
  - Log Ingestor: Normalizes Cowrie/Zeek/Dionaea logs and tags them by session.
  - Binary Analyst: Detects newly downloaded files, hashes them, and runs:
    - Ghidra static feature extraction
    - Angr symbolic analysis (Zorya)
- Output: processed_session_data.json and session_binary_map.json (session -> commands -> downloads -> binary analysis).

### Decision Agent ("The Brain")
- Goal: Predict adversary intent and determine response.
- Responsibilities:
  - Load trained model(s) and vectorizer.
  - Classify session behavior (Recon, Downloader, Exploit, Destructive, APT).
  - Select counter-measure (Allow, Throttle, Redirect, High-Interaction, Block).
- Output: ActionCommand for Deception Agent.

### XAI Agent ("The Narrator")
- Goal: Provide human-readable explanations for autonomous actions.
- Responsibilities:
  - Interpret Decision Agent outputs and confidence.
  - Generate audit trail and operator-friendly summaries.
- Output: xai_audit_log.txt (audit trail).

## 3. Data Flow
1. Discovery finds open services and candidate decoy ports.
2. Deception deploys decoys matching the discovered surface.
3. Attacker interacts with decoy; logs are captured.
4. Analysis correlates session logs with downloaded binaries.
5. Decision predicts intent and issues next-step actions.
6. XAI explains the action and rationale.

## 4. Key Goals
- Enumerate real services and insider-exposable surfaces.
- Mirror and monitor services that the system can handle (SSH/Telnet/HTTP/etc.).
- Learn adversary methodology to predict next actions.
- Adapt defenses by spawning decoys or reconfiguring services to sustain engagement.
- Provide explainable reasoning for every automated action.
- Link downloaded binaries to session logs for model training.

## 5. Portability
- All project outputs live under ./data and ./models.
- Input sources are mounted under ./data/input (copy or mount logs there to run anywhere).
- The system can be moved to another host as a single directory and continue processing.

## 6. Requirements and Installation
### Core Requirements
- Python 3.10+
- pip or a virtual environment (venv recommended)
- scikit-learn, numpy, pyyaml

### Optional (Feature-Specific)
- nmap or masscan (Discovery Agent scanning)
- angr (symbolic binary analysis)
- Ghidra (static binary analysis)

### Install (Minimal)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install scikit-learn numpy pyyaml
```

### Install (With Symbolic Analysis)
```bash
pip install angr
```

### Ghidra Setup (Optional)
- Install Ghidra and ensure it is accessible on your system.
- Set GHIDRA_OUTPUT_DIR if running the Ghidra extraction script.
- The project ships a generator for the script: src/core/malware/ghidra_extract.py

### Required Input Layout
Place or mount logs under:
- ./data/input/cowrie/
- ./data/input/dionaea_bistreams/
- ./data/input/zeek/logs/
- ./data/input/zeek/spool/

### Run
```bash
python ./src/main.py
```
