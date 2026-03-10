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
  - **Log Ingestor** (`core/ingestors/log_parsers.py`): Normalizes Cowrie/Zeek/Dionaea logs and tags them by session.
  - **Binary Analyst** — multi-phase pipeline:
    - **Phase 1 — Static Triage** (`core/malware/static_analyzer.py`): Lightweight analysis using pyelftools + pefile. Classifies binaries by behavior (miner, botnet, recon, destructive, etc.), computes priority scores (0-100), and extracts structural features (entropy, imports, strings, architecture). Handles ELF, PE, and script files.
    - **Phase 2 — Ghidra Deep Analysis** (`core/malware/ghidra_extract.py`): Headless Ghidra decompilation for function-level feature extraction. (Not yet implemented)
    - **Phase 3 — Symbolic Execution** (`core/malware/symbolic.py`): angr-based symbolic analysis for Go binaries and complex ELFs. (Not yet implemented)
  - **Session-Binary Correlator** (`agents/analysis.py`):
    - `correlate_downloads_from_logs()` — Parses Cowrie log events (`cowrie.session.file_download`, `cowrie.session.file_upload`) to directly link SHA256 hashes to session IDs. This replaced the broken mtime-based correlation.
    - `enrich_sessions_with_binary_features()` — Looks up triage results for each session's downloads and computes aggregated boolean features (has_miner, has_botnet, has_destructive, etc.) plus numeric features (num_downloads, max_priority).
- Output:
  - `data/processed/binary_triage/all_triage_results.json` — Per-binary triage results (185 entries, keyed by SHA256)
  - `data/processed/ai_ready/checkpoint_correlated.pkl` — Session-download correlation data (482K sessions)
  - `data/processed/ai_ready/checkpoint_enriched.pkl` — Sessions enriched with binary features
  - Enriched training data fed to the Vectorizer

### Decision Agent ("The Brain")
- Goal: Predict adversary intent and determine response.
- Responsibilities:
  - Load trained model(s) and vectorizer.
  - Classify session behavior (Recon, Downloader, Exploit, Destructive, APT).
  - Select counter-measure (Allow, Throttle, Redirect, High-Interaction, Block).
- Models:
  - `brain_v2_deep.pkl` — Original model trained on synthetic + IP-labeled data only.
  - `brain_v3_enriched.pkl` — **Enriched model** trained on TF-IDF + binary behavior features from Phase 1 triage. Uses 3,011 features (3,000 TF-IDF char n-grams + 11 binary features).
- Vectorizers:
  - `vectorizer_deep.pkl` — Original TF-IDF vectorizer.
  - `vectorizer_enriched.pkl` — Enriched vectorizer (same TF-IDF + binary feature columns).
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
3. Attacker interacts with decoy; logs are captured (Cowrie SSH, Dionaea SMB, Zeek network).
4. Analysis correlates session logs with downloaded binaries:
   a. Phase 1 static triage classifies all captured binaries.
   b. `correlate_downloads_from_logs()` links binary SHA256 hashes to session IDs via log events.
   c. `enrich_sessions_with_binary_features()` computes per-session feature vectors from triage results.
5. Vectorizer builds enriched training dataset (TF-IDF commands + binary behavior features).
6. Decision predicts intent using the enriched model and issues next-step actions.
7. XAI explains the action and rationale.

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
- scikit-learn, numpy, scipy, pyyaml
- pyelftools (ELF binary analysis)
- pefile (PE/DLL binary analysis)

### Optional (Feature-Specific)
- nmap or masscan (Discovery Agent scanning)
- angr (Phase 3 symbolic binary analysis)
- Ghidra (Phase 2 deep static binary analysis)

### Install (Minimal)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
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
# Standard pipeline (original model)
python ./src/main.py

# Phase 1: Triage all captured binaries
PYTHONPATH=src .venv/bin/python src/core/malware/run_triage.py

# Enriched pipeline: correlate + enrich + build dataset + train
PYTHONPATH=src .venv/bin/python src/run_enriched_pipeline.py

# Resume from a specific step (2=enrich, 3=build dataset, 4=train only)
PYTHONPATH=src .venv/bin/python src/run_enriched_pipeline.py --from-step 2

# Train enriched model only (requires dataset already built)
PYTHONPATH=src .venv/bin/python src/training/train_model.py --enriched
```

## 7. Enriched Training Pipeline Architecture

### Overview
The enriched pipeline replaces the original synthetic-only training labels with labels derived from actual binary analysis of malware captured by honeypots.

### Pipeline Steps
```
Cowrie Logs (1.6GB, 64 files)
    |
    v
[Step 1] correlate_downloads_from_logs()  ─── 482K sessions, 47K with downloads
    |
    v
[Step 2] enrich_sessions_with_binary_features()  ─── lookup triage → boolean features
    |
    v
[Step 3] build_enriched_dataset()  ─── TF-IDF (3000) + binary (11) = 3011 features
    |
    v
[Step 4] train_enriched_model()  ─── RandomForest (200 trees, balanced weights)
    |
    v
brain_v3_enriched.pkl
```

### Binary Feature Columns (11)
| Feature | Type | Description |
|---|---|---|
| has_miner | bool | Session downloaded a crypto miner |
| has_botnet | bool | Session downloaded a botnet dropper |
| has_downloader | bool | Session downloaded a downloader/stager |
| has_destructive | bool | Session downloaded destructive malware |
| has_recon | bool | Session downloaded a recon scanner |
| has_credential_access | bool | Session downloaded a credential stealer |
| has_rat | bool | Session downloaded a RAT |
| has_go_binary | bool | Session downloaded a Go binary |
| has_packed | bool | Session downloaded a packed/obfuscated binary |
| num_downloads | float | Number of files downloaded in session |
| max_priority_norm | float | Highest triage priority (0-1) among downloads |

### Classification Labels (6 classes)
| ID | Name | Derived from |
|---|---|---|
| 0 | Safe | Sessions with no malicious binary indicators |
| 1 | Recon | recon_scanner binaries |
| 2 | Downloader | miner, botnet_dropper, downloader binaries |
| 3 | Exploit | credential_stealer, rat, packed_unknown binaries |
| 4 | Destructive | destructive binaries |
| 5 | ADVANCED_APT | Go binaries with >= 4 behavioral tags |

### Current Metrics (Phase 1 only)
- 200 sessions labeled from binary analysis (out of 78,504)
- 47,597 sessions with downloads correlated via log events
- Model accuracy: 99.99% (note: dominated by synthetic data separation — see limitations below)

### Known Limitations
- Only 200/78,504 sessions receive real binary-derived labels; most sessions downloaded files classified as `unknown_script` (command output captures, not actual malware).
- Synthetic training data (4,400 samples) is trivially separable from real commands by TF-IDF, inflating accuracy metrics.
- Binary features contribute only ~0.3% of model importance (TF-IDF dominates at 99.7%).
- Phases 2 (Ghidra) and 3 (angr) will provide deeper features for the 39 ELF + 24 PE binaries.
