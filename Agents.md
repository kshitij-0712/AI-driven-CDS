# AdaptiveShield: Multi-Agent Deception & Analysis Architecture

## 1. System Overview
AdaptiveShield is an autonomous cyber-deception system that proactively detects, traps, and analyzes threats. It uses a cycle of Discovery -> Deception -> Analysis -> Decision -> Explanation. The project is self-contained and portable, with all runtime artifacts stored under ./data.

**Project Origin**: Real honeypot logs (Cowrie SSH, Dionaea multi-protocol, Zeek network monitor) collected from an Azure VM over ~63 days. All binary analysis was performed in a VirtualBox VM (Ubuntu 24.04, no GPU, 7.8GB RAM) specifically because malware binaries get flagged on the Windows host.

**Current State**: All binary analysis (Phases 1-4) is COMPLETE. A portable dataset has been exported to `data/exports/` for neural model training on the host machine (RTX 3050 GPU, 16GB RAM, Windows).

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
  - **Binary Analyst** -- multi-phase pipeline:
    - **Phase 1 -- Static Triage** (`core/malware/static_analyzer.py`): Lightweight analysis using pyelftools + pefile. Classifies binaries by behavior (miner, botnet, recon, destructive, etc.), computes priority scores (0-100), and extracts structural features (entropy, section_count, strings, architecture). Handles ELF, PE, and script files.
     - **Phase 2 -- Ghidra Deep Analysis** (`core/malware/ghidra_extract.py` + `ghidra_scripts/ExtractFeatures.java`): Headless Ghidra decompilation for function-level feature extraction. Uses a Java GhidraScript (Ghidra 12.0 dropped Jython/Python support). Extracts: function count, call graph edges, string categories (IPs, URLs, file paths, registry keys), import categories (network, crypto, file I/O, process, anti-debug), crypto constant detection (AES S-box, SHA-256), and Go binary metadata (version, user vs runtime function separation).
     - **Phase 3 -- Symbolic Execution** (`core/malware/symbolic.py`): angr-based CFGFast analysis for all binaries. Features: function count, basic block count, syscall identification, string extraction and categorization, Go runtime filtering. Includes blob backend fallback for the 31/39 ELFs with corrupted section header string tables, and SIGALRM hard timeout for UPX-packed binaries.
     - **Phase 4 -- Feature Fusion** (`core/malware/feature_merger.py`): Merges Phase 1-3 outputs into a 79-column flat numeric feature vector per binary SHA256. Computes derived cross-source features (mining consensus, function ratio, network signal aggregation). Feeds into enriched training pipeline.
   - **MITRE ATT&CK Integration** -- NEW:
     - **Attack Mapping** (`core/mitre/attack_mapping.py`): Knowledge base with 76 compiled regex command patterns mapped to 53 MITRE ATT&CK sub-techniques across 11 tactics. Includes `BINARY_TAG_TO_TECHNIQUE` for mapping binary analysis tags to techniques, severity scoring (1-10 scale), and tactic definitions with kill chain ordering.
     - **Session Annotator** (`core/mitre/session_annotator.py`): Annotates each session with a 14-dimension tactic vector (one per ATT&CK tactic), severity scores (max/mean/weighted), kill chain coverage score, matched technique lists. Produces 21 numeric features per session via `annotation_to_flat_dict()`.
  - **Session-Binary Correlator** (`agents/analysis.py`):
     - `correlate_downloads_from_logs()` -- Parses Cowrie log events (`cowrie.session.file_download`, `cowrie.session.file_upload`) to directly link SHA256 hashes to session IDs. This replaced the broken mtime-based correlation.
     - `enrich_sessions_with_binary_features()` -- Looks up triage results for each session's downloads and computes aggregated boolean features (has_miner, has_botnet, has_destructive, etc.) plus numeric features (num_downloads, max_priority).
     - `enrich_sessions_with_deep_features()` -- Phase 4 enrichment: loads merged features from all analysis phases, attaches a 79-column `deep_feature_vector` per session (aggregated across all downloaded binaries via max for booleans/complexity, sum for counts).
 - Output:
   - `data/processed/binary_triage/all_triage_results.json` -- Per-binary triage results (185 entries, keyed by SHA256)
   - `data/processed/ghidra_features/` -- Per-binary Ghidra extraction results (41 JSON files)
   - `data/processed/angr_features/` -- Per-binary angr analysis results (41 JSON files)
   - `data/processed/script_features/` -- Shell script analysis results (5 JSON files)
   - `data/processed/merged_binary_features.json` -- Fused 79-column feature vectors for all 185 binaries (41 with deep analysis)
   - `data/processed/ai_ready/checkpoint_correlated.pkl` -- Session-download correlation data (482K sessions)
   - `data/processed/ai_ready/checkpoint_enriched.pkl` -- Sessions enriched with Phase 1 binary features
   - `data/processed/ai_ready/checkpoint_deep_enriched.pkl` -- Sessions enriched with Phase 4 deep features
   - `data/exports/` -- Portable CSV/JSON export (see Section 10)

### Decision Agent ("The Brain")
- Goal: Predict adversary intent and determine response.
- Responsibilities:
  - Load trained model(s) and vectorizer.
  - Classify session behavior (Recon, Downloader, Exploit, Destructive, APT).
  - Select counter-measure (Allow, Throttle, Redirect, High-Interaction, Block).
- Models:
   - `brain_v2_deep.pkl` -- Original model trained on synthetic + IP-labeled data only.
   - `brain_v3_enriched.pkl` -- **Enriched model** trained on TF-IDF + binary behavior features from Phase 1 triage. Uses 3,011 features (3,000 TF-IDF char n-grams + 11 binary features).
   - `brain_v4_deep.pkl` -- **Deep model** trained on TF-IDF + 79-column deep binary feature vectors from all analysis phases (triage + Ghidra + angr + script features + derived cross-source features). **THIS IS THE CURRENT PRODUCTION MODEL** but has known limitations (see Section 9).
   - `brain_v5_neural.pkl` -- **PLANNED**: BiLSTM + structured features neural model to be trained on host machine.
 - Vectorizers:
   - `vectorizer_deep.pkl` -- Original TF-IDF vectorizer.
   - `vectorizer_enriched.pkl` -- Enriched vectorizer (same TF-IDF + binary feature columns).
   - `vectorizer_deep_v4.pkl` -- Deep v4 vectorizer (TF-IDF + 79 deep feature columns).
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
 4. Analysis processes captured binaries through the multi-phase pipeline:
    a. Phase 1 static triage classifies all 195 captured files (45 miners, 12 scanners, 4 packed, 3 downloaders, 2 botnets, 1 destructive, etc.).
    b. Phase 2 Ghidra headless decompilation extracts function-level features from 41 deduplicated binaries.
    c. Phase 3 angr symbolic execution extracts CFG, syscall, and string features from the same 41 binaries.
    d. Phase 4 feature merger fuses all analysis outputs into 79-column vectors per binary.
 5. MITRE ATT&CK annotation maps session commands to 53 sub-techniques across 14 tactics, producing 21 numeric features per session.
 6. Session-binary correlation links binary SHA256 hashes to attacker sessions via Cowrie log events.
 7. Enrichment attaches aggregated binary features (both Phase 1 boolean and Phase 4 deep vectors) to each session.
 8. Portable export packages everything into CSV/JSON files (see Section 10) for host machine training.
 9. Decision predicts intent using the trained model and issues next-step actions.
 10. XAI explains the action and rationale.

## 4. Key Goals
- Enumerate real services and insider-exposable surfaces.
- Mirror and monitor services that the system can handle (SSH/Telnet/HTTP/etc.).
- Learn adversary methodology to predict next actions.
- Adapt defenses by spawning decoys or reconfiguring services to sustain engagement.
- Provide explainable reasoning for every automated action.
- Link downloaded binaries to session logs for model training.
- **Ground threat classification in MITRE ATT&CK domain knowledge** (not just TF-IDF patterns).

## 5. Portability
- All project outputs live under ./data and ./models.
- Input sources are mounted under ./data/input (copy or mount logs there to run anywhere).
- The system can be moved to another host as a single directory and continue processing.
- **Portable export** (`data/exports/`) contains everything needed to train a new model WITHOUT the original binaries or 1.6GB of Cowrie logs.

## 6. Requirements and Installation
### Core Requirements
- Python 3.10+
- pip or a virtual environment (venv recommended)
- scikit-learn, numpy, scipy, pyyaml
- pyelftools (ELF binary analysis)
- pefile (PE/DLL binary analysis)

### Optional (Feature-Specific)
 - nmap or masscan (Discovery Agent scanning)
 - angr (Phase 3 symbolic binary analysis -- installed in .venv)
 - Ghidra 12.0+ with Java 21+ (Phase 2 deep static binary analysis -- installed via snap)

### Host Machine (Neural Model Training)
 - Python 3.10+
 - PyTorch with CUDA (RTX 3050 compatible)
 - pandas (for loading export CSVs)
 - No binary analysis tools needed -- all features are pre-extracted in exports

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

### Install (Host Machine -- Neural Training)
```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
pip install pandas scikit-learn numpy pyyaml
```

### Ghidra Setup (Phase 2)
 - Ghidra 12.0 via snap: `/snap/ghidra/35/ghidra_12.0_PUBLIC/support/analyzeHeadless`
 - Requires Java 21+ (local JDK at `.local/jdk/jdk-21.0.6/`)
 - Set `JAVA_HOME=/home/me/data/AdaptiveShield/.local/jdk/jdk-21.0.6` when invoking Ghidra
 - Uses `-scriptPath` to reference the Java GhidraScript (`ExtractFeatures.java`)
 - NOTE: Ghidra 12.0 dropped Jython (Python 2.7) support -- all scripts must be Java

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

# Phase 1 enriched pipeline: correlate + enrich + build dataset + train v3
PYTHONPATH=src .venv/bin/python src/run_enriched_pipeline.py

# Phase 2+3: Analyze a single binary (Ghidra + angr)
PYTHONPATH=src .venv/bin/python src/analyze_single.py <sha256_prefix>

# Phase 2+3: Batch analyze all remaining binaries
bash src/run_batch_analysis.sh

# Phase 4: Deep pipeline: correlate + deep enrich + build deep dataset + train v4
PYTHONPATH=src .venv/bin/python src/run_deep_pipeline.py

# Resume from a specific step (2=deep enrich, 3=build dataset, 4=train only)
PYTHONPATH=src .venv/bin/python src/run_deep_pipeline.py --from-step 2

# Train deep v4 model only (requires dataset already built)
PYTHONPATH=src .venv/bin/python src/training/train_model.py --deep-v4

# Export portable dataset (produces data/exports/*.csv and *.json)
PYTHONPATH=src .venv/bin/python src/export_portable_dataset.py
```

## 7. Enriched Training Pipeline Architecture (Phase 1)

### Overview
The enriched pipeline replaces the original synthetic-only training labels with labels derived from actual binary analysis of malware captured by honeypots.

### Pipeline Steps
```
Cowrie Logs (1.6GB, 64 files)
    |
    v
[Step 1] correlate_downloads_from_logs()  --- 482K sessions, 47K with downloads
    |
    v
[Step 2] enrich_sessions_with_binary_features()  --- lookup triage -> boolean features
    |
    v
[Step 3] build_enriched_dataset()  --- TF-IDF (3000) + binary (11) = 3011 features
    |
    v
[Step 4] train_enriched_model()  --- RandomForest (200 trees, balanced weights)
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

## 8. Phase 4 Deep Training Pipeline Architecture

### Overview
The Phase 4 deep pipeline extends Phase 1 by incorporating Ghidra (Phase 2) and angr (Phase 3) analysis results into a 79-column feature vector per binary. This provides much richer behavioral features than the 11 boolean/numeric features in Phase 1.

### Pipeline Steps
```
Phase 1-3 Outputs (triage + Ghidra + angr + script JSONs)
    |
    v
[Feature Merger] merge_all_features()  --- 79-column vector per SHA256
    |
    v
[Step 1] correlate_downloads_from_logs()  --- 482K sessions, 47K with downloads
    |
    v
[Step 2] enrich_sessions_with_deep_features()  --- attach 79-col vector per session
    |
    v
[Step 3] build_deep_dataset()  --- TF-IDF (3000) + deep (79) = ~3079 features
    |
    v
[Step 4] train_deep_v4_model()  --- RandomForest (200 trees, balanced weights)
    |
    v
brain_v4_deep.pkl
```

### Deep Feature Vector (79 columns)
| Source | Count | Examples |
|---|---|---|
| triage_* | 12 | entropy, section_count, string_count, is_go, is_stripped |
| ghidra_* | 23 | function_count, call_edges, ip_count, url_count, has_aes, go_user_functions |
| angr_* | 28 | function_count, basic_blocks, syscalls_network, unique_strings, cfg_nodes |
| script_* | 6 | has_wget, has_curl, has_base64, has_cron, has_firewall_mod, downloads_and_executes |
| deep_* | 10 | mining_consensus, func_ratio, network_signals, has_ghidra_results, has_angr_results |

### Key Design Decisions
- **Blob backend fallback**: 31/39 ELFs have corrupted section header string tables. angr's CLE loader fails on these, so we read the ELF header manually and load via `backend='blob'`.
- **Go runtime filtering**: Go binaries have thousands of runtime functions. We count them separately and focus analysis on `main.*` and user-code packages.
- **Java GhidraScript**: Ghidra 12.0 dropped Jython (Python 2.7) support. The extraction script is written in Java (`ExtractFeatures.java`).
- **SIGALRM hard timeout**: UPX-packed binaries cause angr's CFGFast to run indefinitely. A SIGALRM handler kills analysis after the configured timeout.
- **Per-session aggregation**: Sessions may download multiple binaries. Deep features are aggregated via MAX (for booleans/complexity metrics) and SUM (for counts).

### Binary Analysis Coverage
- **41 deduplicated binaries** analyzed (39 ELF + 2 PE representatives)
- **All 41** processed by both Ghidra and angr
- **5 shell scripts** analyzed by the script analyzer
- **Findings**: 19 identical XMRig miners (same Discord webhook C2), 2 Go multi-capability APT tools, 2 Mirai-variant botnet droppers, 4 multi-arch UPX-packed unknowns, 12 recon scanners, 1 WannaCry sample, 1 Monero miner dropper DLL

## 9. Known Model Limitations and Why We Need a Neural Approach

### Problems with Current Model (brain_v4_deep.pkl)
The current RandomForest + TF-IDF model achieves 99.99% accuracy, but this metric is misleading:

1. **No semantic understanding**: TF-IDF char n-grams (2-5) treat commands as opaque character sequences. The model has no concept of what `cat /etc/shadow` means -- it just sees character patterns. It cannot generalize to novel commands that perform the same attack technique.

2. **No threat intelligence grounding**: Zero MITRE ATT&CK integration in the model. The codebase now HAS the MITRE module (76 patterns, 53 sub-techniques), but the v4 model was trained without it.

3. **No cost-sensitivity**: Missing an APT (false negative on class 5) costs far more than over-reacting to recon. The model treats all classification errors equally.

4. **Synthetic data dominance**: 4,400 synthetic samples from ~22 unique command templates inflate accuracy because TF-IDF trivially separates synthetic from real commands (98.95% feature importance from TF-IDF alone).

### Training Data Distribution (v4 model)
| Class | Name | Total | Synthetic | Real | % Real |
|-------|------|-------|-----------|------|--------|
| 0 | Safe | 79,504 | 1,200 | 78,304 | 98.5% |
| 1 | Recon | 800 | 800 | 0 | 0% |
| 2 | Downloader | 624 | 600 | 24 | 3.8% |
| 3 | Exploit | 600 | 600 | 0 | 0% |
| 4 | Destructive | 727 | 600 | 127 | 17.5% |
| 5 | ADVANCED_APT | 649 | 600 | 49 | 7.6% |

### Real-Data-Only Label Distribution (from export)
| Class | Name | Count |
|-------|------|-------|
| 0 | Safe | 78,304 |
| 2 | Downloader | 24 |
| 4 | Destructive | 127 |
| 5 | ADVANCED_APT | 49 |
| 1 | Recon | 0 |
| 3 | Exploit | 0 |

Classes 1 (Recon) and 3 (Exploit) have ZERO real sessions. Only 200 real malicious sessions exist across all classes.

### What the Neural Model Should Fix
- **Semantic command understanding** via character/token embeddings + BiLSTM (learns what commands DO, not just character patterns)
- **MITRE ATT&CK features** as structured input (14-dim tactic vector + severity scores = 21 features)
- **Cost-sensitive loss** (higher penalty for missing APT/Destructive)
- **Hybrid synthetic data** (real sessions primary, synthetic only for rare classes 1 and 3)
- **Focal loss or class-weighted sampling** to handle the 99.7% Safe class imbalance

## 10. Portable Dataset Export

### Overview
The export pipeline (`src/export_portable_dataset.py`) produces a complete, self-contained export of ALL processed data so that the full ML pipeline can be rebuilt on the host machine WITHOUT ever needing the original binaries or Cowrie log files.

### Export Files (in `data/exports/`)

| File | Rows | Cols | Size | Description |
|------|------|------|------|-------------|
| `sessions.csv` | 78,504 | 9 | 40.0 MB | All sessions: commands, timestamps, IPs, download links |
| `downloads.csv` | 50,520 | 6 | 5.9 MB | All Cowrie download/upload events (session -> SHA256) |
| `binary_features.csv` | 185 | 104 | 55.9 KB | All SHA256s with full triage+Ghidra+angr+script features |
| `session_labels.csv` | 78,504 | 16 | 3.4 MB | Per-session labels + binary indicator booleans |
| `sessions_mitre.csv` | 78,504 | 24 | 6.4 MB | MITRE ATT&CK annotations (21 numeric features + metadata) |
| `sessions_complete.csv` | 78,504 | 111 | 67.1 MB | **THE BIG ONE**: everything joined, training-ready |
| `mitre_knowledge_base.json` | -- | -- | 27.7 KB | Portable ATT&CK pattern definitions (76 patterns) |
| `export_manifest.json` | -- | -- | 7.9 KB | Metadata, schemas, provenance, recommended next steps |

### sessions_complete.csv Column Groups (111 total)

| Group | Columns | Description |
|-------|---------|-------------|
| Session metadata | 4 | session_id, src_ip, num_commands, duration_sec |
| Raw text | 1 | commands (semicolon-separated) |
| MITRE tactic features | 14 | mitre_tactic_{reconnaissance,...,impact} -- float counts per tactic |
| MITRE severity features | 7 | severity_max, severity_mean, severity_weighted, kill_chain_score, unique_technique_count, total_commands, matched_commands |
| MITRE metadata | 2 | mitre_severity_tier (categorical), mitre_technique_ids (pipe-separated) |
| Download metadata | 2 | num_downloads, download_shas |
| Deep binary features | 79 | Aggregated triage+Ghidra+angr+script features (max across all session binaries) |
| Labels | 2 | label_id (0-5), label_name |

### MITRE ATT&CK Coverage (from export)
- **94.3%** of sessions (74,005/78,504) matched at least one ATT&CK pattern
- **39,217 sessions** are high-severity (severity_max >= 7)
- 76 command patterns mapped to 53 sub-techniques across 14 ATT&CK tactics

### How to Use the Export on Host Machine
```python
import pandas as pd

# Load the training-ready dataset
df = pd.read_csv("data/exports/sessions_complete.csv")

# Text input for BiLSTM
commands = df["commands"].tolist()

# Structured features (21 MITRE + 79 binary = 100 numeric features)
mitre_cols = [c for c in df.columns if c.startswith("mitre_tactic_") or c.startswith("mitre_severity") or c.startswith("mitre_kill") or c.startswith("mitre_unique") or c.startswith("mitre_total") or c.startswith("mitre_matched")]
# Or use the explicit list from get_mitre_feature_columns()
binary_cols = [c for c in df.columns if c.startswith(("triage_", "ghidra_", "angr_", "script_", "deep_"))]
structured = df[mitre_cols + binary_cols].values

# Labels
labels = df["label_id"].values
```

## 11. Planned Neural Model Architecture (Phase 5)

### Architecture: BiLSTM + Structured Features
```
Input Commands (text)     Structured Features (100-dim)
       |                           |
  Char/Token Embedding      BatchNorm + Dense(64)
       |                           |
  BiLSTM (128 hidden)        ReLU + Dropout
       |                           |
  Attention Pooling                |
       |                           |
       +----------+----------------+
                  |
            Concatenate
                  |
           Dense(128) + ReLU
                  |
           Dense(6) + Softmax
                  |
           Class Prediction (0-5)
```

### Design Decisions (already made)
- **Architecture**: Neural approach (BiLSTM + structured features)
- **Synthetic data strategy**: Hybrid (real sessions primary, synthetic only for rare classes 1 and 3)
- **MITRE depth**: Sub-technique level (T1059.004 not just T1059)
- **Loss function**: Cost-sensitive (higher penalty for missing APT/Destructive)
- **Training hardware**: RTX 3050 GPU with CUDA on Windows host

### Training Approach
1. Load `sessions_complete.csv` from export
2. Character-level or subword tokenization of commands
3. BiLSTM encoder for command sequences
4. Concatenate with 21 MITRE features + 79 binary features = 100-dim structured input
5. Cost-sensitive cross-entropy loss with class weights inversely proportional to frequency
6. Consider focal loss (gamma=2) for extreme imbalance handling
7. Downsample Safe class to ~5,000 or use stratified mini-batches
8. Generate synthetic sessions for classes 1 (Recon) and 3 (Exploit) using MITRE-informed templates

## 12. How 195 Files Became 41 Analysis Targets

- **Cowrie downloads (170 files)**: 39 ELF binaries, 4 bash scripts, 116 text files (~204-byte captured output), 11 empty files
- **Dionaea binaries (24 files)**: 23 identical WannaCry PE32 DLLs + 1 Monero miner DLL
- **Deduplication**: 23 WannaCry -> 1 representative. Final: **41 unique binaries** for deep analysis (39 ELF + 2 PE)

### Key Malware Findings
- **19 stripped XMRig miners**: Same family, Discord webhook C2, same config strings
- **2 Go binaries (30MB each)**: Most sophisticated -- multi-capability APT tools with mining, botnet, credential access, persistence, recon
- **1 WannaCry sample**: PE with kill switch URL
- **2 UPX-packed binaries**: Caused angr CFGFast to run indefinitely (timeout saved partial results)
- **31/39 ELFs**: Missing section header string tables (required blob backend fallback in angr)

## 13. Source File Inventory

### MITRE ATT&CK Module (NEW)
| File | Description |
|------|-------------|
| `src/core/mitre/__init__.py` | Module init |
| `src/core/mitre/attack_mapping.py` | 76 ATT&CK patterns, 53 sub-techniques, severity scoring, binary tag mapping (~35KB) |
| `src/core/mitre/session_annotator.py` | Session annotator producing 21 MITRE features per session (~13KB) |

### Export Pipeline (NEW)
| File | Description |
|------|-------------|
| `src/export_portable_dataset.py` | 8-file export orchestrator (~25KB) |

### Binary Analysis Pipeline
| File | Description |
|------|-------------|
| `src/core/malware/static_analyzer.py` | Phase 1 triage engine with indicator patterns |
| `src/core/malware/ghidra_extract.py` | Ghidra orchestrator |
| `src/core/malware/ghidra_scripts/ExtractFeatures.java` | GhidraScript for Phase 2 |
| `src/core/malware/symbolic.py` | angr analysis with blob fallback |
| `src/core/malware/feature_merger.py` | Phase 4 feature fusion (79 columns) |

### Training Pipeline
| File | Description |
|------|-------------|
| `src/core/processing/vectorizer.py` | TF-IDF + feature building, synthetic data, labeling |
| `src/training/train_model.py` | RandomForest training |
| `src/agents/analysis.py` | Session correlation + binary enrichment |

### Configuration
| File | Description |
|------|-------------|
| `config/settings.yaml` | All paths, model references, export config |

## 14. Git Information
- **Repository**: https://github.com/kshitij-0712/AI-driven-CDS.git
- **Branch**: `fE`
- **Last binary analysis commit**: `dd9998b` (Phases 2-4 complete)
- **MITRE + export files**: committed on top of dd9998b

## 15. Data Provenance Summary
| Metric | Value |
|--------|-------|
| Honeypot duration | ~63 days |
| Cowrie log files | 64 (1.6GB total) |
| Total raw sessions | 482,512 |
| Sessions with commands | 78,504 |
| Sessions with downloads | 47,597 |
| Total download events | 50,520 |
| Unique SHA256 hashes | 160 (in logs) / 185 (with on-disk dedup) |
| Binaries deep-analyzed | 41 (Ghidra + angr) |
| Shell scripts analyzed | 5 |
| Real malicious sessions | 200 (127 Destructive + 49 APT + 24 Downloader) |
| MITRE-matched sessions | 74,005 (94.3%) |
| High-severity sessions | 39,217 (severity >= 7) |
