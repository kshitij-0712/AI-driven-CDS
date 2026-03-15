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
     - **Phase 2 — Ghidra Deep Analysis** (`core/malware/ghidra_extract.py` + `ghidra_scripts/ExtractFeatures.java`): Headless Ghidra decompilation for function-level feature extraction. Uses a Java GhidraScript (Ghidra 12.0 dropped Jython/Python support). Extracts: function count, call graph edges, string categories (IPs, URLs, file paths, registry keys), import categories (network, crypto, file I/O, process, anti-debug), crypto constant detection (AES S-box, SHA-256), and Go binary metadata (version, user vs runtime function separation).
     - **Phase 3 — Symbolic Execution** (`core/malware/symbolic.py`): angr-based CFGFast analysis for all binaries. Features: function count, basic block count, syscall identification, string extraction and categorization, Go runtime filtering. Includes blob backend fallback for the 31/39 ELFs with corrupted section header string tables, and SIGALRM hard timeout for UPX-packed binaries.
     - **Phase 4 — Feature Fusion** (`core/malware/feature_merger.py`): Merges Phase 1-3 outputs into a 79-column flat numeric feature vector per binary SHA256. Computes derived cross-source features (mining consensus, function ratio, network signal aggregation). Feeds into enriched training pipeline.
   - **Session-Binary Correlator** (`agents/analysis.py`):
     - `correlate_downloads_from_logs()` — Parses Cowrie log events (`cowrie.session.file_download`, `cowrie.session.file_upload`) to directly link SHA256 hashes to session IDs. This replaced the broken mtime-based correlation.
     - `enrich_sessions_with_binary_features()` — Looks up triage results for each session's downloads and computes aggregated boolean features (has_miner, has_botnet, has_destructive, etc.) plus numeric features (num_downloads, max_priority).
     - `enrich_sessions_with_deep_features()` — Phase 4 enrichment: loads merged features from all analysis phases, attaches a 79-column `deep_feature_vector` per session (aggregated across all downloaded binaries via max for booleans/complexity, sum for counts).
 - Output:
   - `data/processed/binary_triage/all_triage_results.json` — Per-binary triage results (195 entries, keyed by SHA256)
   - `data/processed/ghidra_features/` — Per-binary Ghidra extraction results (41 JSON files)
   - `data/processed/angr_features/` — Per-binary angr analysis results (41 JSON files)
   - `data/processed/script_features/` — Shell script analysis results (5 JSON files)
   - `data/processed/merged_binary_features.json` — Fused 79-column feature vectors for all binaries
   - `data/processed/ai_ready/checkpoint_correlated.pkl` — Session-download correlation data (482K sessions)
   - `data/processed/ai_ready/checkpoint_enriched.pkl` — Sessions enriched with Phase 1 binary features
   - `data/processed/ai_ready/checkpoint_deep_enriched.pkl` — Sessions enriched with Phase 4 deep features
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
   - `brain_v4_deep.pkl` — **Deep model** trained on TF-IDF + 79-column deep binary feature vectors from all analysis phases (triage + Ghidra + angr + script features + derived cross-source features).
 - Vectorizers:
   - `vectorizer_deep.pkl` — Original TF-IDF vectorizer.
   - `vectorizer_enriched.pkl` — Enriched vectorizer (same TF-IDF + binary feature columns).
   - `vectorizer_deep_v4.pkl` — Deep v4 vectorizer (TF-IDF + 79 deep feature columns).
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
 5. Session-binary correlation links binary SHA256 hashes to attacker sessions via Cowrie log events.
 6. Enrichment attaches aggregated binary features (both Phase 1 boolean and Phase 4 deep vectors) to each session.
 7. Vectorizer builds training dataset (TF-IDF commands + deep features), trains RandomForest classifier.
 8. Decision predicts intent using the trained model and issues next-step actions.
 9. XAI explains the action and rationale.

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
 - angr (Phase 3 symbolic binary analysis — installed in .venv)
 - Ghidra 12.0+ with Java 21+ (Phase 2 deep static binary analysis — installed via snap)

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

### Ghidra Setup (Phase 2)
 - Ghidra 12.0 via snap: `/snap/ghidra/35/ghidra_12.0_PUBLIC/support/analyzeHeadless`
 - Requires Java 21+ (local JDK at `.local/jdk/jdk-21.0.6/`)
 - Set `JAVA_HOME=/home/me/data/AdaptiveShield/.local/jdk/jdk-21.0.6` when invoking Ghidra
 - Uses `-scriptPath` to reference the Java GhidraScript (`ExtractFeatures.java`)
 - NOTE: Ghidra 12.0 dropped Jython (Python 2.7) support — all scripts must be Java

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
 - Phases 2 (Ghidra) and 3 (angr) deep features are now available via the Phase 4 pipeline.

## 8. Phase 4 Deep Training Pipeline Architecture

### Overview
The Phase 4 deep pipeline extends Phase 1 by incorporating Ghidra (Phase 2) and angr (Phase 3) analysis results into a 79-column feature vector per binary. This provides much richer behavioral features than the 11 boolean/numeric features in Phase 1.

### Pipeline Steps
```
Phase 1-3 Outputs (triage + Ghidra + angr + script JSONs)
    |
    v
[Feature Merger] merge_all_features()  ─── 79-column vector per SHA256
    |
    v
[Step 1] correlate_downloads_from_logs()  ─── 482K sessions, 47K with downloads
    |
    v
[Step 2] enrich_sessions_with_deep_features()  ─── attach 79-col vector per session
    |
    v
[Step 3] build_deep_dataset()  ─── TF-IDF (3000) + deep (79) = ~3079 features
    |
    v
[Step 4] train_deep_v4_model()  ─── RandomForest (200 trees, balanced weights)
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
