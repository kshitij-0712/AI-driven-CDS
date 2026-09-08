# AdaptiveShield Implementation Plan — Complete Self-Contained Guide

**Project**: AdaptiveShield — Multi-Agent Cyber Deception Platform
**Branch**: `train` (base)
**Target**: Unified neural model replacing 3-stage pipeline (Regex → Neural → MITRE fallback)
**Runtime**: Docker Compose, CPU-only inference, RTX 3050 (5GB) for training
**LLM**: `deepseek-r1:8b` via Ollama (installed, needs testing) / ` qwen2.5-coder:7b-instruct-q4_K_M` (available)

---

## Executive Summary

Replace the current 3-stage classification pipeline with a **single unified neural model** that fuses:
1. **Command sequence** (BiLSTM, 256-dim)
2. **MITRE tactics** (21-dim, real-time regex annotator)
3. **System changes** (~20-dim, decoy observation encoder)
4. **Static triage** (23-dim, pyelftools/pefile, <100ms)

**Training**: Ghidra/angr deep analysis enriches labels OFFLINE only — model internalizes deep binary understanding. Runtime uses ONLY fast static triage.

**Action Policy**: Only brute-force → nftables block. All other threats → decoy redirect (engage & learn).

**Synthetic Data**: LLM-generated with MITRE KB as hard constraints.

---

## LLM Usage Across the Pipeline

### 1. Training Phase — Synthetic Data & Label Enrichment

| Use Case | Script | Input | Output |
|----------|--------|-------|--------|
| **Generate attack sessions for rare classes** | `src/training/neural/llm_synthetic.py` | MITRE tactics + few-shot real sessions | Full session JSON (commands, system_changes, MITRE features, triage_features, label_id) |
| **Enrich real session labels** | `src/export_portable_dataset.py` (modified) | Real session (commands + binary features) | Rich labels: reasoning + MITRE tactics + confidence |
| **Diversify destructive patterns** | `src/training/neural/llm_synthetic.py` | Target class = Destructive | 10+ distinct patterns (not just SSH key replacement) |
| **Semantic labeling fallback** | `src/training/neural/semantic_labels.py` (modified) | Commands with no regex match | MITRE tactic + technique + severity + reasoning |
| **LLM-assisted MITRE annotation** | `src/core/mitre/session_annotator.py` (modified) | Novel command combinations | Additional technique matches |

**MITRE KB as hard constraints** — LLM must generate sessions that trigger specific patterns from `attack_mapping.py` (76 patterns, 53 techniques).

---

### 2. Runtime — Dynamic Decoy Responses

| Use Case | Script | Trigger | Output |
|----------|--------|---------|--------|
| **Per-command fake filesystem (SSH)** | `src/honeypot/ssh_decoy_builder.py` (enhanced) | Attacker types command in Cowrie | Fake `whoami`, `id`, `uname`, `/etc/passwd`, `/etc/shadow`, `.bash_history` |
| **Session-aware responses (SSH)** | `src/honeypot/ssh_decoy_builder.py` | Session memory (`SessionStateManager`) | Contextual responses based on attacker history |
| **Dynamic HTTP responses** | `src/honeypot/generator.py` (existing) | Attacker hits decoy endpoint | Full HTTP response (HTML/JSON, status, headers) |
| **Application cloning** | `src/honeypot/generator.py` (existing) | First decoy creation | Clones real app structure via crawler |
| **Session state evolution (HTTP)** | `src/honeypot/generator.py` | Attacker interaction history | Evolving decoy state (fake DB, auth, files) |

---

### 3. Runtime — XAI & Analysis

| Use Case | Script | Trigger | Output |
|----------|--------|---------|--------|
| **Binary behavior summarization** | `src/agents/binary_triage_runtime.py` (new) | Triage complete (23-dim) | Natural language summary: "ELF x64, UPX packed, mining imports, C2 to Discord" |
| **Attack narrative generation** | XAI Agent (future) | Session classified as threat | "Attacker did X, then Y, downloaded Z which is a miner" |
| **Decoy configuration** | `src/honeypot/ssh_decoy_builder.py` | New decoy session | Realistic users, services, configs per session |
| **Log anomaly explanation** | Insider Module (future) | Anomalous internal behavior | Why this user's behavior is anomalous |

---

### 4. Modified Pipeline Scripts (LLM-Integrated)

```
┌─────────────────────────────────────────────────────────────────┐
│ MODIFIED PIPELINE (LLM-integrated)                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. export_portable_dataset.py                                 │
│     └─► Add: LLM-enriched labels for each session              │
│         (uses LLMRouter, few-shot from MITRE KB)               │
│                                                                 │
│  2. semantic_labels.py                                         │
│     └─► Add: LLM fallback for commands with no regex match     │
│         "Classify this command: <cmd> → MITRE tactic + severity"│
│                                                                 │
│  3. synthetic.py  →  llm_synthetic.py                          │
│     └─► REPLACE template-based with LLM generator              │
│         (MITRE KB as hard constraints, validation loop)        │
│                                                                 │
│  4. session_annotator.py                                       │
│     └─► Add: LLM-assisted annotation for novel command combos  │
│                                                                 │
│  5. train_neural.py                                            │
│     └─► Integrate: LLM synthetic data + LLM-enriched labels    │
│         Curriculum: cmd → +MITRE → +changes → +triage          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

### 5. What Data the LLM Sees (From Your Raw Logs/Binaries)

| Phase | Data Source | LLM Input |
|-------|-------------|-----------|
| **Training** | `sessions_complete.csv` (78K sessions) | Few-shot: 5 real sessions per class |
| **Training** | `binary_features.csv` (185 binaries) | Triage features → behavior summary |
| **Training** | `merged_binary_features.json` (79-dim) | Deep features → capability description |
| **Runtime (SSH)** | Cowrie tty logs + command stream | Per-command context → fake FS response |
| **Runtime (HTTP)** | Request + app structure | Request context → dynamic HTTP response |
| **Runtime (Binary)** | Static triage (23-dim) | Features → behavior summary for XAI |

---

## Architecture Overview

### Inference Pipeline (Online, CPU-only)

```
Attacker → HTTP:80/SSH:2222 → Guard (FastAPI/asyncssh)
    │
    ├── Safe/Recon → Forward to real service (127.0.0.1:8090)
    ├── Brute-force (SSH/HTTP login) → nftables block IP
    └── Downloader/Exploit/Destructive/APT → Redirect to Decoy
                                                │
                                                ▼
                                    ┌─────────────────────┐
                                    │ Decoy Containers    │
                                    │ • Nginx (HTTP)      │
                                    │ • Cowrie (SSH)      │
                                    └──────────┬──────────┘
                                               │
                                               ▼ (shared volume)
                                    ┌─────────────────────┐
                                    │ Decoy FS Watcher    │
                                    │ runtime/downloads/  │
                                    └──────────┬──────────┘
                                               │
                                               ▼
                                    ┌─────────────────────┐
                                    │ Static Triage       │
                                    │ pyelftools/pefile   │
                                    │ <100ms, cached      │
                                    │ → 23-dim + MITRE    │
                                    └──────────┬──────────┘
                                               │
                                               ▼
                                    ┌─────────────────────┐
                                    │ Unified Model       │
                                    │ [Cmd 256] +         │
                                    │ [MITRE 21] +        │
                                    │ [Changes ~20] +     │
                                    │ [Triage 23]         │
                                    │ → Cross-Attention   │
                                    │ → 6-class Softmax   │
                                    └──────────┬──────────┘
                                               │
                                               ▼
                                    Action Decision
                                    (Safe/Recon→Forward,
                                     Brute→Block,
                                     Others→Decoy)
```

### Training Pipeline (Offline, GPU)

```
Raw Azure VM Logs (63 days, 1.6GB Cowrie, 24 Dionaea, Zeek)
    │
    ▼
Session Correlation → 78,504 sessions (482K total)
    │
    ▼
Binary Deep Analysis (Phases 1-4, 41 binaries)
    ├── Static Triage (195 files) → 23 features
    ├── Ghidra Headless (41) → 23 features
    ├── angr CFGFast (41) → 28 features
    └── Script Analysis (5) → 6 features
    │
    ▼
Feature Merger → 79-dim per SHA256
    │
    ▼
MITRE Annotation → 21-dim per session (76 patterns → 53 techniques)
    │
    ▼
LLM-Enriched Labels (Model + MITRE KB constraints)
    │
    ▼
Training: curriculum learning
    Stage 1: Commands only (78K)
    Stage 2: + MITRE (78K)
    Stage 3: + System changes (47K decoy)
    Stage 4: + Static triage (47K downloads)
    │
    ▼
Production Model: brain_v6_unified.pt (~320-dim input, 6 classes)
```

---

## File Changes Required

### 1. New Files to Create

| File | Purpose | Key Functions |
|------|---------|---------------|
| `src/training/neural/llm_synthetic.py` | LLM synthetic data generator | `generate_synthetic_sessions_llm()`, `parse_llm_session()`, MITRE-constrained prompts |
| `src/agents/binary_triage_runtime.py` | Runtime static triage | `analyze_downloaded_file()`, `run_static_triage()`, SHA256 cache (SQLite) |
| `src/agents/change_encoder.py` | Decoy observation encoder | `encode_file_changes()`, `encode_process_exec()`, `encode_network_conn()`, `encode_user_changes()` → ~20-dim vector |
| `src/training/neural/model.py` | Add `UnifiedThreatClassifier` | 4-path encoder + cross-attention fusion (see model spec below) |

### 2. Existing Files to Modify

| File | Changes |
|------|---------|
| `src/training/neural/train_neural.py` | Curriculum learning (4 stages), LLM synthetic integration, ~320-dim model, progressive unfreezing |
| `src/training/neural/dataset.py` | Support concatenated features (cmd + MITRE + changes + triage), attention masking for missing modalities, random modality dropout |
| `src/training/neural/losses.py` | Cost-sensitive loss (APT=20, Destructive=15, Exploit=10, Downloader=8, Recon=5, Safe=1), auxiliary MITRE tactic prediction loss |
| `src/agents/decision.py` | **MAJOR REWRITE**: Remove 3-stage pipeline; single `classify_unified()` with continuous feature fusion; integrate `binary_triage_runtime` + `change_encoder` |
| `src/interceptor/http_proxy.py` | Remove Destructive/APT → nftables block; only brute-force login → block; all others → decoy redirect |
| `src/interceptor/ssh_proxy.py` | Same: only brute-force threshold → block; all others → decoy redirect |
| `src/interceptor/session_store.py` | Add tables: `binary_cache` (sha256, triage_json, updated_ts), `system_changes` (session_id, change_type, change_json, ts) |
| `src/honeypot/ssh_decoy_builder.py` | Hook shared `runtime/downloads/` watcher; dynamic per-command LLM response; session memory integration |
| `src/honeypot/generator.py` | Hook HTTP file writes into shared `runtime/downloads/` watcher |
| `src/orchestrator/main.py` | Initialize shared downloads watcher; start `binary_triage_runtime` + `change_encoder` |
| `config/settings.yaml` | Add `binary_analysis_runtime`, `change_encoder`, `llm_synthetic` sections |
| `docker/docker-compose.yml` | Add shared volume `runtime/downloads/` for ALL decoys; ensure core watches it |

---

## Unified Model Specification

### Input Dimensions (Concatenated, ~320 total)

| Modality | Dim | Encoder | Availability |
|----------|-----|---------|--------------|
| Command sequence | 256 | BiLSTM(128×2) + Attention | Always (t=0) |
| MITRE tactics | 21 | MitreEncoder (BatchNorm→Dense(64)→ReLU→Dropout→Dense(32)) | Always, updates per cmd |
| System changes | ~20 | ChangeEncoder (Dense(64)→ReLU→Dense(32)) | Accumulates in decoy |
| Static triage | 23 | TriageEncoder (Dense(64)→ReLU→Dense(32)) | When binary appears |

### Architecture

```python
class UnifiedThreatClassifier(nn.Module):
    def __init__(self):
        # Path 1: Commands
        self.cmd_encoder = BiLSTMEncoder(vocab=256, embed=64, hidden=128, layers=2, attention=True)  # → 256
        
        # Path 2: MITRE
        self.mitre_encoder = MitreEncoder(input_dim=21, hidden=64, output=32)  # → 32
        
        # Path 3: System changes (NEW)
        self.changes_encoder = ChangeEncoder(input_dim=20, hidden=64, output=32)  # → 32
        
        # Path 4: Static triage
        self.triage_encoder = TriageEncoder(input_dim=23, hidden=64, output=32)  # → 32
        
        # Cross-attention fusion
        self.cross_attention = MultiheadAttention(embed_dim=352, num_heads=8)  # 256+32+32+32
        
        # Fusion + Classification
        self.fusion = nn.Sequential(
            nn.Linear(352, 128), nn.ReLU(), nn.Dropout(0.3),
            nn.Linear(128, 6)
        )
    
    def forward(self, commands, lengths, mitre, changes, triage, modality_mask):
        # modality_mask: [batch, 4] bool — which modalities present
        cmd_feat = self.cmd_encoder(commands, lengths)           # [B, 256]
        mitre_feat = self.mitre_encoder(mitre)                    # [B, 32]
        changes_feat = self.changes_encoder(changes)              # [B, 32]
        triage_feat = self.triage_encoder(triage)                 # [B, 32]
        
        # Stack and apply cross-attention
        all_feats = torch.stack([cmd_feat, mitre_feat, changes_feat, triage_feat], dim=1)  # [B, 4, dim]
        fused, _ = self.cross_attention(all_feats, all_feats, all_feats, key_padding_mask=~modality_mask)
        fused = fused.mean(dim=1)  # [B, 352]
        
        return self.fusion(fused)
```

### Training Curriculum (Progressive Unfreezing)

| Stage | Samples | Modalities Active | Frozen Encoders | Epochs |
|-------|---------|-------------------|-----------------|--------|
| 1 | 78,504 | Commands only | MITRE, Changes, Triage | 10 |
| 2 | 78,504 | + MITRE | Changes, Triage | 8 |
| 3 | ~47K (decoy) | + Changes | Triage | 8 |
| 4 | ~47K (downloads) | + Triage | None | 10 |

**Loss**: `CombinedLoss(gamma=2.0) + 0.3 * MITRE_Tactic_BCE_Loss`

---

## LLM Synthetic Data Generator (`llm_synthetic.py`)

### Key Components

```python
# Uses existing LLMRouter (Ollama: qwen2.5-coder:7b-instruct-q4_K_M)
# Few-shot from real sessions_complete.csv
# MITRE KB (attack_mapping.py) as HARD CONSTRAINTS

SYSTEM_PROMPT_TEMPLATE = """
You are a red team operator generating realistic attack sessions for cybersecurity training.

TARGET CLASS: {class_name} (id={class_id})
REQUIRED MITRE TACTICS: {tactics_list}
REQUIRED TECHNIQUES: {technique_ids}
FORBIDDEN TACTICS: {forbidden_tactics}

Generate a JSON session with:
{{
  "commands": "semicolon-separated shell commands",
  "system_changes": [
    {{"type": "file_write", "path": "/tmp/x.sh", "size": 1234, "entropy": 6.2}},
    {{"type": "process_exec", "cmdline": "bash /tmp/x.sh", "parent": "sshd"}},
    {{"type": "network_conn", "dst_ip": "192.168.1.100", "dst_port": 4444}},
    {{"type": "user_add", "username": "backdoor", "shell": "/bin/bash"}},
    {{"type": "cron_add", "schedule": "* * * * *", "command": "/tmp/x.sh"}}
  ],
  "mitre_features": {{...21-dim vector matching tactics...}},
  "triage_features": {{...23-dim vector for typical binary...}},
  "label_id": {class_id}
}}

CONSTRAINTS:
- Commands MUST trigger the required MITRE patterns from KB
- System changes MUST be realistic for the attack class
- triage_features MUST match typical binary for this class
- Output ONLY valid JSON
"""

# Validation: Run generated session through annotate_session() + triage simulator
# Reject if MITRE tactics don't match target class
```

### Generation Targets (Fix Class Imbalance)

| Class | Current Real | Current Synthetic | Target Total | LLM Generate |
|-------|-------------|-------------------|--------------|--------------|
| Safe (0) | 5,000 | 0 | 5,000 | 0 |
| Recon (1) | 0 | 11,746 | **12,000** | 12,000 |
| Downloader (2) | 24 | 2 | **5,000** | 4,976 |
| Exploit (3) | 0 | 500 | **8,000** | 8,000 |
| Destructive (4) | 127 | 4,873 | **8,000** | 7,873 |
| APT (5) | 49 | 2,228 | **5,000** | 4,951 |

**Destructive Diversity**: LLM generates 10+ distinct patterns (not just SSH key replacement):
- `rm -rf /var/log/*; shred -u /etc/shadow`
- `dd if=/dev/zero of=/dev/sda bs=1M`
- `openssl enc -aes-256 -in /home -out /home.enc`
- `:(){ :|:& };:` (fork bomb)
- `systemctl stop sshd; iptables -F`

---

## Runtime Static Triage (`binary_triage_runtime.py`)

### Features Extracted (23-dim)

| Feature | Source | Dim |
|---------|--------|-----|
| File type (ELF/PE/script/empty) | magic bytes | 4 (one-hot) |
| Architecture (x86_64, x86, ARM, etc.) | ELF/PE header | 6 (one-hot) |
| Linkage (static/dynamic) | ELF/PE header | 2 (one-hot) |
| Stripped (bool) | symbol table | 1 |
| Packed (UPX/other) | section entropy | 1 |
| Overall entropy | full file | 1 |
| Section count | ELF/PE header | 1 |
| Imported libraries count | dynamic section | 1 |
| Suspicious imports (network, crypto, process, evasion) | import table | 4 |
| Go binary detection | .go.buildinfo, .gopclntab | 1 |
| String indicators (IPs, URLs, mining, shell, paths) | raw strings | 4 |
| MITRE tags from binary | BINARY_TAG_TO_TECHNIQUE | 3 (counts) |

### Cache Schema (SQLite)

```sql
CREATE TABLE binary_cache (
    sha256 TEXT PRIMARY KEY,
    triage_json TEXT NOT NULL,      -- 23-dim features + MITRE tags
    triage_only BOOLEAN DEFAULT 1,  -- 1=triage only, 0=full 79-dim (training only)
    file_size INTEGER,
    file_type TEXT,
    created_ts REAL,
    updated_ts REAL
);

CREATE TABLE system_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    change_type TEXT NOT NULL,      -- file_write, process_exec, network_conn, user_add, cron_add
    change_json TEXT NOT NULL,      -- full change details
    timestamp REAL NOT NULL,
    FOREIGN KEY(session_id) REFERENCES sessions(id)
);
```

### Decoy FS Watcher

```python
# Single watcher on runtime/downloads/ (ALL decoys mount here)
# Uses inotify (asyncio + inotify_simple or watchdog)
# On CREATE/CLOSE_WRITE: compute SHA256 → triage → cache → notify classifier
```

---

## Change Encoder (`change_encoder.py`)

### Input: Decoy Observations → ~20-dim Vector

```python
def encode_session_changes(session_id: str, time_window: int = 300) -> np.ndarray:
    """Query system_changes table for session, encode as fixed vector."""
    changes = query_recent_changes(session_id, time_window)
    
    vec = np.zeros(20, dtype=np.float32)
    
    # File writes (indices 0-5)
    file_writes = [c for c in changes if c['type'] == 'file_write']
    vec[0] = len(file_writes)
    vec[1] = max([c['size'] for c in file_writes], default=0) / 1e6
    vec[2] = max([c['entropy'] for c in file_writes], default=0)
    vec[3] = sum(1 for c in file_writes if 'executable' in c.get('path', ''))
    vec[4] = sum(1 for c in file_writes if any(x in c['path'] for x in ['/etc/', '/root/', '/home/']))
    vec[5] = sum(1 for c in file_writes if c['entropy'] > 7.0)
    
    # Process execution (6-9)
    proc_execs = [c for c in changes if c['type'] == 'process_exec']
    vec[6] = len(proc_execs)
    vec[7] = sum(1 for c in proc_execs if any(x in c['cmdline'] for x in ['wget','curl','bash','sh','python']))
    vec[8] = sum(1 for c in proc_execs if 'sudo' in c['cmdline'] or 'su ' in c['cmdline'])
    vec[9] = sum(1 for c in proc_execs if '/tmp/' in c['cmdline'] or '/var/tmp/' in c['cmdline'])
    
    # Network connections (10-13)
    net_conns = [c for c in changes if c['type'] == 'network_conn']
    vec[10] = len(net_conns)
    vec[11] = len(set(c['dst_ip'] for c in net_conns))
    vec[12] = sum(1 for c in net_conns if c['dst_port'] in [22, 80, 443, 4444, 8080, 6667])
    vec[13] = sum(1 for c in net_conns if is_external_ip(c['dst_ip']))
    
    # User/account changes (14-16)
    user_changes = [c for c in changes if c['type'] in ['user_add', 'ssh_key_add', 'passwd_change']]
    vec[14] = len(user_changes)
    vec[15] = sum(1 for c in user_changes if c['type'] == 'ssh_key_add')
    vec[16] = sum(1 for c in user_changes if 'root' in c.get('username', '') or 'admin' in c.get('username', ''))
    
    # Scheduled tasks (17-19)
    cron_changes = [c for c in changes if c['type'] in ['cron_add', 'systemd_add']]
    vec[17] = len(cron_changes)
    vec[18] = sum(1 for c in cron_changes if '@reboot' in c.get('schedule', ''))
    vec[19] = sum(1 for c in cron_changes if any(x in c.get('command', '') for x in ['wget','curl','bash','sh']))
    
    return vec
```

---

## Configuration (`config/settings.yaml` additions)

```yaml
# Binary analysis at runtime
binary_analysis_runtime:
  enabled: true
  cache_ttl_seconds: 604800          # 7 days
  triage_timeout_ms: 100             # max time for pyelftools/pefile
  cache_db: "./runtime/adaptiveshield.db"  # same as session store
  shared_downloads_dir: "./runtime/downloads"  # ALL decoys mount here

# System change encoding
change_encoder:
  enabled: true
  time_window_seconds: 300           # look back 5 min for changes
  feature_dim: 20

# LLM synthetic data
llm_synthetic:
  enabled: true
  provider: "ollama"
  model: "qwen2.5-coder:7b-instruct-q4_K_M"
  ollama_url: "http://192.168.56.1:11434"
  few_shot_examples: 5
  validation_enabled: true
  target_distribution:
    Safe: 5000
    Recon: 12000
    Downloader: 5000
    Exploit: 8000
    Destructive: 8000
    APT: 5000

# Action policy
decision_policy:
  brute_force_only_block: true
  block_threshold_ssh: 5
  block_threshold_http: 8
  # All other classes → decoy redirect
```

---

## Docker Compose Updates

```yaml
# docker-compose.yml additions
services:
  adaptiveshield:
    volumes:
      - ./runtime:/app/runtime
      - ./runtime/downloads:/app/runtime/downloads  # SHARED downloads dir
    # ... existing config

  # Decoy containers mount shared downloads
  # Cowrie and Nginx decoys get this via DecoyManager volume config
```

**DecoyManager** (`src/agents/deception.py`) already creates per-session dirs. Modify to also bind-mount `runtime/downloads/` into each decoy at `/downloads`.

---

## Training Command

```bash
# From project root on Windows (PowerShell):
$env:PYTHONPATH="src"
.venv\Scripts\python src\training\neural\train_neural.py `
  --epochs 36 `
  --batch-size 64 `
  --lr 1e-3 `
  --model-name brain_v6_unified `
  --use-llm-synthetic `
  --llm-provider ollama `
  --llm-model deepseek-r1:8b`
  --curriculum `
  --output-dir models
```

---

## Verification Checklist

### Unit Tests
- [ ] `test_hybrid.py` passes with unified model
- [ ] MITRE annotator: 76 patterns, 53 techniques, 11 tactics
- [ ] Static triage: <100ms on ELF/PE, 23-dim output
- [ ] Change encoder: produces 20-dim vector from decoy changes
- [ ] LLM synthetic: generates valid JSON, passes MITRE validation
- [ ] Model loads/predicts: `brain_v6_unified.pt` + tokenizer
- [ ] LLM model (deepseek) generates valid synthetic data with MITRE constraints

### Integration Tests
- [ ] `docker compose up -d --build` — full stack healthy
- [ ] `curl http://127.0.0.1/health` — returns model status
- [ ] SQLi payload → decoy redirect (NOT blocked)
- [ ] SSH brute-force (5 attempts) → nftables block
- [ ] HTTP brute-force (8 attempts) → nftables block
- [ ] Downloader/Exploit/Destructive/APT → decoy redirect
- [ ] Payload download in decoy → triage runs → classification updated
- [ ] System changes in decoy → change encoder → model updates
- [ ] Repeated payload (same SHA256) → cache hit → instant

### End-to-End Scenarios
- [ ] External: HTTP exploit → decoy → SSH brute-force → block
- [ ] External: Exploit drops binary → triage enriches → decoy engagement continues
- [ ] Attacker makes changes (useradd, cron, file write) → encoder captures → model updates
- [ ] Repeated payload → cache hit → instant classification
- [ ] LLM synthetic data passes validation → used in training

---

## Dependencies to Install

```bash
# Python (already in requirements.txt)
pip install pyelftools pefile inotify-simple  # for triage + FS watcher

# Ollama (system)
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &
ollama pull deepseek-r1:8b #installed on the windows host 

# Verify
curl -X POST http://192.168.56.1:11434/api/generate -d '{"model":"deepseek-r1:8b","prompt":"test","stream":false}'
```

---

## Execution Order

1. **Setup Ollama + model** (if not done)
2. **Merge `xai-dashboard` → `train`** (Insider + XAI + Dashboard)
3. **Create new modules**: `llm_synthetic.py`, `binary_triage_runtime.py`, `change_encoder.py`
4. **Modify core files**: `train_neural.py`, `dataset.py`, `losses.py`, `model.py`, `decision.py`
5. **Modify interceptors**: `http_proxy.py`, `ssh_proxy.py`, `session_store.py`
6. **Modify decoy integration**: `ssh_decoy_builder.py`, `generator.py`, `orchestrator/main.py`
7. **Update config**: `settings.yaml`, `docker-compose.yml`
8. **Run training**: `train_neural.py` with curriculum + LLM synthetic
9. **Test integration**: Docker Compose + verification checklist

---

## Key References in Codebase

| Component | File |
|-----------|------|
| MITRE KB (76 patterns, 53 techniques) | `src/core/mitre/attack_mapping.py` |
| Session annotation (21-dim) | `src/core/mitre/session_annotator.py` |
| Static triage (Phase 1) | `src/core/malware/static_analyzer.py` |
| Ghidra extraction | `src/core/malware/ghidra_extract.py` |
| angr analysis | `src/core/malware/symbolic.py` |
| Feature merger (79-dim) | `src/core/malware/feature_merger.py` |
| Portable export | `src/export_portable_dataset.py` |
| Semantic labeling | `src/training/neural/semantic_labels.py` |
| Current synthetic | `src/training/neural/synthetic.py` |
| Model architectures | `src/training/neural/model.py` |
| Training entry | `src/training/neural/train_neural.py` |
| HTTP Guard | `src/interceptor/http_proxy.py` |
| SSH Guard | `src/interceptor/ssh_proxy.py` |
| Session store | `src/interceptor/session_store.py` |
| Decoy manager | `src/agents/deception.py` |
| SSH decoy builder | `src/honeypot/ssh_decoy_builder.py` |
| HTTP decoy generator | `src/honeypot/generator.py` |
| LLM router (Ollama/Gemini) | `src/honeypot/router.py` | (uses deepseek-coder:6.7b-instruct-q4_K_M)
| Orchestrator | `src/orchestrator/main.py` |

---

## Notes for Context-Free Execution

- All paths are relative to `/home/me/data/AdaptiveShield/`
- Python commands need `PYTHONPATH=src` (or `src` in sys.path)
- Virtual environment at `.venv/` — use `.venv/bin/python` (Linux) or `.venv\Scripts\python` (Windows)
- Ollama runs on `http://192.168.56.1:11434` with model `deepseek-r1:8b`
- MITRE KB in `attack_mapping.py` is the ground truth for tactics/techniques
- Existing neural models in `models/` — new model will be `brain_v6_unified.pt`
- Database at `runtime/adaptiveshield.db` (SQLite WAL mode)

---

**End of Plan** — This file contains all information needed to implement the unified model architecture without external context.