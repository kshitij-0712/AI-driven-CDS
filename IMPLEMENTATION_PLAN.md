# AdaptiveShield Implementation Plan — Complete Self-Contained Guide

**Project**: AdaptiveShield — Multi-Agent Cyber Deception Platform  
**Branch**: `train` (base)  
**Target**: Unified neural model replacing 3-stage pipeline (Regex → Neural → MITRE fallback)  
**Runtime**: Docker Compose, CPU-only inference, RTX 3050 (5GB) for training  
**LLM**: `qwen2.5-coder:7b-instruct-q4_K_M` via Ollama at `http://192.168.56.1:11434`

---

## Executive Summary

Replace the current 3-stage classification pipeline with a **single unified neural model** that fuses:
1. **Command sequence** (BiLSTM, 256-dim)
2. **MITRE tactics** (21-dim, real-time regex annotator)
3. **System changes** (~20-dim, decoy observation encoder)
4. **Static triage** (14-dim: 12 static + ghidra_score + angr_score via Knowledge Distillation)

**Training**: Ghidra/angr deep analysis enriches labels OFFLINE only — model internalizes deep binary understanding via Knowledge Distillation (KD). Runtime uses ONLY fast static triage.

**Action Policy**: Only brute-force → nftables block. All other threats → decoy redirect (engage & learn).

**Synthetic Data**: LLM-generated via `/api/chat` with conversational retries. MITRE validation uses **soft preferred-techniques scoring** (not strict required), with **forbidden tactics as hard blockers**.

---

## Current State Summary (as of 2026-09-11)

### ✅ Completed
1. **Ollama + Qwen model** — configured at `192.168.56.1:11434`
2. **New modules built**:
   - `llm_synthetic.py` — LLM synthetic data generator with `/api/chat`, conversational retries, soft validation
   - `binary_triage_runtime.py` — 12 static triage features
   - `change_encoder.py` — 20-dim change features
   - `llm_client.py` — `OllamaClient` with both `generate_response()` and `chat_response()`
   - `router.py` — `LLMRouter` with `generate()` and `chat()` methods
3. **Core neural architecture rewritten**:
   - `dataset.py` — 4-modality unified `ThreatDataset`, auto-loads `synthetic_batches.csv` + `active_learning_edges.csv`
   - `model.py` — `UnifiedThreatClassifier` with `TriageEncoder(input_dim=14)`
   - `trainer.py` — extracts and passes `mitre, changes, triage, modality_mask`
   - `train_neural.py` — `model_type='unified'`, LLM Active Learning loop
   - `decision.py` — loads `UnifiedThreatClassifier`, passes 4 modalities for inference

### 🔄 In Progress
4. **Batched synthetic data generation** — run class-by-class on host machine

### ⬜ Not Started
5. Modify runtime interceptors
6. Modify decoy integration
7. Final integration test

---

## Execution Order (Full Pipeline)

### Step 4: Batched Synthetic Data Generation (CURRENT)

Generate 43,000 sessions across 6 classes using the LLM. Run class-by-class on host:

```bash
PYTHONPATH=src python3 src/training/neural/llm_synthetic.py --class_id 0
PYTHONPATH=src python3 src/training/neural/llm_synthetic.py --class_id 1
PYTHONPATH=src python3 src/training/neural/llm_synthetic.py --class_id 2
PYTHONPATH=src python3 src/training/neural/llm_synthetic.py --class_id 3
PYTHONPATH=src python3 src/training/neural/llm_synthetic.py --class_id 4
PYTHONPATH=src python3 src/training/neural/llm_synthetic.py --class_id 5
```

**Output**: `data/exports/synthetic_batches.csv` (appended per run)

| Class | Name | Count | Est. Time |
|-------|------|-------|-----------|
| 0 | Safe | 5,000 | ~1 day |
| 1 | Recon | 12,000 | ~2 days |
| 2 | Downloader | 5,000 | ~1 day |
| 3 | Exploit | 8,000 | ~1.5 days |
| 4 | Destructive | 8,000 | ~1.5 days |
| 5 | ADVANCED_APT | 5,000 | ~1 day |
| **Total** | | **43,000** | **~7 days** |

**Validation Strategy (Soft)**:
- `forbidden_tactics` → HARD block (instant fail)
- `target_tactics` → at least 1 must fire
- `preferred_techniques` → ratio-based threshold (`min_preferred_ratio`: 25-30%)
- If validation fails on attempt 1, errors sent back via `/api/chat` for conversational correction
- If validation fails on final attempt, session is **accepted anyway** (no template fallback)

### Step 4b: Binary Training Data Integration

Synthetic sessions include **Knowledge Distillation (KD) targets** for binary analysis:
- `triage_ghidra_score` and `triage_angr_score` generated per `binary_type`
- Stored in triage features (14-dim: 12 static + 2 KD scores)
- `deep_analysis` tensor (2-dim) is a separate KD target in `dataset.py`

**How binary training works**:
1. `build_triage_features_from_binary_type()` creates realistic Ghidra/angr scores per binary_type
2. `TriageEncoder` learns to correlate static features with KD scores
3. Runtime uses only fast static triage — no Ghidra/angr needed

| binary_type | ghidra_score | angr_score |
|---|---|---|
| miner | 0.5-0.7 | 0.4-0.6 |
| rat | 0.7-0.9 | 0.6-0.85 |
| credential_stealer | 0.6-0.85 | 0.5-0.7 |
| c2 | 0.65-0.85 | 0.55-0.75 |
| packed | 0.8-0.95 | 0.7-0.9 |
| go_binary | 0.3-0.5 | 0.2-0.4 |
| multi_capability | 0.75-0.95 | 0.65-0.85 |
| none | 0.0 | 0.0 |

### Step 5: Run Neural Training

```bash
PYTHONPATH=src python3 src/training/neural/train_neural.py
```

**What it does**:
1. Loads `sessions_complete.csv` (78K) + `synthetic_batches.csv` (43K) + `active_learning_edges.csv`
2. Missing modalities zero-padded with `modality_mask` bits
3. Trains `UnifiedThreatClassifier` with 4-modality fusion
4. Runs LLM Active Learning post-training:
   - `llm_review_misclassifications()` — explains failures
   - `llm_generate_edge_cases()` — adversarial examples for weak classes
   - Saves to `active_learning_edges.csv`
5. Saves `models/brain_v6_unified.pt`

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

1. **`http_proxy.py`**: Feed HTTP requests → unified model. After binary download, re-classify with triage. Accumulate system changes.
2. **`ssh_proxy.py`**: Feed SSH commands → unified model. Update change vector after each command, re-run model.
3. **`session_store.py`**: Add `binary_cache` + `system_changes` tables for progressive feature accumulation.

**Action mapping** (changed from old model):

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

```
Model Output → Deception Agent Flow:

UnifiedThreatClassifier.predict()
    ├── predictions: [class_id]   → action routing
    ├── probabilities: [6-dist]   → decoy adapts engagement style
    ▼
decision.py → {"label": "Exploit", "confidence": 0.87, "action": "redirect_to_decoy",
                "neural_probs": {"Safe": 0.02, ..., "Exploit": 0.87, ...}}
    ▼
Deception Agent:
    - Reads "label" → base template
    - Reads "neural_probs" → adaptive behavior
    - Reads "mitre_tactics" → contextual responses
    - Re-classifies per interaction → real-time adaptation
```

### Step 8: Final Integration Test

```bash
docker compose up -d --build
curl http://127.0.0.1/health
# Test: SQLi → decoy redirect (NOT blocked)
# Test: SSH brute-force (5 attempts) → nftables block
# Test: Exploit drops binary → triage → classification updated
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
| Decision Agent | `src/agents/decision.py` |
| Binary Triage | `src/agents/binary_triage_runtime.py` |
| Change Encoder | `src/agents/change_encoder.py` |
| HTTP Guard | `src/interceptor/http_proxy.py` |
| SSH Guard | `src/interceptor/ssh_proxy.py` |
| SSH Decoy Builder | `src/honeypot/ssh_decoy_builder.py` |
| HTTP Decoy Generator | `src/honeypot/generator.py` |
| Orchestrator | `src/orchestrator/main.py` |

---

**End of Plan**