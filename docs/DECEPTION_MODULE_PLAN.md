# AdaptiveShield — Threat-Conditioned Generative Cyber Deception Engine

> **Target Venues**: IEEE Symposium on Security and Privacy (S&P) / ACM Conference on Computer and Communications Security (CCS) / USENIX Security Symposium / RAID / ACSAC  
> **Status**: Implementation Plan v4 (Generative Deception Architecture — Zero ML Training Requirement)  
> **Core Foundation**: Integrates Operational 94.64% Acc Neural Gateway Classifier + 98.06% Acc MOTIF Binary Distiller (<11ms SLA) + Calibrated Insider Detector + Dual-Perimeter Topology  

---

## 1. Executive Summary & Paradigm Shift

### 1.1 The Problem with Existing Honeypot Approaches
1. **Static Honeypots (Dionaea, Cowrie out-of-the-box)**: Trivial for automated tools and human attackers to fingerprint within 1–2 requests due to rigid response templates and predictable filesystem states.
2. **Naive LLM Honeypots (Galah-style single prompt)**: Prone to hallucinating inconsistent system state between HTTP requests, breaking protocol contracts, generating blank/generic responses, or stalling proxy traffic when external LLM APIs experience latency spikes.
3. **Reinforcement Learning (RL) Honeypots**: Require tens of thousands of simulated training episodes against hand-crafted synthetic attacker models that rarely match real-world adversary behavior, suffer from reward hacking, and require extensive ML training infrastructure.

### 1.2 The AdaptiveShield Solution: Generative Orchestration Layer
AdaptiveShield eliminates the need for RL training by introducing an **Autonomous Threat-Conditioned Generative Deception Layer** directly driven by the system's *already-trained* multi-modal neural and threat intelligence engines:

```
[ Incoming Adversary Traffic ]
              │
              ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. Multi-Modal Threat Assessment (Already Operational)      │
│  • 4-Modality Neural Classifier (Intent & 21-d MITRE, 94.6%)│
│  • MOTIF Binary Triage Distiller (PE Malware, 98.1%, 10.8ms)│
│  • CERT-Calibrated Insider Threat Engine (ROC-AUC 0.9902)   │
└──────────────────────────────┬──────────────────────────────┘
                               │ Structured Threat Context
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Strategic Deception Orchestrator (Rules & State Machine) │
│  • Adversary Trajectory & Session Memory (Turns, MITRE flow)│
│  • Tactical Deception Objective Selection (9 Tactics)       │
│  • Cryptographic Canary & Honeytoken Seeding (Attribution)   │
└──────────────────────────────┬──────────────────────────────┘
                               │ Contextualized Deception Prompt
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Provider-Agnostic LLM Engine (Zero-Stall Guarantee)      │
│  • Gemini / OpenAI / Local Ollama (vLLM / LiteLLM)          │
│  • Strict 2.0s Connect Timeout + Instant Mock Fallback (<5ms│
└──────────────────────────────┬──────────────────────────────┘
                               │ Synthesized Decoy Content
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Decoy Environment Mutator & Sandboxed Delivery           │
│  • Live Docker Nginx Filesystem & Config Reload             │
│  • Reactive File Mutation via watcher.py (Binary droppers)  │
│  • Cowrie SSH Decoy Synchronizer                            │
└─────────────────────────────────────────────────────────────┘
```

This design combines the best of cybersecurity systems engineering with generative AI:
- **No ML/RL training**: The LLM provides the generative creativity; deterministic cybersecurity heuristics provide tactical governance and state coherence.
- **Full context integration**: Real-time classifications (intent, MITRE ATT&CK techniques, binary PE triage, insider risk) directly shape the decoy persona and response strategy.
- **Dynamic attribution**: Cryptographically generated canary honeytokens (AWS credentials, JWTs, database tokens) enable high-confidence breach detection and exfiltration attribution.
- **Production reliability**: Strict bounded timeouts and deterministic mock fallbacks ensure the proxy never stalls incoming traffic.

---

## 2. Scientific & System Architecture

```mermaid
flowchart TD
    subgraph GatewayLayer["Dual-Perimeter Interception"]
        ExtProxy["External HTTP Interceptor (:8000)"]
        IntProxy["Internal HTTP Interceptor (:8001)"]
        SSHProxy["SSH Honeypot Interceptor (:2222)"]
    end

    subgraph ThreatIntelligenceLayer["Trained Multi-Modal Classifiers (Operational)"]
        Neural["4-Modality UnifiedClassifier\n94.64% Acc | 722k Params"]
        Distiller["MOTIF Binary Distiller\n98.06% Acc | 10.8ms SLA"]
        Insider["CERT Insider Engine\n0.9902 ROC-AUC"]
    end

    subgraph DeceptionOrchestrationLayer["NEW: Generative Deception Orchestrator"]
        Tracker["Session State Machine & Memory\n(Interaction Depth, Tactics History)"]
        Canary["Cryptographic Honeytoken Generator\n(AWS Keys, DB Creds, Canary Files)"]
        Director["Tactical Deception Director\n(Selects 1 of 9 Deception Tactics)"]
        Composer["Context-Rich Prompt Composer\n(Target App + Threat Telemetry + Tactic)"]
    end

    subgraph LLMBackend["Provider-Agnostic LLM Engine"]
        Router["GenericLLMClient / Router\nBounded Connect Timeout: min(2.0s, timeout)"]
        Gemini["Gemini API"]
        OpenAI["OpenAI API"]
        Ollama["Local Ollama"]
        MockFallback["Deterministic Mock Fallback\n(<5ms SLA, Authentic Error Traces)"]
    end

    subgraph MutationLayer["Dynamic Decoy Fleet Mutator"]
        Nginx["Docker Nginx Decoys\n(Live Filesystem & Conf Reload)"]
        Watcher["Reactive Binary Watcher\n(Decoy File Mutation on Dropper)"]
        Cowrie["Cowrie SSH Sandbox"]
    end

    GatewayLayer --> ThreatIntelligenceLayer
    ThreatIntelligenceLayer --> DeceptionOrchestrationLayer
    Tracker <--> Director
    Canary --> Director
    Director --> Composer
    Composer --> Router
    Router --> Gemini
    Router --> OpenAI
    Router --> Ollama
    Router --> MockFallback
    Router --> MutationLayer
    Watcher --> MutationLayer
    MutationLayer --> Nginx
    MutationLayer --> Cowrie
```

---

## 3. The 9 Strategic Deception Tactics

The Tactical Deception Director selects an explicit deception objective conditioned on the adversary's intent classification, MITRE ATT&CK techniques, binary triage status, and interaction history:

| Tactic ID | Tactical Objective | Threat Condition Trigger | Operational Behavior & LLM Task |
|---|---|---|---|
| **`T01_CLONE_MASQUERADE`** | Authentic Application Mimicry | `Safe` or initial `Recon` | Serves exact cloned HTML structure matching target application theme. Zero obvious vulnerabilities exposed to preserve normal appearance. |
| **`T02_SYNTHETIC_VULN`** | Progressive Exploit Simulation | `Exploit` (SQLi, XSS, Path Traversal, CMDi) | Synthesizes realistic, target-matched error traces: MariaDB syntax errors, Linux `/etc/passwd` slices, or reflected payloads. Convinces attacker exploit worked. |
| **`T03_CANARY_SEEDING`** | High-Value Credential Baiting | `Recon` on configs / `Exploit` on database / `ADVANCED_APT` | Injects cryptographically signed canary tokens (e.g. `AKIA_CANARY_...`, fake DB credentials, staging API tokens) into HTTP headers or DOM comments. |
| **`T04_DEPTH_ESCALATION`** | Administrative Access Luring | Persistent attacker with multiple successful probes | Serves realistic administrative consoles, developer staging portals, or internal debug dashboards complete with form inputs. |
| **`T05_ADAPTIVE_TARPIT`** | Automated Scanner Resource Drain | `Scanner` or rapid repetitive requests | Injects controlled micro-latencies ($\Delta \tau \in [250\text{ms}, 1500\text{ms}]$) simulating database locking or high server load to stall automated crawlers. |
| **`T06_BREADCRUMB_TRAIL`** | Subnet Steering & Lateral Luring | `ADVANCED_APT` or lateral movement indicators | Injects subtle hints (fake internal IP addresses, `/dev-api/internal/`, git backup references) steering adversary into isolated Cowrie SSH sandboxes. |
| **`T07_TRANSIENT_FAULT`** | Scanner Resilience Probing | Scanner or burst exploitation attempts | Emits authentic HTTP 500/503 errors or gateway connection resets to probe whether the adversary's automated tooling adapts or aborts. |
| **`T08_BINARY_MUTATION`** | In-Flight Malware Containment | `Downloader` or PE upload detected by MOTIF | Signals `watcher.py` to mutate the decoy file tree, creating the exact registry keys, directories, or processes the uploaded dropper expects to find. |
| **`T09_INSIDER_SANDBOX`** | Silent Enterprise Containment | `is_internal=True` with high insider anomaly score | Serves a watermarked internal intranet view with tracked decoy documents, containing insider reconnaissance without triggering employee suspicion. |

---

## 4. Cryptographic Canary & Honeytoken Engine

To support scientific evaluation and high-confidence breach attribution, the deception layer includes a deterministic, cryptographically signed canary token generator:

### 4.1 Supported Canary Token Types
1. **AWS Access Key ID & Secret**: Formatted as `AKIA[20_CHAR_SIGNATURE]`, verifiable via HMAC-SHA256 signature against an internal secret key.
2. **Database Connection Strings**: E.g., `postgresql://db_audit_canary:TOKEN@staging-db.internal:5432/corp_prod`.
3. **API Bearer Tokens / JWTs**: Signed tokens containing embedded session metadata and generation timestamp.
4. **Decoy Corporate Documents**: Fake PDF/DOCX or CSV files containing watermarked tracking strings (`ADSHIELD-CANARY-<UUID>`).

### 4.2 Canary Verification & Provenance
When any seeded canary token is submitted back to the proxy in a subsequent request, query parameter, or SSH login, the system:
1. Instantly verifies the cryptographic signature (confirming it originated from AdaptiveShield).
2. Correlates the token with the original attacker session ID, timestamp, and IP address.
3. Elevates the session classification immediately to `ADVANCED_APT` with maximum monitoring logging.

---

## 5. Adversary Session State Machine & Memory

Unlike single-turn LLM honeypots that forget past interactions, AdaptiveShield maintains a stateful adversary profile per session:

```python
class AdversarySessionProfile:
    session_id: str
    client_ip: str
    interaction_turns: int
    first_seen: float
    last_seen: float
    
    # Cumulative Intelligence
    detected_intents: List[str]
    mitre_techniques_observed: Set[str]
    seeded_honeytokens: Dict[str, str]        # token_id -> token_value
    compromised_honeytokens: List[str]
    exposed_vulnerabilities: List[str]
    submitted_credentials: List[Dict[str, str]]
    dropped_binaries: List[str]
    
    # Current Tactical Posture
    current_tactic: DeceptionTactic
    interaction_depth: int                     # 0 (public) -> 3 (deep admin)
    persistence_score: float                   # Engagement metric
```

This persistent state is passed directly into the LLM prompt context, ensuring that:
- If an attacker previously tried password `admin123` and was rejected, the LLM remembers.
- If an attacker previously retrieved a dumped database row with user ID 1, subsequent queries for user ID 2 remain schema-consistent.
- If an attacker uploads a secondary payload, the system connects it to the initial dropper session.

---

## 6. Zero-Stall LLM Generation & Decoy Mutator

### 6.1 Bounded Connect Timeout Guarantee
- Connect Timeout: $\tau_{\text{connect}} = \min(2.0\text{s}, \tau_{\text{timeout}})$
- Read Timeout: $\tau_{\text{read}} = \tau_{\text{timeout}}$
- If the upstream LLM API takes longer than 2.0s to establish a connection or returns an error, the proxy **never blocks**. It immediately trips `MockLLMClient`, which synthesizes high-fidelity MariaDB errors, Apache stack traces, or Linux file responses in $<5$ms.

### 6.2 Decoy Filesystem Mutation (Docker Nginx + watcher.py)
When the LLM produces response payloads or file specifications:
1. **Path Sanitization**: `sanitize_and_validate_decoy_path` strictly prevents directory traversal (`../`), null-byte injection, and symlink escapes.
2. **File Size Limits**: Hard-capped at 100 KB per synthesized file to prevent resource exhaustion.
3. **Atomic Nginx Write**: Files are written into the shared Docker volume mount (`/usr/share/nginx/html`), `metadata.json` is updated, and `nginx -s reload` is executed inside the container without terminating active TCP connections.
4. **Watcher Coordination**: When the MOTIF binary distiller flags a dropped executable, `watcher.py` triggers `T08_BINARY_MUTATION` to seed fake target files in the Cowrie or Docker environment.

---

## 7. Target File Structure & Module Decomposition

```
src/deception/                                  # Autonomous Generative Deception Module
├── __init__.py                                 # Clean public exports
├── tactics.py                                  # Enum: 9 Strategic Deception Tactics & trigger rules
├── canary.py                                   # Cryptographic Canary Token Generator & Verifier
├── session_tracker.py                          # Stateful Adversary Session Machine & Memory
├── orchestrator.py                             # Tactical Deception Director & Prompt Composer
├── mutator.py                                  # Live Decoy Environment Mutator (Docker + Nginx + Watcher)
└── benchmark/                                  # Scientific Evaluation Harness
    ├── __init__.py
    ├── scenarios.py                            # 5 Real-World Attack Scenarios (SQLi, Dropper, Insider, etc.)
    └── run_deception_eval.py                   # Automated benchmark comparing AdaptiveShield vs Baselines
```

### Clean Integration Points
- [`src/honeypot/generator.py`](file:///home/me/data/AdaptiveShield/src/honeypot/generator.py): Upgrade `HoneypotGenerator` to delegate tactic selection and state management to `DeceptionOrchestrator`.
- [`src/honeypot/prompt_builder.py`](file:///home/me/data/AdaptiveShield/src/honeypot/prompt_builder.py): Refactor prompt templates to inject structured tactical instructions and adversary memory.
- [`src/core/triage/watcher.py`](file:///home/me/data/AdaptiveShield/src/core/triage/watcher.py): Wire in-flight malware notifications to `T08_BINARY_MUTATION`.
- [`config/settings.yaml`](file:///home/me/data/AdaptiveShield/config/settings.yaml): Add configuration section for deception tactics, canary secrets, and tarpitting limits.

---

## 8. Scientific Evaluation Plan for Top-Tier Publication

To demonstrate publication-quality results for IEEE S&P / ACM CCS / USENIX Security, the deception module will be evaluated across four quantitative dimensions:

### 8.1 Evaluated Baselines
1. **Static Cowrie / Dionaea**: Standard open-source honeypots without dynamic response generation.
2. **Naive Single-Prompt LLM (Galah Baseline)**: LLM honeypot responding to isolated requests without threat-awareness or session memory.
3. **AdaptiveShield (Ours)**: Threat-conditioned orchestration + canary seeding + session state machine + decoy mutation.

### 8.2 Evaluation Metrics
- **Adversary Dwell Time ($T_{\text{dwell}}$)**: Cumulative seconds an adversary spends probing the decoy environment before abandoning.
- **Threat Intelligence Yield ($I_{\text{yield}}$)**: Number of distinct MITRE ATT&CK techniques, payloads, and credentials extracted per session.
- **Honeytoken Exfiltration & Attribution Rate ($P_{\text{canary}}$)**: Percentage of sessions where seeded canary credentials are leaked or exercised.
- **Deception Indistinguishability / Fingerprinting Resistance**: Automated probe resistance against common honeypot detection tools (Nmap honeypot scripts, honeybadger heuristics).
- **Runtime Processing Overhead**: Latency introduced by orchestration (<15ms) and overall HTTP response SLA.

---

## 9. Implementation Roadmap & Execution Sprints

- [ ] **Sprint 1: Core Deception Engine (`src/deception/`)**
  - Implement `tactics.py` (9 deception tactics, selection heuristics conditioned on classifiers).
  - Implement `canary.py` (cryptographic HMAC-SHA256 canary generator and validator).
  - Implement `session_tracker.py` (stateful adversary profile, turn tracking, intelligence accumulation).
  - Unit tests: `tests/unit/test_deception_core.py`.

- [ ] **Sprint 2: Strategic Orchestrator & Dynamic Mutation**
  - Implement `orchestrator.py` (tactical prompt composer integrating intent, MITRE, binary triage, and insider signals).
  - Implement `mutator.py` (sandboxed decoy file generator, Docker Nginx config reloader, watcher integration).
  - Upgrade `src/honeypot/generator.py` and `src/honeypot/prompt_builder.py` to seamlessly utilize the orchestrator.
  - Unit tests: `tests/unit/test_deception_orchestrator.py`.

- [ ] **Sprint 3: End-to-End Pipeline Integration**
  - Wire external/internal guard proxies to forward full threat context into `DeceptionOrchestrator`.
  - Connect `watcher.py` binary detection to trigger reactive decoy filesystem mutation (`T08`).
  - Integration tests: `tests/integration/test_generative_deception_pipeline.py`.

- [ ] **Sprint 4: Scientific Benchmark & Publication Results**
  - Implement `src/deception/benchmark/run_deception_eval.py` executing 5 attack scenarios (Recon, SQLi exploit, Malware drop, Scanner flood, Insider probe).
  - Generate comparative performance tables (Dwell Time, Intel Yield, Canary Attribution Rate, Latency SLA).
  - Document findings in `docs/DECEPTION_MODULE_RESULTS.md`.
