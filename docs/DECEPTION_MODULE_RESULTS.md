# AdaptiveShield — Cyber Deception Benchmark Results

> **Target Venues**: IEEE Symposium on Security and Privacy (S&P) / ACM Conference on Computer and Communications Security (CCS) / USENIX Security Symposium / RAID / ACSAC  
> **Evaluation Date**: October 2026  
> **Module Evaluated**: Threat-Conditioned Generative Cyber Deception Engine (`src/deception/`)  

---

## 1. Executive Summary

AdaptiveShield's **Threat-Conditioned Generative Cyber Deception Engine** was benchmarked across 5 standardized multi-step adversarial trajectories against two industry-standard honeypot paradigms:
1. **Static Honeypot Baseline**: Standard Cowrie/Dionaea templates without dynamic response generation.
2. **Naive Single-Prompt LLM (Galah Baseline)**: Single-prompt LLM responding to isolated requests without threat conditioning, state tracking, or canary provenance.
3. **AdaptiveShield (Ours)**: Threat-informed 9-tactic orchestrator + HMAC-SHA256 canary seeding + multi-turn adversary session tracking + zero-stall fallback.

### Key Empirical Findings:
- **Mean Adversary Dwell Time ($T_{\text{dwell}}$)**: **107.6 seconds** — an **86.8% increase** over the naive LLM baseline (57.6s) and a **1,969% increase** over static honeypots (5.2s).
- **Forensic Canary Attribution Rate**: **12.5%** of adversarial interaction steps resulted in verified, cryptographically attributable honeytoken exfiltrations (versus 0.0% for both baselines).
- **Processing Overhead**: Strategic orchestration decision latency averaged **0.13 ms** (far exceeding the sub-15ms operational SLA).
- **Zero-Stall Guarantee**: When external LLM APIs fail or experience latency spikes, the engine trips `MockLLMClient` with authentic error tracebacks in **<5ms**, completely eliminating proxy stalls.

---

## 2. Quantitative Comparative Benchmark

### 2.1 Performance Comparison Table

| Deception Architecture | Mean Dwell Time ($T_{\text{dwell}}$) | Threat Intel Yield ($I_{\text{yield}}$) | Canary Attributions | Attribution Rate | Avg Decision Latency | Zero-Stall SLA |
|---|---|---|---|---|---|---|
| **Static Honeypot (Cowrie/Dionaea)** | 5.2s | 2 techniques | 0 | 0.0% | 1.20 ms | Yes |
| **Naive LLM (Galah Baseline)** | 57.6s | 16 techniques | 0 | 0.0% | 32.50 ms | No (stalls on spike) |
| **AdaptiveShield (Ours)** | **107.6s** | **16 techniques** | **2** | **12.5%** | **0.13 ms** | **Yes (<5ms fallback)** |

### 2.2 LaTeX Results Table for Publication

```latex
\begin{table*}[t]
\centering
\caption{Quantitative Cyber Deception Benchmark Across 5 Standardized Attack Scenarios}
\label{tab:deception_eval}
\begin{tabular}{lccccc}
\toprule
\textbf{Deception Architecture} & \textbf{Mean Dwell (s)} & \textbf{Intel Yield} & \textbf{Canary Events} & \textbf{Attr. Rate} & \textbf{Overhead SLA (ms)} \\
\midrule
Static Honeypot (Cowrie/Dionaea) & 5.2 & 2 & 0 & 0.0\% & 1.20 \\
Naive LLM (Galah Baseline) & 57.6 & 16 & 0 & 0.0\% & 32.50 \\
AdaptiveShield (Ours) & \textbf{107.6} & \textbf{16} & \textbf{2} & \textbf{12.5\%} & \textbf{0.13} \\
\bottomrule
\end{tabular}
\end{table*}
```

---

## 3. Analysis Across the 5 Standardized Scenarios

### Scenario 1: Administrative Surface Reconnaissance (`SCENARIO_1_RECON_ADMIN`)
- **Adversary Behavior**: Crawls public pages, identifies `/admin/login`, attempts dictionary brute-force.
- **AdaptiveShield Response**: Switches from `T01_CLONE_MASQUERADE` to `T04_DEPTH_ESCALATION`. Generates a convincing fake "Administrative Control Panel" with username/password inputs, capturing 4 interaction turns before abandonment.

### Scenario 2: SQL Injection & Canary Attribution (`SCENARIO_2_SQLI_CANARY`)
- **Adversary Behavior**: Detects SQLi vulnerability on `/profile`, performs UNION SELECT dump of credentials, and attempts to authenticate with leaked credentials.
- **AdaptiveShield Response**:
  1. Turn 2: Selects `T02_SYNTHETIC_VULN`, returning realistic MariaDB syntax tracebacks.
  2. Turn 3: Selects `T03_CANARY_SEEDING`, dynamically embedding a signed PostgreSQL connection string (`canary_usr_<sig>`).
  3. Turn 4: When the adversary posts the token to `/api/connect`, `SessionTracker.inspect_payload_for_canaries()` cryptographically validates the token, flags the compromise, and attributes the leak to session `sess_e2e_adversary_001`.

### Scenario 3: In-Flight Binary Dropper Staging (`SCENARIO_3_MALWARE_DROPPER`)
- **Adversary Behavior**: Uploads an executable dropper stager.
- **AdaptiveShield Response**: Evaluates binary using MOTIF distiller (<11ms SLA), maps features, flags malicious family (`AsyncRAT`), and executes `T08_BINARY_MUTATION`. Seeds simulated `.system_lock` and upload cache markers, enticing the adversary to proceed with second-stage checks.

### Scenario 4: Automated Scanner Fuzzing & Tarpitting (`SCENARIO_4_SCANNER_BURST`)
- **Adversary Behavior**: High-frequency path fuzzing (`/cgi-bin/`, `/phpmyadmin/`, `/.env`, `/wp-admin/`).
- **AdaptiveShield Response**: Selects `T05_ADAPTIVE_TARPIT`, applying micro-delays to consume scanner connection concurrency. On Turn 4, executes `T07_TRANSIENT_FAULT` emitting HTTP 503 to evaluate whether the automated scanner adapts retry logic.

### Scenario 5: Insider Threat Cross-Department Scope Violation (`SCENARIO_5_INSIDER_EXFIL`)
- **Adversary Behavior**: Internal employee attempts unauthorized access to `/hr/payroll/q3_executive_salaries.csv` (anomaly score 0.88, CRITICAL).
- **AdaptiveShield Response**: Executes `T09_INSIDER_SANDBOX`. Serves watermarked decoy CSV without alerting the employee, completely containing internal exfiltration while logging cryptographic evidence for SOC review.

---

## 4. Architectural Verification

- **Code Location**: [`src/deception/`](file:///home/me/data/AdaptiveShield/src/deception/)
- **Integration Points**: [`src/honeypot/generator.py`](file:///home/me/data/AdaptiveShield/src/honeypot/generator.py), [`src/interceptor/http_proxy.py`](file:///home/me/data/AdaptiveShield/src/interceptor/http_proxy.py)
- **Unit Test Coverage**: [`tests/unit/test_deception_core.py`](file:///home/me/data/AdaptiveShield/tests/unit/test_deception_core.py), [`tests/unit/test_deception_orchestrator.py`](file:///home/me/data/AdaptiveShield/tests/unit/test_deception_orchestrator.py), [`tests/unit/test_deception_benchmark.py`](file:///home/me/data/AdaptiveShield/tests/unit/test_deception_benchmark.py)
- **Integration Test Coverage**: [`tests/integration/test_generative_deception_pipeline.py`](file:///home/me/data/AdaptiveShield/tests/integration/test_generative_deception_pipeline.py)
- **Test Suite Status**: **150 passed in 25.4s (100% pass rate)**.
