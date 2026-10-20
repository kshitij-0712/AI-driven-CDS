# AdaptiveShield — Insider Module & Adaptive Insider-Deception Plan

**Status:** PLAN v2 (Oct 20, 2026) — all decision points locked (D2–D10, §2.0); surface doctrine updated per owner correction. **Phase 0 execution awaiting owner go/no-go.**
**Scope:** `src/agents/insider/*`, `src/interfaces/*`, `src/interceptor/*`, `src/agents/deception.py`, `src/honeypot/*`, `src/agents/xai.py`, `AGENTS.md`, data pipeline, tests, paper artifacts.
**This document is the execution contract.** Every item is checked off only after your review. Decision points (D1–D10) are locked in §2.0; future additions follow the same review protocol. Old-branch history (xai-dashboard synthetic/CERT eras) is deliberately out of this document — current architecture only.

---

## 0. Evidence Base (verified in this session — what we know is true)

### 0.1 Branch state
- `insider-module` = `train` @ `eef9425` (manual fast-forward merge done by you).
- Working tree: 29 modified tracked files — verified to be **line-ending churn only** (insertions == deletions, content identical) for insider files; plus untracked data files (`sessions_complete_v3.csv`, `unified_external_corpus.csv`, `training_v6/`, `motif/` via symlink) — no collisions.

### 0.2 Verified test results (real trained model loaded)
- **23/23 insider tests PASS** against `models/internal_insider_model.pkl` (unit + regression + behavioral suites run via direct driver because venv pytest is 4.5/py3.10-incompatible — separate issue, see W1).
- 1 SKIP: `test_cert_dataset_roc_auc` — blocked on missing dataset, resolved by Phase 0.

### 0.3 Verified model behavior (probed with sklearn 1.7.2, bundle trained on 1.8.0)
| Probe | Result |
|---|---|
| Benign baseline ML prob | 0.064 |
| Max prob after flipping ANY one feature (incl. counts to 200) | **≈ 0.20 — never crosses even 0.3** |
| CERT-lookalike malicious day (usb=7, files=25, after-hours, dev=0.9) | **prob = 0.033** |
| Bundle pickle load time | 0.49 s |
| Warm `analyze_signal` latency (this machine) | mean 142 ms / median 136 ms per call |
| Raw RF `predict_proba` latency | 72 ms/shot (n_jobs contention suspect) |
| Metadata (CERT r4.2, 330,452 user-days, 0.41% malicious) | acc 0.986, ROC-AUC 0.962, **PR-AUC 0.288, malicious F1 0.246** |

**Implication (must be reflected in AGENTS.md and the paper):** in the deployed blend `risk = max(ML×100, policy_risk)` with deterministic floors (scope violation → 75, IP drift → 65), **every MALICIOUS_INSIDER verdict is policy-engine-driven. The RF is an anomaly *ranking* prior, never the trigger.** This is a defensible, honest architecture claim — but only if documented and ablated, never claimed as "the ML detects insiders."

### 0.4 Verified integration/architecture facts
- Orchestrator runs **two-plane guards**: external HTTP :8000 (`is_internal=False`), internal HTTP :8001 (`is_internal=True`), plus SSH guard :2222 with decoy/internal branches.
- Internal HTTP guard: cookie `nexus_session`/Bearer → `CorporateDirectory.validate_session` → `UserBehaviorSignal` per request → `AdaptiveInsiderDetector.analyze_signal` → **risk exclusively drives policy** (≤30 NORMAL/forward, ≤60 MONITOR/forward, ≤80 ALERT/redirect_to_decoy, >80 CONTAIN → internal ⇒ redirect_to_decoy, external ⇒ drop_and_block).
- Internal session state is keyed `int:{src_ip}` (per-IP, not per-employee); detector is app-scoped (correct), **SSH is not** (bug: fresh `AdaptiveInsiderDetector()` + 25MB unpickle **per SSH command**).
- `DecoyManager}(deception.py): nginx HTTP decoys + Cowrie SSH decoys, scoped external/internal, prewarm pool + LRU recycle + idle cleanup. **No environment-mutation API** — content changes only through `HoneypotGenerator.prepare_decoy_files()`.
- `HoneypotGenerator` (src/honeypot/) — **LLM-adaptive decoy engine already exists** (Galah-style): crawls real app structure, per-request LLM-baked decoy pages written into the decoy's `html_dir`, per-attacker persistent session memory, nginx conf regeneration. Currently driven only by external threat labels; `Insider Anomaly` label is not in its prompt vocabulary, and internal redirects don't feed it insider context (anomaly factors, role, department, risk band).
- `insider_events.jsonl` (dedicated insider telemetry log) exists in runtime, written per internal request.
- XAI: `AdaptiveXAINarrator.generate_explanation()` is already invoked inline for insider decisions in both guards (http_proxy internal branch + ssh internal branch). No *stream* for XAI/dashboard consumption of decoy adaptations yet.
- `record_live_feedback()` (reinforcement CSV appender) exists but is **never called at runtime**.
- Corporate directory: SQLite, SSO login endpoint on internal guard, sha256+static-salt (`qwerty` default), IP whitelists, seeded from `config/company_profile.json` or built-in `default_company_profile.py` (~25–30 employees incl. test personas). `config/company_profile.json` itself is absent (only `.example`).
- Docker: `requirements.docker.txt` → requirements.txt → `scikit-learn>=1.0.0` ✓ (model will unpickle in container, but version drift vs 1.8.0 pickle = risk, see F3).

### 0.5 Data gaps (resolved in Phase 0)
- `data/insider/internal_insider_dataset_base.csv` — absent.
- `data/cert_r4.2/` — absent. **Source confirmed in `/mnt/c/Users/kshit/OneDrive/Desktop/Linux_Shared_Folder/r4.2/`** (http.csv ⚠ **14 GB**, email 1.3 GB, file 185 MB, logon 56 MB, device 28 MB, LDAP/, psychometric.csv).
- `data/cert_answers/insiders.csv` — source confirmed in `.../Linux_Shared_Folder/answers/insiders.csv` (16 KB).

---

## 1. Target Architecture (your vision, formalized against the codebase)

Your stated intent, mapped to the implemented system:

1. **Surface doctrine (D10, owner-corrected Oct 20, 2026).** Exactly three surfaces define the company deployment shape:
   - **External HTTP — the hosted website** (perimeter). What the company *serves the world*: customers, partners, scanners, attackers. Employees do not "work" here; at most they browse it like any visitor. The perimeter guard classifies hostile HTTP → decoy redirect or nftables block.
   - **Internal HTTP :8001 — the employee workspace application.** In the current landscape every internal business function (HR, payroll, finance, ticketing, file share, webmail) is a web app; the employee's day IS this workspace. The internal guard sits **only** in front of the workspace app + SSH — it is **not** a general browsing proxy. Insider intent (scope probing, restricted downloads, exfil uploads) surfaces first here; CERT http.csv is precisely this telemetry.
   - **SSH — one shared door, two audiences** (§2.0 SSH doctrine, credential anchor A): a single SSH endpoint visible to both external attackers and employees; the *credential* decides which world sits behind the handshake.
   - Decision logic differs per plane: external → neural/MITRE classification → block/redirect/decoy. Internal → identity-resolved behavioral analysis (corporate directory + insider RF + policy floors) → **never hard-block; contain into deception**.
   - **HTTPS/443 is removed from the project entirely** (D10) — no interception, no listener, no certificate work in any phase.
2. **Insider containment loop ("they must keep believing they succeed"):**
   `Risk escalation → redirect_to_decoy (same look & feel as real service) → insider keeps operating inside decoy → every decoy interaction re-annotated by the insider model (risk updates, new anomaly factors) → deception keeps **mutating the decoy environment** to sustain engagement → all of it narrated to **XAI**.` The internal employee's malicious session is never told "no" — it is fed an ever-adapting, persona-consistent illusion.
3. **Deception adaptation is insider-aware:** the decoy generator must receive the employee's role/department/authorized+restricted scopes/anomaly factors/whichever resources they probed, and evolve the decoy workspace accordingly (what for external attackers is "become the bank", for insiders is "become their own company, with their own targets visible — and one step more tempting").
4. **XAI as first-class consumer:** insider verdicts *and* every decoy mutation become structured events the XAI module/dashboard can narrate (extends the existing inline narration + `insider_events.jsonl`).

### 1.1 Dependency graph (post-implementation)

```
                       ┌──────────────────────────────────────────────────┐
 real employees ───────►│ Internal HTTP Guard :8001  /  Internal SSH :2222 │
 (corp identity)        │  CorporateDirectory (SSO, whitelist)             │
                       │        │ UserBehaviorSignal per req/cmd           │
                       │        ▼                                          │
                       │  AdaptiveInsiderDetector (stateful per session)   │
                       │   ├─ RF anomaly prior  (internal_insider_model)   │
                       │   └─ policy floors (scopes/IP/temporal)           │
                       │        │ risk_score + anomaly_factors             │
                       │        ▼                                          │
                       │  Policy Engine: NORMAL/MONITOR/ALERT/CONTAIN      │
                       │        │ (≥60: decoy; never internal IP block)    │
                       └────────┼──────────────────────────────┬──────────┘
                                │ DecoyDirective                │ InsiderEvent→jsonl
                                ▼                               ▼
                       ┌──────────────────┐            ┌────────────────────┐
                       │ HoneypotGenerator │◄────ingest─│  XAI Module/Dash   │
                       │ (insider-aware    │  todos/    │  AdaptiveXAINarrator│
                       │  persona prompts) │  events    └────────────────────┘
                       └────────┬─────────┘                       ▲
                                │ mutate html_dir/conf            │
                                ▼                                 │
                       ┌──────────────────┐                       │
                       │ Internal Decoys   │──decoy logs (confirmed-│
                       │  nginx worker /   │   malicious labels) ───┘
                       │  cowrie insider   │         │
                       │  workspace        │         ▼
                       └──────────────────┘  record_live_feedback CSV → offline retrain
```

### 1.2 What stays, what changes

| Component | Keep | Change |
|---|---|---|
| CorporateDirectory | SSO, whitelist, profile resolution | Session-keyed insider identity (D8) |
| insider_adapter/dataset/inference | 35 features, rule fallback, RF bundle | Session identity key fix, TTL eviction, calibrated operating point (D9) |
| Policy bands | ≤30/≤60/≤80/>80 | Map CONTAIN/ALERT decisively to decoy-directive tiers (D2/D3); destructive exception (D4) |
| deception.DecoyManager | pools/scopes/cleanup | + `apply_directive()` mutation surface |
| honeypot.HoneypotGenerator | engine, cache, session memory | Insider-prompt persona mode (D1/D3) + trigger from internal guard |
| XAI (agents/xai.py) | inline narration | + event stream out (D5), contract extension |
| Feedback loop | record_live_feedback | Wire from decoy logs (D6); manual retrain trigger |

### 1.3 Parallel-work contracts — what this track gives & takes (sync surface for simultaneous modules)

Every "provides" entry is a **freeze surface**: parallel modules may consume it freely; changing it requires owner sign-off. Every "expects" entry is a dependency we assume stable — if a parallel module renames/reshapes one, it is a coordination item, never a silent retry. Change protocol: additive fields only, backward-compatible defaults, one PR per module boundary.

| Counterpart | Insider track PROVIDES | Insider track EXPECTS |
|---|---|---|
| **HTTP guard** (`src/interceptor/http_proxy.py`) | App-scoped detector (already correct there), per-session behavioral state, `analyze_signal` verdicts → policy bands, sticky employee/session flag semantics (P2-6) | Well-formed `UserBehaviorSignal` per request (commands/paths/counts/timestamps), identity resolved via `CorporateDirectory`, no ad-hoc routing that bypasses verdicts |
| **SSH guard** (`src/interceptor/ssh_proxy.py`) | D8 state design: employee+session key, single detector (F1), kill-chain accumulation, neural-aux "raise-only" floor rule | Per-connection context (`auth_username`, source IP) handed to the detector, sticky `ssh_flagged_for_decoy` honored, no per-command detector creation |
| **Deception** (`src/agents/deception.py`, `src/honeypot/*`) | `DecoyDirective` (tier, employee_profile, anomaly_factors, intent_paths, trigger_band) + trigger events on band entry/escalation/new-factor | `DecoyManager.apply_directive()` implemented (P2-2), persona-mirrored workspace (D3), mutation cadence per D2, decoy-log health stream |
| **XAI (Person A)** (`src/agents/xai.py`) | Stable verdict payload (risk_score, band, anomaly_factors, risk_components, evidence features), `insider_events.jsonl` schema (with `band`/`risk_components` after Phase 3 polish) | Narration stays inline (D5): no separate stream, `xai_contract.py` unchanged, narration never mutates decisions |
| **Contract seam** (`src/interfaces/insider_contract.py`) | Typed `UserBehaviorSignal` + `InsiderThreatScore` — the single integration edge; additive-only evolution | No module destructures undocumented fields; new requirements arrive as contract-change requests, not as side parsers |
| **Config/org data** | `company_profile.json` schema semantics (D7), profile generator, scope→feature mapping (F6/F10), calibration artifact `models/internal_insider_calibration.json`, `insider:` settings block | Profile file present (shipped or generated), `runtime/` excluded from OneDrive sync, sklearn pin respected |
| **Orchestrator / deployment** | Detector lifecycle contract (one instance, warm), per-request latency envelope from F7 | Single-process ownership of detector construction, no double instantiation at module import |
| **Paper / artifacts (Phase 4)** | Ablation T1, honest claim set ("policy-primary detection with learned anomaly prior"), per-file inventory, repro scripts | No accuracy marketing before T1 lands; claims edited only through this plan |

---

## 2. DECISION POINTS

### 2.0 LOCKED BY OWNER (Oct 18, 2026 session) — implemented as stated

| ID | Locked decision |
|---|---|
| **D2** | **Band + vector driven adaptation.** Mutate decoy on first redirect, band escalation, new anomaly factor. Boredom counter explicitly out of THIS build track — design goes into AGENTS.md as the documented architecture; implementation effort stays elsewhere. Requests between mutations served from existing cache. |
| **D3** | **Persona-mirrored workspace.** Authorized scopes functional as-if-real; restricted scopes render plausible-but-fake content seeded from role/department + observed intent; probed paths become the next batch of bait. |
| **D4** | **Pure containment, sticky, zero hard-block.** Internal identities are never IP-blocked or dropped. Destructive commands are *simulated inside the decoy* — decoy displays the same output the real system would (`rm -rf` "works", nothing is destroyed; Cowrie already emulates shell behavior). **Once an insider is routed to a decoy, all further traffic for that insider stays on the decoy permanently** (sticky containment). SSH already implements half of this via `ssh_flagged_for_decoy` (sticky per source-session); HTTP needs the equivalent sticky flag added at employee/session level (Phase 2 item P2-6). |
| **D5** | **Inline narration only.** No new XAI event stream in this track. Existing inline `AdaptiveXAINarrator` narration in threat/insider event logs stays; AGENTS.md documents that XAI consumption of decoy evolution is a documented-future direction, not built here (`xai_contract.py` unchanged). |
| **D6** | **No reinforcement loop for now.** `record_live_feedback()` stays as designed-but-unwired; decoy interactions are NOT auto-fed as training data this track. AGENTS.md will document the designed loop as future work. |
| **SSH doctrine (validated)** | Owner-confirmed architecture: **SSH is not a public service.** Port 2222 is the entry for both attacker paths: (a) pre-auth brute force → threshold → tripping password accepted → routed to Cowrie decoy → **external** guard (neural `brain_neural.pt` + MITRE rules) decides inside the decoy; (b) **valid employee credentials** (only employees hold them) → transparent proxy to the real backend → insider model watches every command for that connection. **Credential anchor = Option A (LOCKED Oct 20, 2026):** the credential is the gate to the internal plane — a session authenticating with valid employee credentials proceeds into the internal behavioral plane **regardless of source IP**; `unusual_login_time`/`unusual_pc_login` carry the risk signal, and the whitelisted-IP map serves username *attribution* (D7), not employee-ness. No IP-anchored diversion of valid-cred sessions, no middle band (Option C rejected). Failed/brute-forcing origins are the only pre-auth external path → Cowrie decoy + kernel-block escalation. |
| **D8** | **Directory-enriched + neural auxiliary (LOCKED).** Real backend stays the SSH credential authority; `CorporateDirectory` *enriches* the internal SSH session (username → role/department/IP-whitelist for behavioral features; unknown usernames proceed as `normal` role). Insider state keyed by employee+session (not IP); one shared detector; kill-chain accumulates across commands. `brain_neural` runs as a **bounded auxiliary** on internal SSH commands: its Destructive/Exploit/APT labels can **raise** the policy risk floor, never lower it. HTTP and SSH behavioral states stay per-protocol (per-employee). |
| **D7** | **Generator knob (LOCKED).** `config/company_profile.json.example` is the canonical schema/source-of-truth for the synthetic org (work policy, departments/scopes, employees, whitelisted IPs→usernames). Add a deterministic *generator* that extends from this schema (config knob `company_profile.size`, default 100 employees) — same IP-whitelist→username semantics preserved — for the "many insider employees" narrative and stress tests. Shipped `company_profile.json` for the demo stays derived from the example. |
| **D9** | **Investigate → strengthen → calibrate (LOCKED, owner-directed).** Phase 0 extended with a diagnosis sub-phase: (a) RF failure diagnosis on the compiled CERT data (per-feature class distributions, PR curve sweep, scenario-wise error breakdown, proxy-feature collision analysis), (b) strengthen candidate set tried in order: proxy-collision fixes → log-scale/per-role normalization of counts → window-trimmed labels → model family comparison (HistGB/IsolationForest baselines), then (c) calibrate the best artifact. Neural-fusion experiments (`brain_neural` behavior on command text) inform the SSH aux design; fusion stays OUT of the RF feature vector (no CERT-side commands exist → train/serve skew avoidance). Paper reports the final honest table. |
| **D10** | **Surface & plane doctrine (LOCKED Oct 20, 2026, owner-corrected).** (a) **443/HTTPS removed from the project entirely** — no interception, no listener, no cert-handling work item in any phase or future step. (b) External HTTP (perimeter) is the **hosted website** — what the company serves the world; employees do not work on it. (c) Internal HTTP :8001 is the **employee workspace application** — the internal guard fronts only the workspace app + internal SSH, never a general browsing proxy; the workspace is where insider intent surfaces first. (d) SSH remains the single shared door (SSH doctrine row above, both attackers and employees) with **credential anchor A** as stated there. |

### 2.1 REMAINING OPEN — none. All decision points locked (§2.0, incl. D10). D1 and D8/D9 option blocks below are retained only as historical rationale.

**D1 — Insider decoy engagement mode (Phase 2)** — effectively decided by the vision: keep redirect-to-decoy, insider-aware (persona-mode) decoy content. Option A adopted implicitly; B never viable (malicious payloads must never reach the real service).
- A. **(Recommended)** Keep current full redirect-to-decoy (insider's session switches target: real → decoy container), but make the decoy *persona-consistent* via insider-aware prompts, so the switch isinvisible. Same mechanism externals get, but with an "insider persona" prompt mode (employee role/dept/scopes/history baked into system instruction instead of external threat intent).
- B. Shadow-mode (real service responds, decoy receives copy) — strictly worse for insiders: malicious payloads must never reach the real service; violates your vision.

**D2 — Decoy adaptation trigger (Phase 2)**
- A. **(Recommended)** Band-and-vector driven: adapt on (i) first redirect, (ii) every band escalation (60→80→CONTAIN), (iii) appearance of a *new* anomaly factor (e.g., crypto/upload/probe other department), (iv) T-coordinate boredom counter (no proactive-interest events within N requests → seed a plum target). Non-adapt-tick requests are served from cache (existing) — LLM cost bounded.
- B. Every-request LLM regeneration — cost/latency heavy even with cache.
- C. Fixed one-time bake — no adaptivity; fails your vision.

**D3 — What the insider decoy contains (Phase 2)**
- A. **(Recommended)** Persona+department-mirrored workspace: employee's authorized scope is fully navigable; restricted scopes render plausible-but-fake content (payroll CSVs, root tokens, model weights) seeded by the LLM from persona + observed intent (probed paths become the next batch of bait). This is "make their authorized scopes work, weaponize their forbidden scopes."
- B. Generic portal only — weak for scope-targeted insiders.
- C. Only requested path emulation — cheapest, but no anticipation.

**D4 — Insider hard-block exception (Phase 1 fix + Phase 2)** — see **D4 LOCKED** in §2.0: pure containment, sticky, destructive simulated in decoy. The former Phase-1 "session-kill exception" item is **removed** (F-list unchanged otherwise).

**D5 — XAI involvement (Phase 3)** — see **D5 LOCKED** in §2.0: inline narration only; no new stream; `xai_contract.py` unchanged.

**D6 — Reinforcement / ground truth (Phase 3)** — see **D6 LOCKED** in §2.0: no loop this track; documented as future work.

**D7 — (LOCKED, §2.0) historical options below**
- A. **(Recommended)** Keep shipped profile (~25–30 employees, 5 test personas) for runtime demo; add a profile *generator* (config knob `company_profile.size`) that synthesizes N (default 100) employees with roles/departments/IPs/personas deterministically — for the "many insider employees" narrative and stress tests, regenerated per experiment seed.
- B. Ship one fixed 100-employee profile, no generation.
- C. Stay at current ~30 employees.

**D8 — (LOCKED, §2.0) historical options below**
- A. **(Recommended)** Valid-cred internal SSH: identity enriched/matched against `CorporateDirectory` (real backend remains the credential authority; directory supplies role/department/whitelist for behavioral features); insider state keyed by **employee+session** (not IP); single app-scoped detector with per-SSH-session state accumulation; **`brain_neural` consulted as bounded auxiliary signal** (its destructive/exploit labels can raise the insider risk floor, never lower); HTTP and SSH behavioral states stay per-protocol (per-employee).
- B. Fix the state bug only (no directory binding, no neural fusion on SSH).
- C. Descope internal SSH from the paper (HTTP-only evaluation).

**D9 — (LOCKED, §2.0) historical options below**
- A. **(Recommended)** Keep the blend design; add calibration: choose detection threshold on the *validation* PR curve (operating point reporting precision/recall), expose as config (`insider.ml_risk_floor_band`), and run the ablation table (policy-only vs ML-only vs blended vs ML-threshold-calibrated) on the CERT holdout. Notebook/repro script.
- B. Replace threshold-0.5 with anomaly-quantile scoring (IsolationForest as baseline column too).
- C. No calibration (report as-is with limitation).

---

## 3. PHASE PLAN

### Phase 0 — Data restore, re-verification, calibration (data + training only)

**0a. Data restore + verify** (as listed below, items 1–4, 7).
**0b. RF failure diagnosis + strengthen (D9-LOCKED)** — after the dataset compiles:
  1. Class-conditional distributions for all 35 features; identify which proxy features carry signal vs noise (usb_mount/edit triple-collision check).
  2. PR-curve sweep + threshold table; per-scenario (r4.2 S1/S2/S3) error breakdown.
  3. Candidate strengthen slotted in this order: (i) fix proxy collisions (dedupe `usb_write_count`/`download_count`/`file_copy` triple), (ii) log1p + per-role normalization of raw counts, (iii) window-trimmed labels (±1 day around campaign windows re-evaluated), (iv) model family comparison: Balanced RF vs HistGradientBoosting vs IsolationForest-as-baseline-quantile.
  4. Deliberation gate: if none recovers malicious F1 to a defensible level, the RF ships as *anomaly prior only* (documented), and D9-calibration proceeds anyway on whatever ranking survives — the paper claims the policy/identity architecture either way.
**0c. Calibration + ablation** (items 5, 6 — ablation table becomes T1 with 4 arms: policy-only / ML-only / blended / best-strengthened+calibrated).
**0d. Neural behavior read (owner-requested) — RESULTS (Oct 18 session):**
  - `brain_neural` (UnifiedThreatClassifier, 722K params): **20/20 golden regression tests PASS** (`tests/regression/test_known_attacks.py` — HTTP + SSH external attack syntax + safe traffic).
  - **Insider-payload probe: the neural model scores EVERY classic insider payload as `Safe` with 0.90–1.00 confidence.** scp/rsync exfil to external IP → Safe @ 1.000; payroll curl upload → Safe @ 0.996; `history -c` wipe → Safe @ 0.968; `rm -rf /hr/payroll/` → Safe @ 0.990; `dd` to USB → Safe @ 0.989. Only bump anywhere: benign `cat /etc/passwd` → Recon 0.31.
  - **Interpretation:** the model was trained on *external* attack telemetry (honeypot + synthetic attack syntax); insider ops are ordinary admin commands aimed at sensitive internal resources — semantically invisible to it. **The auxiliary neural signal on internal SSH therefore only nets value for the malware/tool-download sub-case (dropper syntax it does know).** Owner's instinct confirmed by data: the insider RF must be strengthened on its own behavioral features (0b path); neural aux stays as the narrow safety net per D8-A, with calibrated expectation documented in AGENTS.md.

Legacy ordering (items as originally planned):

1. **Add CERT sources to the project**
   - Create symlinks (matching the established pattern `data/external` → shared folder):
     - `data/cert_r4.2` → `/mnt/c/Users/kshit/OneDrive/Desktop/Linux_Shared_Folder/r4.2`
     - `data/cert_answers` → `/mnt/c/Users/kshit/OneDrive/Desktop/Linux_Shared_Folder/answers`
   - Rationale: zero-copy (14GB http.csv), consistent with project's existing symlink discipline. If WSL drvfs streaming proves too slow (>2h ETA), fallback: `--http-csv-copy` flag copies http.csv once to `data/cert_r4.2/http_copy.csv` on native disk and uses it. *Decision during run, not a prereq.*
2. **Run `compile_cert_dataset.py`** with chunked streaming (exists; verify date-format handling + LDAP role maps); assert output: user-days ≈ 3.3e5, malicious ≈ 1,364 (±), 35 cols + label. Time budget up to 2h.
3. **Pin sklearn**: requirements.txt `scikit-learn==1.8.0` (bundle pickled with 1.8.0 = reproducibility for reviewers).
4. **Retrain** `train_internal_insider.py` (existing script — no changes) → regenerate bundle + metadata. Sanity: metrics within ±0.02 of stored metadata.
5. **Threshold calibration (D9)**: new `src/agents/insider/calibrate_thresholds.py`: computes validation PR curve, precision/recall at candidate risk-floor bands, writes `models/internal_insider_calibration.json` (chosen operating point + table). Runtime reads floor from config, default changing only if calibration says so.
6. **Re-run all 4 insider test files** through the direct driver (eliminate the sole SKIP) + fix test lane: add `pytest>=8` as a *dev* alternate env (`requirements-dev.txt` + `.venv-py311` recipe in AGENTS.md) — venv pytest 4.5 rides along otherwise.
7. **Ablation experiment (paper table T1)**: policy-only / ML-only / blended / calibrated, on holdout user-days; log headline numbers into `docs/paper_results.md` stub.

**Exit criteria:** compiled CSV exists and matches expected distribution; tests 24/24 pass with dataset; calibration artifact written; ablation numbers recorded.

### Phase 1 — Correctness & hardening fixes (code)
All verified, ranked by risk. Each item is small and independently testable.

| # | Fix | File(s) | Test |
|---|---|---|---|
| F1 | **SSH guard**: single app-scoped `AdaptiveInsiderDetector` (not per-command), per-SSH-session state, no 25MB unpickle per command; wire user identity through `self.auth_username`→directory user | `src/interceptor/ssh_proxy.py` | new: `tests/unit/test_ssh_insider_state.py` |
| F2 | **Internal insider session key**: use cookie/`session_id` (employee+session token) instead of `int:{src_ip}`; geo fallback stays | `src/interceptor/http_proxy.py` | update integration test |
| F3 | **sklearn pin** + InconsistentVersionWarning removal | `requirements.txt` | metadata roundtrip test |
| F4 | **Session state TTL eviction** (idle cap, e.g., 1h + max sessions LRU) | `insider_adapter.py` | unit test |
| F5 | De-noise benign events: only stamp `Insider Anomaly` when risk ≥ MONITOR band or factors non-empty; else keep real classification for logging | `http_proxy.py`, `ssh_proxy.py` | assert log schema |
| F6 | Extract hardcoded whitelists (192.168.1.50/100, subnet `.1`) into `company_profile.json` (`network.whitelist_extra`) — remove dual hardcoded sites | `corporate_directory.py`, `insider_adapter.py`, profile example | unit |
| F7 | `analysis latency`: set `n_jobs=1` for inference-time RF (construct-time only), avoid 72ms/shot thread thrash; measure again (target <25ms) | `train_internal_insider.py` (inference unset), `insider_adapter.py` | latency probe |
| F8 | Auth salt/pass: keep demo `qwerty` but move to profile field + doc header "DEMO ONLY — production deployments must rotate" | profile example, docstring | — |
| F9 | Remove stale `ml.neural_v5_*` config keys (point to deleted v5 files); rename-annotate `neural_v6_model_path` → comment clarifying it loads `brain_neural.pt` | `config/settings.yaml`, `src/agents/decision.py` fallback comment | config-load smoke |
| F10 | **Adapter heuristic coverage v2 (informed by 0d probe):** insider payloads miss flags today — `rm -rf /hr/…` (only `/var/log` counts), `dd if=… of=/dev/sdX` (no usb flag), `tar czf`-then-upload chains, `shred` outside var-log. Add sensitive-path-aware patterns driven by company_profile scopes (not new hardcoded lists). Ties D4 ("decoy simulates destructive ops") to correct detection first. | `src/agents/insider/insider_adapter.py`, profile schema | unit: each payload from 0d battery gains ≥1 anomaly flag |

**Exit criteria:** SSH internal session accumulates state across ≥10 commands without reload; pytest lane green; manual dual-plane smoke via `curl` + SSH loop.

### Phase 2 — Insider-aware adaptive deception (the core of your vision)

1. **Contract first**: `interfaces/deception_contract.py`:
   `DecoyDirective { session_id, scope, trigger_band, employee_profile, anomaly_factors, risk_score, intent_paths[], tier: STEADY|ESCALATING|FULL_CONTAIN }`
   `DecoyAdaptationResult { applied: bool, content_class, stored_at }`
2. **`DecoyManager.apply_directive()`**: maps directive tier → decoy workspace updates (delegates content to `HoneypotGenerator`), persists `metadata.json` marker `mode: insider`. No new pools.
3. **Insider persona mode in `HoneypotGenerator`**:
   - `PromptBuilder.build_insider_prompt(profile, anomaly_factors, intent_paths, band)` — **personas for internal**: their own department workspace (authorized scopes fully functional), restricted-scope bait pages, plum-file teaser under escalation; external threat vocabulary replaced with insider-intent vocabulary.
   - Reuses existing: crawler (app structure), cache, state keying per session, nginx conf regeneration.
4. **Trigger wiring in `http_proxy.py` (internal branch)**: on band entry / escalation / new anomaly factor (boredom counter documented only, per D2), call `decoys.apply_directive(...)` → `honeypot_gen.prepare_decoy_files(mode="insider", directive=...)`; mirror for SSH decoys (cowrie honeyfs seed: files named after probed paths).
5. **Sticky containment (D4)**: HTTP internal guard gains a persistent `flagged_for_decoy` context flag at **employee/session level** (mirroring SSH's `ssh_flagged_for_decoy`): once any request from that insider hit ≥ALERT band, **all subsequent requests route to the decoy permanently** — even if later risk cools down; no path back to the real service for that identity/session. Decoy simulates destructive payloads' expected output without effect (nginx responses; cowrie shell for SSH).
6. **Character continuity**: internal decoy domain must look identical to the real service (same header/footer/login state, employee's own name in UI). Crawler already scrapes the *real* app for this.
7. **Telemetry**: every adaptation writes a record into `insider_events.jsonl` (inline narration covers it for XAI — D5) so an operator can read "why the decoy grew a payroll folder at 14:42".
7. **Tests**:
   - `tests/regression/test_insider_decoy_directives.py` — MockLLMClient (no network): band escalation changes decoy content class; restricted-path probe produces bait page; cache prevents LLM churn.
   - `tests/integration/test_insider_full_loop.py`: login as persona → probe restricted scope → risk crosses 60 → request redirected → decoy response reads as company-internal; escalation adds content; nothing blocks; `insider_events.jsonl` records the whole arc.

**Exit criteria:** demo script (`scripts/demo_insider_decoy.py`) runs the arc end-to-end offline (MockLLM) — zero external APIs needed; with OLLAMA/Gemini optional.

### Phase 3 — Trimmed: telemetry polish only (XAI stream & reinforcement DROPPED per D5/D6)

1. ~~Contract + `runtime/xai_events.jsonl`~~ — **dropped** (D5: inline narration only; no new stream, `xai_contract.py` unchanged).
2. ~~`record_live_feedback` wiring~~ — **dropped** (D6: no reinforcement loop this track; documented as future work in AGENTS.md instead).
3. **Kept (small):** event-schema consistency — `threat_events.jsonl` vs `insider_events.jsonl`: add `band` and `risk_components` fields to insider events; dedupe benign stamping (coordinated with F5, Phase 1); keep XAI inline narration untouched.
4. Light coverage: one test asserting the enriched insider event fields.

### Phase 4 — AGENTS.md rewrite + paper artifact packaging

1. **AGENTS.md new section "17. Insider & Adaptive-Deception Module (CURRENT)"** containing: dual-plane diagram, identity model, 35-feature spec + semantic table (CERT-proxy semantics vs runtime semantics, explicitly!), training data provenance (CERT r4.2, compile pipeline, imbalance handling, calibration, ablation), decoy loop, contracts, decision policy bands, running the demo, limitations (ML as prior + PR-AUC context, demo creds, benchmark proxies). Include per-file inventory and the exact published claims permitted ("policy-primary detection with learned anomaly prior").
2. **Stale-section surgery**: §2 Decision Agent (brain_v6_unified is production, neural path names, confidence semantics — now 0.35 + risk-calibrated thresholds, not "55%"), §11 spec updates to UnifiedThreatClassifier architecture (modality-masked 4-way input), §15 provenance (CERT r4.2 added), §16 rewritten to the *actual implemented* runtime (orchestrator ports 8000/8001/2222, contracts, decoys, nftables retained); **purge every 443/HTTPS-interception mention** (the old "Next Build Steps" HTTPS item is dead per D10).
3. **`docs/paper_results.md`**: consolidated numbers (ablation T1, benchmark T2 from metadata/holdout, runtime overhead T3 incl. per-request latency and decoy-cold-start, qualitative walk-through) — everything reproducible from Phase 0/2 outputs.
4. **Tests count/report** for artifact evaluation: pytest lane behavior documented; `pytest -m insider` group marker.

### Out of scope (flagged, not planned here)
- HTTPS/443 interception — **removed from the project entirely (D10)**: not out-of-scope-pending, but *deleted*; no future track either.
- SSH decoy content *semantic* regeneration via LLM (cowrie honeyfs stays seeded, not LLM-baked, unless you ask).
- Multitenant directory federation/real HR integration.

---

## 4. FULL WORK ITEM LEDGER (files touched per phase)

| Phase | Files |
|---|---|
| 0 | symlinks `data/cert_r4.2`, `data/cert_answers`; `requirements.txt`; new `src/agents/insider/calibrate_thresholds.py`; `docs/paper_results.md` stub; AGENTS.md section 17 stub |
| 1 | `src/interceptor/ssh_proxy.py`, `src/interceptor/http_proxy.py`, `src/agents/insider/insider_adapter.py`, `src/agents/insider/corporate_directory.py`, `src/agents/insider/train_internal_insider.py`, `config/company_profile.json` (created from example), `config/settings.yaml` (bands/whitelist/callouts) |
| 2 | new `src/interfaces/deception_contract.py`; `src/agents/deception.py`; `src/honeypot/generator.py`, `src/honeypot/prompt_builder.py`; `src/interceptor/http_proxy.py`, `src/interceptor/ssh_proxy.py`; `data/datasets/company_profile_generator.py` (D7-A); `scripts/demo_insider_decoy.py` |
| 3 | `src/interceptor/*` event-schema additions only (`band`, `risk_components`); no contract changes |
| 4 | `AGENTS.md` full; `docs/paper_results.md`; `requirements-dev.txt` |

## 5. RUN ORDER & SIGN-OFF PROTOCOL

- You review this doc → adjust decision points → single reply confirming decisions is enough.
- I execute Phase 0 fully, then stop and report (checkpoint A).
- Phase 1 executes on your confirm; stop and report (checkpoint B). All Phase 2 decision points (D1–D4) are locked in §2.0; Phase 2 starts after the Phase 1 checkpoint confirm.
- No model retraining overwrites the shipped bundle without your confirm; retrained bundle saves to `models/internal_insider_model_calibrated.pkl` first, swap only after tests green (reversible).

## 6. RISKS

1. `http.csv` 14 GB on OneDrive/drvfs: compile ETA unknown (2h budget; fallback = copy-once to native disk; could also split-shard). Worst case: compile overnight, everything else proceeds without it.
2. LLM-dependent decoy content: MockLLMClient path keeps tests offline; anything Gemini/Ollama is optional velvet, not blocking.
3. Version-drift reproducibility of pickle: pin==1.8.0 solves; retraining with same seed yields determinism check via metadata diff.
4. Windows/OneDrive sync pressure while runtime writes into `runtime/`: recommend keeping `runtime/` excluded from OneDrive sync in `.gitignore`-adjacent hygiene (already untracked; the OneDrive sync itself is out of our control).
5. The paper claim "ML-capable insider detection" could collapse under calibration results (probe shows RF never crosses 0.2 even on extreme counts). The plan handles this via honest ablation framing (D9-A) — but if you'd rather the paper headline "ML-driven", we should discuss before Phase 0 because it changes what we invest in (e.g., feature engineering to give the RF learnable separation, or quantile scoring).
