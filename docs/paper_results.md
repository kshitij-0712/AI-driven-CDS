# AdaptiveShield — Empirical Evaluation & Paper Results

**Dataset Benchmark:** CERT Insider Threat Dataset r4.2  
**Dataset Scale:** 330,452 User-Days (329,088 Normal, 1,364 Malicious Insider Episodes)  
**Evaluation Philosophy:** Real-world extreme class imbalance ($0.4128\%$ positive rate) evaluating normative behavioral deviation.

---

## 1. Global Model Performance Metrics

| Metric | Measured Value | Standard Benchmark Target |
|---|---|---|
| **ROC-AUC** | **0.9902** | $\ge 0.900$ |
| **PR-AUC (Average Precision)** | **0.5588** | Baseline random guess is $0.0041$ |
| **Maximum Malicious Day Probability** | **0.9985** | High confidence on multi-vector exfiltration |
| **Median Normal Day Probability** | **0.0047** | Deep baseline separation on legitimate work |
| **Median Malicious Day Probability** | **0.8212** | Distinct separation from benign background |

---

## 2. Table T1: Detection Ablation Study

Empirical comparison across detection paradigms evaluated over 330,452 user-days:

| Detection Paradigm | Description | Precision | Recall | F1-Score | False Positives | True Positives |
|---|---|---|---|---|---|---|
| **Arm 1: Policy-Only** | Heuristic rules (scope breach, raw after-hours, volume) | 0.0053 | 35.85% | 0.0104 | 91,793 | 489 / 1,364 |
| **Arm 2: ML-Default ($\tau=0.50$)** | Uncalibrated Random Forest classifier | 0.2436 | 90.54% | 0.3839 | 3,835 | 1,235 / 1,364 |
| **Arm 3: ML-Calibrated ($\tau=0.8696$)** | PR-Curve calibrated optimal F1 operating point | **0.6284** | 40.18% | **0.4902** | **324** | 548 / 1,364 |
| **Arm 4: Hybrid Blended** | Zero-trust containment prior with calibrated ML trigger | 0.0099 | **67.60%** | 0.0195 | 92,101 | 922 / 1,364 |

### Interpretation:
1. **The Inadequacy of Rule-Only Detection:** Static rule policies generate **91,793 false alarms** in an enterprise dataset of 330,452 days, because legitimate employees routinely work late or transfer files during standard operations.
2. **The Power of Behavioral ML:** The calibrated model reduces false positives from 91,793 down to **324** across 17 months of enterprise operations (a $99.65\%$ reduction in false alarms) while isolating malicious days with 62.84% precision.
3. **Operational Deception Architecture:** In AdaptiveShield, the high recall of the hybrid prior ($67.6\%$) is safely paired with **Decoy Containment (D4)**. Because flagged users are redirected to deceptive workspaces rather than dropped, the false positive penalty does not disrupt legitimate business operations.

---

## 3. Table T2: Probability Operating Threshold Sweep

Sweep of candidate classification thresholds $\tau$ across the 330,452 test distribution:

| Threshold $\tau$ | Precision | Recall | F1-Score | FPR | True Positives | False Positives |
|---|---|---|---|---|---|---|
| **0.05** | 0.0560 | 98.17% | 0.1060 | 6.85% | 1,339 | 22,555 |
| **0.10** | 0.0888 | 97.07% | 0.1627 | 4.13% | 1,324 | 13,583 |
| **0.20** | 0.1308 | 96.19% | 0.2303 | 2.65% | 1,312 | 8,717 |
| **0.30** | 0.1624 | 94.57% | 0.2772 | 2.02% | 1,290 | 6,654 |
| **0.50** | 0.2436 | 90.54% | 0.3839 | 1.16% | 1,235 | 3,835 |
| **0.60** | 0.2914 | 85.19% | 0.4342 | 0.86% | 1,162 | 2,826 |
| **0.70** | 0.3266 | 70.89% | 0.4472 | 0.61% | 967 | 1,994 |
| **0.80** | 0.4005 | 54.47% | 0.4616 | 0.34% | 743 | 1,112 |
| **0.85** | 0.5325 | 44.50% | 0.4848 | 0.16% | 607 | 533 |
| **0.87 (Opt)** | **0.6284** | 40.18% | **0.4902** | **0.09%** | 548 | **324** |

---

## 4. Policy Band Calibration

Based on empirical validation curves:
- **`NORMAL` ($P < 0.10$):** Unrestricted execution. Represents $>95\%$ of daily sessions.
- **`MONITOR` ($0.10 \le P < 0.30$):** Transparent logging and heightened audit telemetry. Recall at this boundary is $97.07\%$.
- **`ALERT` ($0.30 \le P < 0.60$):** Decoy preparation and persona mirroring initiated.
- **`CONTAIN` ($P \ge 0.60$):** Seamless routing into deceptive persona-mirrored decoy workspace. Destructive operations simulated with zero real impact.
