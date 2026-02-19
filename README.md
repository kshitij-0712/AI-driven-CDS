# AdaptiveShield

A portable, multi-agent cyber deception and threat analysis system. AdaptiveShield autonomously discovers network surfaces, deploys honeypots, learns attacker behavior through ML, and explains every decision with explainable AI (XAI).

## Overview

AdaptiveShield operates as a coordinated system of five specialized agents:

| Agent | Role | Description |
|-------|------|-------------|
| **Discovery** | The Scout | Scans host/network to map real services and candidate decoy ports |
| **Deception** | The Trapmaker | Deploys and manages honeypots (Cowrie, Dionaea) on candidate ports |
| **Analysis** | The Detective | Ingests logs, correlates sessions with downloaded binaries, extracts features |
| **Decision** | The Brain | Classifies attacker intent using trained ML model, selects countermeasures |
| **XAI** | The Narrator | Generates human-readable explanations for all autonomous actions |

## Threat Classification

The Decision Agent classifies sessions into six intent categories:

| Label | Description | Automated Response |
|-------|-------------|-------------------|
| Safe | Benign activity | Monitor |
| Recon | Network scanning, enumeration | Deploy low-interaction decoy |
| Downloader | Fetching malicious payloads | Deploy medium-interaction decoy |
| Exploit | Active exploitation attempts | Deploy high-interaction decoy |
| Destructive | Data destruction, ransomware | Isolate + high-interaction |
| ADVANCED_APT | Sophisticated persistent threat | Contain and shadow |

## Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Discovery  │───>│  Deception  │───>│  Honeypots  │
│   (nmap)    │    │  (deploy)   │    │  (Cowrie,   │
└─────────────┘    └─────────────┘    │   Dionaea)  │
                                      └──────┬──────┘
                                             │ logs
                                             v
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│     XAI     │<───│  Decision   │<───│  Analysis   │
│ (explain)   │    │ (classify)  │    │ (ingest,    │
└─────────────┘    └─────────────┘    │  correlate) │
                                      └─────────────┘
```

## Data Flow

1. **Discovery** finds open services and candidate decoy ports
2. **Deception** deploys decoys matching the discovered surface
3. Attacker interacts with decoy; logs are captured
4. **Analysis** correlates session logs with downloaded binaries
5. **Decision** predicts intent and issues next-step actions
6. **XAI** explains the action and rationale

## Key Features

- **Autonomous Operation** - Full pipeline from discovery to response without human intervention
- **ML-Powered Classification** - RandomForest classifier trained on honeypot session data
- **Explainable AI** - Every automated action includes human-readable justification
- **Binary Analysis** - Optional Ghidra/angr integration for malware sample analysis
- **Portable** - Self-contained project structure, runs anywhere with Python 3.10+

## Branches

| Branch | Description |
|--------|-------------|
| `main` | Documentation and project overview |
| `fE` | Full implementation with source code |

## Getting Started

Switch to the `fE` branch for the complete implementation:

```bash
git checkout fE
```

See the branch README for installation and usage instructions.

## Requirements

- Python 3.10+
- scikit-learn, numpy, PyYAML
- Optional: nmap, angr, Ghidra

## License

See LICENSE file for details.
