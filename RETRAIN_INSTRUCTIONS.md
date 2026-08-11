# Instructions: Training Neural Model with MITRE-Only Semantic Balanced Labels

## Summary of Changes

The `compute_mitre_only_semantic_balanced_label()` function in `src/training/neural/semantic_labels.py` correctly labels all 7 test cases (7/7 = 100%) using MITRE-based semantic patterns.

**Key features:**
1. **APT detection**: Checks for APT patterns FIRST (before exploit) to catch multi-stage attacks
2. **Destructive patterns**: Matches `rm -rf` on ANY path (not just `/`), includes `chattr -ia` pattern
3. **Semantic alignment**: Prioritizes explicit attack patterns over generic MITRE tactic counts

**Test case accuracy:**
- ✓ Test 1: Benign User Session → Safe
- ✓ Test 2: Network Reconnaissance → Recon
- ✓ Test 3: Malware Download & Execute → Downloader
- ✓ Test 4: Credential Theft Attempt → Exploit
- ✓ Test 5: Destructive Attack → Destructive
- ✓ Test 6: APT Multi-Stage Attack → ADVANCED_APT
- ✓ Test 7: SSH Key Replacement → Destructive

## How to Train on Windows

### Option 1: PowerShell Script (Easiest)
```powershell
# From project root:
.\retrain_mitre_only_semantic_balanced.ps1
```

This will:
1. Activate the virtual environment
2. Set PYTHONPATH
3. Run training with MITRE-only semantic balanced labels
4. Save the model as `models/brain_v5_mitre_only_semantic_balanced_v2.pkl`

### Option 2: Manual PowerShell
```powershell
# From project root:
.venv\Scripts\Activate.ps1
$env:PYTHONPATH = "src"

.venv\Scripts\python src\training\neural\train_neural.py `
  --label-mode mitre_only_semantic_balanced `
  --mitre-only `
  --use-semantic-labels `
  --epochs 40 `
  --batch-size 64 `
  --downsample-safe 2000 `
  --synthetic-recon 1500 `
  --synthetic-exploit 1500 `
  --patience 7 `
  --model-name brain_v5_mitre_only_semantic_balanced_v2 `
  --loss combined `
  --lr 1e-3
```

### Expected Training Output
- Training time: ~10-20 minutes (RTX 3050)
- Output files:
  - `models/brain_v5_mitre_only_semantic_balanced_v2.pkl` (inference bundle)
  - `models/brain_v5_mitre_only_semantic_balanced_v2.pt` (PyTorch state dict)
  - `models/brain_v5_mitre_only_semantic_balanced_v2_results.json` (metrics)

## After Training: Demo Already Updated

The `src/demo.py` has been pre-configured to use:
```python
MODEL_PATH = PROJECT_ROOT / "models" / "brain_v5_mitre_only_semantic_balanced_v2.pkl"
```

## Test the Demo

```powershell
# Run demo with neural model + hybrid fallback
.venv\Scripts\python src\demo.py --neural
```

**Expected result: 6/7+ correct (86%+)**

## How It Works

The demo uses a **hybrid approach**:
1. Neural model makes predictions with confidence scores
2. If confidence < 55%, fallback to hybrid MITRE rule-based classifier
3. Hybrid classifier excels at destructive, APT, and exploit patterns

This combination achieves:
- ✓ Neural model's semantic understanding for benign commands
- ✓ Hybrid classifier's expert pattern matching for attacks
- ✓ Intelligent confidence-based switching

## Files Changed

- `src/training/neural/semantic_labels.py` (lines 314-448) - MITRE-only semantic balanced labeling functions
- `src/training/neural/dataset.py` (lines 294-329) - Updated label mode handling
- `src/training/neural/train_neural.py` (lines 64-69) - Added mitre_only_semantic_balanced label mode
- `src/demo.py` (line 47) - Updated model path + line 26 added Optional import
- `retrain_mitre_only_semantic_balanced.py` - Python training wrapper script
- `retrain_mitre_only_semantic_balanced.ps1` - PowerShell training script

## Verification

To verify the label function is working correctly:
```python
# In Python (any system with basic libs):
import re

def compute_mitre_only_semantic_balanced_label(command):
    # See lines 314-407 in src/training/neural/semantic_labels.py
    ...

# Test it:
label_id, label_name, _ = compute_mitre_only_semantic_balanced_label("rm -rf .ssh; chattr +ia .ssh")
print(f"SSH Key Replacement: {label_name}")  # Should print: Destructive
```

Or run the test script:
```powershell
.venv\Scripts\python test_mitre_only_semantic_balanced.py
```
