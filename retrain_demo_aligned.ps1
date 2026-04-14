# PowerShell script to retrain the neural model with fixed demo-aligned labels
# Run this from the project root on Windows

Write-Host "`n$(("="*80))`n RETRAINING NEURAL MODEL WITH FIXED DEMO-ALIGNED LABELS`n$(("="*80))" -ForegroundColor Cyan

# Activate venv
& .\.venv\Scripts\Activate.ps1

# Set PYTHONPATH
$env:PYTHONPATH = "src"

# Training arguments optimized for demo alignment
$TrainingArgs = @(
    "src/training/neural/train_neural.py",
    "--label-mode", "demo-aligned",
    "--mitre-only",
    "--use-semantic-labels",
    "--epochs", "40",
    "--batch-size", "64",
    "--downsample-safe", "2000",
    "--synthetic-recon", "1500",
    "--synthetic-exploit", "1500",
    "--patience", "7",
    "--model-name", "brain_v5_mitre_only_demo_aligned_v2",
    "--loss", "combined",
    "--lr", "1e-3"
)

Write-Host "`nTraining command:`n" -ForegroundColor Green
Write-Host ".venv\Scripts\python $($TrainingArgs -join ' ')" -ForegroundColor Yellow
Write-Host ""

# Run training
& .\.venv\Scripts\python $TrainingArgs

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n$(("="*80))`n ✓ Training completed successfully!`n$(("="*80))" -ForegroundColor Green
} else {
    Write-Host "`n$(("="*80))`n ✗ Training failed with exit code $LASTEXITCODE`n$(("="*80))" -ForegroundColor Red
}

exit $LASTEXITCODE
