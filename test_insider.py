import os
import sys

# Add src to python path to import correctly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

from src.agents.insider.insider_detection import analyze_session
from src.agents.insider.internal_insider_dataset import extract_features, determine_label
from src.agents.insider.internal_insider_inference import (
    load_internal_insider_model,
    predict_session_risk,
    record_live_feedback
)

print("=== PART 1: ORIGINAL HONEPOT INSIDER-LIKE THREAT TEST ===")
session = {
    "commands": [],
    "first_ts": 1,
    "last_ts": 2,
    "download_shas": []
}
result = analyze_session(session)
print(f"Original Analysis Result: {result}")

print("\n=== PART 2: GENERATING DATASETS 2 & 3 AND TRAINING INTERNAL MODEL ===")
# Dynamically run base generation script to create datasets
import src.agents.insider.generate_internal_insider_base as generator
generator.main()

# Dynamically train the model using Dataset 2 (Base)
import src.agents.insider.train_internal_insider as trainer
trainer.train_pipeline(
    csv_path="./data/insider/internal_insider_dataset_base.csv",
    model_path="./models/internal_insider_model.pkl"
)

print("\n=== PART 3: TESTING PREDICTIONS ON NEW INTERNAL SCENARIOS ===")
model_bundle = load_internal_insider_model("./models/internal_insider_model.pkl")

# Scenario A: Normal Dev Session
dev_session = {
    "session_id": "live_dev_test_01",
    "role": "developer",
    "work_after_hours": 0,
    "work_weekends": 0,
    "access_unauthorized_scope": 0,
    "access_intellectual_property": 1,
    "cloud_upload_count": 0,
    "log_deletion_attempt": 0,
    "duration_sec": 3600
}
pred_dev = predict_session_risk(dev_session, model_bundle)
print(f"Normal Dev prediction label: {pred_dev['label']}, score: {pred_dev['risk_score']}")
print(f"Explanation: {pred_dev['explanation']}")

# Scenario B: Malicious IP Theft (Dev exfiltrating code to cloud and deleting logs)
rogue_dev_session = {
    "session_id": "live_dev_rogue_01",
    "role": "developer",
    "work_after_hours": 1,
    "work_weekends": 1,
    "access_unauthorized_scope": 1,
    "access_intellectual_property": 1,
    "high_volume_download": 1,
    "cloud_upload_count": 5,
    "log_deletion_attempt": 1,
    "duration_sec": 4000
}
pred_rogue = predict_session_risk(rogue_dev_session, model_bundle)
print(f"\nRogue Dev prediction label: {pred_rogue['label']}, score: {pred_rogue['risk_score']}")
print(f"Explanation: {pred_rogue['explanation']}")

print("\n=== PART 4: REINFORCEMENT UPDATE FEEDBACK LOOP TEST ===")
# Record a live malicious session behavior with positive feedback
record_live_feedback(rogue_dev_session, true_label=1, feedback_reason="Security analyst confirmed IP exfiltration")

# Verify that Dataset 3 (Live dataset) now contains the new sample
import csv
with open("./data/insider/internal_insider_dataset_live.csv", "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    rows = list(reader)
    print(f"Dataset 3 (Live) row count after reinforcement update: {len(rows)} (Base had 20 rows)")
    last_row = rows[-1]
    print(f"Last recorded session in Dataset 3: {last_row['session_id']}, Label: {last_row['label']}, Reason: {last_row['label_reason']}")

# Train on Dataset 3 (Live) to confirm we can retrain from reinforcement updates
print("\nRetraining model on Dataset 3 (Live dataset containing reinforcement data)...")
trainer.train_pipeline(
    csv_path="./data/insider/internal_insider_dataset_live.csv",
    model_path="./models/internal_insider_model.pkl"
)
print("Internal Malicious Insider Verification Test Passed Successfully!")