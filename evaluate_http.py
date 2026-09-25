import sys
import torch
import numpy as np
from pathlib import Path

# Add src to path
src_path = Path('src').absolute()
sys.path.insert(0, str(src_path))

from training.neural.model import UnifiedThreatClassifier
from training.neural.compare_models import HTTP_TEST_CASES, encode_commands, extract_mitre_features

CLASS_NAMES = ['Safe', 'Recon', 'Downloader', 'Exploit', 'Destructive', 'ADVANCED_APT']

# Load the best model (2048)
checkpoint = torch.load('models/brain_v6_neural_2048.pt', map_location='cpu', weights_only=False)
model = UnifiedThreatClassifier()
model.load_state_dict(checkpoint['model_state_dict'])
model.eval()

print(f"{'='*100}")
print(f"{'HTTP Attack Detection Breakdown (brain_v6_neural_2048)':^100}")
print(f"{'='*100}\n")

for commands, expected, description in HTTP_TEST_CASES:
    encoded, lengths = encode_commands(commands, 2048)
    mitre_features = extract_mitre_features(commands)
    mitre = torch.tensor([mitre_features], dtype=torch.float32)
    changes = torch.zeros((1, 20), dtype=torch.float32)
    triage = torch.zeros((1, 70), dtype=torch.float32)
    modality_mask = torch.tensor([[False, False, True, True]], dtype=torch.bool)
    
    with torch.no_grad():
        preds, probs = model.predict(encoded, mitre, changes, triage, lengths, modality_mask)
        
    pred_class = preds[0].item()
    pred_name = CLASS_NAMES[pred_class]
    probs_array = probs[0].cpu().numpy()
    
    status = "✅ CORRECT" if pred_name == expected else "❌ FAILED"
    
    print(f"[{status}] {description}")
    print(f"  Payload:  {commands.replace(chr(10), '  ')[:80]}...")
    print(f"  Expected: {expected}")
    print(f"  Result:   {pred_name} ({(probs_array[pred_class]*100):.1f}%)")
    
    # Print the full distribution
    dist = " | ".join([f"{CLASS_NAMES[i]}: {(probs_array[i]*100):.1f}%" for i in range(6)])
    print(f"  Dist:     {dist}\n")

