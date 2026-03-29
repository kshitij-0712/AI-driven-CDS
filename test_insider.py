from src.agents.insider.insider_detection import analyze_session

# Test session (stealthy attacker)
session = {
    "commands": [],
    "first_ts": 1,
    "last_ts": 2,
    "download_shas": []
}

result = analyze_session(session)

print("=== TEST OUTPUT ===")
print(result)