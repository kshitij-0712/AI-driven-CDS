import os
import sys
import yaml
import json
import asyncio
import httpx
import requests
from fastapi import Request
from starlette.datastructures import Headers

# Load .env manually if it exists
if os.path.exists(".env"):
    with open(".env", "r") as f:
        for line in f:
            if line.strip() and not line.startswith("#") and "=" in line:
                key, val = line.strip().split("=", 1)
                os.environ[key] = val

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from interceptor.session_store import SessionStore
from honeypot import HoneypotGenerator
from honeypot.crawler import AppCrawler

def load_config(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

async def test_crawler():
    print("Testing AppCrawler...")
    crawler = AppCrawler(target_url="http://127.0.0.1:8090", output_path="./runtime/app_structure_test.json")
    await crawler.crawl()
    
    assert os.path.exists("./runtime/app_structure_test.json"), "Crawler output file should exist."
    with open("./runtime/app_structure_test.json", "r") as f:
        data = json.load(f)
    print("Crawler test passed! Pages found:")
    for path, page in data.get("pages", {}).items():
        print(f" - {path}: {page.get('title')}")

async def test_generator_mock():
    print("\nTesting HoneypotGenerator (Direct Module Test)...")
    config = load_config("config/settings.yaml")
    store = SessionStore("./runtime/test_adaptiveshield.db")
    generator = HoneypotGenerator(config, store)
    
    class MockRequest:
        def __init__(self, method, path, query="", headers=None):
            self.method = method
            self.url = type('url', (), {'path': path, 'query': query})()
            self.headers = Headers(headers or {})
            
    req = MockRequest("GET", "/admin-panel", "user=attacker")
    decision = {
        "label": "Recon",
        "action": "redirect_to_decoy"
    }
    session_id = store.get_or_create_session("192.168.1.100")
    
    response = await generator.generate_response(req, "", decision, session_id)
    print(f"Honeypot Response Status: {response.status_code}")
    print(f"Honeypot Response Body: {response.body[:150].decode('utf-8')}...")
    
    print("Verifying Cache...")
    cached_val = generator.cache.get(session_id, "GET", "/admin-panel", "user=attacker", "", False)
    assert cached_val is not None, "Cache should store generated response."
    print("Cache verification passed!")
    
    print("Verifying state update persistence...")
    generator.state_manager.update_state(session_id, {"hacked": True, "files": ["rce.sh"]})
    saved_state = generator.state_manager.load_state(session_id)
    assert saved_state.get("hacked") is True, "State should be persisted."
    assert "rce.sh" in saved_state.get("files", []), "State list updates should be merged."
    print("State persistence passed!")
    if os.path.exists("./runtime/test_adaptiveshield.db"):
        os.remove("./runtime/test_adaptiveshield.db")

async def test_gemini_integration():
    print("\nTesting Gemini API Integration...")
    config = load_config("config/settings.yaml")
    store = SessionStore("./runtime/test_adaptiveshield.db")
    generator = HoneypotGenerator(config, store)
    
    class MockRequest:
        def __init__(self, method, path, query="", headers=None):
            self.method = method
            self.url = type('url', (), {'path': path, 'query': query})()
            self.headers = Headers(headers or {})
            
    req = MockRequest("GET", "/login", "id=1' OR '1'='1")
    decision = {
        "label": "Exploit",
        "action": "redirect_to_decoy"
    }
    session_id = store.get_or_create_session("192.168.1.100")
    
    try:
        response = await generator.generate_response(req, "", decision, session_id)
        print(f"Gemini Response Status: {response.status_code}")
        print(f"Gemini Response Body: {response.body[:300].decode('utf-8')}...")
        assert response.status_code in [200, 401, 403, 500], "Should return a realistic status code"
        print("Gemini API integration test passed successfully!")
    except Exception as e:
        print(f"Gemini API test encountered an error: {e}")
        
    if os.path.exists("./runtime/test_adaptiveshield.db"):
        os.remove("./runtime/test_adaptiveshield.db")

def test_live_proxy():
    print("\nTesting Live Proxy integration on http://127.0.0.1:8000...")
    proxy_url = "http://127.0.0.1:8000"
    
    print("[Safe Request] Requesting '/'")
    try:
        r1 = requests.get(f"{proxy_url}/")
        print(f"Status: {r1.status_code}")
        print(f"Body snippet: {r1.text[:100]}...")
        assert "Daamy App" in r1.text or "Adaptive Network Terminal" in r1.text or "Dashboard" in r1.text, "Should forward to dummy app."
    except Exception as e:
        print(f"Failed to reach live proxy: {e}. (Ensure docker container is running with new changes)")
        return

    print("\n[Recon Request] Requesting non-existent admin page '/dev-admin'")
    r2 = requests.get(f"{proxy_url}/dev-admin")
    print(f"Status: {r2.status_code}")
    print(f"Body snippet: {r2.text[:200]}...")

    print("\n[Exploit Request] Sending SQL injection payload '/profile?id=1%27%20OR%201=1--'")
    r3 = requests.get(f"{proxy_url}/profile?id=1%27%20OR%201=1--")
    print(f"Status: {r3.status_code}")
    print(f"Body snippet: {r3.text[:200]}...")

async def main():
    await test_crawler()
    await test_generator_mock()
    await test_gemini_integration()
    test_live_proxy()

if __name__ == "__main__":
    asyncio.run(main())
