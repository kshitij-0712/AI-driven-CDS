import os
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
import logging

app = FastAPI(title="Nexus Cloud - Public Marketing & Customer Portal")
logging.basicConfig(level=logging.INFO)

HTML_PUBLIC_HEAD = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nexus Cloud - Enterprise Distributed Systems & AI Infrastructure</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-body: #0b0f19;
            --bg-card: #111827;
            --text-main: #f9fafb;
            --text-muted: #9ca3af;
            --border-color: #1f2937;
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --accent: #8b5cf6;
            --danger: #ef4444;
            --success: #10b981;
        }
        * { box-sizing: border-box; font-family: 'Inter', sans-serif; }
        body { margin: 0; background-color: var(--bg-body); color: var(--text-main); display: flex; flex-direction: column; min-height: 100vh; }
        nav { background: rgba(17, 24, 39, 0.9); backdrop-filter: blur(10px); border-bottom: 1px solid var(--border-color); padding: 1.25rem 3rem; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 100; }
        .logo-container { display: flex; align-items: center; gap: 12px; text-decoration: none; color: white; font-weight: 800; font-size: 1.35rem; }
        .logo-box { background: linear-gradient(135deg, var(--primary), var(--accent)); color: white; width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; border-radius: 10px; font-weight: 800; }
        .nav-links { display: flex; gap: 2rem; align-items: center; font-size: 0.9rem; font-weight: 500; }
        .nav-links a { color: var(--text-muted); text-decoration: none; transition: color 0.2s; }
        .nav-links a:hover { color: white; }
        .btn-customer { background: linear-gradient(135deg, var(--primary), #2563eb); color: white; padding: 0.6rem 1.4rem; border-radius: 8px; font-weight: 600; text-decoration: none; box-shadow: 0 4px 14px rgba(59, 130, 246, 0.4); }
        main { flex-grow: 1; display: flex; flex-direction: column; align-items: center; padding: 3rem 1.5rem; width: 100%; max-width: 1200px; margin: 0 auto; }
        footer { background: var(--bg-card); border-top: 1px solid var(--border-color); padding: 2rem; text-align: center; color: var(--text-muted); font-size: 0.85rem; margin-top: auto; }
        
        .hero { text-align: center; margin: 2rem 0 3.5rem 0; max-width: 850px; }
        .hero-badge { display: inline-block; background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.3); color: #60a5fa; padding: 0.35rem 0.9rem; border-radius: 999px; font-size: 0.8rem; font-weight: 600; margin-bottom: 1.5rem; }
        h1 { font-size: 3.25rem; font-weight: 900; line-height: 1.15; margin: 0 0 1.25rem 0; background: linear-gradient(180deg, #ffffff, #94a3b8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .subtitle { font-size: 1.2rem; color: var(--text-muted); line-height: 1.6; margin: 0 auto 2.5rem auto; }
        
        .card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 16px; padding: 2rem; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4); margin-bottom: 2rem; }
        .grid-3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.75rem; width: 100%; }
        
        .form-group { margin-bottom: 1.25rem; }
        label { display: block; font-size: 0.85rem; font-weight: 600; color: #cbd5e1; margin-bottom: 0.5rem; }
        input[type="text"], input[type="password"] { width: 100%; padding: 0.85rem 1rem; background: #0b0f19; border: 1px solid #374151; border-radius: 10px; color: white; outline: none; font-size: 0.9rem; }
        input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.25); }
        .btn-submit { background: var(--primary); color: white; border: none; padding: 0.85rem 1.75rem; border-radius: 10px; font-weight: 600; cursor: pointer; transition: 0.2s; }
        .btn-submit:hover { background: var(--primary-hover); }
        .flex-row { display: flex; gap: 0.75rem; }
        .flex-row input { flex-grow: 1; }
        
        .result-box { margin-top: 1.25rem; padding: 1.25rem; border-radius: 10px; font-family: monospace; font-size: 0.875rem; border: 1px solid var(--border-color); background: #0b0f19; display: none; line-height: 1.5; }
        .result-box.error { background: rgba(239, 68, 68, 0.1); border-color: rgba(239, 68, 68, 0.3); color: #f87171; }
        .result-box.success { background: rgba(16, 185, 129, 0.1); border-color: rgba(16, 185, 129, 0.3); color: #34d399; }
    </style>
</head>
<body>
    <nav>
        <a href="/" class="logo-container">
            <div class="logo-box">N</div>
            Nexus Cloud
        </a>
        <div class="nav-links">
            <a href="/">Products</a>
            <a href="/docs">API Reference</a>
            <a href="/login" class="btn-customer">Customer Console</a>
        </div>
    </nav>
    <main>
"""

HTML_PUBLIC_FOOT = """
    </main>
    <footer>
        &copy; 2026 Nexus Cloud Technologies Inc. All rights reserved. | Public Customer Facing Gateway (:8080)
    </footer>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def public_index():
    return HTML_PUBLIC_HEAD + """
        <div class="hero">
            <div class="hero-badge">NEXUS CLOUD 4.0 PLATFORM</div>
            <h1>Global Edge Compute & Distributed AI Workloads</h1>
            <p class="subtitle">
                Run low-latency LLM inference, Kubernetes clusters, and multi-tenant serverless infrastructure across 75 global regions with 99.999% SLA.
            </p>
        </div>

        <div class="card" style="width: 100%; max-width: 800px;">
            <h3 style="margin-top: 0; font-size: 1.25rem;">Network Latency & Endpoint Diagnostic (Public Tool)</h3>
            <p style="color: var(--text-muted); font-size: 0.85rem; margin-bottom: 1.25rem;">
                Test ping and DNS propagation to your domain from our nearest edge cluster.
                <br><span style="color: #60a5fa;">External Security Testing: Try inputting command injection payloads like: <code>google.com; cat /etc/passwd</code></span>
            </p>
            <form onsubmit="event.preventDefault(); submitDiagnostic()">
                <div class="flex-row">
                    <input type="text" id="target-domain" placeholder="e.g. google.com, api.github.com" required>
                    <button type="submit" class="btn-submit">Test Latency</button>
                </div>
            </form>
            <div id="diagnostic-result" class="result-box"></div>
        </div>

        <div class="grid-3">
            <div class="card">
                <h4 style="color: #60a5fa; margin-top: 0; font-size: 1.1rem;">Nexus Foundation AI</h4>
                <p style="color: var(--text-muted); font-size: 0.875rem;">
                    Sub-millisecond token generation across specialized GPU clusters with automated model parallelization.
                </p>
            </div>
            <div class="card">
                <h4 style="color: #a78bfa; margin-top: 0; font-size: 1.1rem;">Zero-Trust Mesh</h4>
                <p style="color: var(--text-muted); font-size: 0.875rem;">
                    mTLS encryption, automated rotation of cryptographic identity keys, and hardware security enclave isolation.
                </p>
            </div>
            <div class="card">
                <h4 style="color: #34d399; margin-top: 0; font-size: 1.1rem;">Global Edge Storage</h4>
                <p style="color: var(--text-muted); font-size: 0.875rem;">
                    Multi-master S3 compatible object storage with automatic geo-replication and instant edge caching.
                </p>
            </div>
        </div>

        <script>
            async function submitDiagnostic() {
                const domain = document.getElementById('target-domain').value;
                const resDiv = document.getElementById('diagnostic-result');
                resDiv.style.display = 'block';
                resDiv.className = 'result-box';
                resDiv.innerText = "Connecting to edge ping probe for " + domain + "...";

                try {
                    const response = await fetch('/api/public/ping', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ target: domain })
                    });
                    
                    if (response.status === 403) {
                        resDiv.className = 'result-box error';
                        resDiv.innerText = "🛡️ ADAPTIVESHIELD GUARD: Request blocked. Command injection / Exploit detected by Neural Threat Classifier.";
                        return;
                    }
                    const data = await response.json();
                    resDiv.className = 'result-box success';
                    resDiv.innerText = data.output || "Ping OK: 14.2ms RTT to " + domain;
                } catch(e) {
                    resDiv.className = 'result-box error';
                    resDiv.innerText = "Connection terminated by proxy guard.";
                }
            }
        </script>
    """ + HTML_PUBLIC_FOOT

@app.get("/login", response_class=HTMLResponse)
async def public_login():
    return HTML_PUBLIC_HEAD + """
        <div class="card" style="max-width: 440px; width: 100%; margin: 2rem auto;">
            <h2 style="text-align: center; margin-top: 0; font-size: 1.75rem;">Customer Console</h2>
            <p style="text-align: center; font-size: 0.85rem; color: var(--text-muted); margin-bottom: 2rem;">
                Sign in to manage your cloud compute clusters and billing subscriptions.
                <br><br><span style="color: #60a5fa;">External Security Testing: Try inputting SQL Injection payloads like: <code>admin' OR '1'='1</code></span>
            </p>

            <form onsubmit="event.preventDefault(); submitLogin()">
                <div class="form-group">
                    <label>Corporate Account Email / Username</label>
                    <input type="text" id="cust-user" placeholder="developer@company.com" required>
                </div>
                <div class="form-group" style="margin-bottom: 2rem;">
                    <label>Account Password</label>
                    <input type="password" id="cust-pass" placeholder="••••••••••••" required>
                </div>
                <button type="submit" class="btn-submit" style="width: 100%;">Authenticate</button>
            </form>
            <div id="login-result" class="result-box"></div>
        </div>

        <script>
            async function submitLogin() {
                const u = document.getElementById('cust-user').value;
                const p = document.getElementById('cust-pass').value;
                const resDiv = document.getElementById('login-result');
                resDiv.style.display = 'block';
                resDiv.className = 'result-box';
                resDiv.innerText = "Validating customer credentials...";

                try {
                    const response = await fetch('/api/public/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username: u, password: p })
                    });
                    
                    if (response.status === 403) {
                        resDiv.className = 'result-box error';
                        resDiv.innerText = "🛡️ ADAPTIVESHIELD GUARD: Authentication blocked. SQL Injection attack pattern detected.";
                        return;
                    }
                    resDiv.className = 'result-box error';
                    resDiv.innerText = "Authentication failed: Invalid credentials for customer account.";
                } catch(e) {
                    resDiv.className = 'result-box error';
                    resDiv.innerText = "Connection rejected by firewall guard.";
                }
            }
        </script>
    """ + HTML_PUBLIC_FOOT

@app.get("/docs", response_class=HTMLResponse)
async def public_docs():
    return HTML_PUBLIC_HEAD + """
        <div style="width: 100%; max-width: 900px;">
            <h1>Nexus Cloud API Documentation</h1>
            <p class="subtitle" style="text-align: left; margin-bottom: 2rem;">
                Public REST API endpoints for customer automation and workload provisioning.
            </p>
            <div class="card">
                <h3 style="margin-top: 0;">GET /v1/regions</h3>
                <p style="color: var(--text-muted); font-size: 0.85rem;">Returns list of active global GPU compute regions.</p>
                <h3 style="margin-top: 1.5rem;">POST /v1/clusters/provision</h3>
                <p style="color: var(--text-muted); font-size: 0.85rem;">Deploys a new Kubernetes worker node group.</p>
            </div>
        </div>
    """ + HTML_PUBLIC_FOOT

@app.post("/api/public/ping")
async def api_ping(request: Request):
    data = await request.json()
    target = data.get("target", "localhost")
    return JSONResponse(content={
        "status": "success",
        "output": f"64 bytes from {target}: icmp_seq=1 ttl=118 time=14.2 ms\n64 bytes from {target}: icmp_seq=2 ttl=118 time=13.8 ms\n-- {target} ping statistics: 0% packet loss --"
    })

@app.post("/api/public/login")
async def api_login(request: Request):
    return JSONResponse(status_code=401, content={"error": "invalid_credentials"})

@app.post("/{path:path}")
async def catch_all_public(path: str, request: Request):
    return JSONResponse(content={"result": f"Public endpoint /{path} handled."})

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)
