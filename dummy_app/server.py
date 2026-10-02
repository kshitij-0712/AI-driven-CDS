import uvicorn
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
import logging
import json

app = FastAPI(title="Nexus Cloud - Enterprise Dummy App")
logging.basicConfig(level=logging.INFO)

# --- REUSABLE HTML COMPONENTS ---
HTML_HEAD = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nexus Cloud</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-body: #f8fafc;
            --bg-card: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border-color: #e2e8f0;
            --primary: #2563eb;
            --primary-hover: #1d4ed8;
            --indigo: #4f46e5;
            --danger: #e11d48;
            --success: #16a34a;
        }
        * { box-sizing: border-box; font-family: 'Inter', sans-serif; }
        body { margin: 0; background-color: var(--bg-body); color: var(--text-main); display: flex; flex-direction: column; min-height: 100vh; }
        nav { background: var(--bg-card); border-bottom: 1px solid var(--border-color); padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .logo-container { display: flex; align-items: center; gap: 10px; text-decoration: none; color: var(--text-main); font-weight: 700; font-size: 1.25rem; }
        .logo-box { background: var(--primary); color: white; width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; border-radius: 8px; font-weight: bold; }
        .nav-links { display: flex; gap: 1.5rem; align-items: center; font-size: 0.875rem; font-weight: 500; }
        .nav-links a { color: var(--text-muted); text-decoration: none; transition: color 0.2s; }
        .nav-links a:hover { color: var(--primary); }
        .btn-employee { background: #e0e7ff; color: var(--indigo); padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600; text-decoration: none; }
        main { flex-grow: 1; display: flex; flex-direction: column; align-items: center; padding: 2rem; width: 100%; }
        footer { background: var(--bg-card); border-top: 1px solid var(--border-color); padding: 1.5rem; text-align: center; color: var(--text-muted); font-size: 0.875rem; margin-top: auto; }
        
        /* Layouts & Cards */
        .max-w-4xl { max-w: 896px; width: 100%; }
        .max-w-6xl { max-width: 1152px; width: 100%; }
        .card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 12px; padding: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        .grid-3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; }
        .grid-2-1 { display: grid; grid-template-columns: 1fr 2fr; gap: 1.5rem; }
        @media (max-width: 768px) { .grid-2-1 { grid-template-columns: 1fr; } }
        
        /* Typography */
        h1 { font-size: 2.5rem; font-weight: 800; margin-bottom: 1rem; text-align: center; }
        .subtitle { font-size: 1.125rem; color: var(--text-muted); text-align: center; margin-bottom: 2rem; }
        h2 { font-size: 1.875rem; font-weight: 700; margin-top: 0; }
        h3 { font-size: 1.125rem; font-weight: 600; margin-top: 0; margin-bottom: 1rem; }
        
        /* Forms & Buttons */
        .form-group { margin-bottom: 1rem; }
        label { display: block; font-size: 0.875rem; font-weight: 500; color: #334155; margin-bottom: 0.5rem; }
        input[type="text"], input[type="password"], select { width: 100%; padding: 0.75rem; border: 1px solid #cbd5e1; border-radius: 8px; outline: none; font-size: 0.875rem; }
        input:focus, select:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(37,99,235,0.1); }
        .btn-primary { background: var(--primary); color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 600; cursor: pointer; transition: 0.2s; }
        .btn-primary:hover { background: var(--primary-hover); }
        .btn-danger { background: var(--danger); color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 600; cursor: pointer; }
        .flex-row { display: flex; gap: 0.5rem; }
        .flex-row input { flex-grow: 1; }
        
        /* Specialized components */
        .result-box { margin-top: 1rem; padding: 1rem; border-radius: 8px; font-family: monospace; font-size: 0.875rem; border: 1px solid var(--border-color); background: #f1f5f9; display: none; }
        .result-box.error { background: #fef2f2; border-color: #fecdd3; color: #9f1239; }
        .result-box.success { background: #f0fdf4; border-color: #bbf7d0; color: #166534; }
        
        .file-item { padding: 0.75rem; border: 1px solid transparent; border-radius: 6px; cursor: pointer; display: flex; align-items: center; gap: 0.5rem; transition: 0.2s; font-size: 0.875rem; }
        .file-item:hover { background: #f1f5f9; border-color: var(--border-color); }
        .file-item.danger { color: var(--danger); }
        
        .badge { background: #e0e7ff; color: var(--indigo); padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; border: 1px solid #c7d2fe; }
    </style>
</head>
<body>
    <nav>
        <a href="/" class="logo-container">
            <div class="logo-box">N</div>
            Nexus Cloud
        </a>
        <div class="nav-links">
            <a href="/">Home</a>
            <a href="/login">Customer Login</a>
            <a href="/workspace" class="btn-employee">Employee Portal</a>
        </div>
    </nav>
    <main>
"""

HTML_FOOT = """
    </main>
    <footer>
        &copy; 2026 Nexus Cloud Solutions Inc. All rights reserved. | AdaptiveShield Test Environment
    </footer>
</body>
</html>
"""

# ==========================================
# PUBLIC ROUTES
# ==========================================

@app.get("/", response_class=HTMLResponse)
async def public_landing():
    return HTML_HEAD + """
        <div style="max-width: 800px; width: 100%;">
            <h1>Enterprise Cloud Infrastructure</h1>
            <p class="subtitle">Providing secure, scalable solutions. Try our domain availability checker below.</p>
            
            <div class="card" style="margin-bottom: 3rem;">
                <h3>Check Domain Availability (Network Tool)</h3>
                <form onsubmit="event.preventDefault(); submitPublic('/api/network_check', 'domain-input')">
                    <div class="flex-row">
                        <input type="text" id="domain-input" placeholder="e.g. google.com (Try appending ; cat /etc/passwd)">
                        <button type="submit" class="btn-primary">Check</button>
                    </div>
                </form>
                <div id="domain-result" class="result-box"></div>
            </div>
            
            <div class="grid-3">
                <div class="card">
                    <h3>Global Edge Network</h3>
                    <p style="color: var(--text-muted); font-size: 0.875rem;">Deploy your applications globally with milliseconds of latency.</p>
                </div>
                <div class="card">
                    <h3>Zero-Trust Security</h3>
                    <p style="color: var(--text-muted); font-size: 0.875rem;">Military-grade encryption and automated threat isolation built-in.</p>
                </div>
                <div class="card">
                    <h3>Infinite Storage</h3>
                    <p style="color: var(--text-muted); font-size: 0.875rem;">S3-compatible object storage that scales instantly with your needs.</p>
                </div>
            </div>
        </div>
        
        <script>
            async function submitPublic(endpoint, inputId) {
                const val = document.getElementById(inputId).value;
                const resDiv = document.getElementById(inputId === 'domain-input' ? 'domain-result' : 'login-result');
                resDiv.style.display = 'block';
                resDiv.className = 'result-box';
                resDiv.innerText = "Processing...";
                
                try {
                    const response = await fetch(endpoint, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ query: val })
                    });
                    
                    if (response.status === 403) {
                        resDiv.innerText = "BLOCKED BY ADAPTIVESHIELD: Malicious payload detected.";
                        resDiv.className = "result-box error";
                        return;
                    }
                    const data = await response.json();
                    resDiv.innerText = data.result || "Success";
                } catch(e) {
                    resDiv.innerText = "Connection failed. Proxy may have dropped the packet.";
                    resDiv.className = "result-box error";
                }
            }
        </script>
    """ + HTML_FOOT


@app.get("/login", response_class=HTMLResponse)
async def public_login():
    return HTML_HEAD + """
        <div class="card" style="max-width: 400px; width: 100%; margin-top: 2rem;">
            <h2 style="text-align: center; margin-bottom: 0.5rem;">Customer Login</h2>
            <p style="text-align: center; font-size: 0.75rem; color: var(--text-muted); margin-bottom: 1.5rem;">
                Test SQL Injection here (e.g. <code style="background: #f1f5f9; padding: 2px 4px; border-radius: 4px;">' OR 1=1 --</code>)
            </p>
            
            <form onsubmit="event.preventDefault(); submitPublic('/api/login', 'username-input')">
                <div class="form-group">
                    <label>Username / Email</label>
                    <input type="text" id="username-input">
                </div>
                <div class="form-group" style="margin-bottom: 1.5rem;">
                    <label>Password</label>
                    <input type="password" id="password-input">
                </div>
                <button type="submit" class="btn-primary" style="width: 100%; background: #0f172a;">Sign In</button>
            </form>
            <div id="login-result" class="result-box"></div>
        </div>
        
        <script>
            async function submitPublic(endpoint, inputId) {
                const user = document.getElementById('username-input').value;
                const pass = document.getElementById('password-input').value;
                const resDiv = document.getElementById('login-result');
                resDiv.style.display = 'block';
                resDiv.className = 'result-box';
                resDiv.innerText = "Authenticating...";
                
                try {
                    const response = await fetch(endpoint, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username: user, password: pass })
                    });
                    
                    if (response.status === 403) {
                        resDiv.innerText = "BLOCKED BY ADAPTIVESHIELD: SQLi/Exploit detected.";
                        resDiv.className = "result-box error";
                        return;
                    }
                    resDiv.innerText = "Invalid credentials.";
                } catch(e) {
                    resDiv.innerText = "Connection dropped by firewall.";
                    resDiv.className = "result-box error";
                }
            }
        </script>
    """ + HTML_FOOT


# ==========================================
# INTERNAL ROUTES
# ==========================================

@app.get("/workspace", response_class=HTMLResponse)
async def internal_workspace():
    return HTML_HEAD + """
        <div class="max-w-6xl">
            <div style="display: flex; justify-content: space-between; align-items: flex-end; border-bottom: 1px solid var(--border-color); padding-bottom: 1rem; margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem;">
                <div>
                    <h2 style="display: flex; align-items: center; gap: 10px; margin-bottom: 0.5rem;">
                        Enterprise Intranet 
                        <span class="badge">INTERNAL ONLY</span>
                    </h2>
                    <p style="margin: 0; color: var(--text-muted); font-size: 0.875rem;">Simulate realistic employee tasks. The Insider ML model analyzes these behaviors.</p>
                </div>
                
                <div class="card" style="padding: 0.75rem 1rem; display: flex; align-items: center; gap: 1rem;">
                    <div id="avatar-icon" style="width: 40px; height: 40px; border-radius: 50%; background: #e2e8f0; display: flex; align-items: center; justify-content: center; font-weight: bold; color: #64748b;">D</div>
                    <div>
                        <label style="font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.25rem;">Active Session</label>
                        <select id="emp-identity" onchange="updateRoleUI()" style="border: none; padding: 0; background: transparent; font-weight: 600; cursor: pointer; color: var(--text-main);">
                            <option value="developer|dev_alice">Alice Smith (Developer)</option>
                            <option value="hr|hr_bob">Bob Jones (HR Manager)</option>
                            <option value="finance|fin_charlie">Charlie Brown (Finance)</option>
                            <option value="admin|admin_dave">Dave (SysAdmin)</option>
                        </select>
                    </div>
                </div>
            </div>

            <div class="grid-2-1">
                <!-- LEFT COLUMN: Corporate File Explorer -->
                <div class="card" style="padding: 0;">
                    <div style="padding: 1rem; border-bottom: 1px solid var(--border-color); background: #f8fafc; font-weight: 600;">
                        Corporate File Share
                    </div>
                    <div style="padding: 1rem; display: flex; flex-direction: column; gap: 0.25rem;">
                        <div class="file-item" onclick="simAction('read_file', '/hr/payroll_2026.csv')">
                            📄 /hr/payroll_2026.csv
                        </div>
                        <div class="file-item" onclick="simAction('read_file', '/finance/Q3_ledger.xlsx')">
                            📊 /finance/Q3_ledger.xlsx
                        </div>
                        <div class="file-item" onclick="simAction('read_file', '/src/core_auth_logic.py')">
                            💻 /src/core_auth_logic.py
                        </div>
                        <div class="file-item danger" onclick="simAction('read_file', '/etc/shadow')">
                            🔒 /etc/shadow (System protected)
                        </div>
                    </div>
                </div>

                <!-- RIGHT COLUMN: Role-Specific Tooling Forms -->
                <div style="display: flex; flex-direction: column; gap: 1.5rem;">
                    
                    <!-- Dynamic Tool Panel -->
                    <div class="card" style="padding: 0; overflow: hidden;">
                        <div id="tool-header" style="padding: 1rem; border-bottom: 1px solid #c7d2fe; background: #e0e7ff; color: #3730a3; font-weight: 600;">
                            Department Tools
                        </div>
                        <div style="padding: 1.5rem;" id="tool-content">
                            <!-- Injected by JS -->
                        </div>
                    </div>

                    <!-- Universal Tool: Cloud Sync (Always visible) -->
                    <div class="card">
                        <h3 style="font-size: 1rem; margin-bottom: 1rem;">External Cloud Sync (Mega/Dropbox)</h3>
                        <div class="flex-row">
                            <input type="text" id="sync-path" value="/src/">
                            <button onclick="simAction('cloud_sync', document.getElementById('sync-path').value)" class="btn-primary" style="background: #0f172a;">Sync Directory</button>
                        </div>
                    </div>

                </div>
            </div>
            
            <!-- Result Console -->
            <div id="action-result" class="result-box"></div>

        </div>

        <script>
            // --- UI Logic ---
            const tools = {
                'developer': `
                    <form onsubmit="event.preventDefault(); simAction('deploy_code', document.getElementById('branch-name').value)">
                        <div class="form-group">
                            <label>Deploy Branch to Production Server</label>
                            <div class="flex-row">
                                <input type="text" id="branch-name" placeholder="feature/auth-bypass">
                                <button type="submit" class="btn-primary">Deploy</button>
                            </div>
                        </div>
                    </form>
                `,
                'hr': `
                    <form onsubmit="event.preventDefault(); simAction('search_employee', document.getElementById('emp-name').value)">
                        <div class="form-group">
                            <label>Search Confidential Employee Record</label>
                            <div class="flex-row">
                                <input type="text" id="emp-name" placeholder="e.g. John Doe">
                                <button type="submit" class="btn-primary" style="background: var(--danger);">Search DB</button>
                            </div>
                        </div>
                    </form>
                `,
                'finance': `
                    <form onsubmit="event.preventDefault(); simAction('wire_transfer', document.getElementById('amount').value)">
                        <div class="form-group">
                            <label>Authorize Internal Ledger Transfer</label>
                            <div class="flex-row">
                                <input type="text" id="amount" placeholder="$ Amount">
                                <button type="submit" class="btn-primary" style="background: var(--success);">Process</button>
                            </div>
                        </div>
                    </form>
                `,
                'admin': `
                    <form onsubmit="event.preventDefault(); simAction('sys_diagnostic', document.getElementById('sys-cmd').value)">
                        <div class="form-group">
                            <label>Run System Diagnostic (Ping/Restart)</label>
                            <div class="flex-row">
                                <input type="text" id="sys-cmd" placeholder="ping 10.0.0.1">
                                <button type="submit" class="btn-primary" style="background: #0f172a;">Execute as Root</button>
                            </div>
                        </div>
                    </form>
                `
            };

            function updateRoleUI() {
                const identity = document.getElementById('emp-identity').value.split('|');
                const role = identity[0];
                document.getElementById('tool-header').innerText = `${role.toUpperCase()} Department Tools`;
                document.getElementById('tool-content').innerHTML = tools[role];
                document.getElementById('avatar-icon').innerText = role.charAt(0).toUpperCase();
            }

            // Initialize
            updateRoleUI();

            // --- Simulation Logic ---
            async function simAction(actionType, targetValue) {
                const identity = document.getElementById('emp-identity').value.split('|');
                const role = identity[0];
                const userId = identity[1];
                
                const resDiv = document.getElementById('action-result');
                resDiv.style.display = 'block';
                resDiv.className = "result-box";
                resDiv.innerText = "Processing request...";

                let simulated_command = "";
                let file_path = "";
                let is_cloud_upload = false;

                if (actionType === 'read_file') {
                    simulated_command = `cat ${targetValue}`;
                    file_path = targetValue;
                } else if (actionType === 'cloud_sync') {
                    simulated_command = `rsync -av ${targetValue} mega.nz/backup`;
                    file_path = targetValue;
                    is_cloud_upload = true;
                } else if (actionType === 'deploy_code') {
                    simulated_command = `git checkout ${targetValue} && make deploy`;
                } else if (actionType === 'search_employee') {
                    simulated_command = `grep "${targetValue}" /hr/database.db`;
                } else if (actionType === 'sys_diagnostic') {
                    simulated_command = targetValue; // Direct admin command execution
                }

                try {
                    const response = await fetch('/workspace/api/action', {
                        method: 'POST',
                        headers: { 
                            'Content-Type': 'application/json',
                            'x-user-id': userId,
                            'x-user-role': role
                        },
                        body: JSON.stringify({
                            action: actionType,
                            command: simulated_command,
                            file_path: file_path,
                            cloud_upload: is_cloud_upload
                        })
                    });
                    
                    if (response.status === 403) {
                        resDiv.className = "result-box error";
                        resDiv.innerText = "🚨 BLOCKED BY ADAPTIVESHIELD: Insider Threat Detected. Session Terminated.";
                        return;
                    }

                    const data = await response.json();
                    resDiv.className = "result-box success";
                    resDiv.innerText = `Success: Action approved by security proxy.\\n\\nBackend Output: ${data.message}`;
                } catch(e) {
                    resDiv.className = "result-box error";
                    resDiv.innerText = `Network Error: Proxy dropped the connection completely.`;
                }
            }
        </script>
    """ + HTML_FOOT


@app.post("/{path:path}")
async def generic_action_handler(path: str, request: Request):
    """Catch-all for the dummy backend to return success."""
    return JSONResponse(content={"result": f"Action on /{path} processed normally by backend.", "message": "Authorized"})


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8090)
