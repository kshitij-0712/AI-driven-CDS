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

# Filter down to 5 representative personas for the identity selector
CORE_EMPLOYEE_IDS = ["usr_dev_01", "usr_sre_02", "usr_sup_03", "usr_hr_04", "usr_fin_05"]
ALL_EMPLOYEES = COMPANY_PROFILE.get("employees", [])
CORE_EMPLOYEES = [e for e in ALL_EMPLOYEES if e.get("user_id") in CORE_EMPLOYEE_IDS]
if not CORE_EMPLOYEES:
    CORE_EMPLOYEES = ALL_EMPLOYEES[:5]

# Real corporate file contents for legitimate task responses
CORPORATE_FILES = {
    "/models/nexus-foundation-70b/config.json": json.dumps({
        "model_type": "transformer",
        "architecture": "NexusLlama-70B-MoE",
        "hidden_size": 8192,
        "num_attention_heads": 64,
        "num_experts": 8,
        "vocab_size": 32000,
        "quantization": "FP8",
        "training_loss": 0.842,
        "checkpoint_status": "staged_evaluation",
        "last_trained": "2026-10-18T04:22:10Z"
    }, indent=2),
    "/models/nexus-foundation-70b/weights_manifest.json": json.dumps({
        "shards": 8,
        "total_size_gb": 138.4,
        "storage_bucket": "s3://nexus-models-internal-prod/checkpoints/run42/",
        "sha256": "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
        "encryption": "AES-256-GCM"
    }, indent=2),
    "/experiments/eval_benchmarks_run42.json": json.dumps({
        "eval_id": "RUN-42-GSM8K",
        "mmlu_score": 88.4,
        "gsm8k_accuracy": 91.2,
        "code_eval_pass1": 74.8,
        "gpu_hours": 1420.5,
        "lead_researcher": "Dr. Sarah Chen"
    }, indent=2),
    "/src/ai/distributed_trainer.py": "# Nexus Foundation Model Distributed Trainer\n# Copyright (c) 2026 Nexus Cloud Technologies Inc.\nimport torch\nimport deepspeed\n\ndef launch_distributed_stage(config_path):\n    print(f'Initializing DeepSpeed ZeRO-3 on {torch.cuda.device_count()} GPUs')\n    return True\n",
    "/infrastructure/terraform.tfstate": json.dumps({
        "version": 4,
        "terraform_version": "1.7.5",
        "serial": 182,
        "resources": [
            {
                "type": "aws_eks_cluster",
                "name": "nexus_primary_cluster",
                "status": "ACTIVE",
                "region": "us-east-1",
                "endpoint": "https://k8s-prod.nexuscloud.internal:6443"
            },
            {
                "type": "aws_s3_bucket",
                "name": "nexus-models-internal-prod",
                "versioning": "Enabled"
            }
        ]
    }, indent=2),
    "/kubernetes/k8s_cluster_nodes.json": json.dumps({
        "cluster": "nexus-k8s-us-east-1",
        "nodes": [
            {"name": "gpu-worker-h100-01", "role": "ai_worker", "status": "Ready", "gpu": "8x H100 SXM5", "alloc_gpu": "100%"},
            {"name": "gpu-worker-h100-02", "role": "ai_worker", "status": "Ready", "gpu": "8x H100 SXM5", "alloc_gpu": "87.5%"},
            {"name": "core-services-node-01", "role": "control_plane", "status": "Ready", "pods": 24, "cpu": "128vCPU"},
            {"name": "ingress-proxy-node-01", "role": "edge_proxy", "status": "Ready", "pods": 16, "cpu": "64vCPU"}
        ]
    }, indent=2),
    "/support/tickets/enterprise_tickets_q3.json": json.dumps([
        {
            "ticket_id": "NEXUS-8910",
            "account": "Enterprise FinTech Global",
            "tier": "Tier-1 Mission Critical",
            "title": "API inference timeout during market close peak",
            "assigned_to": "Carol Rodriguez",
            "sla_remaining_minutes": 45,
            "status": "INVESTIGATING"
        },
        {
            "ticket_id": "NEXUS-8914",
            "account": "BioGen AI Labs",
            "tier": "Enterprise Dedicated",
            "title": "Requesting quota expansion to 64 concurrent GPU worker instances",
            "assigned_to": "Carol Rodriguez",
            "sla_remaining_minutes": 180,
            "status": "APPROVED"
        }
    ], indent=2),
    "/finance/q3_invoices.xlsx": json.dumps({
        "fiscal_quarter": "2026-Q3",
        "total_billed_usd": 14250000.0,
        "recurring_arr_usd": 57000000.0,
        "accounts_receivable_aging_30d": 210000.0,
        "controller_approved": True,
        "sign_off": "David Sterling"
    }, indent=2),
    "/hr/employees_2026.csv": "emp_id,full_name,department,role,work_location\nusr_dev_01,Dr. Sarah Chen,AI_Platform,Lead ML Research Engineer,Austin HQ (Onsite)\nusr_sre_02,Marcus Vance,Cloud_DevOps,Principal Infrastructure SRE,Austin HQ (Onsite)\nusr_sup_03,Carol Rodriguez,Customer_Success,Senior Customer Support Lead,Remote (US)\nusr_hr_04,Bob Jones,Finance_HR,People Operations & HR Manager,Austin HQ (Onsite)\nusr_fin_05,David Sterling,Finance_HR,Corporate Financial Controller,Austin HQ (Onsite)\n",
    "/vault/prod/db_credentials.enc": "[RESTRICTED ENTERPRISE SECRETS VAULT - SCOPE: INFRASTRUCTURE ADMIN ONLY]\nDATABASE_ENDPOINT=postgres-primary.internal.nexuscloud.io:5432/nexus_corp\nDATABASE_MASTER_USER=nexus_superadmin\nDATABASE_MASTER_PASSWORD=Kx9#mP$2026_EnterpriseMasterKey!\nVAULT_SEAL_KEY_01=b84e1b854378f10dc89a7bb29a4309e51c8932454a\n",
    "/vault/prod/api_master_keys.json": json.dumps({
        "root_tokens": {
            "aws_production_root": "AKIA98421074EXAMPLE_ROOT_KEY",
            "stripe_live_secret": "sk_live_9841285091240912EXAMPLE_SECRET",
            "anthropic_enterprise_admin": "sk-ant-admin-9812409EXAMPLE"
        }
    }, indent=2),
    "/hr/payroll_executive_2026.csv": "emp_id,name,role,base_salary,bonus_target,ssn_masked,routing_account\nusr_exec_26,Dr. Eleanor Vance,CTO,$420000,$180000,XXX-XX-8491,121000358:84019284\nusr_exec_27,Arthur Pendelton,CFO,$410000,$175000,XXX-XX-3914,121000358:91048210\nusr_exec_28,Claire Dupont,CISO,$385000,$150000,XXX-XX-7721,121000358:44019285\n"
}

HTML_WORKSPACE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nexus Cloud - Enterprise Intranet & Workspace Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-page: #f1f5f9;
            --bg-card: #ffffff;
            --text-title: #0f172a;
            --text-body: #334155;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --primary: #2563eb;
            --primary-hover: #1d4ed8;
            --indigo: #4f46e5;
            --emerald: #059669;
            --rose: #e11d48;
            --amber: #d97706;
            --slate-800: #1e293b;
            --slate-900: #0f172a;
        }
        * { box-sizing: border-box; font-family: 'Inter', -apple-system, sans-serif; }
        code, pre, .terminal-font { font-family: 'JetBrains Mono', monospace; }
        body { margin: 0; background: var(--bg-page); color: var(--text-body); min-height: 100vh; display: flex; flex-direction: column; }

        /* Top Enterprise Navbar */
        header { background: var(--bg-card); border-bottom: 1px solid var(--border); padding: 0.85rem 2rem; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 50; }
        .brand { display: flex; align-items: center; gap: 12px; text-decoration: none; color: var(--text-title); font-weight: 800; font-size: 1.15rem; }
        .brand-icon { background: linear-gradient(135deg, var(--indigo), var(--primary)); color: white; width: 34px; height: 34px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 1rem; }
        .net-badge { background: #f0fdf4; color: var(--emerald); border: 1px solid #bbf7d0; padding: 0.3rem 0.75rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; display: flex; align-items: center; gap: 6px; }
        .pulse-dot { width: 8px; height: 8px; border-radius: 50%; background: #10b981; }

        /* Identity Switcher Bar */
        .session-banner { background: var(--bg-card); border-bottom: 1px solid var(--border); padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }
        .active-user-meta { display: flex; align-items: center; gap: 1rem; }
        .avatar-circle { width: 44px; height: 44px; border-radius: 50%; background: #e0e7ff; color: var(--indigo); font-weight: 800; font-size: 1.1rem; display: flex; align-items: center; justify-content: center; border: 2px solid #c7d2fe; }
        .meta-text h3 { margin: 0; font-size: 0.95rem; font-weight: 700; color: var(--text-title); }
        .meta-text p { margin: 0.15rem 0 0 0; font-size: 0.8rem; color: var(--text-muted); }
        .badge-pill { background: #f8fafc; border: 1px solid var(--border); padding: 0.2rem 0.55rem; border-radius: 6px; font-size: 0.75rem; font-weight: 600; color: var(--text-muted); }

        .switcher-box { display: flex; align-items: center; gap: 0.6rem; }
        .persona-select { padding: 0.55rem 0.85rem; border: 1px solid #cbd5e1; border-radius: 8px; font-size: 0.85rem; font-weight: 600; outline: none; background: white; color: var(--text-title); cursor: pointer; }
        .persona-select:focus { border-color: var(--primary); }

        /* Main Grid */
        main { flex-grow: 1; padding: 2rem; max-width: 1440px; width: 100%; margin: 0 auto; display: grid; grid-template-columns: 340px 1fr; gap: 2rem; }
        @media (max-width: 1100px) { main { grid-template-columns: 1fr; } }

        .panel { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; display: flex; flex-direction: column; }
        .panel-header { padding: 1rem 1.25rem; border-bottom: 1px solid var(--border); background: #fafafa; display: flex; justify-content: space-between; align-items: center; font-weight: 700; font-size: 0.9rem; color: var(--text-title); }
        .panel-body { padding: 1.25rem; }

        /* Resource Directory Tree */
        .resource-category { font-size: 0.75rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin: 1rem 0 0.5rem 0; }
        .resource-category:first-child { margin-top: 0; }
        .file-entry { padding: 0.55rem 0.75rem; border-radius: 6px; font-size: 0.8rem; display: flex; align-items: center; justify-content: space-between; cursor: pointer; transition: background 0.15s; border: 1px solid transparent; }
        .file-entry:hover { background: #f8fafc; border-color: var(--border); }
        .file-entry.active-file { background: #eff6ff; border-color: #bfdbfe; color: var(--primary); font-weight: 600; }
        .file-name { display: flex; align-items: center; gap: 8px; word-break: break-all; }

        /* Terminal Window */
        .terminal-container { background: var(--slate-900); border-radius: 10px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.15); display: flex; flex-direction: column; }
        .terminal-header { background: #1e293b; padding: 0.6rem 1rem; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; }
        .mac-dots { display: flex; gap: 6px; }
        .mac-dot { width: 10px; height: 10px; border-radius: 50%; }
        .dot-red { background: #ef4444; }
        .dot-yellow { background: #f59e0b; }
        .dot-green { background: #10b981; }
        .terminal-title { font-size: 0.75rem; color: #94a3b8; font-weight: 600; }

        .terminal-console { padding: 1.25rem; min-height: 280px; max-height: 480px; overflow-y: auto; color: #e2e8f0; font-size: 0.825rem; line-height: 1.6; white-space: pre-wrap; word-break: break-all; }
        .prompt-line { color: #38bdf8; font-weight: 600; }
        .terminal-input-bar { display: flex; background: #1e293b; border-top: 1px solid #334155; padding: 0.75rem 1rem; gap: 0.75rem; align-items: center; }
        .cli-prompt { color: #38bdf8; font-weight: 700; font-size: 0.85rem; white-space: nowrap; }
        .cli-input { flex-grow: 1; background: transparent; border: none; outline: none; color: white; font-size: 0.85rem; font-family: 'JetBrains Mono', monospace; }
        .btn-run { background: var(--primary); color: white; border: none; padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 0.8rem; transition: background 0.15s; }
        .btn-run:hover { background: var(--primary-hover); }

        /* Quick Tasks Row */
        .quick-chips { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1rem; }
        .chip-btn { background: #f1f5f9; border: 1px solid #cbd5e1; border-radius: 6px; padding: 0.35rem 0.65rem; font-size: 0.75rem; font-weight: 600; color: #334155; cursor: pointer; transition: all 0.15s; }
        .chip-btn:hover { background: #e2e8f0; border-color: #94a3b8; }
        
        footer { background: var(--bg-card); border-top: 1px solid var(--border); padding: 1.25rem; text-align: center; font-size: 0.8rem; color: var(--text-muted); margin-top: auto; }
    </style>
</head>
<body>
    <header>
        <a href="/workspace" class="brand">
            <div class="brand-icon">N</div>
            <span>Nexus Cloud Enterprise Portal</span>
        </a>
        <div class="net-badge">
            <span class="pulse-dot"></span>
            Internal Corporate Gateway (:8090)
        </div>
    </header>

    <div class="session-banner">
        <div class="active-user-meta">
            <div class="avatar-circle" id="user-avatar">SC</div>
            <div class="meta-text">
                <h3 id="disp-name">Dr. Sarah Chen</h3>
                <p>
                    <span id="disp-role">Lead ML Research Engineer</span> &bull; 
                    <span id="disp-dept">AI_Platform</span> &bull; 
                    <span class="badge-pill" id="disp-ip">IP: 10.10.4.52</span>
                </p>
            </div>
        </div>

        <div class="switcher-box">
            <label style="font-size: 0.8rem; font-weight: 700; color: var(--text-muted);">Switch Active Session:</label>
            <select class="persona-select" id="persona-selector" onchange="switchPersona(this.value)">
                <!-- 5 Representative Employees Injected Below -->
            </select>
        </div>
    </div>

    <main>
        <!-- Left: Corporate File & Scope Browser -->
        <div class="panel">
            <div class="panel-header">
                <span>Enterprise Resource Directory</span>
                <span class="badge-pill" id="file-count">11 Files</span>
            </div>
            <div class="panel-body" style="padding-top: 0.75rem;">
                <div class="resource-category">🧠 AI & Foundation Models</div>
                <div class="file-entry" onclick="selectResource('/models/nexus-foundation-70b/config.json')">
                    <span class="file-name">📄 config.json</span>
                    <span class="badge-pill">70B MoE</span>
                </div>
                <div class="file-entry" onclick="selectResource('/models/nexus-foundation-70b/weights_manifest.json')">
                    <span class="file-name">📦 weights_manifest.json</span>
                    <span class="badge-pill">138 GB</span>
                </div>
                <div class="file-entry" onclick="selectResource('/experiments/eval_benchmarks_run42.json')">
                    <span class="file-name">📊 eval_run42.json</span>
                    <span class="badge-pill">Benchmark</span>
                </div>
                <div class="file-entry" onclick="selectResource('/src/ai/distributed_trainer.py')">
                    <span class="file-name">🐍 distributed_trainer.py</span>
                    <span class="badge-pill">Source</span>
                </div>

                <div class="resource-category">☁️ Cloud Infrastructure & Ops</div>
                <div class="file-entry" onclick="selectResource('/infrastructure/terraform.tfstate')">
                    <span class="file-name">🏗️ terraform.tfstate</span>
                    <span class="badge-pill">AWS/EKS</span>
                </div>
                <div class="file-entry" onclick="selectResource('/kubernetes/k8s_cluster_nodes.json')">
                    <span class="file-name">☸️ k8s_cluster_nodes.json</span>
                    <span class="badge-pill">GPU Nodes</span>
                </div>

                <div class="resource-category">🎧 Customer Operations</div>
                <div class="file-entry" onclick="selectResource('/support/tickets/enterprise_tickets_q3.json')">
                    <span class="file-name">🎫 enterprise_tickets.json</span>
                    <span class="badge-pill">Support Q3</span>
                </div>

                <div class="resource-category">📊 Finance & Corporate Ledger</div>
                <div class="file-entry" onclick="selectResource('/finance/q3_invoices.xlsx')">
                    <span class="file-name">📈 q3_invoices.xlsx</span>
                    <span class="badge-pill">Finance</span>
                </div>

                <div class="resource-category">👥 People Operations (HR)</div>
                <div class="file-entry" onclick="selectResource('/hr/employees_2026.csv')">
                    <span class="file-name">📋 employees_2026.csv</span>
                    <span class="badge-pill">Directory</span>
                </div>
                <div class="file-entry" onclick="selectResource('/hr/payroll_executive_2026.csv')">
                    <span class="file-name">🔒 payroll_executive_2026.csv</span>
                    <span class="badge-pill">Restricted</span>
                </div>

                <div class="resource-category">🔐 Enterprise Secrets & Credentials</div>
                <div class="file-entry" onclick="selectResource('/vault/prod/db_credentials.enc')">
                    <span class="file-name">🔑 db_credentials.enc</span>
                    <span class="badge-pill">Production</span>
                </div>
                <div class="file-entry" onclick="selectResource('/vault/prod/api_master_keys.json')">
                    <span class="file-name">🗝️ api_master_keys.json</span>
                    <span class="badge-pill">Master Keys</span>
                </div>
            </div>
        </div>

        <!-- Right: Interactive Operations Console -->
        <div style="display: flex; flex-direction: column; gap: 1.25rem;">
            <div class="panel">
                <div class="panel-header">
                    <span>Operational Tasks & Quick Actions</span>
                    <span style="font-size: 0.75rem; color: var(--text-muted);" id="user-dept-tag">Active Role: Lead ML Engineer</span>
                </div>
                <div class="panel-body">
                    <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.75rem;">
                        Click a typical internal command or select a resource on the left to run in your authenticated terminal session:
                    </div>
                    <div class="quick-chips" id="quick-tasks-container">
                        <!-- Injected based on active department -->
                    </div>
                </div>
            </div>

            <!-- Terminal Console -->
            <div class="terminal-container">
                <div class="terminal-header">
                    <div class="mac-dots">
                        <span class="mac-dot dot-red"></span>
                        <span class="mac-dot dot-yellow"></span>
                        <span class="mac-dot dot-green"></span>
                    </div>
                    <span class="terminal-title" id="terminal-session-label">nexus-sh &bull; sarah.chen@10.10.4.52</span>
                    <span style="font-size: 0.7rem; color: #64748b; font-family: monospace;">bash 5.2</span>
                </div>
                <div class="terminal-console terminal-font" id="terminal-output">Welcome to Nexus Enterprise Operations Shell.
Logged in as Dr. Sarah Chen (usr_dev_01) on internal subnet.
Type any command below or select an enterprise resource on the left.
</div>
                <div class="terminal-input-bar">
                    <span class="cli-prompt terminal-font" id="cli-prompt">sarah@nexus:~$</span>
                    <input type="text" id="cli-cmd" class="cli-input" placeholder="e.g. cat /models/nexus-foundation-70b/config.json or git status" onkeydown="if(event.key==='Enter') executeCommand();">
                    <button class="btn-run" onclick="executeCommand()">Run Task</button>
                </div>
            </div>
        </div>
    </main>

    <footer>
        &copy; 2026 Nexus Cloud Technologies Inc. &bull; Internal Enterprise Architecture Portal (:8090)
    </footer>

    <script>
        const CORE_EMPLOYEES = """ + json.dumps(CORE_EMPLOYEES) + """;
        let activeUid = "usr_dev_01";

        function initSelector() {
            const select = document.getElementById("persona-selector");
            select.innerHTML = "";
            CORE_EMPLOYEES.forEach(emp => {
                const opt = document.createElement("option");
                opt.value = emp.user_id;
                opt.innerText = `${emp.name} — ${emp.role} (${emp.department})`;
                select.appendChild(opt);
            });
            select.value = activeUid;
        }

        function switchPersona(uid) {
            activeUid = uid;
            document.cookie = `nexus_session=${uid}; path=/; max-age=86400; SameSite=Lax`;
            const emp = CORE_EMPLOYEES.find(e => e.user_id === uid);
            if (!emp) return;

            document.getElementById("persona-selector").value = uid;
            document.getElementById("disp-name").innerText = emp.name;
            document.getElementById("disp-role").innerText = emp.role;
            document.getElementById("disp-dept").innerText = emp.department;
            document.getElementById("disp-ip").innerText = `IP: ${emp.assigned_ip}`;
            document.getElementById("user-dept-tag").innerText = `Active Role: ${emp.role}`;

            const initials = emp.name.split(" ").map(p => p[0]).join("").slice(0, 2);
            document.getElementById("user-avatar").innerText = initials;

            const handle = emp.name.toLowerCase().split(" ")[0];
            document.getElementById("cli-prompt").innerText = `${handle}@nexus:~$`;
            document.getElementById("terminal-session-label").innerText = `nexus-sh • ${handle}@${emp.assigned_ip}`;

            renderQuickTasks(emp.department);
            logToTerminal(`[SYSTEM] Switched active session context to ${emp.name} (${emp.user_id}).`);
        }

        function renderQuickTasks(dept) {
            const container = document.getElementById("quick-tasks-container");
            let tasks = [];

            if (dept === "AI_Platform") {
                tasks = [
                    { label: "Inspect 70B Model Config", cmd: "cat /models/nexus-foundation-70b/config.json" },
                    { label: "Check Weights Manifest", cmd: "cat /models/nexus-foundation-70b/weights_manifest.json" },
                    { label: "View Evaluation Benchmarks", cmd: "cat /experiments/eval_benchmarks_run42.json" },
                    { label: "Git Repository Status", cmd: "git status" }
                ];
            } else if (dept === "Cloud_DevOps") {
                tasks = [
                    { label: "Review Terraform State", cmd: "cat /infrastructure/terraform.tfstate" },
                    { label: "Inspect K8s GPU Nodes", cmd: "cat /kubernetes/k8s_cluster_nodes.json" },
                    { label: "Kubectl Pod Health", cmd: "kubectl get pods -n production" },
                    { label: "Check Systemctl Daemon", cmd: "systemctl status auditd" }
                ];
            } else if (dept === "Customer_Success") {
                tasks = [
                    { label: "View Support Ticket Queue", cmd: "cat /support/tickets/enterprise_tickets_q3.json" },
                    { label: "Query Support API", cmd: "curl -s http://internal.nexuscloud/api/tickets" },
                    { label: "Check Documentation Index", cmd: "ls -la /support/docs" }
                ];
            } else if (dept === "Finance_HR") {
                tasks = [
                    { label: "Inspect Company Directory", cmd: "cat /hr/employees_2026.csv" },
                    { label: "Audit Q3 Invoices Ledger", cmd: "cat /finance/q3_invoices.xlsx" },
                    { label: "Review Department Roster", cmd: "ls -la /finance" }
                ];
            } else {
                tasks = [
                    { label: "Inspect Home Directory", cmd: "ls -la /home" },
                    { label: "Check Network Routing", cmd: "ip route" }
                ];
            }

            container.innerHTML = "";
            tasks.forEach(t => {
                const btn = document.createElement("button");
                btn.className = "chip-btn";
                btn.innerText = t.label;
                btn.onclick = () => {
                    document.getElementById("cli-cmd").value = t.cmd;
                    executeCommand();
                };
                container.appendChild(btn);
            });
        }

        function selectResource(path) {
            document.querySelectorAll(".file-entry").forEach(e => e.classList.remove("active-file"));
            event.currentTarget.classList.add("active-file");
            document.getElementById("cli-cmd").value = `cat ${path}`;
            executeCommand();
        }

        function logToTerminal(text) {
            const out = document.getElementById("terminal-output");
            out.innerText += "\\n" + text;
            out.scrollTop = out.scrollHeight;
        }

        async function executeCommand() {
            const input = document.getElementById("cli-cmd");
            const cmd = input.value.trim();
            if (!cmd) return;

            const emp = CORE_EMPLOYEES.find(e => e.user_id === activeUid);
            const prompt = document.getElementById("cli-prompt").innerText;
            logToTerminal(`${prompt} ${cmd}`);

            // Determine file_path if it's a cat command
            let filePath = "";
            let isCloudUpload = false;
            let actionType = "command_exec";

            if (cmd.startsWith("cat ")) {
                filePath = cmd.slice(4).trim();
                actionType = "read_file";
            } else if (cmd.includes("s3 sync") || cmd.includes("upload")) {
                isCloudUpload = true;
                actionType = "cloud_sync";
                filePath = cmd.split(" ")[2] || "";
            }

            try {
                const response = await fetch('/workspace/api/action', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-user-id': emp.user_id,
                        'x-user-role': emp.role,
                        'x-user-department': emp.department
                    },
                    body: JSON.stringify({
                        action: actionType,
                        command: cmd,
                        file_path: filePath,
                        cloud_upload: isCloudUpload,
                        source_ip: emp.assigned_ip,
                        timestamp: new Date().toISOString()
                    })
                });

                if (response.status === 403) {
                    logToTerminal(`[SECURITY GATEWAY 403 FORBIDDEN] Access to '${filePath || cmd}' denied by policy.`);
                    return;
                }

                const data = await response.json();
                if (data.output) {
                    logToTerminal(data.output);
                } else if (data.message) {
                    logToTerminal(data.message);
                } else {
                    logToTerminal(JSON.stringify(data, null, 2));
                }
            } catch(e) {
                logToTerminal(`[NETWORK ERROR] Could not reach endpoint: ${e.message}`);
            }
        }

        window.addEventListener("DOMContentLoaded", () => {
            initSelector();
            const match = document.cookie.match(/(?:^|;\\s*)nexus_session=([^;]+)/);
            const savedPersona = match ? match[1] : "usr_dev_01";
            switchPersona(savedPersona);
        });
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
@app.get("/workspace", response_class=HTMLResponse)
async def internal_workspace():
    return HTML_WORKSPACE

@app.post("/workspace/api/action")
@app.post("/api/action")
async def internal_action_handler(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}

    cmd = body.get("command", "")
    file_path = body.get("file_path", "")

    # If reading a file, return the realistic corporate file content
    output = ""
    if file_path and file_path in CORPORATE_FILES:
        output = CORPORATE_FILES[file_path]
    elif cmd.startswith("cat "):
        p = cmd[4:].strip()
        output = CORPORATE_FILES.get(p, f"cat: {p}: No such file or directory")
    elif cmd == "git status":
        output = "On branch main\nYour branch is up to date with 'origin/main'.\nnothing to commit, working tree clean"
    elif "kubectl get pods" in cmd:
        output = "NAME                                    READY   STATUS    RESTARTS   AGE\nnexus-gateway-7b9f8d67c4-2k9lx           1/1     Running   0          4d12h\ninference-worker-h100-84849ff7-p9qwx     1/1     Running   0          18h\ninference-worker-h100-84849ff7-t4k21     1/1     Running   0          18h\ntelemetry-collector-daemon-5421x        1/1     Running   0          9d"
    elif "systemctl status" in cmd:
        output = "● auditd.service - Security Audit Daemon\n   Loaded: loaded (/lib/systemd/system/auditd.service; enabled)\n   Active: active (running) since Wed 2026-10-21 08:00:00 UTC\n   Main PID: 742 (auditd)\n   Tasks: 4 (limit: 4915)\n   Memory: 18.4M"
    elif "ip route" in cmd:
        output = "default via 10.10.0.1 dev eth0 proto dhcp src 10.10.4.52 metric 100\n10.10.0.0/16 dev eth0 proto kernel scope link src 10.10.4.52"
    elif "ls -la" in cmd:
        output = "total 28\ndrwxr-xr-x 4 nexus staff 4096 Oct 21 08:00 .\ndrwxr-xr-x 8 nexus staff 4096 Oct 18 14:00 ..\n-rw-r--r-- 1 nexus staff 1204 Oct 21 08:30 README.md\n-rw-r--r-- 1 nexus staff 3412 Oct 20 12:15 package.json\ndrwxr-xr-x 2 nexus staff 4096 Oct 21 09:00 src"
    else:
        output = f"[nexus-task-runner] Command executed successfully: {cmd}"

    return JSONResponse(content={
        "status": "success",
        "command": cmd,
        "output": output,
        "payload": body
    })

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8090)
