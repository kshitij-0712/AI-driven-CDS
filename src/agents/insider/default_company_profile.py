"""
Default Corporate Profile & Directory seed data.
Used as baseline fallback when config/company_profile.json is not present (e.g. CI environments).
"""

import json

DEFAULT_COMPANY_PROFILE = json.loads("""{
  "company_info": {
    "name": "Nexus Cloud Technologies Inc.",
    "domain": "nexuscloud.io",
    "internal_domain": "corp.nexuscloud.internal",
    "industry": "Cloud Infrastructure, Distributed Systems & Enterprise AI",
    "headquarters": "Austin, TX, USA",
    "total_employees": 45
  },
  "work_policy": {
    "timezone": "America/Chicago",
    "standard_start_hour": 8,
    "standard_end_hour": 18,
    "work_days": [0, 1, 2, 3, 4],
    "after_hours_threshold": 19,
    "early_hours_threshold": 7
  },
  "departments": {
    "AI_Platform": {
      "display_name": "AI & Foundation Model Research",
      "privilege_tier": "technical_specialist",
      "authorized_scopes": [
        "/models/",
        "/training_data/",
        "/src/ai/",
        "/weights/",
        "/experiments/",
        "/gpu_clusters/"
      ],
      "restricted_scopes": [
        "/vault/prod/",
        "/finance/",
        "/hr/payroll/",
        "/customers/tenants/"
      ]
    },
    "Cloud_DevOps": {
      "display_name": "Cloud Infrastructure & SRE",
      "privilege_tier": "admin_infrastructure",
      "authorized_scopes": [
        "/infrastructure/",
        "/kubernetes/",
        "/vault/",
        "/production/",
        "/terraform/",
        "/monitoring/",
        "/logs/"
      ],
      "restricted_scopes": [
        "/hr/payroll/",
        "/finance/tax/",
        "/executive/strategy/"
      ]
    },
    "Customer_Success": {
      "display_name": "Global Support & Customer Operations",
      "privilege_tier": "standard_user",
      "authorized_scopes": [
        "/support/",
        "/tickets/",
        "/customers/portal/",
        "/kb/articles/",
        "/docs/"
      ],
      "restricted_scopes": [
        "/infrastructure/",
        "/models/weights/",
        "/vault/",
        "/hr/payroll/",
        "/customers/tenants/export_all"
      ]
    },
    "Finance_HR": {
      "display_name": "Corporate Finance, HR & Legal",
      "privilege_tier": "restricted_business",
      "authorized_scopes": [
        "/hr/personnel/",
        "/hr/payroll/",
        "/finance/billing/",
        "/finance/ledger/",
        "/contracts/",
        "/legal/"
      ],
      "restricted_scopes": [
        "/infrastructure/",
        "/kubernetes/",
        "/vault/",
        "/models/",
        "/src/"
      ]
    },
    "Executive_Strategy": {
      "display_name": "Executive Leadership & Board",
      "privilege_tier": "executive_read",
      "authorized_scopes": [
        "/executive/",
        "/board/",
        "/strategy/",
        "/financial_reports/",
        "/investors/"
      ],
      "restricted_scopes": [
        "/vault/root_tokens/",
        "/infrastructure/keys/"
      ]
    }
  },
  "ssh_policy": {
    "bastion_host": "bastion.corp.nexuscloud.internal",
    "bastion_port": 2222,
    "allowed_roles": [
      "Cloud_DevOps",
      "AI_Platform"
    ],
    "prohibited_roles": [
      "Customer_Success",
      "Finance_HR",
      "Executive_Strategy",
      "General_Staff"
    ],
    "permitted_commands": [
      "kubectl", "docker", "systemctl status", "journalctl", "ps", "top",
      "tail", "grep", "git", "python", "nvidia-smi", "ping", "traceroute"
    ],
    "high_risk_commands": [
      "systemctl stop auditd", "service rsyslog stop", "rm -rf /var/log",
      "history -c", "chmod 777", "visudo", "/etc/sudoers", "nc -e",
      "bash -i", "sh -i", "base64 -d", "dd if=", "mkfs"
    ]
  },
  "test_personas": {
    "test_ai_engineer": {
      "user_id": "usr_dev_01",
      "name": "Dr. Sarah Chen",
      "role": "Lead ML Research Engineer",
      "department": "AI_Platform",
      "assigned_device": "MAC-ENG-9102",
      "assigned_ip": "10.10.4.52",
      "ssh_allowed": true,
      "test_scenario": "Scenario 1: AI Model Weight & Training Data Exfiltration (Modern IP Theft)"
    },
    "test_cloud_sre": {
      "user_id": "usr_sre_02",
      "name": "Marcus Vance",
      "role": "Principal Cloud Infrastructure SRE",
      "department": "Cloud_DevOps",
      "assigned_device": "LNX-SRE-1004",
      "assigned_ip": "10.10.2.15",
      "ssh_allowed": true,
      "test_scenario": "Scenario 2: Cloud Infrastructure & Secret Harvesting (Privileged Admin)"
    },
    "test_support_lead": {
      "user_id": "usr_sup_03",
      "name": "Carol Rodriguez",
      "role": "Senior Customer Success Lead",
      "department": "Customer_Success",
      "assigned_device": "WIN-OPS-4401",
      "assigned_ip": "10.10.6.88",
      "ssh_allowed": false,
      "test_scenario": "Scenario 3: Multi-Tenant Customer Data Scraping (Rogue Support Representative)"
    },
    "test_hr_manager": {
      "user_id": "usr_hr_04",
      "name": "Bob Jones",
      "role": "People Operations & HR Manager",
      "department": "Finance_HR",
      "assigned_device": "MAC-BUS-3011",
      "assigned_ip": "10.10.8.20",
      "ssh_allowed": false,
      "test_scenario": "Scenario 4: Unauthorized SSH Probing & Lateral Reconnaissance"
    },
    "test_finance_controller": {
      "user_id": "usr_fin_05",
      "name": "David Sterling",
      "role": "Corporate Financial Controller",
      "department": "Finance_HR",
      "assigned_device": "WIN-FIN-2005",
      "assigned_ip": "10.10.8.44",
      "ssh_allowed": false,
      "test_scenario": "Scenario 5: Pre-Resignation Payroll & Executive Equity Ledger Tampering"
    }
  },
  "employees": [
    {
      "user_id": "usr_dev_01",
      "name": "Dr. Sarah Chen",
      "email": "sarah.chen@nexuscloud.io",
      "role": "Lead ML Research Engineer",
      "department": "AI_Platform",
      "assigned_device": "MAC-ENG-9102",
      "assigned_ip": "10.10.4.52",
      "is_active": true
    },
    {
      "user_id": "usr_sre_02",
      "name": "Marcus Vance",
      "email": "marcus.vance@nexuscloud.io",
      "role": "Principal Cloud Infrastructure SRE",
      "department": "Cloud_DevOps",
      "assigned_device": "LNX-SRE-1004",
      "assigned_ip": "10.10.2.15",
      "is_active": true
    },
    {
      "user_id": "usr_sup_03",
      "name": "Carol Rodriguez",
      "email": "carol.rodriguez@nexuscloud.io",
      "role": "Senior Customer Success Lead",
      "department": "Customer_Success",
      "assigned_device": "WIN-OPS-4401",
      "assigned_ip": "10.10.6.88",
      "is_active": true
    },
    {
      "user_id": "usr_hr_04",
      "name": "Bob Jones",
      "email": "bob.jones@nexuscloud.io",
      "role": "People Operations & HR Manager",
      "department": "Finance_HR",
      "assigned_device": "MAC-BUS-3011",
      "assigned_ip": "10.10.8.20",
      "is_active": true
    },
    {
      "user_id": "usr_fin_05",
      "name": "David Sterling",
      "email": "david.sterling@nexuscloud.io",
      "role": "Corporate Financial Controller",
      "department": "Finance_HR",
      "assigned_device": "WIN-FIN-2005",
      "assigned_ip": "10.10.8.44",
      "is_active": true
    },
    {
      "user_id": "usr_dev_06",
      "name": "Alex Mercer",
      "email": "alex.mercer@nexuscloud.io",
      "role": "Senior Distributed Systems Engineer",
      "department": "AI_Platform",
      "assigned_device": "LNX-ENG-9105",
      "assigned_ip": "10.10.4.55",
      "is_active": true
    },
    {
      "user_id": "usr_dev_07",
      "name": "Priya Sharma",
      "email": "priya.sharma@nexuscloud.io",
      "role": "Computer Vision & Multimodal Scientist",
      "department": "AI_Platform",
      "assigned_device": "MAC-ENG-9108",
      "assigned_ip": "10.10.4.60",
      "is_active": true
    },
    {
      "user_id": "usr_dev_08",
      "name": "Lucas Dubois",
      "email": "lucas.dubois@nexuscloud.io",
      "role": "MLOps & Pipeline Engineer",
      "department": "AI_Platform",
      "assigned_device": "LNX-ENG-9110",
      "assigned_ip": "10.10.4.65",
      "is_active": true
    },
    {
      "user_id": "usr_dev_09",
      "name": "Elena Rostova",
      "email": "elena.rostova@nexuscloud.io",
      "role": "LLM Alignment & Safety Researcher",
      "department": "AI_Platform",
      "assigned_device": "MAC-ENG-9112",
      "assigned_ip": "10.10.4.70",
      "is_active": true
    },
    {
      "user_id": "usr_dev_10",
      "name": "Hassan Al-Mansoor",
      "email": "hassan.almansoor@nexuscloud.io",
      "role": "Data Systems Architect",
      "department": "AI_Platform",
      "assigned_device": "LNX-ENG-9115",
      "assigned_ip": "10.10.4.75",
      "is_active": true
    },
    {
      "user_id": "usr_sre_11",
      "name": "Jordan Hayes",
      "email": "jordan.hayes@nexuscloud.io",
      "role": "Kubernetes Cluster Administrator",
      "department": "Cloud_DevOps",
      "assigned_device": "LNX-SRE-1008",
      "assigned_ip": "10.10.2.20",
      "is_active": true
    },
    {
      "user_id": "usr_sre_12",
      "name": "Tanya Kowalski",
      "email": "tanya.kowalski@nexuscloud.io",
      "role": "Cloud Security & IAM Architect",
      "department": "Cloud_DevOps",
      "assigned_device": "MAC-SRE-1012",
      "assigned_ip": "10.10.2.25",
      "is_active": true
    },
    {
      "user_id": "usr_sre_13",
      "name": "Kenji Sato",
      "email": "kenji.sato@nexuscloud.io",
      "role": "Network Reliability Engineer",
      "department": "Cloud_DevOps",
      "assigned_device": "LNX-SRE-1015",
      "assigned_ip": "10.10.2.30",
      "is_active": true
    },
    {
      "user_id": "usr_sre_14",
      "name": "Rachel Adams",
      "email": "rachel.adams@nexuscloud.io",
      "role": "Observability & Telemetry Engineer",
      "department": "Cloud_DevOps",
      "assigned_device": "LNX-SRE-1018",
      "assigned_ip": "10.10.2.35",
      "is_active": true
    },
    {
      "user_id": "usr_sre_15",
      "name": "Gabriel Santos",
      "email": "gabriel.santos@nexuscloud.io",
      "role": "Database Operations Specialist",
      "department": "Cloud_DevOps",
      "assigned_device": "LNX-SRE-1022",
      "assigned_ip": "10.10.2.40",
      "is_active": true
    },
    {
      "user_id": "usr_sup_16",
      "name": "Jessica Taylor",
      "email": "jessica.taylor@nexuscloud.io",
      "role": "Tier 3 Technical Support Specialist",
      "department": "Customer_Success",
      "assigned_device": "WIN-OPS-4405",
      "assigned_ip": "10.10.6.90",
      "is_active": true
    },
    {
      "user_id": "usr_sup_17",
      "name": "Liam O'Connor",
      "email": "liam.oconnor@nexuscloud.io",
      "role": "Enterprise Onboarding Manager",
      "department": "Customer_Success",
      "assigned_device": "MAC-OPS-4410",
      "assigned_ip": "10.10.6.95",
      "is_active": true
    },
    {
      "user_id": "usr_sup_18",
      "name": "Amira Nour",
      "email": "amira.nour@nexuscloud.io",
      "role": "Customer Solutions Architect",
      "department": "Customer_Success",
      "assigned_device": "MAC-OPS-4415",
      "assigned_ip": "10.10.6.100",
      "is_active": true
    },
    {
      "user_id": "usr_sup_19",
      "name": "Brandon Miller",
      "email": "brandon.miller@nexuscloud.io",
      "role": "Customer Support Representative",
      "department": "Customer_Success",
      "assigned_device": "WIN-OPS-4420",
      "assigned_ip": "10.10.6.105",
      "is_active": true
    },
    {
      "user_id": "usr_sup_20",
      "name": "Chloe Bennett",
      "email": "chloe.bennett@nexuscloud.io",
      "role": "Knowledge Base & Documentation Lead",
      "department": "Customer_Success",
      "assigned_device": "MAC-OPS-4425",
      "assigned_ip": "10.10.6.110",
      "is_active": true
    },
    {
      "user_id": "usr_fin_21",
      "name": "Victor Hwang",
      "email": "victor.hwang@nexuscloud.io",
      "role": "Senior Revenue Accountant",
      "department": "Finance_HR",
      "assigned_device": "WIN-FIN-2010",
      "assigned_ip": "10.10.8.50",
      "is_active": true
    },
    {
      "user_id": "usr_fin_22",
      "name": "Megan O'Reilly",
      "email": "megan.oreilly@nexuscloud.io",
      "role": "Payroll & Benefits Specialist",
      "department": "Finance_HR",
      "assigned_device": "MAC-BUS-3015",
      "assigned_ip": "10.10.8.25",
      "is_active": true
    },
    {
      "user_id": "usr_fin_23",
      "name": "Samuel Jackson",
      "email": "samuel.jackson@nexuscloud.io",
      "role": "Financial Planning & Analysis Manager",
      "department": "Finance_HR",
      "assigned_device": "WIN-FIN-2015",
      "assigned_ip": "10.10.8.55",
      "is_active": true
    },
    {
      "user_id": "usr_hr_24",
      "name": "Natalie Wright",
      "email": "natalie.wright@nexuscloud.io",
      "role": "Technical Talent Acquisition Lead",
      "department": "Finance_HR",
      "assigned_device": "MAC-BUS-3020",
      "assigned_ip": "10.10.8.30",
      "is_active": true
    },
    {
      "user_id": "usr_hr_25",
      "name": "Derek Powell",
      "email": "derek.powell@nexuscloud.io",
      "role": "Corporate Legal Counsel",
      "department": "Finance_HR",
      "assigned_device": "WIN-LEG-5001",
      "assigned_ip": "10.10.8.60",
      "is_active": true
    },
    {
      "user_id": "usr_exec_26",
      "name": "Dr. Eleanor Vance",
      "email": "eleanor.vance@nexuscloud.io",
      "role": "Chief Technology Officer",
      "department": "Executive_Strategy",
      "assigned_device": "MAC-EXEC-0002",
      "assigned_ip": "10.10.1.10",
      "is_active": true
    },
    {
      "user_id": "usr_exec_27",
      "name": "Arthur Pendelton",
      "email": "arthur.pendelton@nexuscloud.io",
      "role": "Chief Financial Officer",
      "department": "Executive_Strategy",
      "assigned_device": "WIN-EXEC-0003",
      "assigned_ip": "10.10.1.15",
      "is_active": true
    },
    {
      "user_id": "usr_exec_28",
      "name": "Claire Dupont",
      "email": "claire.dupont@nexuscloud.io",
      "role": "Chief Information Security Officer",
      "department": "Executive_Strategy",
      "assigned_device": "MAC-EXEC-0004",
      "assigned_ip": "10.10.1.20",
      "is_active": true
    },
    {
      "user_id": "usr_dev_29",
      "name": "Tyler Brooks",
      "email": "tyler.brooks@nexuscloud.io",
      "role": "Full Stack Cloud Platform Engineer",
      "department": "AI_Platform",
      "assigned_device": "MAC-ENG-9120",
      "assigned_ip": "10.10.4.80",
      "is_active": true
    },
    {
      "user_id": "usr_dev_30",
      "name": "Zoe Martinez",
      "email": "zoe.martinez@nexuscloud.io",
      "role": "Distributed Storage Systems Engineer",
      "department": "AI_Platform",
      "assigned_device": "LNX-ENG-9125",
      "assigned_ip": "10.10.4.85",
      "is_active": true
    }
  ]
}
""")
