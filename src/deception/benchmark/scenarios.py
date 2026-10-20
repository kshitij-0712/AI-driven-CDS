"""
AdaptiveShield Benchmark Scenarios
Standardized multi-step adversarial trajectories for evaluating deception effectiveness.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from deception.tactics import DeceptionTactic


@dataclass
class ScenarioStep:
    """A discrete turn within an adversarial attack sequence."""
    step_num: int
    method: str
    path: str
    query: str = ""
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    intent_label: str = "Recon"
    mitre_techniques: List[str] = field(default_factory=list)
    binary_triage: Optional[Dict[str, Any]] = None
    insider_context: Optional[Dict[str, Any]] = None
    expected_tactic: DeceptionTactic = DeceptionTactic.T01_CLONE_MASQUERADE
    description: str = ""


@dataclass
class AttackScenario:
    """An end-to-end multi-step adversarial scenario."""
    scenario_id: str
    name: str
    category: str
    description: str
    steps: List[ScenarioStep]
    mitre_tactics: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 5 Standardized Attack Scenarios
# ---------------------------------------------------------------------------

SCENARIOS: List[AttackScenario] = [
    # Scenario 1: Web Application Reconnaissance & Admin Surface Discovery
    AttackScenario(
        scenario_id="SCENARIO_1_RECON_ADMIN",
        name="Administrative Surface Reconnaissance",
        category="Reconnaissance",
        description="Adversary surveys public assets, identifies hidden administrative endpoints, and attempts credential harvesting.",
        mitre_tactics=["TA0043 (Reconnaissance)", "TA0001 (Initial Access)"],
        steps=[
            ScenarioStep(
                step_num=1,
                method="GET",
                path="/",
                intent_label="Safe",
                mitre_techniques=[],
                expected_tactic=DeceptionTactic.T01_CLONE_MASQUERADE,
                description="Initial crawler visit on dashboard",
            ),
            ScenarioStep(
                step_num=2,
                method="GET",
                path="/robots.txt",
                intent_label="Recon",
                mitre_techniques=["T1592"],
                expected_tactic=DeceptionTactic.T01_CLONE_MASQUERADE,
                description="Crawling robots.txt for hidden paths",
            ),
            ScenarioStep(
                step_num=3,
                method="GET",
                path="/admin/login",
                intent_label="Recon",
                mitre_techniques=["T1595"],
                expected_tactic=DeceptionTactic.T04_DEPTH_ESCALATION,
                description="Probing administrative portal surface",
            ),
            ScenarioStep(
                step_num=4,
                method="POST",
                path="/admin/login",
                body="username=admin&password=Password123!",
                intent_label="Recon",
                mitre_techniques=["T1110"],
                expected_tactic=DeceptionTactic.T04_DEPTH_ESCALATION,
                description="Attempting dictionary login",
            ),
        ],
    ),

    # Scenario 2: SQL Injection, Canary Token Seeding, and Attribution
    AttackScenario(
        scenario_id="SCENARIO_2_SQLI_CANARY",
        name="SQL Injection & Honeytoken Attribution",
        category="Web Exploitation",
        description="Adversary detects SQLi on user profile endpoint, extracts seeded database canary, and leaks it.",
        mitre_tactics=["TA0001 (Initial Access)", "TA0006 (Credential Access)", "TA0010 (Exfiltration)"],
        steps=[
            ScenarioStep(
                step_num=1,
                method="GET",
                path="/profile",
                query="id=1",
                intent_label="Recon",
                mitre_techniques=["T1595"],
                expected_tactic=DeceptionTactic.T01_CLONE_MASQUERADE,
                description="Initial normal request to profile",
            ),
            ScenarioStep(
                step_num=2,
                method="GET",
                path="/profile",
                query="id=1' OR '1'='1",
                intent_label="Exploit",
                mitre_techniques=["T1190"],
                expected_tactic=DeceptionTactic.T02_SYNTHETIC_VULN,
                description="SQL injection boolean probe",
            ),
            ScenarioStep(
                step_num=3,
                method="GET",
                path="/profile",
                query="id=1' UNION SELECT 1,username,password,conn_str FROM users--",
                intent_label="Exploit",
                mitre_techniques=["T1190", "T1552"],
                expected_tactic=DeceptionTactic.T03_CANARY_SEEDING,
                description="SQL injection database dump attempting credential harvest",
            ),
            ScenarioStep(
                step_num=4,
                method="POST",
                path="/api/connect",
                body="conn_str=postgresql://canary_usr_seed",
                intent_label="ADVANCED_APT",
                mitre_techniques=["T1078"],
                expected_tactic=DeceptionTactic.T06_BREADCRUMB_TRAIL,
                description="Adversary attempts to authenticate using extracted canary connection string",
            ),
        ],
    ),

    # Scenario 3: Binary Dropper & Reactive Malware Watcher
    AttackScenario(
        scenario_id="SCENARIO_3_MALWARE_DROPPER",
        name="In-Flight Malware Dropper Staging",
        category="Malware Execution",
        description="Adversary uploads executable stager into decoy, triggering sub-11ms MOTIF binary classification and reactive mutation.",
        mitre_tactics=["TA0002 (Execution)", "TA0011 (Command and Control)"],
        steps=[
            ScenarioStep(
                step_num=1,
                method="POST",
                path="/api/upload",
                body="stager_payload_bytes_MZ_header",
                intent_label="Downloader",
                mitre_techniques=["T1105"],
                binary_triage={"has_binary": True, "is_malicious": True, "family_name": "AsyncRAT"},
                expected_tactic=DeceptionTactic.T08_BINARY_MUTATION,
                description="Adversary drops stage-1 executable binary",
            ),
            ScenarioStep(
                step_num=2,
                method="GET",
                path="/status/task",
                query="task_id=99",
                intent_label="Downloader",
                mitre_techniques=["T1105"],
                expected_tactic=DeceptionTactic.T08_BINARY_MUTATION,
                description="Checking execution status of dropped payload",
            ),
        ],
    ),

    # Scenario 4: Automated Vulnerability Scanner Fuzzing & Tarpitting
    AttackScenario(
        scenario_id="SCENARIO_4_SCANNER_BURST",
        name="Automated Scanner Fuzzing & Tarpit",
        category="Automated Scanning",
        description="Nikto / SQLmap automated fuzzing burst, triggering adaptive tarpitting and transient fault injection.",
        mitre_tactics=["TA0043 (Reconnaissance)"],
        steps=[
            ScenarioStep(
                step_num=1,
                method="GET",
                path="/cgi-bin/test.cgi",
                intent_label="Scanner",
                mitre_techniques=["T1595"],
                expected_tactic=DeceptionTactic.T05_ADAPTIVE_TARPIT,
                description="Scanner probe 1",
            ),
            ScenarioStep(
                step_num=2,
                method="GET",
                path="/phpmyadmin/index.php",
                intent_label="Scanner",
                mitre_techniques=["T1595"],
                expected_tactic=DeceptionTactic.T05_ADAPTIVE_TARPIT,
                description="Scanner probe 2",
            ),
            ScenarioStep(
                step_num=3,
                method="GET",
                path="/.env",
                intent_label="Scanner",
                mitre_techniques=["T1595"],
                expected_tactic=DeceptionTactic.T05_ADAPTIVE_TARPIT,
                description="Scanner probe 3",
            ),
            ScenarioStep(
                step_num=4,
                method="GET",
                path="/wp-admin/",
                intent_label="Scanner",
                mitre_techniques=["T1595"],
                expected_tactic=DeceptionTactic.T07_TRANSIENT_FAULT,
                description="Scanner probe 4 (evaluates retry handling)",
            ),
        ],
    ),

    # Scenario 5: Insider Threat Cross-Department Scope Violation
    AttackScenario(
        scenario_id="SCENARIO_5_INSIDER_EXFIL",
        name="Insider Threat Silent Sandbox Containment",
        category="Insider Threat",
        description="Internal employee violates departmental boundaries, attempting to access restricted financial compensation records.",
        mitre_tactics=["TA0009 (Collection)", "TA0010 (Exfiltration)"],
        steps=[
            ScenarioStep(
                step_num=1,
                method="GET",
                path="/engineering/docs/architecture.pdf",
                intent_label="Safe",
                insider_context={"is_internal": True, "anomaly_score": 0.10, "risk_level": "LOW"},
                expected_tactic=DeceptionTactic.T01_CLONE_MASQUERADE,
                description="Authorized engineering document access",
            ),
            ScenarioStep(
                step_num=2,
                method="GET",
                path="/hr/payroll/q3_executive_salaries.csv",
                intent_label="Exploit",
                insider_context={"is_internal": True, "anomaly_score": 0.88, "risk_level": "CRITICAL"},
                expected_tactic=DeceptionTactic.T09_INSIDER_SANDBOX,
                description="Unauthorized high-risk scope access to executive payroll",
            ),
        ],
    ),
]

BENCHMARK_SCENARIOS = SCENARIOS
