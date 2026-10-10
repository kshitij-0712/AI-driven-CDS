import os
import json
import sqlite3
import hashlib
import time
import uuid
from typing import Dict, Any, Optional, List
from pathlib import Path

DEFAULT_DB_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "runtime", "corporate_directory.db")
)

def resolve_profile_path(custom_path: Optional[str] = None) -> str:
    """
    Resolves the company profile path with fallback priority:
    1. Explicitly passed custom_path (if exists)
    2. COMPANY_PROFILE_PATH environment variable
    3. config/company_profile.json
    4. runtime/company_profile.json
    """
    if custom_path and os.path.exists(custom_path):
        return os.path.abspath(custom_path)
    env_path = os.environ.get("COMPANY_PROFILE_PATH")
    if env_path and os.path.exists(env_path):
        return os.path.abspath(env_path)
    config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "config", "company_profile.json"))
    if os.path.exists(config_path):
        return config_path
    runtime_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "runtime", "company_profile.json"))
    if os.path.exists(runtime_path):
        return runtime_path
    return custom_path or config_path

DEFAULT_PROFILE_PATH = resolve_profile_path()
DEFAULT_PASSWORD = "qwerty"


def hash_password(password: str, salt: str = "nexus_salt_2026") -> str:
    """Hash password using sha256 with static salt for deterministic verification."""
    return hashlib.sha256(f"{salt}:{password}".encode("utf-8")).hexdigest()


class CorporateDirectory:
    """
    Manages the corporate identity database, employee directory, credentials,
    whitelisted remote IPs, and session lifecycle.
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH, profile_path: Optional[str] = None):
        self.db_path = os.path.abspath(db_path)
        self.profile_path = resolve_profile_path(profile_path)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS employees (
                    user_id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    department TEXT NOT NULL,
                    assigned_device TEXT,
                    assigned_ip TEXT,
                    whitelisted_ips_json TEXT,
                    is_active INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    client_ip TEXT NOT NULL,
                    user_agent TEXT,
                    FOREIGN KEY(user_id) REFERENCES employees(user_id)
                );
            """)

            # Seed if employees table is empty
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM employees")
            count = cur.fetchone()[0]
            if count == 0:
                self._seed_from_profile(conn)

    def _seed_from_profile(self, conn: sqlite3.Connection):
        profile = None
        if os.path.exists(self.profile_path):
            try:
                with open(self.profile_path, "r", encoding="utf-8") as f:
                    profile = json.load(f)
            except Exception as e:
                print(f"Warning: Failed to load company profile from {self.profile_path}: {e}")

        if not profile:
            try:
                from agents.insider.default_company_profile import DEFAULT_COMPANY_PROFILE
                profile = DEFAULT_COMPANY_PROFILE
            except ImportError:
                return

        default_hash = hash_password(DEFAULT_PASSWORD)
        employees = profile.get("employees", [])

        for emp in employees:
            user_id = emp.get("user_id")
            email = emp.get("email")
            name = emp.get("name")
            role = emp.get("role")
            dept = emp.get("department")
            device = emp.get("assigned_device")
            assigned_ip = emp.get("assigned_ip")
            is_active = 1 if emp.get("is_active", True) else 0

            # Whitelisted IPs: assigned_ip + corporate subnet variations + localhost for testing
            whitelisted = [assigned_ip] if assigned_ip else []
            if assigned_ip:
                # Add corporate subnet prefix
                parts = assigned_ip.split(".")
                if len(parts) == 4:
                    subnet_base = f"{parts[0]}.{parts[1]}.{parts[2]}"
                    whitelisted.append(f"{subnet_base}.1")
            # Always permit localhost/internal test runners
            whitelisted.extend(["127.0.0.1", "::1", "192.168.1.50", "192.168.1.100"])

            conn.execute("""
                INSERT OR REPLACE INTO employees 
                (user_id, email, password_hash, name, role, department, assigned_device, assigned_ip, whitelisted_ips_json, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id, email, default_hash, name, role, dept, device, assigned_ip,
                json.dumps(list(set(whitelisted))), is_active
            ))
        conn.commit()

    def get_company_profile(self) -> Dict[str, Any]:
        """Load the company profile, falling back to built-in default if missing."""
        if os.path.exists(self.profile_path):
            try:
                with open(self.profile_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        try:
            from agents.insider.default_company_profile import DEFAULT_COMPANY_PROFILE
            return DEFAULT_COMPANY_PROFILE
        except ImportError:
            return {}

    def authenticate_employee(self, username_or_email: str, password: str) -> Optional[Dict[str, Any]]:
        """Verify employee credentials and return employee record if valid."""
        expected_hash = hash_password(password)
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT user_id, email, name, role, department, assigned_device, assigned_ip, whitelisted_ips_json, is_active
                FROM employees
                WHERE (email = ? OR user_id = ?) AND password_hash = ? AND is_active = 1
            """, (username_or_email.strip().lower(), username_or_email.strip(), expected_hash))
            row = cur.fetchone()
            if row:
                emp = dict(row)
                emp["whitelisted_ips"] = json.loads(emp.get("whitelisted_ips_json") or "[]")
                return emp
        return None

    def get_employee(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve employee profile by user_id."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT user_id, email, name, role, department, assigned_device, assigned_ip, whitelisted_ips_json, is_active
                FROM employees WHERE user_id = ?
            """, (user_id,))
            row = cur.fetchone()
            if row:
                emp = dict(row)
                emp["whitelisted_ips"] = json.loads(emp.get("whitelisted_ips_json") or "[]")
                return emp
        return None

    def create_session(self, user_id: str, client_ip: str, user_agent: str = "") -> str:
        """Create a new corporate session token."""
        token = str(uuid.uuid4())
        now = time.time()
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO sessions (token, user_id, created_at, client_ip, user_agent)
                VALUES (?, ?, ?, ?, ?)
            """, (token, user_id, now, client_ip, user_agent))
            conn.commit()
        return token

    def validate_session(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate session token and return user profile + session info."""
        if not token:
            return None
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT s.token, s.created_at, s.client_ip as session_ip, s.user_agent,
                       e.user_id, e.email, e.name, e.role, e.department, e.assigned_device, e.assigned_ip, e.whitelisted_ips_json
                FROM sessions s
                JOIN employees e ON s.user_id = e.user_id
                WHERE s.token = ? AND e.is_active = 1
            """, (token,))
            row = cur.fetchone()
            if row:
                res = dict(row)
                res["whitelisted_ips"] = json.loads(res.get("whitelisted_ips_json") or "[]")
                return res
        return None

    def check_ip_whitelist(self, user_id: str, client_ip: str) -> bool:
        """Return True if client_ip is recognized in the employee's whitelisted IPs."""
        clean_ip = client_ip.strip() if client_ip else ""
        if clean_ip in ("127.0.0.1", "::1", "localhost", "192.168.1.50", "192.168.1.100"):
            return True
        emp = self.get_employee(user_id)
        if not emp:
            return False
        whitelisted = emp.get("whitelisted_ips", [])
        return clean_ip in whitelisted

    def terminate_session(self, token: str):
        """Invalidate session token."""
        if not token:
            return
        with self._get_connection() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()

    def get_test_personas(self) -> List[Dict[str, Any]]:
        """Return the 5 test personas defined in company_profile.json for demo interfaces."""
        profile = self.get_company_profile()
        personas = profile.get("test_personas", {})
        result = []
        for key, p in personas.items():
            result.append({
                "persona_key": key,
                "user_id": p.get("user_id"),
                "name": p.get("name"),
                "role": p.get("role"),
                "department": p.get("department"),
                "assigned_device": p.get("assigned_device"),
                "assigned_ip": p.get("assigned_ip"),
                "scenario": p.get("test_scenario")
            })
        return result
