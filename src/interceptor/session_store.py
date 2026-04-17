import json
import os
import sqlite3
import time
import uuid
from typing import Dict, Optional


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    src_ip TEXT NOT NULL,
    first_seen_ts REAL NOT NULL,
    last_seen_ts REAL NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    last_label TEXT,
    blocked INTEGER NOT NULL DEFAULT 0,
    blocked_until_ts REAL,
    context_json TEXT
);

CREATE TABLE IF NOT EXISTS request_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    ts REAL NOT NULL,
    method TEXT,
    path TEXT,
    label TEXT,
    action TEXT,
    rule TEXT,
    details_json TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(id)
);
"""


class SessionStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.executescript(SCHEMA_SQL)
        self.conn.commit()

    def get_or_create_session(self, src_ip: str) -> str:
        now = time.time()
        cur = self.conn.cursor()
        cur.execute(
            "SELECT id FROM sessions WHERE src_ip = ? AND blocked = 0 ORDER BY last_seen_ts DESC LIMIT 1",
            (src_ip,),
        )
        row = cur.fetchone()
        if row:
            session_id = row[0]
            cur.execute(
                "UPDATE sessions SET last_seen_ts = ?, request_count = request_count + 1 WHERE id = ?",
                (now, session_id),
            )
            self.conn.commit()
            return session_id

        session_id = str(uuid.uuid4())
        cur.execute(
            """
            INSERT INTO sessions(id, src_ip, first_seen_ts, last_seen_ts, request_count, context_json)
            VALUES(?, ?, ?, ?, 1, ?)
            """,
            (session_id, src_ip, now, now, json.dumps({})),
        )
        self.conn.commit()
        return session_id

    def mark_blocked(self, session_id: str, block_for_seconds: int):
        now = time.time()
        blocked_until = now + block_for_seconds
        self.conn.execute(
            "UPDATE sessions SET blocked = 1, blocked_until_ts = ? WHERE id = ?",
            (blocked_until, session_id),
        )
        self.conn.commit()

    def get_blocked_until(self, src_ip: str) -> Optional[float]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT blocked_until_ts FROM sessions WHERE src_ip = ? AND blocked = 1 ORDER BY last_seen_ts DESC LIMIT 1",
            (src_ip,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return row[0]

    def write_event(self, session_id: str, event: Dict):
        now = time.time()
        self.conn.execute(
            """
            INSERT INTO request_events(session_id, ts, method, path, label, action, rule, details_json)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                now,
                event.get("method"),
                event.get("path"),
                event.get("label"),
                event.get("action"),
                event.get("rule"),
                json.dumps(event),
            ),
        )
        self.conn.commit()

    def _get_context(self, session_id: str) -> Dict:
        cur = self.conn.cursor()
        cur.execute("SELECT context_json FROM sessions WHERE id = ?", (session_id,))
        row = cur.fetchone()
        if not row or not row[0]:
            return {}
        try:
            return json.loads(row[0])
        except Exception:
            return {}

    def increment_counter(self, session_id: str, key: str) -> int:
        ctx = self._get_context(session_id)
        current = int(ctx.get(key, 0))
        current += 1
        ctx[key] = current
        self.conn.execute(
            "UPDATE sessions SET context_json = ? WHERE id = ?",
            (json.dumps(ctx), session_id),
        )
        self.conn.commit()
        return current

    def get_counter(self, session_id: str, key: str) -> int:
        ctx = self._get_context(session_id)
        return int(ctx.get(key, 0))
