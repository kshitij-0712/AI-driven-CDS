import os
import json
import sqlite3
import hashlib
import time
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class BinaryTriageRuntime:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS binary_cache (
                    sha256 TEXT PRIMARY KEY,
                    triage_json TEXT NOT NULL,
                    triage_only BOOLEAN DEFAULT 1,
                    file_size INTEGER,
                    file_type TEXT,
                    created_ts REAL,
                    updated_ts REAL
                )
            ''')
            conn.commit()

    def _compute_sha256(self, filepath: str) -> str:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def get_cached_triage(self, sha256: str) -> Dict[str, Any]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT triage_json FROM binary_cache WHERE sha256 = ?', (sha256,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
        return None

    def analyze_file(self, filepath: str) -> Dict[str, float]:
        if not os.path.exists(filepath):
            return self._empty_triage()
            
        sha256 = self._compute_sha256(filepath)
        cached = self.get_cached_triage(sha256)
        if cached:
            return cached
            
        # Fast static analysis (stub implementation of pefile/pyelftools logic)
        triage = self._empty_triage()
        try:
            size = os.path.getsize(filepath)
            triage['triage_file_size'] = float(size)
            
            # Very basic entropy estimation
            with open(filepath, 'rb') as f:
                data = f.read(min(size, 1024 * 1024))
            
            if data:
                import math
                entropy = 0
                for x in range(256):
                    p_x = data.count(x) / len(data)
                    if p_x > 0:
                        entropy += - p_x * math.log2(p_x)
                triage['triage_entropy'] = entropy
                if entropy > 7.0:
                    triage['triage_is_packed'] = 1.0
            
            # Simple magic byte checks
            if data.startswith(b'\x7fELF'):
                triage['triage_priority'] = 75.0
            elif data.startswith(b'MZ'):
                triage['triage_priority'] = 70.0
                
            # Check for Go strings
            if b'Go build' in data or b'Go cmd' in data:
                triage['triage_is_go'] = 1.0
                
            # Check for basic strings
            if b'stratum+tcp' in data:
                triage['triage_score_mining'] = 0.9
            if b'/bin/sh' in data or b'cmd.exe' in data:
                triage['triage_score_botnet'] = 0.5
                
            # Cache the result
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO binary_cache 
                    (sha256, triage_json, triage_only, file_size, file_type, created_ts, updated_ts)
                    VALUES (?, ?, 1, ?, 'unknown', ?, ?)
                ''', (sha256, json.dumps(triage), size, time.time(), time.time()))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Error analyzing file {filepath}: {e}")
            
        return triage

    def _empty_triage(self) -> Dict[str, float]:
        triage_cols = [
            'triage_file_size', 'triage_entropy', 'triage_priority',
            'triage_is_go', 'triage_is_packed', 'triage_is_stripped',
            'triage_is_dll', 'triage_is_static', 'triage_score_mining',
            'triage_score_botnet', 'triage_score_recon', 'triage_score_destructive',
        ]
        return {col: 0.0 for col in triage_cols}
