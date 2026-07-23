import hashlib
import time
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class HoneypotCache:
    def __init__(self, config: Dict):
        galah_cfg = config.get("galah_honeypot", {})
        cache_cfg = galah_cfg.get("cache", {})
        
        self.enabled = cache_cfg.get("enabled", True)
        self.ttl_seconds = cache_cfg.get("ttl_seconds", 3600)
        self._store: Dict[str, tuple] = {}

    def _generate_hash(self, text: str) -> str:
        if not text:
            return ""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _make_key(self, session_id: str, method: str, path: str, query: str, body: str, is_dynamic: bool) -> str:
        body_hash = self._generate_hash(body)
        # Dynamic POST requests or exploits are cached per-session to maintain consistency.
        # Basic GET requests (e.g. recon crawling) can be cached globally.
        if is_dynamic or method.upper() != "GET":
            return f"session:{session_id}:{method}:{path}:{query}:{body_hash}"
        return f"global:{method}:{path}:{query}:{body_hash}"

    def get(
        self,
        session_id: str,
        method: str,
        path: str,
        query: str,
        body: str,
        is_dynamic: bool
    ) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
            
        key = self._make_key(session_id, method, path, query, body, is_dynamic)
        cached = self._store.get(key)
        
        if cached:
            response_dict, expiry = cached
            if expiry > time.time():
                logger.info(f"Honeypot cache hit for: {key}")
                return response_dict
            else:
                self._store.pop(key, None)
                logger.debug(f"Honeypot cache expired for: {key}")
                
        return None

    def set(
        self,
        session_id: str,
        method: str,
        path: str,
        query: str,
        body: str,
        is_dynamic: bool,
        response_dict: Dict[str, Any]
    ):
        if not self.enabled:
            return
            
        key = self._make_key(session_id, method, path, query, body, is_dynamic)
        expiry = time.time() + self.ttl_seconds
        self._store[key] = (response_dict, expiry)
        logger.info(f"Cached honeypot response for: {key} (TTL: {self.ttl_seconds}s)")

    def clear(self):
        self._store.clear()
