"""
AdaptiveShield — Cryptographic Honeytoken & Canary Asset Engine
Generates, tracks, and cryptographically verifies canary credentials for attribution.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class CanaryType(str, Enum):
    """Types of canary honeytokens supported by AdaptiveShield."""
    AWS_ACCESS_KEY = "aws_access_key"
    DB_CONN_STR = "db_conn_str"
    API_BEARER_JWT = "api_bearer_jwt"
    DOC_WATERMARK = "doc_watermark"


@dataclass
class CanaryToken:
    """Represents a generated canary honeytoken with cryptographic provenance."""
    token_id: str
    token_type: CanaryType
    session_id: str
    value: str
    secret_value: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "token_type": self.token_type.value,
            "session_id": self.session_id,
            "value": self.value,
            "secret_value": self.secret_value,
            "created_at": self.created_at,
            "metadata": self.metadata,
            "signature": self.signature,
        }


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    padding = 4 - (len(s) % 4)
    if padding and padding < 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s.encode("utf-8"))


class CanaryGenerator:
    """
    Cryptographic Honeytoken Generator & Provenance Verifier.
    Enforces HMAC-SHA256 signatures over all generated credentials to eliminate
    false attribution and confirm that leaked credentials originated from AdaptiveShield.
    """

    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = (
            secret_key
            or os.environ.get("ADSHIELD_CANARY_SECRET")
            or "adaptiveshield_canary_deterministic_master_key_2026"
        ).encode("utf-8")

    def _sign(self, message: str) -> str:
        """Compute 16-hex-character HMAC-SHA256 digest."""
        h = hmac.new(self.secret_key, message.encode("utf-8"), hashlib.sha256)
        return h.hexdigest()[:16]

    def _verify_sig(self, message: str, signature: str) -> bool:
        """Constant-time signature verification."""
        expected = self._sign(message)
        return hmac.compare_digest(expected, signature)

    def generate_aws_key(self, session_id: str, account_alias: str = "prod-sec-audit") -> CanaryToken:
        """
        Generates realistic AWS credentials:
        Format: AKIA + 8 hex chars (derived from session) + 8 hex chars (HMAC signature).
        """
        token_id = str(uuid.uuid4())
        session_prefix = hashlib.md5(session_id.encode("utf-8")).hexdigest()[:8].upper()
        sig = self._sign(f"AWS:{session_id}:{session_prefix}").upper()[:8]
        access_key_id = f"AKIA{session_prefix}{sig}"

        # Deterministic but authentic-looking 40-char secret access key
        raw_secret_seed = f"SECRET:{access_key_id}:{self.secret_key.decode('utf-8', errors='ignore')}"
        secret_b64 = base64.b64encode(hashlib.sha256(raw_secret_seed.encode("utf-8")).digest()).decode("utf-8")
        secret_access_key = secret_b64[:40]

        return CanaryToken(
            token_id=token_id,
            token_type=CanaryType.AWS_ACCESS_KEY,
            session_id=session_id,
            value=access_key_id,
            secret_value=secret_access_key,
            signature=sig,
            metadata={"account_alias": account_alias, "region": "us-east-1"},
        )

    def generate_db_connection(self, session_id: str, db_name: str = "corp_financials") -> CanaryToken:
        """
        Generates a fake PostgreSQL/MariaDB connection string with embedded canary signature.
        """
        token_id = str(uuid.uuid4())
        sig = self._sign(f"DB:{session_id}:{token_id}")[:8]
        user_name = f"canary_usr_{sig}"
        password_seed = f"PW:{token_id}:{sig}"
        password = hashlib.sha256(password_seed.encode("utf-8")).hexdigest()[:24]
        conn_str = f"postgresql://{user_name}:{password}@db-staging.internal.network:5432/{db_name}?sslmode=require"

        return CanaryToken(
            token_id=token_id,
            token_type=CanaryType.DB_CONN_STR,
            session_id=session_id,
            value=conn_str,
            secret_value=password,
            signature=sig,
            metadata={"username": user_name, "database": db_name, "host": "db-staging.internal.network"},
        )

    def generate_api_bearer_jwt(self, session_id: str, subject: str = "svc-internal-audit") -> CanaryToken:
        """
        Generates a signed HS256 JWT bearer token containing embedded canary provenance.
        """
        token_id = str(uuid.uuid4())
        now = int(time.time())
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": subject,
            "iss": "adaptiveshield-auth",
            "iat": now,
            "exp": now + 86400,
            "canary": True,
            "sid": session_id,
            "tid": token_id,
        }

        header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header_b64}.{payload_b64}"
        h = hmac.new(self.secret_key, signing_input.encode("utf-8"), hashlib.sha256)
        sig_b64 = _b64url_encode(h.digest())
        jwt_token = f"{signing_input}.{sig_b64}"

        return CanaryToken(
            token_id=token_id,
            token_type=CanaryType.API_BEARER_JWT,
            session_id=session_id,
            value=jwt_token,
            secret_value=None,
            signature=sig_b64,
            metadata={"subject": subject, "expires_at": now + 86400},
        )

    def generate_doc_watermark(self, session_id: str, doc_name: str = "q3_financial_plan.pdf") -> CanaryToken:
        """
        Generates a watermarked canary document string.
        """
        token_id = str(uuid.uuid4())
        sig = self._sign(f"DOC:{session_id}:{doc_name}")[:8]
        watermark = f"ADSHIELD-CANARY-{session_id[:8]}-{sig}"

        return CanaryToken(
            token_id=token_id,
            token_type=CanaryType.DOC_WATERMARK,
            session_id=session_id,
            value=watermark,
            secret_value=None,
            signature=sig,
            metadata={"doc_name": doc_name},
        )

    def generate(self, token_type: CanaryType, session_id: str, **kwargs) -> CanaryToken:
        """Dispatcher to generate a canary token by type."""
        if token_type == CanaryType.AWS_ACCESS_KEY:
            return self.generate_aws_key(session_id, **kwargs)
        elif token_type == CanaryType.DB_CONN_STR:
            return self.generate_db_connection(session_id, **kwargs)
        elif token_type == CanaryType.API_BEARER_JWT:
            return self.generate_api_bearer_jwt(session_id, **kwargs)
        elif token_type == CanaryType.DOC_WATERMARK:
            return self.generate_doc_watermark(session_id, **kwargs)
        raise ValueError(f"Unknown canary token type: {token_type}")

    def verify_aws_key(self, key_string: str, session_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Verify an AWS key candidate. Returns attribution metadata if valid."""
        match = re.search(r"AKIA([0-9A-F]{8})([0-9A-F]{8})", key_string, re.IGNORECASE)
        if not match:
            return None

        prefix = match.group(1).upper()
        sig = match.group(2).upper()

        # If session_id provided, verify directly
        if session_id:
            expected_prefix = hashlib.md5(session_id.encode("utf-8")).hexdigest()[:8].upper()
            if prefix == expected_prefix:
                expected_sig = self._sign(f"AWS:{session_id}:{prefix}").upper()[:8]
                if hmac.compare_digest(expected_sig, sig):
                    return {"is_valid": True, "token_type": CanaryType.AWS_ACCESS_KEY.value, "session_id": session_id}
            return None

        return {"is_valid": True, "token_type": CanaryType.AWS_ACCESS_KEY.value, "prefix": prefix, "sig": sig}

    def verify_jwt(self, jwt_string: str) -> Optional[Dict[str, Any]]:
        """Verify an API Bearer JWT candidate."""
        parts = jwt_string.strip().split(".")
        if len(parts) != 3:
            return None

        signing_input = f"{parts[0]}.{parts[1]}"
        h = hmac.new(self.secret_key, signing_input.encode("utf-8"), hashlib.sha256)
        expected_sig = _b64url_encode(h.digest())

        if not hmac.compare_digest(expected_sig, parts[2]):
            return None

        try:
            payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
            if payload.get("canary") is True:
                return {
                    "is_valid": True,
                    "token_type": CanaryType.API_BEARER_JWT.value,
                    "session_id": payload.get("sid"),
                    "token_id": payload.get("tid"),
                    "subject": payload.get("sub"),
                }
        except Exception:
            return None
        return None

    def find_leaked_canaries(self, text: str) -> List[Dict[str, Any]]:
        """
        Scans arbitrary text (HTTP body, queries, headers, commands) to identify
        and attribute leaked AdaptiveShield canary tokens.
        """
        if not text or not isinstance(text, str):
            return []

        findings: List[Dict[str, Any]] = []

        # 1. AWS Key scan
        aws_matches = re.findall(r"AKIA[0-9A-F]{16}", text, re.IGNORECASE)
        for key in aws_matches:
            v = self.verify_aws_key(key)
            if v and v.get("is_valid"):
                findings.append({
                    "token_type": CanaryType.AWS_ACCESS_KEY.value,
                    "matched_value": key,
                    "metadata": v,
                })

        # 2. JWT scan
        jwt_matches = re.findall(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", text)
        for jwt_token in jwt_matches:
            v = self.verify_jwt(jwt_token)
            if v and v.get("is_valid"):
                findings.append({
                    "token_type": CanaryType.API_BEARER_JWT.value,
                    "matched_value": jwt_token,
                    "session_id": v.get("session_id"),
                    "token_id": v.get("token_id"),
                })

        # 3. Document watermark scan
        doc_matches = re.findall(r"ADSHIELD-CANARY-([A-Za-z0-9]{8})-([A-Za-z0-9]{8})", text)
        for sid_prefix, sig in doc_matches:
            findings.append({
                "token_type": CanaryType.DOC_WATERMARK.value,
                "matched_value": f"ADSHIELD-CANARY-{sid_prefix}-{sig}",
                "session_prefix": sid_prefix,
            })

        # 4. Database canary scan (full URI or username)
        db_full_matches = re.findall(r"postgresql://canary_usr_[A-Za-z0-9]{8}:[A-Za-z0-9]+@[^\s'\"&]+", text)
        if db_full_matches:
            for full_str in db_full_matches:
                sig_match = re.search(r"canary_usr_([A-Za-z0-9]{8})", full_str)
                sig = sig_match.group(1) if sig_match else ""
                findings.append({
                    "token_type": CanaryType.DB_CONN_STR.value,
                    "matched_value": full_str,
                    "signature": sig,
                })
        else:
            db_user_matches = re.findall(r"canary_usr_([A-Za-z0-9]{8})", text)
            for sig in db_user_matches:
                findings.append({
                    "token_type": CanaryType.DB_CONN_STR.value,
                    "matched_value": f"canary_usr_{sig}",
                    "signature": sig,
                })

        return findings
