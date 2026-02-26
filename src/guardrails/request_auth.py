from __future__ import annotations

import hashlib
import hmac
import time


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sign_v1(secret: str, *, timestamp: str, nonce: str, body: bytes) -> str:
    """Create a signature for (timestamp, nonce, body)."""
    base = b"v1:" + timestamp.encode("utf-8") + b":" + nonce.encode("utf-8") + b":" + body
    digest = hmac.new(secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
    return "v1=" + digest


def verify_v1(
    secret: str,
    *,
    timestamp: str,
    nonce: str,
    body: bytes,
    signature: str,
    tolerance_seconds: int,
) -> tuple[bool, str]:
    """Verify signature + timestamp freshness (anti-replay window)."""
    if not secret:
        return False, "shared_secret_not_configured"
    try:
        ts = int(timestamp)
    except Exception:
        return False, "invalid_timestamp"
    now = int(time.time())
    if abs(now - ts) > tolerance_seconds:
        return False, "timestamp_out_of_tolerance"
    expected = sign_v1(secret, timestamp=timestamp, nonce=nonce, body=body)
    if not hmac.compare_digest(expected, signature):
        return False, "invalid_signature"
    return True, "ok"
