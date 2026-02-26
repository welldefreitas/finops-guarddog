from __future__ import annotations

import hashlib
import hmac
import time

from .config import settings


def verify_slack_signature(*, timestamp: str, body: bytes, signature: str, tolerance_seconds: int = 60 * 5) -> bool:
    """Verify Slack request signature (HMAC SHA256).

    Slack signs: v0:{timestamp}:{body}
    signature: v0=...
    """
    try:
        ts = int(timestamp)
    except ValueError:
        return False

    if abs(int(time.time()) - ts) > tolerance_seconds:
        return False

    base = b"v0:" + timestamp.encode("utf-8") + b":" + body
    digest = hmac.new(settings.slack_signing_secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
    expected = "v0=" + digest
    return hmac.compare_digest(expected, signature)
