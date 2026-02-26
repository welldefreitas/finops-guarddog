from __future__ import annotations

import secrets
import time

from guardrails.request_auth import sign_v1, verify_v1


def test_sign_and_verify_ok():
    secret = "s3cr3t"
    ts = str(int(time.time()))
    nonce = secrets.token_urlsafe(8)
    body = b'{"proposal_id":"abc"}'
    sig = sign_v1(secret, timestamp=ts, nonce=nonce, body=body)
    ok, reason = verify_v1(secret, timestamp=ts, nonce=nonce, body=body, signature=sig, tolerance_seconds=300)
    assert ok is True
    assert reason == "ok"
