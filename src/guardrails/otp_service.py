from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .config import settings


@dataclass
class OTPRecord:
    code_hash: str
    expires_at: datetime
    attempts_left: int


def _hash_code(code: str, salt: str) -> str:
    # salted SHA256; store only hash
    msg = (salt + ":" + code).encode("utf-8")
    return hashlib.sha256(msg).hexdigest()


class OTPService:
    """In-memory OTP store (MVP).

    For production: replace with Redis or other shared state store.
    """

    def __init__(self) -> None:
        self._store: dict[str, OTPRecord] = {}
        self._salt = secrets.token_hex(16)

    def issue(self) -> tuple[str, str, datetime]:
        """Returns (otp_id, code, expires_at). Code is returned only at issuance time."""
        otp_id = secrets.token_urlsafe(16)
        code = self._generate_code()
        expires_at = datetime.now(UTC) + timedelta(seconds=settings.otp_ttl_seconds)
        rec = OTPRecord(
            code_hash=_hash_code(code, self._salt),
            expires_at=expires_at,
            attempts_left=settings.otp_max_attempts,
        )
        self._store[otp_id] = rec
        return otp_id, code, expires_at

    def verify(self, otp_id: str, code: str) -> tuple[bool, str]:
        rec = self._store.get(otp_id)
        if not rec:
            return False, "otp_not_found"
        if datetime.now(UTC) > rec.expires_at:
            self._store.pop(otp_id, None)
            return False, "otp_expired"
        if rec.attempts_left <= 0:
            self._store.pop(otp_id, None)
            return False, "otp_locked"
        expected = rec.code_hash
        got = _hash_code(code, self._salt)
        ok = hmac.compare_digest(expected, got)
        if ok:
            self._store.pop(otp_id, None)
            return True, "ok"
        rec.attempts_left -= 1
        if rec.attempts_left <= 0:
            self._store.pop(otp_id, None)
            return False, "otp_locked"
        return False, "otp_invalid"

    @staticmethod
    def _generate_code() -> str:
        # Human-friendly short code e.g. ALPACA-17
        animals = ["ALPACA", "OTTER", "PANDA", "WOLF", "FALCON", "KOALA", "TIGER", "LYNX", "EAGLE", "GECKO"]
        word = secrets.choice(animals)
        num = secrets.randbelow(90) + 10  # 10..99
        return f"{word}-{num}"
