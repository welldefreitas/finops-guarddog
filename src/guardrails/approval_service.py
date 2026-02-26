from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from .config import settings


@dataclass
class ApprovalRequest:
    request_id: str
    created_at: datetime
    expires_at: datetime
    required: int
    approvers: set[str] = field(default_factory=set)
    # optional metadata
    env: str = "dev"
    action_id: str = ""
    resource_id: str = ""
    channel_id: str | None = None
    message_ts: str | None = None


class ApprovalService:
    """In-memory approval coordinator (MVP).

    For production, replace with Redis / DB to handle multiple instances.
    """

    def __init__(self) -> None:
        self._store: dict[str, ApprovalRequest] = {}

    def _cleanup(self) -> None:
        now = datetime.now(UTC)
        expired = [rid for rid, req in self._store.items() if now > req.expires_at]
        for rid in expired:
            self._store.pop(rid, None)

    def create_or_get(
        self,
        *,
        key: str,
        required: int,
        env: str,
        action_id: str,
        resource_id: str,
        channel_id: str | None = None,
        message_ts: str | None = None,
    ) -> ApprovalRequest:
        """Create a request keyed by a deterministic key (e.g. proposal_id), or return existing."""
        self._cleanup()
        if key in self._store:
            return self._store[key]
        now = datetime.now(UTC)
        req = ApprovalRequest(
            request_id=secrets.token_urlsafe(12),
            created_at=now,
            expires_at=now + timedelta(seconds=settings.approval_window_seconds),
            required=required,
            env=env,
            action_id=action_id,
            resource_id=resource_id,
            channel_id=channel_id,
            message_ts=message_ts,
        )
        self._store[key] = req
        return req

    def record_approval(self, *, key: str, user_id: str) -> tuple[bool, str, int, int]:
        """Returns (complete, reason, approved_count, required)."""
        self._cleanup()
        req = self._store.get(key)
        if not req:
            return False, "approval_request_not_found", 0, 0
        now = datetime.now(UTC)
        if now > req.expires_at:
            self._store.pop(key, None)
            return False, "approval_window_expired", 0, req.required
        req.approvers.add(user_id)
        approved = len(req.approvers)
        if approved >= req.required:
            # complete; keep briefly? for MVP we delete to avoid reuse
            self._store.pop(key, None)
            return True, "approved", approved, req.required
        return False, "partial", approved, req.required

    def peek(self, key: str) -> ApprovalRequest | None:
        self._cleanup()
        return self._store.get(key)
