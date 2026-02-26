from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .config import settings
from .schema import ActionProposal


@dataclass
class ProposalRecord:
    proposal: ActionProposal
    created_at: datetime
    expires_at: datetime


class ProposalStore:
    """In-memory proposal store (MVP).

    Used to correlate Slack interactions back to a proposal.
    For production: Redis/DB + integrity protections.
    """

    def __init__(self) -> None:
        self._store: dict[str, ProposalRecord] = {}

    def _cleanup(self) -> None:
        now = datetime.now(UTC)
        expired = [pid for pid, rec in self._store.items() if now > rec.expires_at]
        for pid in expired:
            self._store.pop(pid, None)

    def new_id(self) -> str:
        return secrets.token_urlsafe(12)

    def put(self, proposal: ActionProposal) -> None:
        self._cleanup()
        now = datetime.now(UTC)
        # keep proposals for same window as approvals
        self._store[proposal.proposal_id] = ProposalRecord(
            proposal=proposal,
            created_at=now,
            expires_at=now + timedelta(seconds=settings.approval_window_seconds),
        )

    def get(self, proposal_id: str) -> ActionProposal | None:
        self._cleanup()
        rec = self._store.get(proposal_id)
        return rec.proposal if rec else None
