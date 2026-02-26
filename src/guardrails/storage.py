from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import redis.asyncio as redis

from .config import settings
from .crypto import hmac_sha256_hex
from .schema import ActionProposal


def _utcnow() -> datetime:
    return datetime.now(UTC)


# -----------------------------
# OTP store
# -----------------------------
@dataclass(frozen=True)
class OTPIssueOut:
    otp_id: str
    code: str
    expires_at: datetime


class OTPStore:
    async def issue(self) -> OTPIssueOut:  # pragma: no cover
        raise NotImplementedError

    async def verify(self, otp_id: str, code: str) -> tuple[bool, str]:  # pragma: no cover
        raise NotImplementedError


class InMemoryOTPStore(OTPStore):
    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}

    async def issue(self) -> OTPIssueOut:
        otp_id = secrets.token_urlsafe(16)
        code = _generate_code()
        expires_at = _utcnow() + timedelta(seconds=settings.otp_ttl_seconds)
        self._store[otp_id] = {
            "hash": hmac_sha256_hex(settings.app_secret, code),
            "expires_at": expires_at,
            "attempts": settings.otp_max_attempts,
        }
        return OTPIssueOut(otp_id=otp_id, code=code, expires_at=expires_at)

    async def verify(self, otp_id: str, code: str) -> tuple[bool, str]:
        rec = self._store.get(otp_id)
        if not rec:
            return False, "otp_not_found"
        if _utcnow() > rec["expires_at"]:
            self._store.pop(otp_id, None)
            return False, "otp_expired"
        if rec["attempts"] <= 0:
            self._store.pop(otp_id, None)
            return False, "otp_locked"
        expected = rec["hash"]
        got = hmac_sha256_hex(settings.app_secret, code)
        if secrets.compare_digest(expected, got):
            self._store.pop(otp_id, None)
            return True, "ok"
        rec["attempts"] -= 1
        if rec["attempts"] <= 0:
            self._store.pop(otp_id, None)
            return False, "otp_locked"
        return False, "otp_invalid"


class RedisOTPStore(OTPStore):
    def __init__(self, r: redis.Redis) -> None:
        self._r = r

    def _key(self, otp_id: str) -> str:
        return f"cg:otp:{otp_id}"

    async def issue(self) -> OTPIssueOut:
        otp_id = secrets.token_urlsafe(16)
        code = _generate_code()
        expires_at = _utcnow() + timedelta(seconds=settings.otp_ttl_seconds)
        key = self._key(otp_id)
        await self._r.hset(
            key,
            mapping={
                "hash": hmac_sha256_hex(settings.app_secret, code),
                "attempts": str(settings.otp_max_attempts),
            },
        )
        await self._r.expire(key, settings.otp_ttl_seconds)
        return OTPIssueOut(otp_id=otp_id, code=code, expires_at=expires_at)

    async def verify(self, otp_id: str, code: str) -> tuple[bool, str]:
        key = self._key(otp_id)
        data = await self._r.hgetall(key)
        if not data:
            return False, "otp_not_found_or_expired"
        attempts = int((data.get(b"attempts") or b"0").decode("utf-8"))
        if attempts <= 0:
            await self._r.delete(key)
            return False, "otp_locked"
        expected = (data.get(b"hash") or b"").decode("utf-8")
        got = hmac_sha256_hex(settings.app_secret, code)
        if secrets.compare_digest(expected, got):
            await self._r.delete(key)
            return True, "ok"
        attempts -= 1
        if attempts <= 0:
            await self._r.delete(key)
            return False, "otp_locked"
        await self._r.hset(key, mapping={"attempts": str(attempts)})
        return False, "otp_invalid"


# -----------------------------
# Proposal store
# -----------------------------
class ProposalStore:
    async def put(self, proposal: ActionProposal) -> None:  # pragma: no cover
        raise NotImplementedError

    async def get(self, proposal_id: str) -> ActionProposal | None:  # pragma: no cover
        raise NotImplementedError


class InMemoryProposalStore(ProposalStore):
    def __init__(self) -> None:
        self._store: dict[str, tuple[ActionProposal, datetime]] = {}

    async def put(self, proposal: ActionProposal) -> None:
        expires_at = _utcnow() + timedelta(seconds=settings.approval_window_seconds)
        self._store[proposal.proposal_id] = (proposal, expires_at)

    async def get(self, proposal_id: str) -> ActionProposal | None:
        rec = self._store.get(proposal_id)
        if not rec:
            return None
        proposal, expires_at = rec
        if _utcnow() > expires_at:
            self._store.pop(proposal_id, None)
            return None
        return proposal


class RedisProposalStore(ProposalStore):
    def __init__(self, r: redis.Redis) -> None:
        self._r = r

    def _key(self, proposal_id: str) -> str:
        return f"cg:proposal:{proposal_id}"

    async def put(self, proposal: ActionProposal) -> None:
        key = self._key(proposal.proposal_id)
        payload = proposal.model_dump_json().encode("utf-8")
        await self._r.set(key, payload, ex=settings.approval_window_seconds)

    async def get(self, proposal_id: str) -> ActionProposal | None:
        key = self._key(proposal_id)
        data = await self._r.get(key)
        if not data:
            return None
        return ActionProposal.model_validate_json(data)


# -----------------------------
# Approval coordinator
# -----------------------------
@dataclass(frozen=True)
class ApprovalStatus:
    complete: bool
    approved_count: int
    required: int
    reason: str


class ApprovalStore:
    async def init_request(
        self,
        *,
        key: str,
        required: int,
        env: str,
        action_id: str,
        resource_id: str,
        channel_id: str | None,
        message_ts: str | None,
    ) -> None:  # pragma: no cover
        raise NotImplementedError

    async def add_approver(self, *, key: str, user_id: str) -> ApprovalStatus:  # pragma: no cover
        raise NotImplementedError

    async def get_meta(self, *, key: str) -> dict[str, Any]:  # pragma: no cover
        raise NotImplementedError


class InMemoryApprovalStore(ApprovalStore):
    def __init__(self) -> None:
        self._meta: dict[str, dict[str, Any]] = {}
        self._approvers: dict[str, set[str]] = {}
        self._expires: dict[str, datetime] = {}

    def _cleanup(self) -> None:
        now = _utcnow()
        for k in list(self._expires.keys()):
            if now > self._expires[k]:
                self._expires.pop(k, None)
                self._meta.pop(k, None)
                self._approvers.pop(k, None)

    async def init_request(
        self,
        *,
        key: str,
        required: int,
        env: str,
        action_id: str,
        resource_id: str,
        channel_id: str | None,
        message_ts: str | None,
    ) -> None:
        self._cleanup()
        if key in self._meta:
            return
        expires_at = _utcnow() + timedelta(seconds=settings.approval_window_seconds)
        self._meta[key] = {
            "required": required,
            "env": env,
            "action_id": action_id,
            "resource_id": resource_id,
            "channel_id": channel_id,
            "message_ts": message_ts,
        }
        self._approvers[key] = set()
        self._expires[key] = expires_at

    async def add_approver(self, *, key: str, user_id: str) -> ApprovalStatus:
        self._cleanup()
        meta = self._meta.get(key)
        if not meta:
            return ApprovalStatus(False, 0, 0, "approval_request_not_found_or_expired")
        self._approvers[key].add(user_id)
        approved = len(self._approvers[key])
        required = int(meta["required"])
        if approved >= required:
            self._meta.pop(key, None)
            self._approvers.pop(key, None)
            self._expires.pop(key, None)
            return ApprovalStatus(True, approved, required, "approved")
        return ApprovalStatus(False, approved, required, "partial")

    async def get_meta(self, *, key: str) -> dict[str, Any]:
        self._cleanup()
        return self._meta.get(key, {})


class RedisApprovalStore(ApprovalStore):
    def __init__(self, r: redis.Redis) -> None:
        self._r = r

    def _meta_key(self, key: str) -> str:
        return f"cg:approval:{key}:meta"

    def _set_key(self, key: str) -> str:
        return f"cg:approval:{key}:approvers"

    async def init_request(
        self,
        *,
        key: str,
        required: int,
        env: str,
        action_id: str,
        resource_id: str,
        channel_id: str | None,
        message_ts: str | None,
    ) -> None:
        mk = self._meta_key(key)
        exists = await self._r.exists(mk)
        if exists:
            return
        await self._r.hset(
            mk,
            mapping={
                "required": str(required),
                "env": env,
                "action_id": action_id,
                "resource_id": resource_id,
                "channel_id": (channel_id or ""),
                "message_ts": (message_ts or ""),
            },
        )
        await self._r.expire(mk, settings.approval_window_seconds)
        await self._r.expire(self._set_key(key), settings.approval_window_seconds)

    async def add_approver(self, *, key: str, user_id: str) -> ApprovalStatus:
        mk = self._meta_key(key)
        meta = await self._r.hgetall(mk)
        if not meta:
            return ApprovalStatus(False, 0, 0, "approval_request_not_found_or_expired")
        required = int((meta.get(b"required") or b"0").decode("utf-8"))
        sk = self._set_key(key)
        pipe = self._r.pipeline()
        pipe.sadd(sk, user_id)
        pipe.scard(sk)
        res = await pipe.execute()
        approved = int(res[1])
        if approved >= required and required > 0:
            await self._r.delete(mk, sk)
            return ApprovalStatus(True, approved, required, "approved")
        return ApprovalStatus(False, approved, required, "partial")

    async def get_meta(self, *, key: str) -> dict[str, Any]:
        mk = self._meta_key(key)
        meta = await self._r.hgetall(mk)
        if not meta:
            return {}
        out: dict[str, Any] = {}
        for k, v in meta.items():
            out[k.decode("utf-8")] = v.decode("utf-8")
        return out


# -----------------------------
# Replay (nonce) store
# -----------------------------
class ReplayNonceStore:
    async def claim(self, *, nonce: str, ttl_seconds: int) -> tuple[bool, str]:  # pragma: no cover
        raise NotImplementedError


class InMemoryReplayNonceStore(ReplayNonceStore):
    def __init__(self) -> None:
        self._nonces: dict[str, float] = {}

    def _cleanup(self) -> None:
        now = datetime.now(UTC).timestamp()
        for n, exp in list(self._nonces.items()):
            if now > exp:
                self._nonces.pop(n, None)

    async def claim(self, *, nonce: str, ttl_seconds: int) -> tuple[bool, str]:
        self._cleanup()
        if nonce in self._nonces:
            return False, "replay_detected"
        self._nonces[nonce] = datetime.now(UTC).timestamp() + ttl_seconds
        return True, "ok"


class RedisReplayNonceStore(ReplayNonceStore):
    def __init__(self, r: redis.Redis) -> None:
        self._r = r

    def _key(self, nonce: str) -> str:
        return f"cg:nonce:{nonce}"

    async def claim(self, *, nonce: str, ttl_seconds: int) -> tuple[bool, str]:
        key = self._key(nonce)
        # SET NX EX ensures uniqueness and TTL
        ok = await self._r.set(key, b"1", nx=True, ex=ttl_seconds)
        if not ok:
            return False, "replay_detected"
        return True, "ok"


# -----------------------------
# Idempotency store
# -----------------------------
@dataclass(frozen=True)
class IdempotencyGet:
    status: str  # "processing" | "completed"
    payload_hash: str
    response_json: dict[str, Any] | None


class IdempotencyStore:
    async def start(
        self, *, key: str, payload_hash: str, ttl_seconds: int
    ) -> tuple[bool, IdempotencyGet | None]:  # pragma: no cover
        raise NotImplementedError

    async def complete(
        self, *, key: str, payload_hash: str, response_json: dict[str, Any], ttl_seconds: int
    ) -> None:  # pragma: no cover
        raise NotImplementedError

    async def get(self, *, key: str) -> IdempotencyGet | None:  # pragma: no cover
        raise NotImplementedError


class InMemoryIdempotencyStore(IdempotencyStore):
    def __init__(self) -> None:
        self._store: dict[str, tuple[float, dict[str, Any]]] = {}

    def _cleanup(self) -> None:
        now = datetime.now(UTC).timestamp()
        for k, (exp, _) in list(self._store.items()):
            if now > exp:
                self._store.pop(k, None)

    async def start(self, *, key: str, payload_hash: str, ttl_seconds: int) -> tuple[bool, IdempotencyGet | None]:
        self._cleanup()
        if key in self._store:
            rec = self._store[key][1]
            return False, IdempotencyGet(
                status=rec["status"],
                payload_hash=rec["payload_hash"],
                response_json=rec.get("response_json"),
            )
        exp = datetime.now(UTC).timestamp() + ttl_seconds
        self._store[key] = (exp, {"status": "processing", "payload_hash": payload_hash})
        return True, None

    async def complete(self, *, key: str, payload_hash: str, response_json: dict[str, Any], ttl_seconds: int) -> None:
        exp = datetime.now(UTC).timestamp() + ttl_seconds
        self._store[key] = (exp, {"status": "completed", "payload_hash": payload_hash, "response_json": response_json})

    async def get(self, *, key: str) -> IdempotencyGet | None:
        self._cleanup()
        rec = self._store.get(key)
        if not rec:
            return None
        data = rec[1]
        return IdempotencyGet(
            status=data["status"], payload_hash=data["payload_hash"], response_json=data.get("response_json")
        )


class RedisIdempotencyStore(IdempotencyStore):
    def __init__(self, r: redis.Redis) -> None:
        self._r = r

    def _key(self, key: str) -> str:
        return f"cg:idem:{key}"

    async def start(self, *, key: str, payload_hash: str, ttl_seconds: int) -> tuple[bool, IdempotencyGet | None]:
        rk = self._key(key)
        value = json.dumps({"status": "processing", "payload_hash": payload_hash}, separators=(",", ":")).encode(
            "utf-8"
        )
        ok = await self._r.set(rk, value, nx=True, ex=ttl_seconds)
        if ok:
            return True, None
        existing = await self._r.get(rk)
        if not existing:
            return False, None
        data = json.loads(existing.decode("utf-8"))
        return False, IdempotencyGet(
            status=data["status"], payload_hash=data["payload_hash"], response_json=data.get("response_json")
        )

    async def complete(self, *, key: str, payload_hash: str, response_json: dict[str, Any], ttl_seconds: int) -> None:
        rk = self._key(key)
        value = json.dumps(
            {"status": "completed", "payload_hash": payload_hash, "response_json": response_json},
            separators=(",", ":"),
        ).encode("utf-8")
        await self._r.set(rk, value, ex=ttl_seconds)

    async def get(self, *, key: str) -> IdempotencyGet | None:
        rk = self._key(key)
        existing = await self._r.get(rk)
        if not existing:
            return None
        data = json.loads(existing.decode("utf-8"))
        return IdempotencyGet(
            status=data["status"], payload_hash=data["payload_hash"], response_json=data.get("response_json")
        )


# -----------------------------
# Factory
# -----------------------------
class Stores:
    def __init__(
        self,
        *,
        otp: OTPStore,
        proposals: ProposalStore,
        approvals: ApprovalStore,
        replay_nonces: ReplayNonceStore,
        idempotency: IdempotencyStore,
        redis_client: redis.Redis | None = None,
    ) -> None:
        self.otp = otp
        self.proposals = proposals
        self.approvals = approvals
        self.replay_nonces = replay_nonces
        self.idempotency = idempotency
        self.redis_client = redis_client


async def build_stores() -> Stores:
    if settings.redis_url:
        r = redis.from_url(settings.redis_url, decode_responses=False)
        return Stores(
            otp=RedisOTPStore(r),
            proposals=RedisProposalStore(r),
            approvals=RedisApprovalStore(r),
            replay_nonces=RedisReplayNonceStore(r),
            idempotency=RedisIdempotencyStore(r),
            redis_client=r,
        )
    return Stores(
        otp=InMemoryOTPStore(),
        proposals=InMemoryProposalStore(),
        approvals=InMemoryApprovalStore(),
        replay_nonces=InMemoryReplayNonceStore(),
        idempotency=InMemoryIdempotencyStore(),
        redis_client=None,
    )


def _generate_code() -> str:
    animals = ["ALPACA", "OTTER", "PANDA", "WOLF", "FALCON", "KOALA", "TIGER", "LYNX", "EAGLE", "GECKO"]
    word = secrets.choice(animals)
    num = secrets.randbelow(90) + 10  # 10..99
    return f"{word}-{num}"
