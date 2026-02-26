from __future__ import annotations

import json
import logging
from urllib.parse import parse_qs

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from .audit_log import make_event
from .config import settings
from .llm_explainer import explain
from .policy_engine import PolicyEngine
from .request_auth import sha256_hex, verify_v1
from .runbook_executor import execute as execute_runbook
from .schema import ActionProposal, NormalizedAlert, OTPIssue, OTPVerifyRequest, OTPVerifyResponse
from .slack_blocks import build_approval_modal
from .slack_client import SlackClient, SlackConfig
from .slack_verify import verify_slack_signature
from .storage import Stores, build_stores

app = FastAPI(title="Cloud Guardrails Bot", version="0.4.0")

logger = logging.getLogger(__name__)

policy = PolicyEngine()
stores: Stores | None = None


@app.on_event("startup")
async def _startup():
    global stores
    stores = await build_stores()

    # Fail-fast in non-dev: secrets must be explicitly set (no placeholders).
    if settings.app_env != "dev" and not settings.app_secret:
        raise RuntimeError("APP_SECRET must be set in non-dev environments")
    if settings.app_env != "dev" and not settings.slack_signing_secret:
        raise RuntimeError("SLACK_SIGNING_SECRET must be set in non-dev environments")


def _ensure_stores() -> Stores:
    if stores is None:
        raise HTTPException(status_code=500, detail="stores_not_initialized")
    return stores


@app.get("/healthz")
def healthz():
    return {
        "ok": True,
        "service": "cloud-guardrails-bot",
        "version": "0.4.0",
        "redis_enabled": bool(settings.redis_url),
    }


@app.post("/webhook/alert", response_model=ActionProposal)
async def ingest_alert(alert: NormalizedAlert):
    decision = policy.evaluate(alert)
    expl = explain(alert, decision.action_id)

    st = _ensure_stores()
    import secrets as _secrets

    proposal_id = _secrets.token_urlsafe(12)
    proposal = ActionProposal(
        proposal_id=proposal_id,
        alert=alert,
        decision=decision,
        summary=expl["summary"],
        impact_estimate=expl.get("impact_estimate", {}),
    )
    await st.proposals.put(proposal)
    return proposal


@app.post("/otp/issue", response_model=OTPIssue)
async def issue_otp():
    st = _ensure_stores()
    issued = await st.otp.issue()
    # NOTE: In production, do NOT return code. Deliver it via Slack DM only.
    return JSONResponse(
        status_code=200,
        content={
            "otp_id": issued.otp_id,
            "expires_at": issued.expires_at.isoformat(),
            "dev_note_code": issued.code,
        },
    )


@app.post("/otp/verify", response_model=OTPVerifyResponse)
async def verify_otp(req: OTPVerifyRequest):
    st = _ensure_stores()
    ok, reason = await st.otp.verify(req.otp_id, req.code)
    return OTPVerifyResponse(valid=ok, reason=None if ok else reason)


def _slack_client() -> SlackClient:
    if not settings.slack_bot_token:
        raise HTTPException(status_code=500, detail="SLACK_BOT_TOKEN not configured")
    return SlackClient(SlackConfig(bot_token=settings.slack_bot_token))


def _extract_payload_form(body: bytes) -> dict:
    parsed = parse_qs(body.decode("utf-8"))
    if "payload" not in parsed:
        return {}
    return json.loads(parsed["payload"][0])


def _get_view_value(payload: dict, block_id: str) -> str:
    state = payload.get("view", {}).get("state", {}).get("values", {})
    block = state.get(block_id, {})
    for _, v in block.items():
        return (v.get("value") or "").strip()
    return ""


async def _execute_after_approval(proposal_id: str, *, idem_key: str, payload_hash: str) -> None:
    st = _ensure_stores()
    proposal = await st.proposals.get(proposal_id)
    if not proposal or not proposal.decision.eligible or not proposal.decision.action_id:
        resp = {"ok": False, "reason": "proposal_missing_or_ineligible", "proposal_id": proposal_id}
        await st.idempotency.complete(
            key=idem_key,
            payload_hash=payload_hash,
            response_json=resp,
            ttl_seconds=settings.idempotency_ttl_seconds,
        )
        return

    res = execute_runbook(
        proposal.decision.action_id,
        resource_id=proposal.alert.resource.id,
        region=proposal.alert.resource.region,
        env=proposal.alert.env,
    )
    resp = {"ok": res.ok, "message": res.message, "details": res.details, "proposal_id": proposal_id}

    await st.idempotency.complete(
        key=idem_key,
        payload_hash=payload_hash,
        response_json=resp,
        ttl_seconds=settings.idempotency_ttl_seconds,
    )


def _require_n8n_headers(
    *,
    timestamp: str | None,
    nonce: str | None,
    signature: str | None,
    body: bytes,
) -> None:
    if not timestamp or not nonce or not signature:
        raise HTTPException(status_code=401, detail="missing_hmac_headers")

    ok, reason = verify_v1(
        settings.n8n_shared_secret,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
        signature=signature,
        tolerance_seconds=settings.replay_tolerance_seconds,
    )
    if not ok:
        raise HTTPException(status_code=401, detail=f"hmac_verification_failed:{reason}")


@app.post("/execute")
async def execute_endpoint(
    request: Request,
    background: BackgroundTasks,
    x_cg_timestamp: str | None = Header(default=None, alias="X-CG-Timestamp"),
    x_cg_nonce: str | None = Header(default=None, alias="X-CG-Nonce"),
    x_cg_signature: str | None = Header(default=None, alias="X-CG-Signature"),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    """Execution trigger endpoint (hardened).

    Security properties:
    - **HMAC signed** requests between n8n ↔ API
    - **Replay protection** using (timestamp tolerance + nonce uniqueness)
    - **Idempotency keys** to prevent duplicate executions

    Required headers:
    - X-CG-Timestamp: unix epoch seconds
    - X-CG-Nonce: random unique string
    - X-CG-Signature: v1=<hex> where base is v1:{timestamp}:{nonce}:{body}
    - Idempotency-Key: unique key per intended execution (recommended)

    Body:
    { "proposal_id": "..." }
    """
    st = _ensure_stores()
    body = await request.body()

    _require_n8n_headers(timestamp=x_cg_timestamp, nonce=x_cg_nonce, signature=x_cg_signature, body=body)

    # Replay protection: claim nonce for the same tolerance window
    claimed, replay_reason = await st.replay_nonces.claim(
        nonce=x_cg_nonce, ttl_seconds=settings.replay_tolerance_seconds
    )
    if not claimed:
        raise HTTPException(status_code=409, detail=replay_reason)

    try:
        payload = json.loads(body.decode("utf-8")) if body else {}
    except Exception as err:
        raise HTTPException(status_code=400, detail="invalid_json") from err

    proposal_id = (payload.get("proposal_id") or "").strip()
    if not proposal_id:
        raise HTTPException(status_code=400, detail="proposal_id_required")

    # Idempotency handling
    idem_key = (idempotency_key or f"execute:{proposal_id}").strip()
    payload_hash = sha256_hex(body)

    started, existing = await st.idempotency.start(
        key=idem_key, payload_hash=payload_hash, ttl_seconds=settings.idempotency_ttl_seconds
    )
    if not started and existing:
        # If payload differs, that's suspicious (same key used for different request)
        if existing.payload_hash != payload_hash:
            raise HTTPException(status_code=409, detail="idempotency_key_reuse_with_different_payload")
        if existing.status == "completed" and existing.response_json is not None:
            return JSONResponse(
                status_code=200, content={"ok": True, "idempotent": True, "response": existing.response_json}
            )
        # processing
        return JSONResponse(status_code=202, content={"ok": True, "idempotent": True, "status": "processing"})

    # First time: queue execution
    background.add_task(_execute_after_approval, proposal_id, idem_key=idem_key, payload_hash=payload_hash)
    return {"ok": True, "queued": True, "proposal_id": proposal_id, "idempotency_key": idem_key}


@app.post("/slack/actions")
async def slack_actions(
    request: Request,
    background: BackgroundTasks,
    x_slack_request_timestamp: str = Header(default=""),
    x_slack_signature: str = Header(default=""),
):
    body = await request.body()
    if not verify_slack_signature(timestamp=x_slack_request_timestamp, body=body, signature=x_slack_signature):
        raise HTTPException(status_code=401, detail="invalid_slack_signature")

    payload = _extract_payload_form(body)
    if not payload:
        return {"ok": True}

    st = _ensure_stores()
    event_type = payload.get("type")

    if event_type == "block_actions":
        actions = payload.get("actions", [])
        if not actions:
            return {"ok": True}
        action = actions[0]
        action_id = action.get("action_id", "")
        proposal_id = action.get("value", "")
        trigger_id = payload.get("trigger_id", "")
        user_id = payload.get("user", {}).get("id", "")

        proposal = await st.proposals.get(proposal_id)
        if not proposal:
            return JSONResponse(status_code=200, content={"response_type": "ephemeral", "text": "Proposal expired."})

        if action_id == "approve_proposal":
            otp_id = None
            if proposal.decision.otp_required:
                issued = await st.otp.issue()
                otp_id = issued.otp_id
                try:
                    await _slack_client().dm(
                        user_id=user_id, text=f"Your OTP for approval: `{issued.code}` (expires in 5 min)"
                    )
                except Exception:
                    logger.warning("slack_dm_failed", exc_info=True)

            meta = {
                "proposal_id": proposal_id,
                "action_id": proposal.decision.action_id,
                "resource_id": proposal.alert.resource.id,
                "env": proposal.alert.env,
                "otp_required": proposal.decision.otp_required,
                "otp_id": otp_id,
                "channel_id": payload.get("channel", {}).get("id"),
                "message_ts": payload.get("message", {}).get("ts"),
            }
            view = build_approval_modal(
                action_id=proposal.decision.action_id or "UNKNOWN",
                resource_id=proposal.alert.resource.id,
                otp_required=proposal.decision.otp_required,
                private_metadata=json.dumps(meta),
            )
            await _slack_client().open_modal(trigger_id=trigger_id, view=view)
            return {"ok": True}

        if action_id == "deny_proposal":
            return JSONResponse(status_code=200, content={"response_type": "ephemeral", "text": "Denied."})
        if action_id == "snooze_proposal":
            return JSONResponse(
                status_code=200, content={"response_type": "ephemeral", "text": "Snoozed (MVP placeholder)."}
            )
        if action_id == "exception_proposal":
            return JSONResponse(
                status_code=200, content={"response_type": "ephemeral", "text": "Exception flow (MVP placeholder)."}
            )
        return {"ok": True}

    if event_type == "view_submission":
        user_id = payload.get("user", {}).get("id", "")
        meta = payload.get("view", {}).get("private_metadata", "{}")
        try:
            meta_obj = json.loads(meta)
        except Exception:
            meta_obj = {}

        proposal_id = meta_obj.get("proposal_id", "")
        action_id = meta_obj.get("action_id", "")
        resource_id = meta_obj.get("resource_id", "")
        env = meta_obj.get("env", "dev")
        otp_required = bool(meta_obj.get("otp_required", False))
        otp_id = meta_obj.get("otp_id")

        proposal = await st.proposals.get(proposal_id)
        if not proposal:
            return JSONResponse(
                status_code=200,
                content={"response_action": "errors", "errors": {"typed_confirmation": "Proposal expired"}},
            )

        typed = _get_view_value(payload, "typed_confirmation")
        expected = f"APPLY {action_id} {resource_id}"
        if typed != expected:
            return JSONResponse(
                status_code=200,
                content={"response_action": "errors", "errors": {"typed_confirmation": f"Type exactly: {expected}"}},
            )

        justification = _get_view_value(payload, "justification")
        ticket = _get_view_value(payload, "ticket")

        if env == "prod" and not ticket:
            return JSONResponse(
                status_code=200,
                content={"response_action": "errors", "errors": {"ticket": "Ticket/Change ID required for PROD"}},
            )

        if otp_required:
            code = _get_view_value(payload, "otp_code")
            if not otp_id or not code:
                return JSONResponse(
                    status_code=200, content={"response_action": "errors", "errors": {"otp_code": "OTP required"}}
                )
            ok, reason = await st.otp.verify(otp_id, code)
            if not ok:
                return JSONResponse(
                    status_code=200,
                    content={"response_action": "errors", "errors": {"otp_code": f"OTP invalid: {reason}"}},
                )

        required = 2 if env == "prod" else 1
        await st.approvals.init_request(
            key=proposal_id,
            required=required,
            env=env,
            action_id=action_id,
            resource_id=resource_id,
            channel_id=meta_obj.get("channel_id"),
            message_ts=meta_obj.get("message_ts"),
        )
        status = await st.approvals.add_approver(key=proposal_id, user_id=user_id)

        try:
            meta2 = await st.approvals.get_meta(key=proposal_id)
            channel_id = meta2.get("channel_id") or meta_obj.get("channel_id")
            if channel_id:
                await _slack_client().post_message(
                    channel=channel_id,
                    text=f"✅ Approval recorded for `{action_id}` on `{resource_id}` ({env}). Approvals: {status.approved_count}/{status.required}.",
                )
        except Exception:
            logger.warning("slack_post_message_failed", exc_info=True)

        if status.complete:
            # In production, you might call /execute via n8n here (decoupled). For MVP, we execute locally.
            idem_key = f"execute:{proposal_id}"
            payload = json.dumps({"proposal_id": proposal_id}, separators=(",", ":")).encode("utf-8")
            payload_hash = sha256_hex(payload)
            await st.idempotency.start(
                key=idem_key, payload_hash=payload_hash, ttl_seconds=settings.idempotency_ttl_seconds
            )
            background.add_task(_execute_after_approval, proposal_id, idem_key=idem_key, payload_hash=payload_hash)

        audit = make_event(
            "approval_complete" if status.complete else "approval_recorded",
            {
                "proposal_id": proposal_id,
                "action_id": action_id,
                "resource_id": resource_id,
                "env": env,
                "approver": user_id,
                "approved_count": status.approved_count,
                "required": status.required,
                "justification": justification,
                "ticket": ticket,
            },
        )

        return JSONResponse(status_code=200, content={"response_action": "clear", "audit": audit})

    event = make_event("slack_action_received", {"type": event_type})
    return {"ok": True, "event": event}
