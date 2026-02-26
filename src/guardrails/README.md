# guardrails package

Core services:
- `policy_engine.py` — deterministic policy evaluation (deny-by-default)
- `storage.py` — Redis-backed (or in-memory fallback) state for OTP / proposals / approvals / replay nonces / idempotency
- `request_auth.py` — HMAC signing verification helpers + payload hashing
- `slack_verify.py` — Slack request signature verification
- `slack_client.py` — minimal Slack Web API client (views.open, chat.postMessage, DM)
- `runbook_executor.py` — placeholder runbook dispatcher
- `app.py` — FastAPI endpoints: alert ingest + Slack interactivity + hardened /execute
