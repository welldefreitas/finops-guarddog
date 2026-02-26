# cloud-guardrails-bot

[![ci](https://github.com/welldefreitas/cloud-guardrails-bot/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_GITHUB_USERNAME/cloud-guardrails-bot/actions/workflows/ci.yml)
[![security](https://github.com/welldefreitas/cloud-guardrails-bot/actions/workflows/security.yml/badge.svg)](https://github.com/YOUR_GITHUB_USERNAME/cloud-guardrails-bot/actions/workflows/security.yml)

> 🔧 Replace `YOUR_GITHUB_USERNAME` in badge URLs after you create the repo.

Policy-driven **FinOps & Security** remediation via **Slack approvals** — with **OTP step-up** + **dual approval for PROD**.

> **Design stance:** policy-as-code is the decision engine. The LLM is *optional* and only explains/enriches context inside a strict schema.

## What this repo provides (MVP skeleton)

- FastAPI service that:
  - receives normalized alerts via webhook
  - evaluates them against **deny-by-default** policies
  - issues an **Action Proposal** (what, why, risk tier)
  - manages **OTP** (rotating code with TTL + max attempts)
  - exposes Slack verification helpers + payload schema (ready for interactive modals)

- Policy & runbook scaffolding:
  - `policies/rego/` examples (OPA-ready)
  - `runbooks/aws/` placeholders for action executors
  - `slack/` blocks + app manifest templates
  - `docs/` architecture, threat model, ADRs

## Security controls (built-in)
- **Least privilege by design:** executor roles are per-runbook (recommended)
- **Step-up confirmation:** typed confirmation + OTP (no static shared passwords)
- **Dual approval for PROD:** 2 distinct approvers within time window (recommended integration point)
- **Slack request verification:** signature validation helper (HMAC SHA256)
- **Audit trail interface:** structured events (JSONL-friendly) for SIEM ingestion

## Quickstart (local)

### 1) Create a virtualenv and install
```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ".[dev]"
```

### 2) Run the API
```bash
uvicorn guardrails.app:app --reload --port 8000
```

### 3) Health check
```bash
curl -s http://localhost:8000/healthz | jq
```

### 4) Simulate an alert
```bash
curl -s http://localhost:8000/webhook/alert \
  -H "Content-Type: application/json" \
  -d '{
    "provider":"aws",
    "account_id":"111111111111",
    "env":"dev",
    "event_id":"evt-123",
    "resource": {"type":"ec2_instance","id":"i-0abc123","region":"us-east-1","tags":{"owner":"team-a"}},
    "finding": {"category":"finops","title":"EC2 left running out of hours","cost_per_day_usd": 50.0},
    "observed_at":"2026-02-26T08:00:00Z"
  }' | jq
```

## Architecture (Mermaid)

```mermaid
%% Cloud Guardrails Bot - Architecture (MVP)
graph TD
  A[Cloud Alerts<br/>(AWS/GCP)] -->|Webhook (signed)| B[Ingress (n8n or FastAPI)]
  B --> C[Normalize + Enrich<br/>(tags/labels,cost,risk)]
  C --> D[Policy Engine<br/>deny-by-default]
  D -->|Proposal| E[Slack Card<br/>Approve/Deny/Snooze/Exception]
  E -->|Approve| F[Slack Modal<br/>typed confirmation]
  F -->|Step-up| G[OTP (DM)<br/>TTL + max attempts]
  G --> H{Approval rules}
  H -->|DEV/STAGE: 1| I[Execute Runbook<br/>(least-priv role)]
  H -->|PROD: 2| I
  I --> J[Audit Log + Metrics]
  J --> E
```


## Repo map
- `src/guardrails/` — FastAPI app + services (OTP, policy, Slack verify, audit)
- `policies/` — policy examples (OPA-ready) + sample inputs
- `slack/` — Slack app manifest + Block Kit payload templates
- `workflows/n8n/` — placeholder flow JSONs (ingest → normalize → policy → notify → approve → execute)
- `runbooks/` — action executors (placeholder)

## Roadmap
- OPA/Rego evaluation server-side (optional) or Conftest-based pipeline checks
- Slack interactive modals (Approve → typed confirmation + OTP)
- Dual-approval coordinator for PROD (2 users, timeboxed)
- Terraform plan/apply executor (with diff surfaced in Slack)

---

### Disclaimer
This project is a **starter kit**. Do **not** point it at production accounts without hardening IAM, secrets handling, and change-management integration.


## Threat model (quick view)

**Primary threats**
- Forged webhooks / event injection
- Slack request forgery + replay
- Unauthorized approvals (compromised Slack session)
- Over-privileged IAM roles / blast radius expansion
- Prompt-injection via alert payloads (if LLM enabled)

**Baseline mitigations**
- Verify webhook authenticity + rate-limit + dedupe
- Verify Slack signatures + timestamp tolerance (anti-replay)
- Closed action catalog + **deny-by-default** policies
- OTP step-up (TTL + max attempts) and **dual approval for PROD**
- Per-runbook least-privilege roles; no long-lived keys
- Append-only audit trail (recommended)

Full notes: `docs/threat-model.md`


## Redis upgrade (recommended)

This repo now supports Redis-backed state for:
- OTP issuance/verification
- Proposal correlation (Slack ↔ proposal)
- PROD dual-approval coordination

Set `REDIS_URL` to enable. If `REDIS_URL` is unset, the app falls back to in-memory stores (dev only).

Quick start with Docker:
```bash
cp .env.example .env
# edit .env (set APP_SECRET, Slack secrets/tokens)
docker compose up --build
```


## Hardened /execute (idempotency + replay protection + HMAC)

The `/execute` endpoint is designed for a **trusted runner** (e.g. n8n) and includes:
- **HMAC request signing** (shared secret) to prevent tampering/forgery
- **Replay protection**: timestamp tolerance + **nonce uniqueness**
- **Idempotency keys**: prevents duplicate executions if n8n retries

### Required headers (from n8n)
- `X-CG-Timestamp`: unix epoch seconds (e.g. `1700000000`)
- `X-CG-Nonce`: random unique string per request
- `X-CG-Signature`: `v1=<hex>` where base is: `v1:{timestamp}:{nonce}:{raw_body}`
- `Idempotency-Key`: unique key per execution (recommended)

### Example signature (Python)
```python
import time, secrets, hmac, hashlib, json

secret = "YOUR_SHARED_SECRET"
ts = str(int(time.time()))
nonce = secrets.token_urlsafe(12)
body = json.dumps({"proposal_id":"abc"}).encode()

base = b"v1:" + ts.encode() + b":" + nonce.encode() + b":" + body
sig = "v1=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
print(ts, nonce, sig)
```

Configure in `.env`:
- `N8N_SHARED_SECRET`
- `REPLAY_TOLERANCE_SECONDS`
- `IDEMPOTENCY_TTL_SECONDS`



## 📜 License
MIT — see [LICENSE](LICENSE).

---

<p align="center">
  <b>Developed by Wellington de Freitas</b> | <i>Cloud Security & DevSecOps Architect</i>
  <br><br>
  <a href="https://linkedin.com/in/welldefreitas" target="_blank">
    <img src="https://img.shields.io/badge/LinkedIn-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn">
  </a>
  <a href="https://github.com/welldefreitas" target="_blank">
    <img src="https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub">
  </a>
  <a href="https://instagram.com/welldefreitas" target="_blank">
    <img src="https://img.shields.io/badge/Instagram-E4405F?style=for-the-badge&logo=instagram&logoColor=white" alt="Instagram">
  </a>
</p>
