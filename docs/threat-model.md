# Threat Model (starter)

## Assets
- Cloud credentials/roles used for runbooks (highest value)
- Slack workspace trust boundary (approvals)
- Audit logs (integrity)
- Policies (decision logic)

## Primary threats
- Forged webhook events
- Slack request forgery / replay
- Prompt injection via alert payloads (if LLM used)
- Over-privileged IAM roles leading to blast radius expansion
- Unauthorized approvals (stolen Slack account/session)
- Audit log tampering

## Baseline mitigations
- Verify webhook authenticity (HMAC/signature/allowlist)
- Verify Slack signature and timestamp; prevent replay
- Strict policy-as-code; deny-by-default; closed action catalog
- OTP step-up for MEDIUM/HIGH and PROD; max attempts + TTL
- Dual approval for PROD (2 distinct user IDs + timebox)
- Least-privilege roles per runbook; no long-lived keys
- Write audit logs to append-only/immutable storage (recommended)

## Non-goals (MVP)
- Full change-management integration (ServiceNow/Jira)
- Automatic rollback orchestration for all actions
