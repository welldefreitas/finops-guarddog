# Slack UX (starter)

## Alert Card
- Summary (what happened)
- Impact estimate (cost/day or security severity)
- Evidence (resource id, tags, region)
- Buttons: Approve / Deny / Snooze / Create Exception

## Approve flow
1) User clicks Approve
2) Bot opens Modal requiring typed confirmation:
   - `APPLY <ACTION_ID> <RESOURCE_ID>`
3) If action is MEDIUM/HIGH or env==prod, require OTP
   - OTP sent via DM, expires in 5 minutes, 3 attempts max

## PROD dual approval
Collect approvals from 2 distinct Slack users within time window (suggested 15 min).


## FastAPI interactive endpoint
This repo includes `/slack/actions` which:
- verifies Slack signatures
- opens the approval modal on button click
- validates typed confirmation + OTP on submit
- enforces **dual approval for PROD** (2 distinct approvers)

> Note: The actual *execution* is intentionally decoupled. Wire it to n8n / runbook executor where marked.
