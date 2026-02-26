# Runbooks (starter)

Runbooks are action executors. Keep each runbook:
- **idempotent**
- scoped to minimal IAM permissions
- producing structured output suitable for audit logs

Each runbook folder contains:
- `action.json` (metadata: action_id, risk tier, required permissions)
- implementation (Python handler, Terraform module, etc.)


## Execution handoff (Slack approval -> runbook)
In this MVP skeleton, the approval completion is logged as an audit event.
In a real deployment, you typically:
- call n8n webhook `.../execute` OR
- enqueue a job (SQS/PubSub) OR
- start a Step Function / Cloud Workflow

Keep that boundary explicit (change-management friendly).
