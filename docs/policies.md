# Policies (MVP)

This repository assumes policies are the **decision engine**.
The initial MVP includes:
- A simple **Python policy evaluator** (for local runs/tests)
- Example **OPA/Rego** policies (optional integration)

## Policy inputs
See `src/guardrails/schema.py` for the canonical schema.

## Environment approvals
- DEV/STAGE: 1 approval
- PROD: 2 approvals (distinct approvers) + OTP + typed confirmation
