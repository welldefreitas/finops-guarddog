# ADR-0002: OTP step-up confirmation

## Decision
Use rotating OTP codes with TTL and max attempts, delivered via Slack DM, for MEDIUM/HIGH and PROD.

## Rationale
- reduces misclick and unauthorized approvals
- avoids static shared secrets ("pikachu problem")

## Consequences
- require state store (in-memory for MVP; Redis recommended)
