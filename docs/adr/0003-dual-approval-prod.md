# ADR-0003: Dual approval in production

## Decision
Require 2 distinct approvers for PROD actions, timeboxed.

## Rationale
- aligns with enterprise change controls
- reduces blast radius of compromised accounts

## Consequences
- introduce approval coordinator state
