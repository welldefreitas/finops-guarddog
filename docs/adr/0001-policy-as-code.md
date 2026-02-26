# ADR-0001: Policy-as-code as decision engine

## Decision
Use policy-as-code (deny-by-default) to decide *eligibility* and *action id*.

## Rationale
- predictable, testable, auditable decisions
- avoids LLM-driven execution risks

## Consequences
- policy management becomes a core part of the product
