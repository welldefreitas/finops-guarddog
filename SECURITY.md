# Security Policy

## Reporting a Vulnerability
Please do **not** open public issues for security vulnerabilities.
Instead, contact the maintainer privately with:
- a clear description of the issue
- reproduction steps / PoC
- impact assessment
- suggested remediation (if available)

## Hardening notes (production)
- Use OIDC/AssumeRole, **never** long-lived keys.
- Verify Slack request signatures for all interactive routes.
- Enforce strict allowlists for accounts/workspaces/channels.
- Store secrets in Secret Manager/Vault (never in n8n nodes).
- Implement rate limiting + dedupe on webhook ingress.
- Maintain a full audit trail (immutable storage preferred).
