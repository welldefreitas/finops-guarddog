from __future__ import annotations

from .schema import NormalizedAlert, PolicyDecision


class PolicyEngine:
    """Deterministic policy evaluator (MVP).

    - deny-by-default
    - closed action selection
    - outputs governance requirements (approvals + otp)
    """

    def evaluate(self, alert: NormalizedAlert) -> PolicyDecision:
        # Deny-by-default
        decision = PolicyDecision(
            eligible=False,
            action_id=None,
            risk_tier="LOW",
            reasons=["deny-by-default"],
            approval_required=1,
            otp_required=False,
        )

        # Example rule: stop non-prod EC2 instance for FinOps
        if (
            alert.env in {"dev", "test", "stage"}
            and alert.provider == "aws"
            and alert.finding.category == "finops"
            and alert.resource.type == "ec2_instance"
            and str(alert.resource.tags.get("do_not_stop", "false")).lower() != "true"
            and str(alert.resource.tags.get("owner", "")).strip() != ""
        ):
            decision.eligible = True
            decision.action_id = "aws_ec2_stop_dev_out_of_hours"
            decision.risk_tier = "LOW"
            decision.reasons = ["non-prod EC2 running (policy match)"]
            decision.approval_required = 1
            decision.otp_required = False

        # Governance overlay
        if decision.eligible and alert.env == "prod":
            decision.approval_required = 2
            decision.otp_required = True

        if decision.eligible and decision.risk_tier in {"MEDIUM", "HIGH"}:
            decision.otp_required = True

        return decision
