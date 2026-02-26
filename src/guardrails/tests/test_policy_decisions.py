from __future__ import annotations

from datetime import UTC, datetime

from guardrails.policy_engine import PolicyEngine
from guardrails.schema import NormalizedAlert


def test_nonprod_ec2_finops_is_eligible():
    engine = PolicyEngine()
    alert = NormalizedAlert(
        provider="aws",
        account_id="111111111111",
        env="dev",
        event_id="evt-1",
        resource={"type": "ec2_instance", "id": "i-1", "region": "us-east-1", "tags": {"owner": "team-a"}},
        finding={"category": "finops", "title": "EC2 left running out of hours", "cost_per_day_usd": 10.0},
        observed_at=datetime.now(UTC),
    )
    decision = engine.evaluate(alert)
    assert decision.eligible is True
    assert decision.action_id == "aws_ec2_stop_dev_out_of_hours"
    assert decision.approval_required == 1
    assert decision.otp_required is False
