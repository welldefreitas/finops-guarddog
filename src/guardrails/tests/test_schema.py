from __future__ import annotations

from datetime import UTC, datetime

from guardrails.schema import NormalizedAlert


def test_schema_accepts_minimal_alert():
    a = NormalizedAlert(
        provider="aws",
        account_id="111111111111",
        env="dev",
        event_id="evt-1",
        resource={"type": "ec2_instance", "id": "i-1", "region": "us-east-1", "tags": {"owner": "x"}},
        finding={"category": "finops", "title": "test", "cost_per_day_usd": 1.23},
        observed_at=datetime.now(UTC),
    )
    assert a.provider == "aws"
