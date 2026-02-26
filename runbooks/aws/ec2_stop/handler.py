"""Runbook handler placeholder.

In a real deployment, this module would:
- assume a minimal IAM role (per-runbook)
- call AWS APIs (boto3) to stop the instance
- emit structured audit output

This repo keeps the handler as a placeholder to avoid AWS SDK coupling in the MVP skeleton.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RunbookResult:
    ok: bool
    message: str
    details: dict


def execute(instance_id: str, region: str) -> RunbookResult:
    # Placeholder logic
    return RunbookResult(
        ok=True,
        message=f"Stopped {instance_id} in {region} (placeholder)",
        details={
            "instance_id": instance_id,
            "region": region,
            "note": "Implement boto3 call + IAM assume role in production",
        },
    )
