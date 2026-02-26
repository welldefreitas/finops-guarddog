from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RunbookResult:
    ok: bool
    message: str
    details: dict[str, Any]


def execute(action_id: str, *, resource_id: str, region: str | None, env: str) -> RunbookResult:
    """Runbook dispatcher (MVP placeholder).

    In production:
    - assume a per-runbook least-priv role
    - execute Terraform plan/apply or cloud API calls
    - emit structured audit outputs
    """
    # Placeholder implementations
    if action_id == "aws_ec2_stop_dev_out_of_hours":
        return RunbookResult(
            ok=True,
            message=f"[placeholder] would stop EC2 instance {resource_id} (env={env}, region={region})",
            details={"action_id": action_id, "resource_id": resource_id, "env": env, "region": region},
        )

    return RunbookResult(
        ok=False,
        message=f"Unknown or unimplemented action_id: {action_id}",
        details={"action_id": action_id},
    )
