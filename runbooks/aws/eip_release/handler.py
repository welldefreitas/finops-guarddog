from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RunbookResult:
    ok: bool
    message: str
    details: dict


def execute(allocation_id: str, region: str) -> RunbookResult:
    return RunbookResult(
        ok=True,
        message=f"Released EIP {allocation_id} in {region} (placeholder)",
        details={"allocation_id": allocation_id, "region": region},
    )
