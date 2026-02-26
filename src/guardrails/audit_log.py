from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def make_event(event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "ts": now_iso(),
        "event_type": event_type,
        "payload": payload,
    }


def to_json_line(event: dict[str, Any]) -> str:
    return json.dumps(event, separators=(",", ":"), ensure_ascii=False)
