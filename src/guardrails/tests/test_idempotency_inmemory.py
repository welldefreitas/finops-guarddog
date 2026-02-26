from __future__ import annotations

import pytest

from guardrails.storage import InMemoryIdempotencyStore


@pytest.mark.asyncio
async def test_idempotency_start_then_complete():
    store = InMemoryIdempotencyStore()
    started, existing = await store.start(key="k1", payload_hash="h1", ttl_seconds=60)
    assert started is True
    assert existing is None

    # second start should not start
    started2, existing2 = await store.start(key="k1", payload_hash="h1", ttl_seconds=60)
    assert started2 is False
    assert existing2 is not None
    assert existing2.status == "processing"

    await store.complete(key="k1", payload_hash="h1", response_json={"ok": True}, ttl_seconds=60)
    got = await store.get(key="k1")
    assert got is not None
    assert got.status == "completed"
    assert got.response_json == {"ok": True}
