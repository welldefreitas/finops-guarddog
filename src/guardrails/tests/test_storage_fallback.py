from __future__ import annotations

import pytest

from guardrails.storage import InMemoryOTPStore


@pytest.mark.asyncio
async def test_inmemory_otp_store_roundtrip():
    store = InMemoryOTPStore()
    issued = await store.issue()
    ok, reason = await store.verify(issued.otp_id, issued.code)
    assert ok is True
    assert reason == "ok"
