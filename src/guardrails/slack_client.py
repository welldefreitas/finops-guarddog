from __future__ import annotations

import json
from typing import Any

import httpx
from pydantic import BaseModel


class SlackConfig(BaseModel):
    bot_token: str
    api_base: str = "https://slack.com/api"


class SlackClient:
    def __init__(self, cfg: SlackConfig) -> None:
        self._cfg = cfg

    async def _post(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self._cfg.api_base}/{method}"
        headers = {
            "Authorization": f"Bearer {self._cfg.bot_token}",
            "Content-Type": "application/json; charset=utf-8",
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(url, headers=headers, content=json.dumps(payload))
            r.raise_for_status()
            data = r.json()
        return data

    async def open_modal(self, *, trigger_id: str, view: dict[str, Any]) -> dict[str, Any]:
        return await self._post("views.open", {"trigger_id": trigger_id, "view": view})

    async def open_im(self, *, user_id: str) -> str:
        data = await self._post("conversations.open", {"users": user_id})
        if not data.get("ok"):
            raise RuntimeError(f"conversations.open failed: {data}")
        return data["channel"]["id"]

    async def post_message(self, *, channel: str, text: str, blocks: list[dict] | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"channel": channel, "text": text}
        if blocks is not None:
            payload["blocks"] = blocks
        data = await self._post("chat.postMessage", payload)
        if not data.get("ok"):
            raise RuntimeError(f"chat.postMessage failed: {data}")
        return data

    async def dm(self, *, user_id: str, text: str) -> dict[str, Any]:
        channel = await self.open_im(user_id=user_id)
        return await self.post_message(channel=channel, text=text)
