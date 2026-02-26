from __future__ import annotations

import os

from dotenv import load_dotenv
from pydantic import BaseModel

load_dotenv()


class Settings(BaseModel):
    app_env: str = os.getenv("APP_ENV", "dev")

    # Crypto (used for HMAC hashing OTP codes; and optionally request signing)
    # NOTE: In non-dev environments, this should be a long random value.
    app_secret: str = os.getenv("APP_SECRET", "")

    # Slack
    slack_signing_secret: str = os.getenv("SLACK_SIGNING_SECRET", "")
    slack_bot_token: str = os.getenv("SLACK_BOT_TOKEN", "")

    # Storage (Redis)
    redis_url: str | None = os.getenv("REDIS_URL") or None

    # Governance
    otp_ttl_seconds: int = int(os.getenv("OTP_TTL_SECONDS", "300"))  # 5 minutes
    otp_max_attempts: int = int(os.getenv("OTP_MAX_ATTEMPTS", "3"))
    approval_window_seconds: int = int(os.getenv("APPROVAL_WINDOW_SECONDS", "900"))  # 15 minutes

    # n8n ↔ API signing + replay protection
    n8n_shared_secret: str = os.getenv("N8N_SHARED_SECRET", "")
    replay_tolerance_seconds: int = int(os.getenv("REPLAY_TOLERANCE_SECONDS", "300"))  # 5 min

    # Idempotency
    idempotency_ttl_seconds: int = int(os.getenv("IDEMPOTENCY_TTL_SECONDS", "3600"))  # 1 hour


settings = Settings()
