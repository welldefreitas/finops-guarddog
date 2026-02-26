from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Provider = Literal["aws", "gcp"]
Env = Literal["dev", "test", "stage", "prod"]
Category = Literal["finops", "security"]
RiskTier = Literal["LOW", "MEDIUM", "HIGH"]


class Resource(BaseModel):
    type: str
    id: str
    region: str | None = None
    tags: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    category: Category
    title: str
    cost_per_day_usd: float | None = None
    severity: str | None = None


class NormalizedAlert(BaseModel):
    provider: Provider
    account_id: str
    env: Env
    event_id: str
    resource: Resource
    finding: Finding
    observed_at: datetime


class PolicyDecision(BaseModel):
    eligible: bool
    action_id: str | None = None
    risk_tier: RiskTier = "LOW"
    reasons: list[str] = Field(default_factory=list)

    # governance outputs
    approval_required: int = 1
    otp_required: bool = False


class ActionProposal(BaseModel):
    proposal_id: str
    alert: NormalizedAlert
    decision: PolicyDecision
    summary: str
    impact_estimate: dict[str, Any] = Field(default_factory=dict)


class OTPIssue(BaseModel):
    otp_id: str
    expires_at: datetime


class OTPVerifyRequest(BaseModel):
    otp_id: str
    code: str


class OTPVerifyResponse(BaseModel):
    valid: bool
    reason: str | None = None
