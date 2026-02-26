from __future__ import annotations

from typing import Any

from .schema import NormalizedAlert


def explain(alert: NormalizedAlert, decision_action_id: str | None) -> dict[str, Any]:
    """LLM stub (MVP).

    In production, replace with OpenAI/Gemini call that returns STRICT JSON schema.
    Here we keep it deterministic to avoid network calls in the skeleton.
    """
    impact: dict[str, Any] = {}
    if alert.finding.cost_per_day_usd is not None:
        impact["cost_per_day_usd"] = alert.finding.cost_per_day_usd

    summary = f"{alert.finding.title} | env={alert.env} | resource={alert.resource.type}:{alert.resource.id}"
    return {
        "summary": summary,
        "impact_estimate": impact,
        "recommended_action_id": decision_action_id,
        "confidence": 0.6 if decision_action_id else 0.2,
        "assumptions": ["LLM disabled in MVP skeleton; using deterministic explainer"],
    }
