from __future__ import annotations

from typing import Any


def build_alert_card(
    *, proposal_id: str, action_id: str, resource_id: str, env: str, impact: str
) -> list[dict[str, Any]]:
    return [
        {"type": "header", "text": {"type": "plain_text", "text": "Cloud Guardrails Alert"}},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Action:*\n{action_id}"},
                {"type": "mrkdwn", "text": f"*Resource:*\n{resource_id}"},
                {"type": "mrkdwn", "text": f"*Env:*\n{env}"},
                {"type": "mrkdwn", "text": f"*Impact:*\n{impact}"},
            ],
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": "Approve remediation?"}},
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "style": "primary",
                    "value": proposal_id,
                    "action_id": "approve_proposal",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Deny"},
                    "style": "danger",
                    "value": proposal_id,
                    "action_id": "deny_proposal",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Snooze"},
                    "value": proposal_id,
                    "action_id": "snooze_proposal",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Create Exception"},
                    "value": proposal_id,
                    "action_id": "exception_proposal",
                },
            ],
        },
    ]


def build_approval_modal(
    *, action_id: str, resource_id: str, otp_required: bool, private_metadata: str
) -> dict[str, Any]:
    typed_hint = f"APPLY {action_id} {resource_id}"
    blocks: list[dict[str, Any]] = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Step-up approval*\nType the confirmation and provide OTP if required.",
            },
        },
        {
            "type": "input",
            "block_id": "typed_confirmation",
            "label": {"type": "plain_text", "text": "Type confirmation"},
            "element": {
                "type": "plain_text_input",
                "action_id": "value",
                "placeholder": {"type": "plain_text", "text": typed_hint},
            },
        },
    ]
    blocks.append(
        {
            "type": "input",
            "optional": not otp_required,
            "block_id": "otp_code",
            "label": {
                "type": "plain_text",
                "text": "OTP (required for MEDIUM/HIGH & PROD)" if otp_required else "OTP (if required)",
            },
            "element": {
                "type": "plain_text_input",
                "action_id": "value",
                "placeholder": {"type": "plain_text", "text": "e.g., ALPACA-17"},
            },
        }
    )
    blocks.extend(
        [
            {
                "type": "input",
                "optional": False,
                "block_id": "justification",
                "label": {"type": "plain_text", "text": "Justification"},
                "element": {"type": "plain_text_input", "action_id": "value", "multiline": True},
            },
            {
                "type": "input",
                "optional": True,
                "block_id": "ticket",
                "label": {"type": "plain_text", "text": "Ticket / Change ID (required for PROD)"},
                "element": {"type": "plain_text_input", "action_id": "value"},
            },
        ]
    )

    return {
        "type": "modal",
        "callback_id": "guardrails_approve_modal",
        "title": {"type": "plain_text", "text": "Approve Remediation"},
        "submit": {"type": "plain_text", "text": "Approve"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "private_metadata": private_metadata,
        "blocks": blocks,
    }
