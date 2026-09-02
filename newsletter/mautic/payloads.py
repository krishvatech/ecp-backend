"""Payload builders for Mautic newsletter email entities."""

from __future__ import annotations

from typing import Any


def _mautic_segment_id(value: object) -> int | str:
    normalized = str(value or "").strip()
    if normalized.isdigit():
        return int(normalized)
    return normalized


def build_campaign_email_payload(
    campaign,
    *,
    publish: bool = False,
) -> dict[str, Any]:
    """Build the Mautic list-email payload for an ECP newsletter campaign."""

    segment_ids = [
        _mautic_segment_id(category.mautic_segment_id)
        for category in campaign.audiences.all().order_by("slug", "id")
    ]

    return {
        "name": campaign.name,
        "subject": campaign.subject,
        "fromName": campaign.from_name,
        "fromAddress": campaign.from_email,
        "plainText": campaign.plain_text,
        "customHtml": campaign.html_content,
        "emailType": "list",
        "lists": segment_ids,
        "isPublished": bool(publish),
    }


def build_test_email_payload(campaign) -> dict[str, Any]:
    """Build an isolated Mautic email payload for a single test send."""

    return {
        "name": f"{campaign.name} - Test",
        "subject": campaign.subject,
        "fromName": campaign.from_name,
        "fromAddress": campaign.from_email,
        "plainText": campaign.plain_text,
        "customHtml": campaign.html_content,
        "emailType": "template",
        "isPublished": True,
    }
