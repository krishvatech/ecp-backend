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


#: Mautic's Email form parses publishUp/publishDown with a date-picker widget
#: whose format is ``yyyy-MM-dd HH:mm`` (Mautic\CoreBundle\Form\Type\
#: DatePickerType). An ISO-8601 string carrying an offset is rejected outright
#: with "Please enter a valid date and time.", verified against the running
#: 7.1.3 instance. The naive string is then interpreted in Mautic's configured
#: ``default_timezone``, which is UTC here, so converting to UTC before
#: formatting is what preserves the exact instant the admin chose.
MAUTIC_SCHEDULE_DATETIME_FORMAT = "%Y-%m-%d %H:%M"


def format_mautic_schedule_datetime(value) -> str:
    """Render one aware datetime the way Mautic's Email form accepts it."""
    from datetime import timezone as datetime_timezone

    from django.utils import timezone as django_timezone

    if value is None:
        return ""
    if django_timezone.is_naive(value):
        value = django_timezone.make_aware(value, datetime_timezone.utc)
    return value.astimezone(datetime_timezone.utc).strftime(
        MAUTIC_SCHEDULE_DATETIME_FORMAT
    )


def build_scheduled_campaign_email_payload(campaign, *, scheduled_at):
    """Content + audience + the native fields that arm a future broadcast.

    ``mautic:broadcasts:send`` selects list emails through
    EmailRepository::getPublishedBroadcastsQuery(), which calls
    getPublishedByDateExpression(..., allowNullForPublishedUp: false). That
    means a broadcast is only picked up when it is published *and* carries a
    non-null publishUp that has already passed. So an armed future schedule is
    ``isPublished=True`` plus a future ``publishUp`` — not an unpublished row.
    """
    payload = build_campaign_email_payload(campaign, publish=True)
    payload["publishUp"] = format_mautic_schedule_datetime(scheduled_at)
    return payload


def build_cancelled_schedule_email_payload(campaign):
    """The native state that disarms a scheduled broadcast.

    Clearing publishUp alone already makes the email ineligible (the query
    requires a non-null publishUp), and unpublishing alone does too. Both are
    sent so the provider row also reads as "not scheduled" to a human, and so
    cancellation does not depend on either guard individually. Verified against
    the running instance: this clears publish_up to NULL and is_published to 0.
    The email itself is never deleted.
    """
    payload = build_campaign_email_payload(campaign, publish=False)
    payload["publishUp"] = ""
    return payload
