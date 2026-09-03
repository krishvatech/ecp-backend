from collections import Counter

from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

from .mautic import MauticClient, MauticError
from .models import NewsletterCampaignTrackingEvent


def _rate(numerator, denominator):
    if not denominator:
        return 0
    return numerator / denominator


def _recipient_identity(event):
    if event.user_id:
        return f"user:{event.user_id}"
    if event.mautic_contact_id:
        return f"mautic:{event.mautic_contact_id}"
    if event.recipient_email:
        return f"email:{event.recipient_email.lower()}"
    return None


def _truthy(value):
    if value is True:
        return True
    if value is False or value is None:
        return False
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "read"}
    return bool(value)


def _rows_from_mautic_stats(payload):
    if not isinstance(payload, dict):
        return []

    for key in ("data", "stats"):
        rows = payload.get(key)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
        if isinstance(rows, dict):
            return [row for row in rows.values() if isinstance(row, dict)]
    return []


def _mautic_recipient_identity(row):
    lead_id = row.get("lead_id") or row.get("leadId")
    if lead_id:
        return f"mautic:{lead_id}"

    email = row.get("email_address") or row.get("emailAddress")
    if email:
        return f"email:{str(email).strip().lower()}"

    return None


def _mautic_open_summary(campaign):
    metadata = {
        "sources": ["ecp"],
        "mautic_email_id": campaign.mautic_email_id or None,
        "mautic_available": False,
        "warnings": [],
    }

    email_id = str(campaign.mautic_email_id or "").strip()
    if not email_id:
        return None, metadata

    metadata["sources"].append("mautic")

    try:
        payload = MauticClient().get_email_stats(email_id)
    except MauticError as exc:
        metadata["warnings"].append(str(exc))
        return None, metadata

    rows = _rows_from_mautic_stats(payload)
    opened_count = 0
    unique_open_identities = set()

    for row in rows:
        opened = (
            _truthy(row.get("is_read"))
            or _truthy(row.get("isRead"))
            or bool(row.get("date_read"))
            or bool(row.get("dateRead"))
            or bool(row.get("last_opened"))
            or bool(row.get("lastOpened"))
        )
        if not opened:
            continue

        opened_count += 1
        identity = _mautic_recipient_identity(row)
        if identity:
            unique_open_identities.add(identity)

    metadata["mautic_available"] = True
    metadata["mautic_stats_count"] = len(rows)
    metadata["mautic_refreshed_at"] = timezone.now()
    return {
        "opened_count": opened_count,
        "unique_open_count": len(unique_open_identities),
    }, metadata


def get_campaign_analytics(campaign):
    try:
        send_event = campaign.send_event
    except ObjectDoesNotExist:
        send_event = None
    sent_count = send_event.provider_sent_count if send_event else 0
    failed_count = send_event.provider_failed_count if send_event else 0
    delivered_denominator = sent_count + failed_count

    tracking_events = list(
        campaign.tracking_events.only(
            "event_type",
            "user_id",
            "mautic_contact_id",
            "recipient_email",
        )
    )
    event_counts = Counter(event.event_type for event in tracking_events)

    opened_identities = set()
    clicked_identities = set()
    for event in tracking_events:
        if event.event_type not in (
            NewsletterCampaignTrackingEvent.EventType.OPENED,
            NewsletterCampaignTrackingEvent.EventType.CLICKED,
        ):
            continue

        identity = _recipient_identity(event)
        if not identity:
            continue

        if event.event_type == NewsletterCampaignTrackingEvent.EventType.OPENED:
            opened_identities.add(identity)
        elif event.event_type == NewsletterCampaignTrackingEvent.EventType.CLICKED:
            clicked_identities.add(identity)

    delivered_count = event_counts[NewsletterCampaignTrackingEvent.EventType.DELIVERED]
    opened_count = event_counts[NewsletterCampaignTrackingEvent.EventType.OPENED]
    clicked_count = event_counts[NewsletterCampaignTrackingEvent.EventType.CLICKED]
    unsubscribe_count = event_counts[
        NewsletterCampaignTrackingEvent.EventType.UNSUBSCRIBED
    ]
    unique_open_count = len(opened_identities)

    mautic_open_summary, metadata = _mautic_open_summary(campaign)
    if mautic_open_summary is not None:
        opened_count = mautic_open_summary["opened_count"]
        unique_open_count = mautic_open_summary["unique_open_count"]

    rate_denominator = delivered_count or sent_count

    return {
        "campaign_uuid": str(campaign.uuid),
        "status": campaign.status,
        "timestamps": {
            "scheduled_at": campaign.scheduled_at,
            "send_started_at": campaign.send_started_at,
            "sent_at": campaign.sent_at,
        },
        "send_summary": {
            "sent_count": sent_count,
            "failed_count": failed_count,
            "success_rate": _rate(sent_count, delivered_denominator),
            "attempt_count": send_event.attempt_count if send_event else 0,
            "send_status": send_event.status if send_event else "",
        },
        "engagement": {
            "delivered_count": delivered_count,
            "opened_count": opened_count,
            "unique_open_count": unique_open_count,
            "clicked_count": clicked_count,
            "unique_click_count": len(clicked_identities),
            "unsubscribe_count": unsubscribe_count,
            "bounced_count": event_counts[
                NewsletterCampaignTrackingEvent.EventType.BOUNCED
            ],
            "failed_count": event_counts[
                NewsletterCampaignTrackingEvent.EventType.FAILED
            ],
        },
        "rates": {
            "open_rate": _rate(unique_open_count, rate_denominator),
            "click_rate": _rate(len(clicked_identities), rate_denominator),
            "unsubscribe_rate": _rate(unsubscribe_count, rate_denominator),
        },
        "metadata": metadata,
    }
