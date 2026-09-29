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


def _stats_total(payload, fallback):
    try:
        return int(payload.get("total"))
    except (AttributeError, TypeError, ValueError):
        return fallback


def _mautic_stats_summary(campaign, *, include_send_summary):
    """Read provider email stats once and derive what they objectively prove.

    Opens come from ``is_read``/``date_read``. A send summary is derived only
    when asked for (no ECP send event exists): every email_stats row is a
    recorded send attempt and ``is_failed`` marks the failures. Neither is a
    mailbox delivery confirmation.
    """
    metadata = {
        "sources": ["ecp"],
        "mautic_email_id": campaign.mautic_email_id or None,
        "mautic_available": False,
        "warnings": [],
    }

    email_id = str(campaign.mautic_email_id or "").strip()
    if not email_id:
        return None, None, metadata

    metadata["sources"].append("mautic")

    try:
        client = MauticClient()
        payload = client.get_email_stats(email_id)
        rows = _rows_from_mautic_stats(payload)
        total = _stats_total(payload, len(rows))
        # The stats API returns one page (100 rows by default) but an exact
        # total; past one page, counts come from filtered totals instead.
        truncated = total > len(rows)

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
        unique_open_count = len(unique_open_identities)

        if truncated:
            # One email_stats row per contact for a list email, so the read
            # rows are also the unique opens.
            opened_count = unique_open_count = client.count_email_stats(
                email_id, is_read=1
            )

        send_summary = None
        if include_send_summary:
            if truncated:
                failed_count = client.count_email_stats(email_id, is_failed=1)
            else:
                failed_count = sum(
                    1
                    for row in rows
                    if _truthy(row.get("is_failed")) or _truthy(row.get("isFailed"))
                )
            send_summary = {
                "sent_count": max(total - failed_count, 0),
                "failed_count": failed_count,
            }
    except MauticError as exc:
        metadata["warnings"].append(str(exc))
        return None, None, metadata

    metadata["mautic_available"] = True
    metadata["mautic_stats_count"] = total
    metadata["mautic_refreshed_at"] = timezone.now()
    return {
        "opened_count": opened_count,
        "unique_open_count": unique_open_count,
    }, send_summary, metadata


def get_campaign_analytics(campaign):
    try:
        send_event = campaign.send_event
    except ObjectDoesNotExist:
        send_event = None
    # An ECP send event (Send Now / ECP-owned schedule) stays the source of
    # truth for sends; natively scheduled broadcasts have none, so Mautic's own
    # stats are used for them instead.
    mautic_open_summary, mautic_send_summary, metadata = _mautic_stats_summary(
        campaign,
        include_send_summary=send_event is None,
    )
    if send_event is not None:
        sent_count = send_event.provider_sent_count
        failed_count = send_event.provider_failed_count
        metadata["send_summary_source"] = "ecp"
    elif mautic_send_summary is not None:
        sent_count = mautic_send_summary["sent_count"]
        failed_count = mautic_send_summary["failed_count"]
        metadata["send_summary_source"] = "mautic"
    else:
        sent_count = failed_count = 0
        metadata["send_summary_source"] = ""
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
