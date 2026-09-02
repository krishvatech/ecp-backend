from collections import Counter

from django.core.exceptions import ObjectDoesNotExist

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
            "unique_open_count": len(opened_identities),
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
            "open_rate": _rate(len(opened_identities), rate_denominator),
            "click_rate": _rate(len(clicked_identities), rate_denominator),
            "unsubscribe_rate": _rate(unsubscribe_count, rate_denominator),
        },
    }
