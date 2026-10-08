"""Read-only delivery inspection for one Email Broadcast.

Lets an operator see exactly where a broadcast stands: ECP's own state, the
send event and its provider-send boundary, and what Mautic currently records.
It is for diagnosis only:

* it never sends, publishes, unpublishes or updates anything in Mautic - every
  provider call is a service-account GET;
* it never writes to the database, so inspecting cannot reconcile, retry or
  close a broadcast, and can be repeated freely;
* it never claims more than the evidence proves. Mautic reports how many
  emails it recorded as sent (``sentCount`` and ``email_stats``) but not how
  many were due, so a lost Send Now response can show that delivery happened,
  never that it finished. A native broadcast that recorded no sends past its
  grace period may have had no eligible recipients, or Mautic cron may not
  have run: the API cannot tell these apart.
"""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.http import Http404
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .campaign_send_processor import UNCERTAIN_SEND_MESSAGE
from .marketing_permissions import HasMarketingHubAccess
from .mautic import MauticClient, MauticError
from .mautic.payloads import provider_schedule_minute
from .models import MauticIdentityAuditLog, NewsletterCampaign, NewsletterCampaignSendEvent
from .native_broadcast_reconciliation import (
    NATIVE_NO_SEND_GRACE,
    NativeDeliveryState,
    classify_native_delivery,
    classify_provider_error,
)
from .task_heartbeats import task_stale_after_seconds

AUDIT_HISTORY_LIMIT = 10

# --- categories ---------------------------------------------------------------
NOT_SENT = "not_sent"
SEND_QUEUED = "send_queued"
SEND_IN_PROGRESS = "send_in_progress"
SEND_OUTCOME_UNCONFIRMED = "send_outcome_unconfirmed"
SENT = "sent"
FAILED_BEFORE_SEND = "failed_before_send"
FAILED = "failed"
CANCELLED = "cancelled"
ECP_SCHEDULED = "ecp_scheduled"
ECP_SCHEDULE_OVERDUE = "ecp_schedule_overdue"
NATIVE_NOT_DUE = "native_not_due"
NATIVE_AWAITING_FIRST_SEND = "native_awaiting_first_send"
NATIVE_DUE_NO_SENDS_RECORDED = "native_due_no_sends_recorded"
NATIVE_SENDING = "native_sending"
NATIVE_COMPLETED = "native_completed_awaiting_reconciliation"
NATIVE_PROVIDER_STATE_MISMATCH = "native_provider_state_mismatch"
NATIVE_PROVIDER_EMAIL_MISSING = "native_provider_email_missing"
PROVIDER_UNAVAILABLE = "provider_unavailable"

GUIDANCE = {
    NOT_SENT: "Nothing has been sent.",
    SEND_QUEUED: "A send was requested and has not reached Mautic yet; background recovery will pick it up.",
    SEND_IN_PROGRESS: "Mautic was asked to send this broadcast and has not answered yet. Wait.",
    SEND_OUTCOME_UNCONFIRMED: (
        "Mautic never confirmed this send. It may have delivered to everyone, some or no "
        "recipients. It will not be retried. Check this email's sends in Mautic before any "
        "action; do not duplicate and re-send it until you know who received it."
    ),
    SENT: "Delivery was confirmed.",
    FAILED_BEFORE_SEND: "The send failed before Mautic was asked to deliver it. Send Now may be used again.",
    FAILED: "Mautic rejected the send, or never received it. Nothing more will be attempted.",
    CANCELLED: "This broadcast was cancelled.",
    ECP_SCHEDULED: "Scheduled; ECP will send it at the scheduled time.",
    ECP_SCHEDULE_OVERDUE: (
        "Past its scheduled time and not dispatched. Check that Celery Beat and a worker are running."
    ),
    NATIVE_NOT_DUE: "Scheduled in Mautic; not due yet.",
    NATIVE_AWAITING_FIRST_SEND: "Due; waiting for Mautic's broadcast cron to send it.",
    NATIVE_DUE_NO_SENDS_RECORDED: (
        "Mautic has recorded no sends although the broadcast is past due. Either nobody in its "
        "segments was eligible at the scheduled minute, or Mautic cron has not run. The API cannot "
        "tell these apart: check the Mautic cron log. Contacts who join the segment later are never "
        "sent it, but a member who was ineligible at the scheduled minute (do-not-contact, no email "
        "address) and becomes eligible while the email stays published could still receive it."
    ),
    NATIVE_SENDING: "Mautic is sending this broadcast.",
    NATIVE_COMPLETED: "Mautic finished sending; ECP will mark it sent on the next reconciliation run.",
    NATIVE_PROVIDER_STATE_MISMATCH: (
        "The Mautic email no longer matches this schedule; it was changed outside ECP. Review it in Mautic."
    ),
    NATIVE_PROVIDER_EMAIL_MISSING: "The scheduled Mautic email no longer exists.",
    PROVIDER_UNAVAILABLE: "Mautic could not be read; try again.",
}

_NATIVE_CATEGORIES = {
    NativeDeliveryState.NOT_DUE: NATIVE_NOT_DUE,
    NativeDeliveryState.SENDING: NATIVE_SENDING,
    NativeDeliveryState.COMPLETED: NATIVE_COMPLETED,
    NativeDeliveryState.DISARMED_EXTERNALLY: NATIVE_PROVIDER_STATE_MISMATCH,
    NativeDeliveryState.INCONSISTENT: NATIVE_PROVIDER_STATE_MISMATCH,
    NativeDeliveryState.MISSING: NATIVE_PROVIDER_EMAIL_MISSING,
    NativeDeliveryState.PROVIDER_UNAVAILABLE: PROVIDER_UNAVAILABLE,
    NativeDeliveryState.PROVIDER_REJECTED: PROVIDER_UNAVAILABLE,
}


def _provider_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _read_provider(client, email_id) -> dict:
    """Service-account GETs only. Never raises."""
    evidence = {"checked": True, "available": False, "error": "", "email": None}
    try:
        email = client.get_email(email_id)
    except MauticError as exc:
        state = classify_provider_error(exc).state
        evidence["error"] = "missing" if state == NativeDeliveryState.MISSING else "unavailable"
        evidence["native_state"] = state
        return evidence

    evidence.update(
        available=True,
        email=email,
        is_published=email.get("isPublished") is True if isinstance(email, dict) else None,
        publish_up=email.get("publishUp") if isinstance(email, dict) else None,
        sent_count=_provider_int(email.get("sentCount")) if isinstance(email, dict) else None,
    )
    try:
        recorded = client.count_email_stats(email_id)
        failed = client.count_email_stats(email_id, is_failed=1)
        latest = client.get_latest_email_send(email_id)
    except MauticError:
        evidence["stats"] = None
    else:
        evidence["stats"] = {
            "recorded": recorded,
            "failed": failed,
            "last_sent_at": (latest or {}).get("date_sent"),
        }
    return evidence


def _ecp_category(campaign, event, now):
    """Category for a broadcast ECP itself sends (Send Now / ECP schedule)."""
    boundary = event.provider_send_started_at if event else None
    if campaign.status == NewsletterCampaign.Status.SENT:
        return SENT
    if campaign.status == NewsletterCampaign.Status.CANCELLED:
        return CANCELLED
    if campaign.status == NewsletterCampaign.Status.FAILED:
        return FAILED if boundary else FAILED_BEFORE_SEND
    if campaign.status == NewsletterCampaign.Status.SENDING:
        timeout = max(1, int(getattr(settings, "MAUTIC_SYNC_PROCESSING_TIMEOUT_SECONDS", 600)))
        lost = str(event.last_error if event else "").startswith(UNCERTAIN_SEND_MESSAGE)
        started = campaign.send_started_at or boundary
        overdue = started is not None and (now - started).total_seconds() >= timeout
        return SEND_OUTCOME_UNCONFIRMED if (lost or overdue) else SEND_IN_PROGRESS
    if campaign.status == NewsletterCampaign.Status.SCHEDULED:
        window = task_stale_after_seconds("newsletter.dispatch_due_scheduled_campaigns")
        if (
            window is not None
            and campaign.scheduled_at
            and (now - campaign.scheduled_at).total_seconds() > window
        ):
            return ECP_SCHEDULE_OVERDUE
        return ECP_SCHEDULED
    if event is not None and event.status == NewsletterCampaignSendEvent.Status.FAILED:
        return FAILED_BEFORE_SEND
    if event is not None and event.status in (
        NewsletterCampaignSendEvent.Status.PENDING,
        NewsletterCampaignSendEvent.Status.PROCESSING,
    ):
        return SEND_QUEUED
    return NOT_SENT


def _native_category(campaign, provider, now):
    if not provider.get("available"):
        return _NATIVE_CATEGORIES[provider["native_state"]], provider["native_state"].value
    classification = classify_native_delivery(
        provider["email"], scheduled_at=campaign.scheduled_at, now=now
    )
    state = classification.state
    if state == NativeDeliveryState.AWAITING_FIRST_SEND:
        due = provider_schedule_minute(campaign.scheduled_at)
        if due is not None and now - due >= NATIVE_NO_SEND_GRACE:
            return NATIVE_DUE_NO_SENDS_RECORDED, state.value
        return NATIVE_AWAITING_FIRST_SEND, state.value
    return _NATIVE_CATEGORIES[state], state.value


def _iso(value):
    return value.isoformat() if value else None


def inspect_broadcast_delivery(campaign, *, client=None, now=None) -> dict:
    now = now or timezone.now()
    event = NewsletterCampaignSendEvent.objects.filter(campaign=campaign).first()
    email_id = str(campaign.mautic_email_id or "").strip()
    native = (
        campaign.status == NewsletterCampaign.Status.SCHEDULED
        and campaign.schedule_owner == NewsletterCampaign.ScheduleOwner.MAUTIC
    )

    provider = {"checked": False}
    if email_id:
        provider = _read_provider(client or MauticClient(), email_id)

    native_state = ""
    if native and email_id:
        category, native_state = _native_category(campaign, provider, now)
    elif native:
        category = NATIVE_PROVIDER_EMAIL_MISSING
    else:
        category = _ecp_category(campaign, event, now)

    boundary = event.provider_send_started_at if event else None
    sent_count = provider.get("sent_count")
    recorded = (provider.get("stats") or {}).get("recorded")
    delivery_recorded = None
    if provider.get("available"):
        delivery_recorded = bool((sent_count or 0) > 0 or (recorded or 0) > 0)

    audit = [
        {
            "action": row.action,
            "status": row.status,
            "auth_mode": row.auth_mode,
            "error_code": row.error_code,
            "actor": row.ecp_user_label,
            "created_at": row.created_at,
        }
        for row in MauticIdentityAuditLog.objects.filter(
            resource="newsletter_campaign", resource_id=str(campaign.uuid)
        ).order_by("-created_at", "-id")[:AUDIT_HISTORY_LIMIT]
    ]

    return {
        "checked_at": now,
        "campaign": {
            "uuid": str(campaign.uuid),
            "name": campaign.name,
            "status": campaign.status,
            "schedule_owner": campaign.schedule_owner,
            "scheduled_at": campaign.scheduled_at,
            "send_started_at": campaign.send_started_at,
            "sent_at": campaign.sent_at,
            "mautic_email_id": email_id or None,
            "last_error": campaign.last_error,
        },
        "send_event": None if event is None else {
            "event_uuid": str(event.event_uuid),
            "status": event.status,
            "attempt_count": event.attempt_count,
            "processing_started_at": event.processing_started_at,
            "provider_send_started_at": boundary,
            "completed_at": event.completed_at,
            "provider_sent_count": event.provider_sent_count,
            "provider_failed_count": event.provider_failed_count,
            "last_error": event.last_error,
            "seconds_since_provider_send_started": (
                round((now - boundary).total_seconds()) if boundary else None
            ),
        },
        "provider": {
            "checked": provider.get("checked", False),
            "available": provider.get("available", False),
            "error": provider.get("error", ""),
            "is_published": provider.get("is_published"),
            "publish_up": provider.get("publish_up"),
            "sent_count": sent_count,
            "stats": provider.get("stats"),
            "native_state": native_state or None,
        },
        "delivery": {
            "category": category,
            "delivery_recorded": delivery_recorded,
            # Only Mautic's own terminal evidence (a confirmed Send Now
            # response, or a native broadcast it auto-unpublished after
            # sending) proves that delivery finished.
            "completion_provable": category in (SENT, NATIVE_COMPLETED),
            # Recovery only ever re-dispatches work that never reached Mautic.
            "automatic_retry_allowed": bool(
                event is not None
                and boundary is None
                and event.status in (
                    NewsletterCampaignSendEvent.Status.PENDING,
                    NewsletterCampaignSendEvent.Status.PROCESSING,
                )
            ),
            "provider_send_boundary_crossed": boundary is not None,
            "guidance": GUIDANCE[category],
        },
        "audit": audit,
    }


class NewsletterAdminCampaignDeliveryInspectionView(APIView):
    """GET only: a diagnosis, never an action."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, uuid):
        campaign = NewsletterCampaign.objects.filter(uuid=uuid).first()
        if campaign is None:
            raise Http404
        return Response(inspect_broadcast_delivery(campaign), status=status.HTTP_200_OK)
