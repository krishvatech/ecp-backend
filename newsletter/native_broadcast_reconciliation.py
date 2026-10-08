"""Reconcile natively scheduled Email Broadcasts from Mautic back into ECP.

A broadcast scheduled with ``schedule_owner=mautic`` is delivered by Mautic's
``mautic:broadcasts:send`` cron, so ECP only learns that it went out by reading
the provider Email. This module is that read side: service-account GETs only,
followed by a locked local update. It never creates, updates, publishes or sends
anything in Mautic and never mints a human identity assertion.

Mautic 7.1.3 semantics this relies on (audited from source and the local
runtime, see EmailBundle\\EventListener\\BroadcastSubscriber):

* A due broadcast is ``isPublished`` with a non-null ``publishUp`` in the past.
* Each cron run sends to contacts in the segments that have no ``email_stats``
  row yet, then increments ``sentCount`` for the successful sends.
* When a later run finds nobody left and nothing was sent, Mautic unpublishes
  the email itself - but only when ``sentCount > 0`` and ``continueSending`` is
  off (Email::shouldCheckForUnpublishEmail()). ECP never sets continueSending.

So "unpublished, same publishUp, sentCount > 0" is the provider's own terminal
state. A due broadcast that reached nobody is never unpublished by Mautic: it
stays armed. That state is reported, never guessed into SENT.

Who an armed broadcast can still reach: with continueSending off,
EmailModel::getPendingLeads() passes publishUp as the segment cutoff, so only
contacts already in the segment at the scheduled minute are eligible - a
contact who joins later is never sent it. A member who was in the segment then
but ineligible (do-not-contact, no email address) and becomes eligible while
the email stays published could still be sent it on a later cron run.

The API exposes no pending-recipient count, so "no eligible recipients" and
"Mautic cron has not run" look identical from ECP; neither is ever inferred.
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone as dt_timezone

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import APIException

from .mautic import MauticClient, MauticError, PermanentMauticError
from .mautic.payloads import provider_schedule_minute
from .models import NewsletterCampaign


logger = logging.getLogger(__name__)

#: Reschedule/Cancel are refused from this long before the provider due minute,
#: so an asserted update can never land while the cron run for that minute has
#: already loaded the email.
NATIVE_CHANGE_CUTOFF = timedelta(minutes=1)

#: How long a due broadcast may show no sends before it is flagged. A large
#: send only bumps sentCount when its batch finishes, so this is a reporting
#: threshold, not proof that nothing is in progress.
NATIVE_NO_SEND_GRACE = timedelta(minutes=5)

MISSING_EMAIL_ERROR = (
    "Scheduled Mautic email is missing; delivery state could not be reconciled."
)
PROVIDER_UNAVAILABLE_ERROR = (
    "Mautic was unavailable while checking native broadcast delivery; "
    "it will be checked again."
)
PROVIDER_REJECTED_ERROR = (
    "Mautic rejected the native broadcast delivery-state lookup."
)
INCONSISTENT_STATE_ERROR = (
    "Mautic email state does not match this native schedule ({reason}); "
    "delivery state was not reconciled."
)
DISARMED_EXTERNALLY_ERROR = (
    "Mautic email was unpublished outside ECP before any contact was sent it; "
    "delivery state was not reconciled."
)
NO_SENDS_YET_ERROR = (
    "Native broadcast is past its scheduled time but Mautic has not recorded "
    "any sends; the email remains armed in Mautic."
)

_RECONCILIATION_DIAGNOSTIC_PREFIXES = (
    MISSING_EMAIL_ERROR,
    PROVIDER_UNAVAILABLE_ERROR,
    PROVIDER_REJECTED_ERROR,
    INCONSISTENT_STATE_ERROR.split("(", 1)[0],
    DISARMED_EXTERNALLY_ERROR,
    NO_SENDS_YET_ERROR,
)


class NativeDeliveryState(str, enum.Enum):
    NOT_DUE = "not_due"
    AWAITING_FIRST_SEND = "awaiting_first_send"
    SENDING = "sending"
    COMPLETED = "completed"
    DISARMED_EXTERNALLY = "disarmed_externally"
    INCONSISTENT = "inconsistent"
    MISSING = "missing"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    PROVIDER_REJECTED = "provider_rejected"


@dataclass(frozen=True)
class NativeDeliveryClassification:
    state: NativeDeliveryState
    reason: str = ""
    sent_count: int = 0


class CampaignNativeDeliveryStarted(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = (
        "The delivery window for this native broadcast has started; it can no "
        "longer be rescheduled or cancelled."
    )
    default_code = "native_delivery_started"


class CampaignAlreadySent(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = "This broadcast has already been sent by Mautic."
    default_code = "campaign_already_sent"


def _parse_provider_datetime(value):
    """Parse a Mautic datetime into an aware UTC datetime, or None.

    The Email API returns ISO-8601 with an offset; email_stats rows come back
    as naive ``Y-m-d H:i:s`` strings, which Mautic stores in UTC.
    """
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace(" ", "T", 1))
    except ValueError:
        return None
    if timezone.is_naive(parsed):
        parsed = parsed.replace(tzinfo=dt_timezone.utc)
    return parsed.astimezone(dt_timezone.utc)


def _provider_int(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return None


def classify_provider_error(exc) -> NativeDeliveryClassification:
    """Map a failed provider read to a state. Only a 404 means "missing"."""
    if isinstance(exc, PermanentMauticError):
        if "HTTP 404" in str(exc):
            return NativeDeliveryClassification(NativeDeliveryState.MISSING)
        return NativeDeliveryClassification(NativeDeliveryState.PROVIDER_REJECTED)
    return NativeDeliveryClassification(NativeDeliveryState.PROVIDER_UNAVAILABLE)


def classify_native_delivery(email, *, scheduled_at, now) -> NativeDeliveryClassification:
    """Classify one provider Email against the ECP schedule. Pure function.

    ``email`` is the ``GET /api/emails/{id}`` payload. Anything that does not
    match the schedule ECP armed is INCONSISTENT rather than a guess.
    """
    expected_minute = provider_schedule_minute(scheduled_at)
    if not isinstance(email, dict) or expected_minute is None:
        return NativeDeliveryClassification(
            NativeDeliveryState.INCONSISTENT, "invalid_provider_email"
        )

    if str(email.get("emailType") or "") != "list":
        return NativeDeliveryClassification(
            NativeDeliveryState.INCONSISTENT, "not_a_list_email"
        )

    sent_count = _provider_int(email.get("sentCount"))
    if sent_count is None or sent_count < 0:
        return NativeDeliveryClassification(
            NativeDeliveryState.INCONSISTENT, "invalid_sent_count"
        )

    if _parse_provider_datetime(email.get("publishDown")) is not None:
        return NativeDeliveryClassification(
            NativeDeliveryState.INCONSISTENT, "publish_down_set", sent_count
        )

    published = email.get("isPublished") is True
    raw_publish_up = email.get("publishUp")
    publish_up = _parse_provider_datetime(raw_publish_up)

    if publish_up is None:
        if published or str(raw_publish_up or "").strip():
            # Published "immediately", or a value we cannot read: neither is
            # the armed schedule ECP created.
            return NativeDeliveryClassification(
                NativeDeliveryState.INCONSISTENT, "publish_up_missing", sent_count
            )
        if sent_count == 0:
            # Disarmed in Mautic without ECP's Cancel. Nothing was sent.
            return NativeDeliveryClassification(
                NativeDeliveryState.DISARMED_EXTERNALLY, "", sent_count
            )
        return NativeDeliveryClassification(
            NativeDeliveryState.INCONSISTENT, "publish_up_cleared", sent_count
        )

    if publish_up.replace(second=0, microsecond=0) != expected_minute:
        return NativeDeliveryClassification(
            NativeDeliveryState.INCONSISTENT, "publish_up_mismatch", sent_count
        )

    if now < expected_minute:
        if published and sent_count == 0:
            return NativeDeliveryClassification(NativeDeliveryState.NOT_DUE)
        if not published and sent_count == 0:
            return NativeDeliveryClassification(
                NativeDeliveryState.DISARMED_EXTERNALLY, "", sent_count
            )
        # Sent before its own time: not the schedule ECP armed any more.
        return NativeDeliveryClassification(
            NativeDeliveryState.INCONSISTENT, "changed_before_due", sent_count
        )

    if published:
        if sent_count > 0:
            # Sending, or waiting for the run that finds nobody left and
            # unpublishes it. Not terminal yet.
            return NativeDeliveryClassification(
                NativeDeliveryState.SENDING, "", sent_count
            )
        return NativeDeliveryClassification(
            NativeDeliveryState.AWAITING_FIRST_SEND, "", sent_count
        )

    if sent_count > 0:
        return NativeDeliveryClassification(
            NativeDeliveryState.COMPLETED, "", sent_count
        )
    # Mautic never auto-unpublishes a broadcast that sent nothing.
    return NativeDeliveryClassification(
        NativeDeliveryState.DISARMED_EXTERNALLY, "", sent_count
    )


def native_reconciliation_candidates(*, now=None, batch_size: int = 100):
    """Due native schedules, oldest first. Ownership comes from the row only."""
    now = now or timezone.now()
    return list(
        NewsletterCampaign.objects.filter(
            status=NewsletterCampaign.Status.SCHEDULED,
            schedule_owner=NewsletterCampaign.ScheduleOwner.MAUTIC,
            scheduled_at__isnull=False,
            scheduled_at__lte=now,
        )
        .exclude(mautic_email_id="")
        .order_by("scheduled_at", "id")[: max(1, int(batch_size))]
    )


def native_delivery_window_started(campaign, *, now=None) -> bool:
    """True once a native schedule can no longer be safely changed."""
    if not (
        campaign.status == NewsletterCampaign.Status.SCHEDULED
        and campaign.schedule_owner == NewsletterCampaign.ScheduleOwner.MAUTIC
    ):
        return False
    due = provider_schedule_minute(campaign.scheduled_at)
    if due is None:
        return False
    return (now or timezone.now()) >= due - NATIVE_CHANGE_CUTOFF


def _is_reconciliation_diagnostic(message) -> bool:
    text = str(message or "")
    return any(text.startswith(prefix) for prefix in _RECONCILIATION_DIAGNOSTIC_PREFIXES)


def _locked_native_row(snapshot):
    """Re-read the row under lock; None if it changed since the snapshot.

    Same status, owner, provider Email and schedule instant are all required,
    so a cancel or reschedule that landed during the provider read wins.
    """
    return (
        NewsletterCampaign.objects.select_for_update()
        .filter(
            pk=snapshot.pk,
            status=NewsletterCampaign.Status.SCHEDULED,
            schedule_owner=NewsletterCampaign.ScheduleOwner.MAUTIC,
            mautic_email_id=snapshot.mautic_email_id,
            scheduled_at=snapshot.scheduled_at,
        )
        .first()
    )


def _set_diagnostic(snapshot, message) -> bool:
    """Write (or clear) last_error only; lifecycle fields are never touched."""
    # Most ticks change nothing: skip the row lock when the snapshot already
    # holds the wanted value.
    if message is None and not _is_reconciliation_diagnostic(snapshot.last_error):
        return True
    if message is not None and snapshot.last_error == message:
        return True
    with transaction.atomic():
        locked = _locked_native_row(snapshot)
        if locked is None:
            return False
        if message is None:
            if not _is_reconciliation_diagnostic(locked.last_error):
                return True
            message = ""
        if locked.last_error == message:
            return True
        locked.last_error = message
        locked.save(update_fields=["last_error", "updated_at"])
    return True


def _latest_send_time(client, email_id):
    try:
        row = client.get_latest_email_send(email_id)
    except MauticError:
        logger.warning(
            "Could not read latest send time for Mautic email id=%s; using "
            "reconciliation time as sent_at",
            email_id,
        )
        return None
    if not row:
        return None
    return _parse_provider_datetime(row.get("date_sent"))


def _mark_sent(snapshot, *, sent_at) -> bool:
    with transaction.atomic():
        locked = _locked_native_row(snapshot)
        if locked is None:
            return False
        locked.status = NewsletterCampaign.Status.SENT
        locked.sent_at = sent_at
        locked.schedule_owner = ""
        locked.last_error = ""
        locked.save(
            update_fields=[
                "status",
                "sent_at",
                "schedule_owner",
                "last_error",
                "updated_at",
            ]
        )
    return True


def reconcile_native_campaign(campaign, *, client=None, now=None) -> str:
    """Observe one native schedule in Mautic and apply what it proves.

    Returns one of: "reconciled", "pending", "skipped", "missing",
    "inconsistent", "failed". The provider read happens outside any
    transaction; only the local write takes a row lock.
    """
    now = now or timezone.now()
    email_id = str(campaign.mautic_email_id or "").strip()
    if not (
        email_id
        and campaign.status == NewsletterCampaign.Status.SCHEDULED
        and campaign.schedule_owner == NewsletterCampaign.ScheduleOwner.MAUTIC
        and campaign.scheduled_at is not None
    ):
        return "skipped"

    client = client or MauticClient()
    try:
        email = client.get_email(email_id)
    except MauticError as exc:
        classification = classify_provider_error(exc)
    else:
        classification = classify_native_delivery(
            email, scheduled_at=campaign.scheduled_at, now=now
        )

    state = classification.state

    if state == NativeDeliveryState.COMPLETED:
        # sent_at is the provider's last successful send; without one it is
        # the time ECP detected completion.
        sent_at = _latest_send_time(client, email_id) or now
        if not _mark_sent(campaign, sent_at=sent_at):
            return "skipped"
        logger.info(
            "Native broadcast reconciled to sent campaign_uuid=%s mautic_email_id=%s "
            "sent_count=%s",
            campaign.uuid,
            email_id,
            classification.sent_count,
        )
        return "reconciled"

    if state == NativeDeliveryState.MISSING:
        logger.warning(
            "Native broadcast provider email missing campaign_uuid=%s mautic_email_id=%s",
            campaign.uuid,
            email_id,
        )
        return "missing" if _set_diagnostic(campaign, MISSING_EMAIL_ERROR) else "skipped"

    if state in (
        NativeDeliveryState.PROVIDER_UNAVAILABLE,
        NativeDeliveryState.PROVIDER_REJECTED,
    ):
        logger.warning(
            "Native broadcast reconciliation provider %s campaign_uuid=%s "
            "mautic_email_id=%s",
            "failure" if state == NativeDeliveryState.PROVIDER_REJECTED else "unavailable",
            campaign.uuid,
            email_id,
        )
        message = (
            PROVIDER_REJECTED_ERROR
            if state == NativeDeliveryState.PROVIDER_REJECTED
            else PROVIDER_UNAVAILABLE_ERROR
        )
        return "failed" if _set_diagnostic(campaign, message) else "skipped"

    if state in (
        NativeDeliveryState.INCONSISTENT,
        NativeDeliveryState.DISARMED_EXTERNALLY,
    ):
        logger.warning(
            "Native broadcast provider state mismatch campaign_uuid=%s "
            "mautic_email_id=%s state=%s reason=%s",
            campaign.uuid,
            email_id,
            state.value,
            classification.reason or "-",
        )
        message = (
            DISARMED_EXTERNALLY_ERROR
            if state == NativeDeliveryState.DISARMED_EXTERNALLY
            else INCONSISTENT_STATE_ERROR.format(reason=classification.reason)
        )
        return "inconsistent" if _set_diagnostic(campaign, message) else "skipped"

    # NOT_DUE, SENDING, AWAITING_FIRST_SEND: nothing is terminal yet.
    due = provider_schedule_minute(campaign.scheduled_at)
    stalled = (
        state == NativeDeliveryState.AWAITING_FIRST_SEND
        and now - due >= NATIVE_NO_SEND_GRACE
    )
    if not _set_diagnostic(campaign, NO_SENDS_YET_ERROR if stalled else None):
        return "skipped"
    return "pending"


def reconcile_native_scheduled_campaigns(batch_size: int = 100, *, now=None) -> dict:
    """Reconcile due native schedules. Gated on Mautic sync only.

    Deliberately not gated on MAUTIC_NATIVE_BROADCAST_SCHEDULING_ENABLED: that
    flag only stops new native schedules, and rows already owned by Mautic must
    keep draining after it is turned off.
    """
    summary = {
        "disabled": False,
        "selected": 0,
        "reconciled": 0,
        "pending": 0,
        "skipped": 0,
        "missing": 0,
        "inconsistent": 0,
        "failed": 0,
    }
    if not getattr(settings, "MAUTIC_SYNC_ENABLED", False):
        summary["disabled"] = True
        return summary

    candidates = native_reconciliation_candidates(now=now, batch_size=batch_size)
    summary["selected"] = len(candidates)
    if not candidates:
        return summary

    client = MauticClient()
    for campaign in candidates:
        try:
            outcome = reconcile_native_campaign(campaign, client=client, now=now)
        except Exception:
            # One broken row must not stop the rest of the batch.
            logger.exception(
                "Native broadcast reconciliation failed campaign_uuid=%s",
                campaign.uuid,
            )
            outcome = "failed"
        summary[outcome] += 1
    return summary


def guard_native_schedule_change(campaign, *, now=None) -> None:
    """Refuse Reschedule/Cancel once a native delivery window has started.

    Runs before any assertion is minted or provider mutation is attempted. A
    service-account read decides only which refusal to give: if Mautic already
    finished, the row is reconciled to SENT on the way.
    """
    now = now or timezone.now()
    if not native_delivery_window_started(campaign, now=now):
        return

    outcome = None
    if (
        getattr(settings, "MAUTIC_SYNC_ENABLED", False)
        and provider_schedule_minute(campaign.scheduled_at) <= now
    ):
        try:
            outcome = reconcile_native_campaign(campaign, now=now)
        except Exception:
            logger.exception(
                "Native broadcast reconciliation failed during a schedule change "
                "campaign_uuid=%s",
                campaign.uuid,
            )
    if outcome == "reconciled":
        raise CampaignAlreadySent()
    raise CampaignNativeDeliveryStarted()
