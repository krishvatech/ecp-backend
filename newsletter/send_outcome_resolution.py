"""Investigation and safe resolution of a Send Now whose outcome is unknown (B11).

When Mautic does not answer a Send Now after the provider-send boundary, the
event stays PROCESSING and the campaign SENDING, and nothing ever retries it
(see ``campaign_send_processor``). This module lets an administrator close
such a send only when Mautic's own sending record proves what happened. It
never sends, retries, redispatches or creates a send event.

Evidence (``GET ecp/emails/{id}/send-evidence``) is attributed to this one
attempt: the broadcast's own Mautic email, stats split at the boundary, and
Mautic's own pending query limited to contacts who were already in the
email's segments when the boundary was crossed. It is authoritative because
Mautic saves a recipient's stat row before handing the message to the
transport, and deletes it only when the transport reports that recipient
failed: every message Mautic sent has a stat, and "pending" is exactly who
Mautic would still send to.

Classifications (administrator-facing, not new statuses):

* confirmed_sent: sends recorded after the boundary, none before, nobody due,
  nothing queued, counters agree -> may be resolved to the existing
  SUCCEEDED / SENT outcome.
* still_processing: too recent to judge; Mautic may still be sending.
* uncertain: e.g. no sends recorded (with or without anyone now due), a
  partial send, messages queued.
* conflicting: evidence does not belong to this attempt alone.
* evidence_unavailable: Mautic could not be read or cannot answer.

There is deliberately no "not sent" decision. The absence of sends never
proves the original request will not send: Mautic records nothing about an
API request until it saves the first stat, the request has no enforced
wall-clock limit (PHP's time limit excludes network and database waits),
and the email stays published with its segments, so a request that is
delayed or still running can send at any later time. Such a send stays
protected and unresolved.

The sent decision is only offered after the settle window, so that a
request still finishing cannot change the evidence afterwards.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .campaign_send_processor import UNCERTAIN_SEND_MESSAGE
from .models import (
    MauticIdentityAuditLog,
    MauticUserConnection,
    NewsletterCampaign,
    NewsletterCampaignSendEvent,
    NewsletterCampaignTrackingEvent,
)

logger = logging.getLogger(__name__)

CONFIRMED_SENT = "confirmed_sent"
#: Not a classification: named only so a request for it gets a clear refusal.
NOT_SENT_DECISION = "confirmed_not_sent"
STILL_PROCESSING = "still_processing"
UNCERTAIN = "uncertain"
CONFLICTING = "conflicting"
EVIDENCE_UNAVAILABLE = "evidence_unavailable"
NOT_APPLICABLE = "not_applicable"

RESOLUTIONS = (CONFIRMED_SENT,)

#: Audit action for a resolution. Deliberately not added to
#: MauticIdentityAuditLog.Action: that would change the field's choices and so
#: need a migration. Django does not enforce choices on save, and the audit
#: view files every "newsletter." action under Delivery.
AUDIT_ACTION = "newsletter.send_outcome.resolve"
AUDIT_RESOURCE = "newsletter_campaign"

#: Allowed disagreement between the ECP and Mautic clocks. Each cut-off is
#: moved in the conservative direction: stats are attributed to this attempt
#: from CLOCK_SKEW before the boundary, while "still due" counts everyone who
#: joined a segment up to CLOCK_SKEW after it, so a member the send may have
#: been meant to reach is never left out (which could make a partial send
#: look complete).
CLOCK_SKEW = timedelta(seconds=120)

EXPLANATIONS = {
    CONFIRMED_SENT: (
        "Mautic recorded sends for this email after this Send Now started, none before it, and no "
        "contact who was in its segments at that time is still due. The original send completed."
    ),
    "no_sends_recorded": (
        "Mautic has recorded no send for this email yet, while contacts are still due. That does "
        "not prove nothing will be sent: Mautic keeps no record of a request before its first "
        "send, the request has no enforced time limit, and the email stays ready to send. It "
        "stays protected and is never resent."
    ),
    STILL_PROCESSING: (
        "This send started too recently to judge: Mautic may still be sending. Check again after "
        "the settle period."
    ),
    "partially_sent": (
        "Mautic recorded some sends, but contacts who were in the segments when sending started "
        "are still due. The send did not complete. It will not be resent automatically."
    ),
    "no_sends_none_due": (
        "Mautic has recorded no send for this email and nobody in its segments is due now. That "
        "does not show the original audience was empty or that nothing will be sent: "
        "contacts may have left the segments since, and a delayed request could still send to "
        "current members. It stays protected and is never resent."
    ),
    "messages_queued": (
        "Mautic has messages for this email waiting in its message queue, so delivery is not "
        "finished."
    ),
    "stats_before_send": (
        "Mautic recorded sends of this email before this Send Now started, so its statistics do "
        "not belong to this attempt alone."
    ),
    "sent_count_mismatch": "Mautic's sent counter does not match its recorded sends for this email.",
    "related_emails": "This Mautic email has variants or translations, so sends cannot be attributed.",
    "not_a_segment_email": "The Mautic email is not a segment email.",
    "tracking_without_sends": (
        "Delivery or engagement events were received for this broadcast, but Mautic records no send."
    ),
    "counter_without_stats": "Mautic's sent counter shows sends that have no send record.",
    EVIDENCE_UNAVAILABLE: "Mautic could not be read, so the outcome cannot be judged now. Try again later.",
    "plugin_outdated": "The deployed ECP Marketing Bridge cannot report send evidence yet.",
    "email_missing": "The Mautic email for this broadcast no longer exists.",
    "no_email": "This broadcast has no Mautic email.",
}


class ResolutionRefused(Exception):
    """A resolution that must not be applied; nothing was changed."""

    def __init__(self, code: str, detail: str, *, http_status: int = 409):
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.http_status = http_status


def settle_seconds() -> float:
    configured = getattr(settings, "NEWSLETTER_SEND_OUTCOME_SETTLE_SECONDS", 3600)
    try:
        value = float(configured)
    except (TypeError, ValueError):
        value = 3600.0
    # Never shorter than ECP's own wait for the response.
    return max(value, float(getattr(settings, "MAUTIC_REQUEST_TIMEOUT", 15)) + 1)


def is_unresolved_send(event) -> bool:
    """The only state this module acts on: provider boundary crossed, no
    outcome recorded."""
    return bool(
        event is not None
        and event.provider_send_started_at is not None
        and event.status == NewsletterCampaignSendEvent.Status.PROCESSING
    )


def _parse(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if timezone.is_aware(parsed) else None


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def read_send_evidence(campaign, event, *, client=None) -> tuple[dict | None, str]:
    """Mautic's evidence for this attempt. Returns (evidence, error); never
    raises, never sends."""
    from .mautic import MauticClient, MauticError, PermanentMauticError

    email_id = str(campaign.mautic_email_id or "").strip()
    if not email_id:
        return None, "no_email"
    boundary = event.provider_send_started_at
    timeout = float(getattr(settings, "NEWSLETTER_SEND_EVIDENCE_TIMEOUT_SECONDS", 5))
    try:
        client = client or MauticClient()
        return client.get_email_send_evidence(
            email_id, since=boundary - CLOCK_SKEW, due_before=boundary + CLOCK_SKEW, timeout=timeout
        ), ""
    except PermanentMauticError as exc:
        message = str(exc)
        if "HTTP 404" in message:
            # Either the route (older plugin) or the email is missing; the
            # plugin names the email in its own 404.
            return None, "email_missing" if "Email not found" in message else "plugin_outdated"
        return None, "evidence_unavailable"
    except MauticError:
        return None, "evidence_unavailable"
    except Exception:
        logger.warning("Unexpected error reading Mautic send evidence", exc_info=True)
        return None, "evidence_unavailable"


def _tracking_since(campaign, boundary) -> int:
    return NewsletterCampaignTrackingEvent.objects.filter(
        campaign=campaign, occurred_at__gte=boundary - CLOCK_SKEW
    ).count()


def classify(campaign, event, evidence, *, evidence_error="", now=None, tracking_events=0) -> dict:
    """Pure decision over one attempt's evidence."""
    now = now or timezone.now()
    if not is_unresolved_send(event):
        return {"classification": NOT_APPLICABLE, "reason": "not_unresolved", "allowed_resolution": None}

    boundary = event.provider_send_started_at
    age = max(0.0, (now - boundary).total_seconds())
    settle = settle_seconds()
    base = {"seconds_since_boundary": round(age), "settle_seconds": round(settle)}

    def result(classification, reason, allowed=None):
        return {**base, "classification": classification, "reason": reason, "allowed_resolution": allowed}

    if evidence is None:
        return result(EVIDENCE_UNAVAILABLE, evidence_error or EVIDENCE_UNAVAILABLE)

    email = evidence.get("email") if isinstance(evidence.get("email"), dict) else {}
    stats = evidence.get("stats") if isinstance(evidence.get("stats"), dict) else {}
    if str(email.get("id")) != str(campaign.mautic_email_id or "").strip():
        return result(CONFLICTING, "email_mismatch")
    if email.get("email_type") != "list":
        return result(CONFLICTING, "not_a_segment_email")
    # A broadcast with A/B variants or translations is one send over several
    # emails; only evidence that counts the whole family can describe it.
    if email.get("related_email_ids") and evidence.get("family_aggregated") is not True:
        return result(CONFLICTING, "related_emails")

    total = _int(stats.get("total"))
    before = _int(stats.get("before_since"))
    since = _int(stats.get("since"))
    sent_count = _int(email.get("sent_count"))
    pending = _int(evidence.get("pending"))
    queued = _int(evidence.get("queued"))
    if None in (total, before, since, sent_count, pending, queued):
        return result(EVIDENCE_UNAVAILABLE, "malformed_evidence")

    if before > 0:
        return result(CONFLICTING, "stats_before_send")
    if age < settle:
        return result(STILL_PROCESSING, STILL_PROCESSING)
    if queued > 0:
        return result(UNCERTAIN, "messages_queued")

    if since > 0:
        if sent_count != since:
            return result(CONFLICTING, "sent_count_mismatch")
        if pending > 0:
            return result(UNCERTAIN, "partially_sent")
        return result(CONFIRMED_SENT, CONFIRMED_SENT, CONFIRMED_SENT)

    # No stats at all for this email.
    if sent_count > 0:
        return result(CONFLICTING, "counter_without_stats")
    if tracking_events > 0:
        return result(CONFLICTING, "tracking_without_sends")
    if pending == 0:
        # "Nobody due now" says nothing about who was due when the request
        # ran, or about a request that has not run yet.
        return result(UNCERTAIN, "no_sends_none_due")
    # Absence of activity is never proof that the request will not send.
    return result(UNCERTAIN, "no_sends_recorded")


def _event_summary(event):
    return {
        "event_uuid": str(event.event_uuid),
        "status": event.status,
        "requested_at": event.created_at,
        "processing_started_at": event.processing_started_at,
        "provider_send_started_at": event.provider_send_started_at,
        "uncertain_response": str(event.last_error or "").startswith(UNCERTAIN_SEND_MESSAGE),
    }


def investigate(campaign, event, *, client=None, now=None, provider_unavailable=False) -> dict:
    """Read-only: classify one attempt. Writes nothing, sends nothing.

    ``provider_unavailable``: the caller has just failed to reach Mautic, so
    no second request (and second timeout) is made.
    """
    now = now or timezone.now()
    if not is_unresolved_send(event):
        return {
            "observed_at": now,
            "applicable": False,
            **classify(campaign, event, None, now=now),
            "explanation": "",
            "evidence": None,
            "investigation_complete": True,
        }

    if provider_unavailable:
        evidence, error = None, EVIDENCE_UNAVAILABLE
    else:
        evidence, error = read_send_evidence(campaign, event, client=client)
    tracking = _tracking_since(campaign, event.provider_send_started_at)
    decision = classify(campaign, event, evidence, evidence_error=error, now=now, tracking_events=tracking)
    reason = decision["reason"]
    return {
        "observed_at": now,
        "applicable": True,
        **decision,
        "explanation": EXPLANATIONS.get(reason) or EXPLANATIONS.get(decision["classification"], ""),
        "investigation_complete": decision["classification"] not in (STILL_PROCESSING, EVIDENCE_UNAVAILABLE),
        "send_event": _event_summary(event),
        "evidence": None if evidence is None else {
            "source": "Mautic send record via ECP Marketing Bridge",
            "mautic_observed_at": evidence.get("generated_at"),
            "attributed_from": evidence.get("since"),
            "mautic_email_id": (evidence.get("email") or {}).get("id"),
            "sent_count": (evidence.get("email") or {}).get("sent_count"),
            "stats": evidence.get("stats"),
            "pending": evidence.get("pending"),
            "queued": evidence.get("queued"),
            "tracking_events_since_send": tracking,
            "limitations": (
                "Recorded sends mean Mautic handed the message to the mail transport, not that it "
                "reached an inbox. Opens, clicks and bounces arrive later and are not proof of a send."
            ),
        },
    }


def _audit_detail(event, previous, resolution, evidence, note) -> str:
    stats = (evidence or {}).get("stats") or {}
    email = (evidence or {}).get("email") or {}
    parts = [
        f"event={event.event_uuid}",
        f"from={previous}",
        f"email={email.get('id')}",
        f"stats_since={stats.get('since')}",
        f"stats_before={stats.get('before_since')}",
        f"sent_count={email.get('sent_count')}",
        f"pending={(evidence or {}).get('pending')}",
        f"queued={(evidence or {}).get('queued')}",
        f"boundary={event.provider_send_started_at.isoformat()}",
        f"observed={(evidence or {}).get('generated_at')}",
    ]
    if note:
        parts.append(f"note={note}")
    return " ".join(parts)[:255]


def _record_audit(user, campaign, event, *, status, code, detail):
    connection = (
        MauticUserConnection.objects.filter(user_id=user.pk, is_active=True)
        .values_list("mautic_user_id", flat=True)
        .first()
    )
    # Not record_identity_audit(): that helper swallows errors, and a
    # resolution must not be applied without its audit row.
    return MauticIdentityAuditLog.objects.create(
        ecp_user=user,
        ecp_user_label=user.get_username()[:191],
        mautic_user_id=connection,
        action=AUDIT_ACTION,
        resource=AUDIT_RESOURCE,
        resource_id=str(campaign.uuid),
        status=status,
        auth_mode="ecp_admin",
        correlation_id=str(event.event_uuid),
        error_code=code[:64],
        detail=detail[:255],
    )


def record_refusal(user, campaign, event, code, detail) -> None:
    """Best effort record of a refused attempt; never blocks the response."""
    if event is None:
        return
    try:
        _record_audit(
            user, campaign, event,
            status=MauticIdentityAuditLog.Status.DENIED, code=code, detail=detail,
        )
    except Exception:
        logger.exception("Could not record refused send-outcome resolution")


def resolve(campaign, *, user, event_uuid, resolution, note="", client=None, now=None) -> dict:
    """Apply one evidence-backed decision to the original send event.

    Fresh evidence is read first (outside any transaction), then the event and
    campaign are locked and re-checked: the decision is applied only if the
    attempt is still the unresolved one the evidence was read for. Nothing is
    sent and no send event is created.
    """
    if resolution == NOT_SENT_DECISION:
        raise ResolutionRefused(
            "not_sent_unsupported",
            "A send cannot be marked as not sent: Mautic keeps no record that proves a request it "
            "may have received will never send. It stays protected.",
            http_status=400,
        )
    if resolution not in RESOLUTIONS:
        raise ResolutionRefused("invalid_resolution", "Unsupported resolution.", http_status=400)
    note = str(note or "").strip()[:120]

    event = NewsletterCampaignSendEvent.objects.filter(campaign=campaign).first()
    if event is None or str(event.event_uuid) != str(event_uuid or ""):
        raise ResolutionRefused("stale_event", "This send event is not the broadcast's current send.")
    if not is_unresolved_send(event):
        raise ResolutionRefused(
            "already_resolved", f"This send is no longer unresolved (status: {event.status})."
        )

    boundary = event.provider_send_started_at
    evidence, error = read_send_evidence(campaign, event, client=client)
    now = now or timezone.now()
    tracking = _tracking_since(campaign, boundary)
    decision = classify(campaign, event, evidence, evidence_error=error, now=now, tracking_events=tracking)
    if decision["classification"] == EVIDENCE_UNAVAILABLE:
        raise ResolutionRefused(
            EVIDENCE_UNAVAILABLE,
            "Mautic's send record could not be read, so nothing was changed. Try again later.",
            http_status=503,
        )
    if decision["allowed_resolution"] != resolution:
        raise ResolutionRefused(
            "evidence_does_not_support",
            f"Current evidence does not support this decision ({decision['classification']}: "
            f"{decision['reason']}).",
        )

    stats = evidence["stats"]
    with transaction.atomic():
        locked_event = NewsletterCampaignSendEvent.objects.select_for_update().get(pk=event.pk)
        locked_campaign = NewsletterCampaign.objects.select_for_update().get(pk=campaign.pk)
        if (
            not is_unresolved_send(locked_event)
            or locked_event.provider_send_started_at != boundary
            or locked_campaign.status != NewsletterCampaign.Status.SENDING
        ):
            raise ResolutionRefused("state_changed", "This send changed while it was being resolved.")

        previous = f"{locked_event.status}/{locked_campaign.status}"
        resolved_at = timezone.now()
        # The existing success outcome, on the original event; nothing is sent.
        locked_event.status = NewsletterCampaignSendEvent.Status.SUCCEEDED
        locked_event.provider_sent_count = int(stats["since"])
        locked_event.last_error = ""
        locked_event.completed_at = resolved_at
        locked_event.save(
            update_fields=["status", "provider_sent_count", "last_error", "completed_at", "updated_at"]
        )
        locked_campaign.status = NewsletterCampaign.Status.SENT
        locked_campaign.sent_at = _parse(stats.get("last_sent_at")) or resolved_at
        locked_campaign.last_error = ""
        locked_campaign.save(update_fields=["status", "sent_at", "last_error", "updated_at"])
        new_state = f"{locked_event.status}/{locked_campaign.status}"
        _record_audit(
            user, locked_campaign, locked_event,
            status=MauticIdentityAuditLog.Status.SUCCEEDED,
            code=resolution,
            detail=_audit_detail(locked_event, previous, resolution, evidence, note),
        )

    logger.info(
        "Send outcome resolved campaign=%s event=%s %s -> %s by user_id=%s",
        campaign.uuid, event.event_uuid, previous, new_state, user.pk,
    )
    return {
        "resolution": resolution,
        "previous_state": previous,
        "new_state": new_state,
        "resolved_at": resolved_at,
        "event_uuid": str(event.event_uuid),
    }
