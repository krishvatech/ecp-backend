import logging

from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.utils import timezone
from rest_framework import serializers
from rest_framework.exceptions import APIException

from .campaign_send_events import (
    create_campaign_send_event,
    dispatch_campaign_send_event_safely,
)
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.exceptions import MauticBridgeRejectedError
from .mautic.payloads import (
    build_campaign_email_payload,
    build_cancelled_schedule_email_payload,
    build_scheduled_campaign_email_payload,
    build_test_email_payload,
)
from .category_segment_services import repair_campaign_audience_segments
from .models import (
    NewsletterCampaign,
    NewsletterCampaignSendEvent,
    NewsletterCategory,
)


logger = logging.getLogger(__name__)


class CampaignNotEditable(serializers.ValidationError):
    pass


class CampaignMauticValidationError(serializers.ValidationError):
    pass


class CampaignSendNotAllowed(serializers.ValidationError):
    pass


class CampaignScheduleNotAllowed(serializers.ValidationError):
    pass


class CampaignMauticUnavailable(APIException):
    status_code = 503
    default_detail = "Mautic newsletter synchronization is unavailable."
    default_code = "mautic_unavailable"


class CampaignMauticSyncFailed(APIException):
    status_code = 502
    default_detail = "Mautic newsletter synchronization failed."
    default_code = "mautic_sync_failed"


class CampaignMauticDeleteFailed(APIException):
    status_code = 502
    default_detail = "Mautic newsletter draft deletion failed."
    default_code = "mautic_delete_failed"


class CampaignMauticTestEmailFailed(APIException):
    status_code = 502
    default_detail = "Mautic newsletter test email failed."
    default_code = "mautic_test_email_failed"


def list_campaigns():
    return (
        NewsletterCampaign.objects.select_related("created_by", "updated_by")
        .prefetch_related("audiences")
        .order_by("-created_at", "-id")
    )


def list_active_categories():
    return NewsletterCategory.objects.filter(is_active=True).order_by("name")


def get_campaign(uuid):
    return (
        NewsletterCampaign.objects.select_related("created_by", "updated_by")
        .prefetch_related("audiences")
        .get(uuid=uuid)
    )


def _categories_from_slugs(slugs):
    if slugs is None:
        return None
    unique_slugs = list(dict.fromkeys(slugs))
    return list(
        NewsletterCategory.objects.filter(slug__in=unique_slugs, is_active=True)
    )


def validate_campaign_delivery_readiness(campaign):
    required_fields = (
        ("name", "Campaign name is required before delivery."),
        ("subject", "Campaign subject is required before delivery."),
        ("from_name", "Campaign sender name is required before delivery."),
        ("from_email", "Campaign sender email is required before delivery."),
    )
    for field, message in required_fields:
        if not str(getattr(campaign, field, "") or "").strip():
            raise CampaignMauticValidationError(message)

    try:
        validate_email(campaign.from_email)
    except DjangoValidationError as exc:
        raise CampaignMauticValidationError(
            "Campaign sender email must be valid before delivery."
        ) from exc

    if not (
        str(campaign.html_content or "").strip()
        or str(campaign.plain_text or "").strip()
    ):
        raise CampaignMauticValidationError(
            "Campaign content is required before delivery."
        )

    audiences = list(campaign.audiences.all().order_by("slug", "id"))
    if not audiences:
        raise CampaignMauticValidationError(
            "At least one newsletter audience is required before delivery."
        )

    for category in audiences:
        if not category.is_active:
            raise CampaignMauticValidationError(
                f"Newsletter audience '{category.name}' is inactive."
            )
        if not str(category.mautic_segment_id or "").strip():
            raise CampaignMauticValidationError(
                f"Newsletter audience '{category.name}' is not mapped to a Mautic segment."
            )

    return audiences


def validate_campaign_for_mautic_sync(campaign):
    if campaign.status != NewsletterCampaign.Status.DRAFT:
        raise CampaignMauticValidationError(
            "Only draft newsletter campaigns can be synchronized to Mautic."
        )
    return validate_campaign_delivery_readiness(campaign)


def validate_campaign_for_worker_delivery(campaign):
    if campaign.status not in {
        NewsletterCampaign.Status.DRAFT,
        NewsletterCampaign.Status.SCHEDULED,
    }:
        raise CampaignMauticValidationError(
            "Newsletter campaign is not eligible for delivery."
        )
    return validate_campaign_delivery_readiness(campaign)


def _record_mautic_sync_error(campaign, error):
    campaign.last_error = str(error or "Mautic newsletter synchronization failed.")[:500]
    campaign.save(update_fields=["last_error", "updated_at"])


def _repair_audience_segments(campaign, service_client):
    """Heal definitively-missing audience segment mappings before a sync.

    ``service_client`` is always a service-account client, never the caller's
    asserted-user client: recreating a Mautic segment is system work and must
    not be attributed to the human saving the broadcast.
    """
    try:
        return repair_campaign_audience_segments(campaign, client=service_client)
    except TemporaryMauticError as exc:
        _record_mautic_sync_error(campaign, exc)
        raise CampaignMauticUnavailable(
            "Mautic newsletter synchronization is temporarily unavailable."
        ) from exc
    except PermanentMauticError as exc:
        _record_mautic_sync_error(campaign, exc)
        raise CampaignMauticSyncFailed(
            "Mautic rejected the newsletter subscription list synchronization."
        ) from exc


def sync_campaign_to_mautic(campaign, *, actor=None, client=None):
    """Synchronize one draft broadcast into its Mautic list email.

    ``client`` is the interactive execution client. When per-user execution is
    enabled the caller passes an asserted-user client so Mautic records the
    acting human on createdBy/modifiedBy; otherwise the service account is used,
    which is also what the background worker path always does.
    """
    if not getattr(settings, "MAUTIC_SYNC_ENABLED", False):
        raise CampaignMauticUnavailable(
            "Mautic newsletter synchronization is disabled."
        )

    # Local validation first, so an incomplete draft never reaches the provider.
    validate_campaign_for_mautic_sync(campaign)

    # Segment work is infrastructure and always runs on the service account.
    # When no asserted client was injected this is also the client that performs
    # the email mutation, so a plain save still builds exactly one client.
    service_client = MauticClient()

    # A Subscription List whose Mautic segment has been deleted would otherwise
    # make Mautic reject the whole email. Repairing here, before the payload is
    # built, is what makes the payload carry the live segment id.
    _repair_audience_segments(campaign, service_client)

    payload = build_campaign_email_payload(campaign, publish=False)

    try:
        client = client or service_client
        existing_email_id = str(campaign.mautic_email_id or "").strip()

        if existing_email_id:
            client.update_email(existing_email_id, payload)
        else:
            email = client.create_email(payload)
            campaign.mautic_email_id = str(email["id"])
    except TemporaryMauticError as exc:
        _record_mautic_sync_error(campaign, exc)
        raise CampaignMauticUnavailable(
            "Mautic newsletter synchronization is temporarily unavailable."
        ) from exc
    except PermanentMauticError as exc:
        _record_mautic_sync_error(campaign, exc)
        raise CampaignMauticSyncFailed(
            "Mautic rejected the newsletter campaign synchronization."
        ) from exc

    campaign.last_synced_to_mautic_at = timezone.now()
    campaign.last_error = ""
    update_fields = [
        "mautic_email_id",
        "last_synced_to_mautic_at",
        "last_error",
        "updated_at",
    ]
    if actor is not None:
        campaign.updated_by = actor
        update_fields.append("updated_by")
    campaign.save(update_fields=update_fields)
    return campaign


def sync_campaign_for_worker_delivery(campaign, *, actor=None):
    if not getattr(settings, "MAUTIC_SYNC_ENABLED", False):
        raise CampaignMauticUnavailable(
            "Mautic newsletter synchronization is disabled."
        )

    validate_campaign_for_worker_delivery(campaign)

    # The worker path has no asserted identity at all, so one service-account
    # client serves both the segment repair and the email mutation.
    service_client = MauticClient()
    _repair_audience_segments(campaign, service_client)

    payload = build_campaign_email_payload(campaign, publish=False)

    try:
        client = service_client
        existing_email_id = str(campaign.mautic_email_id or "").strip()

        if existing_email_id:
            client.update_email(existing_email_id, payload)
        else:
            email = client.create_email(payload)
            campaign.mautic_email_id = str(email["id"])
    except TemporaryMauticError as exc:
        _record_mautic_sync_error(campaign, exc)
        raise CampaignMauticUnavailable(
            "Mautic newsletter synchronization is temporarily unavailable."
        ) from exc
    except PermanentMauticError as exc:
        _record_mautic_sync_error(campaign, exc)
        raise CampaignMauticSyncFailed(
            "Mautic rejected the newsletter campaign synchronization."
        ) from exc

    campaign.last_synced_to_mautic_at = timezone.now()
    campaign.last_error = ""
    update_fields = [
        "mautic_email_id",
        "last_synced_to_mautic_at",
        "last_error",
        "updated_at",
    ]
    if actor is not None:
        campaign.updated_by = actor
        update_fields.append("updated_by")
    campaign.save(update_fields=update_fields)
    return campaign


def sync_campaign_draft_to_mautic(campaign, *, actor=None, action="synchronized", client=None):
    """Synchronize an admin draft while serializing against Send Now."""
    pending_error = None
    synced_campaign = None

    with transaction.atomic():
        campaign = (
            NewsletterCampaign.objects.select_for_update()
            .prefetch_related("audiences")
            .get(pk=campaign.pk)
        )
        if NewsletterCampaignSendEvent.objects.filter(
            campaign_id=campaign.pk
        ).exists():
            raise CampaignSendNotAllowed(
                f"Newsletter campaign cannot be {action} after send has been requested."
            )

        try:
            synced_campaign = sync_campaign_to_mautic(
                campaign,
                actor=actor,
                client=client,
            )
        except (CampaignMauticUnavailable, CampaignMauticSyncFailed) as exc:
            # sync_campaign_to_mautic records last_error before translating
            # Mautic failures. Catch inside the transaction so that error state
            # commits, then re-raise after releasing the campaign row lock.
            pending_error = exc

    if pending_error is not None:
        raise pending_error
    return synced_campaign


def send_campaign_test_email(campaign, recipient_email, *, actor=None, client=None):
    recipient = str(recipient_email or "").strip().lower()
    if not recipient:
        raise CampaignMauticValidationError("Test recipient email is required.")

    try:
        validate_email(recipient)
    except DjangoValidationError as exc:
        raise CampaignMauticValidationError(
            "Test recipient email must be valid."
        ) from exc

    if not getattr(settings, "MAUTIC_SYNC_ENABLED", False):
        raise CampaignMauticUnavailable(
            "Mautic newsletter synchronization is disabled."
        )

    with transaction.atomic():
        campaign = (
            NewsletterCampaign.objects.select_for_update()
            .prefetch_related("audiences")
            .get(pk=campaign.pk)
        )
        if NewsletterCampaignSendEvent.objects.filter(
            campaign_id=campaign.pk
        ).exists():
            raise CampaignSendNotAllowed(
                "Newsletter campaign cannot be test emailed after send has been requested."
            )
        validate_campaign_for_mautic_sync(campaign)

    provider_client = None
    send_client = client
    temporary_contact = False
    contact_id = ""
    temporary_email_id = ""

    try:
        provider_client = MauticClient()
        if send_client is None:
            send_client = provider_client
        temporary_email = provider_client.create_email(build_test_email_payload(campaign))
        temporary_email_id = str(temporary_email.get("id") or "").strip()
        if not temporary_email_id:
            raise TemporaryMauticError(
                "Mautic test email creation returned an invalid email"
            )

        contact = provider_client.find_contact_by_email(recipient)
        if contact is None:
            contact = provider_client.create_contact({"email": recipient})
            temporary_contact = True

        contact_id = str(contact.get("id") or "").strip()
        if not contact_id:
            raise TemporaryMauticError(
                "Mautic test recipient returned an invalid contact"
            )

        send_client.send_email_to_contact(temporary_email_id, contact_id)
    except TemporaryMauticError as exc:
        _record_mautic_sync_error(campaign, exc)
        raise CampaignMauticUnavailable(
            "Mautic newsletter test email is temporarily unavailable."
        ) from exc
    except MauticBridgeRejectedError:
        raise
    except PermanentMauticError as exc:
        _record_mautic_sync_error(campaign, exc)
        raise CampaignMauticTestEmailFailed(
            "Mautic rejected the newsletter test email."
        ) from exc
    finally:
        if provider_client is not None and temporary_email_id:
            try:
                provider_client.delete_email(temporary_email_id)
            except (TemporaryMauticError, PermanentMauticError):
                logger.warning(
                    "Could not delete temporary Mautic newsletter test email id=%s",
                    temporary_email_id,
                    exc_info=True,
                )
        if provider_client is not None and temporary_contact and contact_id:
            try:
                provider_client.delete_contact(contact_id)
            except (TemporaryMauticError, PermanentMauticError):
                logger.warning(
                    "Could not delete temporary Mautic newsletter test contact id=%s",
                    contact_id,
                    exc_info=True,
                )

    return {
        "recipient_email": recipient,
        "contact_id": contact_id,
        "temporary_contact": temporary_contact,
    }


@transaction.atomic
def create_campaign(validated_data, *, user):
    audience_slugs = validated_data.pop("audience_slugs", [])
    campaign = NewsletterCampaign.objects.create(
        **validated_data,
        status=NewsletterCampaign.Status.DRAFT,
        created_by=user,
        updated_by=user,
    )
    campaign.audiences.set(_categories_from_slugs(audience_slugs))
    return campaign


def _ensure_campaign_can_change(campaign, *, action):
    if campaign.status != NewsletterCampaign.Status.DRAFT:
        raise CampaignNotEditable(
            f"Only draft newsletter campaigns can be {action}."
        )
    if NewsletterCampaignSendEvent.objects.filter(
        campaign_id=campaign.pk
    ).exists():
        raise CampaignNotEditable(
            "Newsletter campaign cannot be changed after send has been requested."
        )


@transaction.atomic
def update_campaign(campaign, validated_data, *, user):
    campaign = NewsletterCampaign.objects.select_for_update().get(pk=campaign.pk)
    _ensure_campaign_can_change(campaign, action="edited")

    audience_slugs = validated_data.pop("audience_slugs", None)
    for field, value in validated_data.items():
        setattr(campaign, field, value)
    campaign.updated_by = user
    campaign.save()

    categories = _categories_from_slugs(audience_slugs)
    if categories is not None:
        campaign.audiences.set(categories)
    return campaign


def delete_draft_campaign(campaign, *, client=None):
    pending_error = None
    pending_cause = None

    with transaction.atomic():
        campaign = NewsletterCampaign.objects.select_for_update().get(pk=campaign.pk)
        _ensure_campaign_can_change(campaign, action="deleted")

        mautic_email_id = str(campaign.mautic_email_id or "").strip()
        if not mautic_email_id:
            campaign.delete()
            return

        if not getattr(settings, "MAUTIC_SYNC_ENABLED", False):
            raise CampaignMauticUnavailable(
                "Mautic newsletter synchronization is disabled; "
                "the linked Mautic draft was not deleted."
            )

        try:
            (client or MauticClient()).delete_email(mautic_email_id)
        except TemporaryMauticError as exc:
            _record_mautic_sync_error(campaign, exc)
            pending_error = CampaignMauticUnavailable(
                "Mautic newsletter draft deletion is temporarily unavailable."
            )
            pending_cause = exc
        except PermanentMauticError as exc:
            _record_mautic_sync_error(campaign, exc)
            pending_error = CampaignMauticDeleteFailed(
                "Mautic rejected the newsletter draft deletion."
            )
            pending_cause = exc
        else:
            campaign.delete()

    # Raise after the transaction commits so last_error survives provider
    # failures while the row remained locked against concurrent send requests.
    if pending_error is not None:
        raise pending_error from pending_cause


def native_scheduling_enabled() -> bool:
    """Feature flag for NEW native schedules only."""
    return bool(
        getattr(settings, "MAUTIC_NATIVE_BROADCAST_SCHEDULING_ENABLED", False)
    )


def effective_schedule_owner(campaign) -> str:
    """Owner of an existing schedule, defaulting a blank scheduled row to ECP.

    Reading blank as ECP is the safe direction: a row the backfill missed keeps
    being delivered by the ECP dispatcher instead of being silently owned by
    nobody.
    """
    owner = str(getattr(campaign, "schedule_owner", "") or "").strip()
    if owner:
        return owner
    if campaign.status == NewsletterCampaign.Status.SCHEDULED:
        return NewsletterCampaign.ScheduleOwner.ECP
    return ""


def is_mautic_scheduled(campaign) -> bool:
    return (
        campaign.status == NewsletterCampaign.Status.SCHEDULED
        and effective_schedule_owner(campaign)
        == NewsletterCampaign.ScheduleOwner.MAUTIC
    )


def resolve_schedule_owner_for_request(campaign) -> str:
    """Which scheduler should own this Schedule/Reschedule request.

    An already-scheduled broadcast keeps its owner whatever the flag now says,
    so turning the flag on cannot hijack ECP schedules and turning it off
    cannot strand Mautic ones. Only a fresh schedule consults the flag.
    """
    existing = effective_schedule_owner(campaign)
    if existing:
        return existing
    return (
        NewsletterCampaign.ScheduleOwner.MAUTIC
        if native_scheduling_enabled()
        else NewsletterCampaign.ScheduleOwner.ECP
    )


def _validate_schedule_request(campaign, scheduled_at, *, rescheduling=False):
    """Local-only checks. Runs before any provider contact."""
    now = timezone.now()
    if scheduled_at is None:
        raise CampaignScheduleNotAllowed("Scheduled time is required.")
    if scheduled_at <= now:
        raise CampaignScheduleNotAllowed(
            "Scheduled time must be strictly in the future."
        )

    existing_event = NewsletterCampaignSendEvent.objects.filter(
        campaign_id=campaign.pk
    ).first()

    if campaign.status == NewsletterCampaign.Status.DRAFT:
        if existing_event is not None:
            raise CampaignScheduleNotAllowed(
                "Newsletter campaign cannot be scheduled after send has been requested."
            )
    elif campaign.status == NewsletterCampaign.Status.SCHEDULED:
        if existing_event is not None:
            raise CampaignScheduleNotAllowed(
                "Scheduled newsletter campaign cannot be rescheduled after send has been requested."
            )
    else:
        raise CampaignScheduleNotAllowed(
            "Newsletter campaign cannot be scheduled in its current status."
        )

    validate_campaign_delivery_readiness(campaign)


def _native_schedule_mutation(campaign, payload, *, client):
    """Run one provider Email mutation for a scheduling change.

    Chooses create vs update from whether a native Email already exists, which
    is the same decision the caller used to bind the assertion operation, so a
    create assertion is never spent on an update or the reverse.
    """
    if not getattr(settings, "MAUTIC_SYNC_ENABLED", False):
        raise CampaignMauticUnavailable(
            "Mautic newsletter synchronization is disabled."
        )

    service_client = MauticClient()
    _repair_audience_segments(campaign, service_client)
    # Re-read after repair so the payload carries the live segment ids.
    payload = payload()

    provider = client or service_client
    existing_email_id = str(campaign.mautic_email_id or "").strip()

    try:
        if existing_email_id:
            provider.update_email(existing_email_id, payload)
            return existing_email_id, False
        email = provider.create_email(payload)
        return str(email["id"]), True
    except TemporaryMauticError as exc:
        _record_mautic_sync_error(campaign, exc)
        raise CampaignMauticUnavailable(
            "Mautic newsletter scheduling is temporarily unavailable."
        ) from exc
    except PermanentMauticError as exc:
        _record_mautic_sync_error(campaign, exc)
        raise CampaignMauticSyncFailed(
            "Mautic rejected the newsletter campaign schedule."
        ) from exc


def _compensate_native_schedule(campaign, payload_builder, *, client, note):
    """Best-effort undo after the provider succeeded but ECP could not persist.

    Never raises: the caller is already failing, and the original failure must
    stay the reported one. Not a retry loop — one attempt, then a loud log.
    """
    email_id = str(campaign.mautic_email_id or "").strip()
    if not email_id:
        return
    try:
        (client or MauticClient()).update_email(email_id, payload_builder())
    except Exception:
        logger.exception(
            "Could not compensate Mautic schedule for campaign uuid=%s (%s); "
            "provider and ECP schedule state may disagree",
            campaign.uuid,
            note,
        )


def schedule_campaign_natively(campaign, *, scheduled_at, user, client=None):
    """Arm a future native Mautic broadcast and mark the ECP row scheduled."""
    with transaction.atomic():
        campaign = (
            NewsletterCampaign.objects.select_for_update()
            .prefetch_related("audiences")
            .get(pk=campaign.pk)
        )
        _validate_schedule_request(campaign, scheduled_at)

    previous_email_id = str(campaign.mautic_email_id or "").strip()
    previous_scheduled_at = campaign.scheduled_at

    email_id, created = _native_schedule_mutation(
        campaign,
        lambda: build_scheduled_campaign_email_payload(
            campaign,
            scheduled_at=scheduled_at,
        ),
        client=client,
    )

    try:
        with transaction.atomic():
            locked = NewsletterCampaign.objects.select_for_update().get(pk=campaign.pk)
            locked.mautic_email_id = email_id
            locked.status = NewsletterCampaign.Status.SCHEDULED
            locked.scheduled_at = scheduled_at
            locked.schedule_owner = NewsletterCampaign.ScheduleOwner.MAUTIC
            locked.last_synced_to_mautic_at = timezone.now()
            locked.last_error = ""
            locked.updated_by = user
            locked.save(
                update_fields=[
                    "mautic_email_id",
                    "status",
                    "scheduled_at",
                    "schedule_owner",
                    "last_synced_to_mautic_at",
                    "last_error",
                    "updated_by",
                    "updated_at",
                ]
            )
    except Exception:
        # Mautic is now armed but ECP does not know: disarm it rather than
        # leave a broadcast that nothing on this side is tracking.
        campaign.mautic_email_id = email_id
        _compensate_native_schedule(
            campaign,
            lambda: build_cancelled_schedule_email_payload(campaign),
            client=client,
            note="schedule rollback",
        )
        if created:
            logger.warning(
                "Mautic email id=%s was created for campaign uuid=%s but the "
                "local schedule could not be saved; the email was disarmed",
                email_id,
                campaign.uuid,
            )
        raise

    campaign.refresh_from_db()
    del previous_email_id, previous_scheduled_at
    return campaign


def reschedule_campaign_natively(campaign, *, scheduled_at, user, client=None):
    """Move an existing native schedule; the Mautic Email id never changes."""
    with transaction.atomic():
        campaign = (
            NewsletterCampaign.objects.select_for_update()
            .prefetch_related("audiences")
            .get(pk=campaign.pk)
        )
        _validate_schedule_request(campaign, scheduled_at, rescheduling=True)

        if not str(campaign.mautic_email_id or "").strip():
            # Fail closed: never quietly create a second Email for a schedule
            # that is supposed to already exist in Mautic.
            raise CampaignMauticSyncFailed(
                "This scheduled broadcast has no linked Mautic email."
            )

    previous_scheduled_at = campaign.scheduled_at

    _native_schedule_mutation(
        campaign,
        lambda: build_scheduled_campaign_email_payload(
            campaign,
            scheduled_at=scheduled_at,
        ),
        client=client,
    )

    try:
        with transaction.atomic():
            locked = NewsletterCampaign.objects.select_for_update().get(pk=campaign.pk)
            locked.scheduled_at = scheduled_at
            locked.schedule_owner = NewsletterCampaign.ScheduleOwner.MAUTIC
            locked.status = NewsletterCampaign.Status.SCHEDULED
            locked.last_synced_to_mautic_at = timezone.now()
            locked.last_error = ""
            locked.updated_by = user
            locked.save(
                update_fields=[
                    "scheduled_at",
                    "schedule_owner",
                    "status",
                    "last_synced_to_mautic_at",
                    "last_error",
                    "updated_by",
                    "updated_at",
                ]
            )
    except Exception:
        _compensate_native_schedule(
            campaign,
            lambda: build_scheduled_campaign_email_payload(
                campaign,
                scheduled_at=previous_scheduled_at,
            ),
            client=client,
            note="reschedule rollback",
        )
        raise

    campaign.refresh_from_db()
    return campaign


def cancel_native_schedule(campaign, *, user, client=None):
    """Disarm a native schedule, then mark the ECP row cancelled."""
    with transaction.atomic():
        campaign = (
            NewsletterCampaign.objects.select_for_update()
            .prefetch_related("audiences")
            .get(pk=campaign.pk)
        )
        if campaign.status != NewsletterCampaign.Status.SCHEDULED:
            raise CampaignScheduleNotAllowed(
                "Only scheduled newsletter campaigns can be cancelled."
            )

        event = NewsletterCampaignSendEvent.objects.filter(
            campaign_id=campaign.pk
        ).first()
        if event is not None and event.provider_send_started_at is not None:
            raise CampaignScheduleNotAllowed(
                "Newsletter campaign cannot be cancelled after provider delivery has started."
            )

        if not str(campaign.mautic_email_id or "").strip():
            raise CampaignMauticSyncFailed(
                "This scheduled broadcast has no linked Mautic email."
            )

    previous_scheduled_at = campaign.scheduled_at

    # Disarm the provider first. If this fails the ECP row deliberately stays
    # SCHEDULED/mautic, because Mautic would still deliver it.
    _native_schedule_mutation(
        campaign,
        lambda: build_cancelled_schedule_email_payload(campaign),
        client=client,
    )

    try:
        with transaction.atomic():
            locked = NewsletterCampaign.objects.select_for_update().get(pk=campaign.pk)
            locked.status = NewsletterCampaign.Status.CANCELLED
            locked.schedule_owner = ""
            locked.last_error = ""
            locked.updated_by = user
            locked.save(
                update_fields=[
                    "status",
                    "schedule_owner",
                    "last_error",
                    "updated_by",
                    "updated_at",
                ]
            )
    except Exception:
        _compensate_native_schedule(
            campaign,
            lambda: build_scheduled_campaign_email_payload(
                campaign,
                scheduled_at=previous_scheduled_at,
            ),
            client=client,
            note="cancel rollback",
        )
        raise

    campaign.refresh_from_db()
    return campaign


@transaction.atomic
def schedule_campaign(campaign, *, scheduled_at, user):
    now = timezone.now()
    if scheduled_at is None:
        raise CampaignScheduleNotAllowed("Scheduled time is required.")
    if scheduled_at <= now:
        raise CampaignScheduleNotAllowed(
            "Scheduled time must be strictly in the future."
        )

    campaign = (
        NewsletterCampaign.objects.select_for_update()
        .prefetch_related("audiences")
        .get(pk=campaign.pk)
    )
    existing_event = NewsletterCampaignSendEvent.objects.filter(
        campaign_id=campaign.pk
    ).first()

    if campaign.status == NewsletterCampaign.Status.DRAFT:
        if existing_event is not None:
            raise CampaignScheduleNotAllowed(
                "Newsletter campaign cannot be scheduled after send has been requested."
            )
    elif campaign.status == NewsletterCampaign.Status.SCHEDULED:
        if existing_event is not None:
            raise CampaignScheduleNotAllowed(
                "Scheduled newsletter campaign cannot be rescheduled after send has been requested."
            )
    else:
        raise CampaignScheduleNotAllowed(
            "Newsletter campaign cannot be scheduled in its current status."
        )

    validate_campaign_delivery_readiness(campaign)
    campaign.status = NewsletterCampaign.Status.SCHEDULED
    campaign.scheduled_at = scheduled_at
    # Stamped explicitly so the ECP dispatcher keeps selecting it even after
    # native scheduling is switched on globally.
    campaign.schedule_owner = NewsletterCampaign.ScheduleOwner.ECP
    campaign.updated_by = user
    campaign.last_error = ""
    campaign.save(
        update_fields=[
            "status",
            "scheduled_at",
            "schedule_owner",
            "updated_by",
            "last_error",
            "updated_at",
        ]
    )
    return campaign


@transaction.atomic
def cancel_scheduled_campaign(campaign, *, user):
    now = timezone.now()
    event = (
        NewsletterCampaignSendEvent.objects.select_for_update()
        .filter(campaign_id=campaign.pk)
        .first()
    )
    campaign = NewsletterCampaign.objects.select_for_update().get(pk=campaign.pk)

    if campaign.status != NewsletterCampaign.Status.SCHEDULED:
        raise CampaignScheduleNotAllowed(
            "Only scheduled newsletter campaigns can be cancelled."
        )

    if event is None:
        event = (
            NewsletterCampaignSendEvent.objects.select_for_update()
            .filter(campaign_id=campaign.pk)
            .first()
        )

    if event is not None:
        if event.provider_send_started_at is not None:
            raise CampaignScheduleNotAllowed(
                "Newsletter campaign cannot be cancelled after provider delivery has started."
            )
        if event.status == NewsletterCampaignSendEvent.Status.SUCCEEDED:
            raise CampaignScheduleNotAllowed(
                "Newsletter campaign has already been sent."
            )

        event.status = NewsletterCampaignSendEvent.Status.FAILED
        event.completed_at = now
        event.last_error = (
            "Newsletter campaign cancelled before provider delivery started."
        )
        event.save(
            update_fields=[
                "status",
                "completed_at",
                "last_error",
                "updated_at",
            ]
        )

    campaign.status = NewsletterCampaign.Status.CANCELLED
    campaign.schedule_owner = ""
    campaign.updated_by = user
    campaign.last_error = ""
    campaign.save(
        update_fields=[
            "status",
            "schedule_owner",
            "updated_by",
            "last_error",
            "updated_at",
        ]
    )
    return campaign


def _campaign_send_dispatchable(event):
    return (
        event.provider_send_started_at is None
        and event.status
        in {
            NewsletterCampaignSendEvent.Status.PENDING,
            NewsletterCampaignSendEvent.Status.PROCESSING,
            NewsletterCampaignSendEvent.Status.FAILED,
        }
    )


def request_campaign_send(campaign, *, user):
    """Create/reuse one send event and dispatch it only after commit."""
    with transaction.atomic():
        campaign = (
            NewsletterCampaign.objects.select_for_update()
            .prefetch_related("audiences")
            .get(pk=campaign.pk)
        )

        # Lifecycle safety is evaluated from the locked database row before the
        # provider feature flag so Send Now can never bypass ECP scheduling.
        if campaign.status == NewsletterCampaign.Status.SCHEDULED:
            raise CampaignSendNotAllowed(
                "Scheduled newsletter campaign cannot be sent before its scheduled time."
            )

        if not getattr(settings, "MAUTIC_SYNC_ENABLED", False):
            raise CampaignMauticUnavailable(
                "Mautic newsletter synchronization is disabled."
            )

        event = NewsletterCampaignSendEvent.objects.filter(
            campaign=campaign
        ).first()

        if event is None:
            validate_campaign_for_mautic_sync(campaign)
            event = create_campaign_send_event(
                campaign,
                requested_by=user,
            )
        elif event.status == NewsletterCampaignSendEvent.Status.SUCCEEDED:
            raise CampaignSendNotAllowed(
                "Newsletter campaign has already been sent."
            )
        elif (
            event.status == NewsletterCampaignSendEvent.Status.FAILED
            and event.provider_send_started_at is not None
        ):
            raise CampaignSendNotAllowed(
                "Newsletter campaign cannot be retried because provider "
                "delivery may already have started."
            )

        if _campaign_send_dispatchable(event):
            transaction.on_commit(
                lambda event_id=event.pk: dispatch_campaign_send_event_safely(
                    event_id
                )
            )

        return event
