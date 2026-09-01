import logging

from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.utils import timezone
from rest_framework import serializers
from rest_framework.exceptions import APIException

from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.payloads import build_campaign_email_payload
from .models import NewsletterCampaign, NewsletterCategory


logger = logging.getLogger(__name__)


class CampaignNotEditable(serializers.ValidationError):
    pass


class CampaignMauticValidationError(serializers.ValidationError):
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


def validate_campaign_for_mautic_sync(campaign):
    if campaign.status != NewsletterCampaign.Status.DRAFT:
        raise CampaignMauticValidationError(
            "Only draft newsletter campaigns can be synchronized to Mautic."
        )

    required_fields = (
        ("name", "Campaign name is required before Mautic sync."),
        ("subject", "Campaign subject is required before Mautic sync."),
        ("from_name", "Campaign sender name is required before Mautic sync."),
        ("from_email", "Campaign sender email is required before Mautic sync."),
    )
    for field, message in required_fields:
        if not str(getattr(campaign, field, "") or "").strip():
            raise CampaignMauticValidationError(message)

    try:
        validate_email(campaign.from_email)
    except DjangoValidationError as exc:
        raise CampaignMauticValidationError(
            "Campaign sender email must be valid before Mautic sync."
        ) from exc

    if not (
        str(campaign.html_content or "").strip()
        or str(campaign.plain_text or "").strip()
    ):
        raise CampaignMauticValidationError(
            "Campaign content is required before Mautic sync."
        )

    audiences = list(campaign.audiences.all().order_by("slug", "id"))
    if not audiences:
        raise CampaignMauticValidationError(
            "At least one newsletter audience is required before Mautic sync."
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


def _record_mautic_sync_error(campaign, error):
    campaign.last_error = str(error or "Mautic newsletter synchronization failed.")[:500]
    campaign.save(update_fields=["last_error", "updated_at"])


def sync_campaign_to_mautic(campaign, *, actor=None):
    if not getattr(settings, "MAUTIC_SYNC_ENABLED", False):
        raise CampaignMauticUnavailable(
            "Mautic newsletter synchronization is disabled."
        )

    validate_campaign_for_mautic_sync(campaign)
    payload = build_campaign_email_payload(campaign, publish=False)

    try:
        client = MauticClient()
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


def send_campaign_test_email(campaign, recipient_email, *, actor=None):
    recipient = str(recipient_email or "").strip().lower()
    if not recipient:
        raise CampaignMauticValidationError("Test recipient email is required.")

    try:
        validate_email(recipient)
    except DjangoValidationError as exc:
        raise CampaignMauticValidationError(
            "Test recipient email must be valid."
        ) from exc

    campaign = sync_campaign_to_mautic(campaign, actor=actor)
    client = MauticClient()
    temporary_contact = False
    contact_id = ""

    try:
        contact = client.find_contact_by_email(recipient)
        if contact is None:
            contact = client.create_contact({"email": recipient})
            temporary_contact = True

        contact_id = str(contact.get("id") or "").strip()
        if not contact_id:
            raise TemporaryMauticError(
                "Mautic test recipient returned an invalid contact"
            )

        client.send_email_to_contact(campaign.mautic_email_id, contact_id)
    except TemporaryMauticError as exc:
        _record_mautic_sync_error(campaign, exc)
        raise CampaignMauticUnavailable(
            "Mautic newsletter test email is temporarily unavailable."
        ) from exc
    except PermanentMauticError as exc:
        _record_mautic_sync_error(campaign, exc)
        raise CampaignMauticTestEmailFailed(
            "Mautic rejected the newsletter test email."
        ) from exc
    finally:
        if temporary_contact and contact_id:
            try:
                client.delete_contact(contact_id)
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


@transaction.atomic
def update_campaign(campaign, validated_data, *, user):
    if campaign.status != NewsletterCampaign.Status.DRAFT:
        raise CampaignNotEditable("Only draft newsletter campaigns can be edited.")

    audience_slugs = validated_data.pop("audience_slugs", None)
    for field, value in validated_data.items():
        setattr(campaign, field, value)
    campaign.updated_by = user
    campaign.save()

    categories = _categories_from_slugs(audience_slugs)
    if categories is not None:
        campaign.audiences.set(categories)
    return campaign


def delete_draft_campaign(campaign):
    if campaign.status != NewsletterCampaign.Status.DRAFT:
        raise CampaignNotEditable("Only draft newsletter campaigns can be deleted.")

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
        MauticClient().delete_email(mautic_email_id)
    except TemporaryMauticError as exc:
        _record_mautic_sync_error(campaign, exc)
        raise CampaignMauticUnavailable(
            "Mautic newsletter draft deletion is temporarily unavailable."
        ) from exc
    except PermanentMauticError as exc:
        _record_mautic_sync_error(campaign, exc)
        raise CampaignMauticDeleteFailed(
            "Mautic rejected the newsletter draft deletion."
        ) from exc

    campaign.delete()
