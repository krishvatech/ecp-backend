"""A/B variants and translations of an Email Broadcast (native Mautic email families).

A broadcast is one Mautic segment email. Its variants and translations are
copies of that email (variantParent / translationParent), kept in Mautic like
Templates are, with their visual design stored in ECP by Mautic email id.
Mautic splits the broadcast's send between the email and its variants by
weight and sends a translation to contacts whose preferred locale matches;
after the send, the results per version come from Mautic's own A/B numbers.

Agreed rules (2026-10-29): versions can be added, edited and removed only
while the broadcast is a draft; the broadcast's sender and segments are shared
(campaign_services.sync_family_shared_fields); there is no winner action, as a
broadcast is sent once.
"""

from __future__ import annotations

import logging
from typing import Any

from django.db import DatabaseError
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .admin_views import BROADCAST_PROVIDER_ERRORS, _get_campaign_or_404
from .campaign_services import sync_campaign_draft_to_mautic
from .email_design_services import (
    TemplateSaveInProgress,
    copy_campaign_design_to_email,
    delete_template_design,
    html_fingerprint,
    save_template_design,
    template_save_lock,
)
from .marketing_permissions import HasMarketingHubAccess
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.operations import EMAIL_DELETE, EMAIL_TRANSLATION_CREATE, EMAIL_UPDATE, EMAIL_VARIANT_CREATE, EMAIL_VARIANT_UPDATE
from .mautic_identity_execution import asserted_client_or_none, run_interactive_mutation
from .models import NewsletterCampaign, NewsletterCampaignSendEvent
from .template_views import (
    _LANGUAGE_RE,
    _family_fields,
    _normalize_template,
    _optional_name,
    _parse_base_fingerprint,
    _parse_criteria,
    _parse_weight,
    _prepare_visual_design,
    _split_visual_fields,
    _template_with_design,
    normalize_template_abtest,
)

logger = logging.getLogger(__name__)

_VERSION_FIELDS = {"name", "subject", "preheaderText", "plainText", "customHtml", "language"}


def _error(message: str, *, code: str, http_status=status.HTTP_409_CONFLICT) -> Response:
    return Response({"detail": message, "code": code}, status=http_status)


def is_family_editable(campaign) -> bool:
    """Draft only, and never once a send was requested (what was reviewed is what is sent)."""
    return (
        campaign.status == NewsletterCampaign.Status.DRAFT
        and not NewsletterCampaignSendEvent.objects.filter(campaign_id=campaign.pk).exists()
    )


def _locked() -> Response:
    return _error("Variants and translations can only be changed while the broadcast is a draft.", code="broadcast_not_draft")


def _provider_error(exc) -> Response:
    message = str(exc)
    if isinstance(exc, PermanentMauticError) and "HTTP 409" in message:
        return _error(message.split(": ", 1)[1] if ": " in message else message, code="broadcast_family_conflict")
    if isinstance(exc, PermanentMauticError) and "HTTP 404" in message:
        return _error("That version was not found in Mautic.", code="version_not_found", http_status=status.HTTP_404_NOT_FOUND)
    if isinstance(exc, PermanentMauticError) and any(f"HTTP {code}" in message for code in (400, 422)):
        return _error(message.split(": ", 1)[1] if ": " in message else message, code="invalid_setting", http_status=status.HTTP_400_BAD_REQUEST)
    return _error("Mautic could not be reached. Nothing was changed; try again.", code="mautic_error", http_status=status.HTTP_502_BAD_GATEWAY)


def _version(email: dict[str, Any]) -> dict[str, Any]:
    normalized = _normalize_template(email)
    return {
        key: normalized[key]
        for key in ("id", "name", "subject", "preheaderText", "plainText", "customHtml", "language", "role",
                    "variantParentId", "translationParentId", "isPublished", "dateModified")
    }


def _child_of(campaign, email_id, client=None) -> tuple[dict[str, Any] | None, Response | None]:
    """The broadcast's own variant or translation, or a 404."""
    parent_id = str(campaign.mautic_email_id or "").strip()
    if not parent_id or not str(email_id).isdigit():
        return None, _error("That version was not found.", code="version_not_found", http_status=status.HTTP_404_NOT_FOUND)
    try:
        email = (client or MauticClient()).get_email(email_id)
    except (TemporaryMauticError, PermanentMauticError) as exc:
        return None, _provider_error(exc)
    family = _family_fields(email)
    if parent_id not in (family["variantParentId"], family["translationParentId"]) or email.get("emailType") != "list":
        return None, _error("That version was not found.", code="version_not_found", http_status=status.HTTP_404_NOT_FOUND)
    return email, None


class NewsletterAdminCampaignFamilyView(APIView):
    """The broadcast's variants, translations and (after a send) its A/B results."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, uuid):
        campaign = _get_campaign_or_404(uuid)
        email_id = str(campaign.mautic_email_id or "").strip()
        base = {"editable": is_family_editable(campaign), "mauticEmailId": email_id or None,
                "language": "", "variants": [], "translations": [], "abTest": None}
        if not email_id:
            return Response(base)
        client = MauticClient()
        try:
            family = _family_fields(client.get_email(email_id))
            test = normalize_template_abtest(client.get_broadcast_abtest(email_id)) if family["variants"] else None
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        return Response({**base, "language": family["language"], "variants": family["variants"],
                         "translations": family["translations"], "abTest": test})


def _create_member(request, uuid, *, action, create):
    """Sync the draft first, so the copy starts from the content being reviewed."""
    campaign = _get_campaign_or_404(uuid)
    if not is_family_editable(campaign):
        return _locked()

    def mutate(client):
        synced = sync_campaign_draft_to_mautic(campaign, actor=request.user, client=asserted_client_or_none(client))
        return synced, create(client, synced.mautic_email_id)

    try:
        result, error_response = run_interactive_mutation(
            request,
            action=action,
            resource="newsletter_campaign",
            resource_id=str(campaign.uuid),
            mutate=mutate,
            client_factory=MauticClient,
            audit_and_reraise=(TemporaryMauticError, PermanentMauticError, *BROADCAST_PROVIDER_ERRORS),
        )
    except (TemporaryMauticError, PermanentMauticError) as exc:
        return _provider_error(exc)
    if error_response is not None:
        return error_response

    synced, created = result
    member = _version(created)
    try:
        stored = MauticClient().get_email(member["id"])
        member["designCopied"] = copy_campaign_design_to_email(
            synced, member["id"], str(stored.get("customHtml") or ""), user=request.user
        ) is not None
    except (TemporaryMauticError, PermanentMauticError, DatabaseError):
        logger.warning("Could not copy the broadcast design to version id=%s", member["id"], exc_info=True)
        member["designCopied"] = False
    return Response(member, status=status.HTTP_201_CREATED)


class NewsletterAdminCampaignVariantCreateView(APIView):
    """Add an A/B variant: a copy of the broadcast with its share of the send."""

    permission_classes = [HasMarketingHubAccess]

    def post(self, request, uuid):
        try:
            weight = _parse_weight(request.data.get("weight"))
            criteria = _parse_criteria(request.data.get("winnerCriteria"))
            name = _optional_name(request.data)
        except ValueError as exc:
            return _error(str(exc), code="invalid_setting", http_status=status.HTTP_400_BAD_REQUEST)
        return _create_member(
            request, uuid, action=EMAIL_VARIANT_CREATE,
            create=lambda client, email_id: client.create_broadcast_variant(email_id, weight=weight, winner_criteria=criteria, name=name or None),
        )


class NewsletterAdminCampaignTranslationCreateView(APIView):
    """Add a translation: a copy of the broadcast for contacts whose locale matches."""

    permission_classes = [HasMarketingHubAccess]

    def post(self, request, uuid):
        language = str(request.data.get("language") or "").strip()
        try:
            if not _LANGUAGE_RE.match(language):
                raise ValueError("Language must be a locale code such as fr or fr_CA.")
            name = _optional_name(request.data)
        except ValueError as exc:
            return _error(str(exc), code="invalid_setting", http_status=status.HTTP_400_BAD_REQUEST)
        return _create_member(
            request, uuid, action=EMAIL_TRANSLATION_CREATE,
            create=lambda client, email_id: client.create_broadcast_translation(email_id, language=language, name=name or None),
        )


def _parse_version_payload(data) -> dict[str, Any]:
    unsupported = sorted(set(data.keys()) - _VERSION_FIELDS)
    if unsupported:
        raise ValueError("Unsupported field(s): " + ", ".join(unsupported))
    payload = {}
    for field in ("name", "subject", "preheaderText", "plainText", "customHtml"):
        if field in data:
            value = str(data.get(field) or "")
            payload[field] = value.strip() if field in ("name", "subject") else value
    if "name" in payload and not payload["name"]:
        raise ValueError("Name is required.")
    if "subject" in payload and not payload["subject"]:
        raise ValueError("Subject is required.")
    if len(payload.get("subject", "")) > 190 or len(payload.get("name", "")) > 190:
        raise ValueError("Name and subject cannot exceed 190 characters.")
    if "language" in data:
        language = str(data.get("language") or "").strip()
        if not _LANGUAGE_RE.match(language):
            raise ValueError("Language must be a locale code such as fr or fr_CA.")
        payload["language"] = language
    return payload


def _language_conflict(campaign, email, language) -> Response | None:
    if _family_fields(email)["role"] != "translation":
        return _error("Only a translation has its own language.", code="invalid_setting", http_status=status.HTTP_400_BAD_REQUEST)
    try:
        parent = _family_fields(MauticClient().get_email(campaign.mautic_email_id))
    except (TemporaryMauticError, PermanentMauticError) as exc:
        return _provider_error(exc)
    others = [row["language"] for row in parent["translations"] if row["id"] != str(email.get("id"))]
    if language[:2] == parent["language"][:2] or language in others:
        return _error(f"Another version of this broadcast already uses {language}.", code="broadcast_language_taken")
    return None


class NewsletterAdminCampaignVersionView(APIView):
    """Read, edit (draft only) or remove (draft only) one variant or translation."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, uuid, email_id):
        campaign = _get_campaign_or_404(uuid)
        email, error = _child_of(campaign, email_id)
        if error is not None:
            return error
        version = _template_with_design(_version(email))
        return Response({**version, "editable": is_family_editable(campaign),
                         "broadcast": {"uuid": str(campaign.uuid), "name": campaign.name}})

    def patch(self, request, uuid, email_id):
        campaign = _get_campaign_or_404(uuid)
        if not is_family_editable(campaign):
            return _locked()
        email, error = _child_of(campaign, email_id)
        if error is not None:
            return error
        plain, visual = _split_visual_fields(request.data)
        try:
            prepared = _prepare_visual_design(visual, plain)
            payload = _parse_version_payload(plain) if plain or prepared is None else {}
            base_fingerprint = _parse_base_fingerprint(visual, required=prepared is not None)
        except ValueError as exc:
            return _error(str(exc), code="invalid_setting", http_status=status.HTTP_400_BAD_REQUEST)
        if prepared is not None:
            payload["customHtml"] = prepared.html
        if not payload:
            return _error("Nothing to save.", code="invalid_setting", http_status=status.HTTP_400_BAD_REQUEST)
        if "language" in payload:
            conflict = _language_conflict(campaign, email, payload["language"])
            if conflict is not None:
                return conflict
        if base_fingerprint is not None and html_fingerprint(str(email.get("customHtml") or "")) != base_fingerprint:
            return _error("This version was changed since you opened it. Your changes were not saved; reopen it.", code="version_changed")

        try:
            with template_save_lock(email_id):
                _, error_response = run_interactive_mutation(
                    request,
                    action=EMAIL_UPDATE,
                    resource="newsletter_campaign_version",
                    resource_id=str(email_id),
                    mutate=lambda client: client.update_email(email_id, {**payload, "emailType": "list"}),
                    client_factory=MauticClient,
                    audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
                )
                if error_response is not None:
                    return error_response
                stored = MauticClient().get_email(email_id)
                if prepared is not None:
                    try:
                        save_template_design(email_id, prepared, str(stored.get("customHtml") or ""), user=request.user)
                    except DatabaseError:
                        logger.exception("Could not store the visual design of broadcast version id=%s", email_id)
                        return _error("The version was saved in Mautic, but its visual design could not be stored. Its HTML is safe.",
                                      code="design_not_saved", http_status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except TemplateSaveInProgress:
            return _error("This version is being saved by another request. Try again in a moment.", code="version_save_in_progress")
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        return Response({**_template_with_design(_version(stored)), "editable": True,
                         "broadcast": {"uuid": str(campaign.uuid), "name": campaign.name}})

    def delete(self, request, uuid, email_id):
        campaign = _get_campaign_or_404(uuid)
        if not is_family_editable(campaign):
            return _locked()
        _, error = _child_of(campaign, email_id)
        if error is not None:
            return error
        try:
            _, error_response = run_interactive_mutation(
                request,
                action=EMAIL_DELETE,
                resource="newsletter_campaign_version",
                resource_id=str(email_id),
                mutate=lambda client: client.delete_email(email_id),
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        if error_response is not None:
            return error_response
        delete_template_design(email_id)
        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminCampaignAbTestView(APIView):
    """Change a variant's share ({"emailId", "weight"}) or the test's criteria ({"winnerCriteria"}); draft only."""

    permission_classes = [HasMarketingHubAccess]

    def patch(self, request, uuid):
        campaign = _get_campaign_or_404(uuid)
        if not is_family_editable(campaign):
            return _locked()
        data = request.data if hasattr(request.data, "keys") else {}
        if not data or set(data.keys()) - {"emailId", "weight", "winnerCriteria"} or ("weight" in data) != ("emailId" in data):
            return _error("Send a variant's emailId with its weight, and/or winnerCriteria.", code="invalid_payload",
                          http_status=status.HTTP_400_BAD_REQUEST)
        try:
            weight = _parse_weight(data["weight"]) if "weight" in data else None
            criteria = _parse_criteria(data["winnerCriteria"]) if "winnerCriteria" in data else None
        except ValueError as exc:
            return _error(str(exc), code="invalid_setting", http_status=status.HTTP_400_BAD_REQUEST)
        target = str(data.get("emailId") or campaign.mautic_email_id or "")
        if "emailId" in data:
            _, error = _child_of(campaign, target)
            if error is not None:
                return error
        try:
            _, error_response = run_interactive_mutation(
                request,
                action=EMAIL_VARIANT_UPDATE,
                resource="newsletter_campaign",
                resource_id=str(campaign.uuid),
                mutate=lambda client: client.update_broadcast_variant(target, weight=weight, winner_criteria=criteria),
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        if error_response is not None:
            return error_response
        return NewsletterAdminCampaignFamilyView().get(request, uuid)
