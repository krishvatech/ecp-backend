"""Per-link click counts of an email, and a broadcast's delivery options
(Reply-To, UTM tags, attachments) kept on its Mautic email.

Clicks are read the way Mautic's own email page lists them ("Click counts"):
the email's tracked links (``channel_url_trackables``, channel ``email``) with
their total and unique hits, joined to the links' addresses
(``page_redirects``). A template or broadcast family (A/B variants and
translations) is summed per address, with each version's own counts.
"""

from __future__ import annotations

import logging
from typing import Any

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .admin_views import _get_campaign_or_404
from .broadcast_family_views import _provider_error, is_family_editable
from .email_delivery_options import (
    FIELDS as DELIVERY_FIELDS,
    DeliveryOptionsError,
    normalize_delivery_options,
    options_match,
    parse_delivery_options,
    with_excluded_segments,
)
from .marketing_permissions import HasMarketingHubAccess
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.operations import EMAIL_UPDATE
from .mautic_identity_execution import run_interactive_mutation

logger = logging.getLogger(__name__)

STATS_PAGE_SIZE = 500
MAX_LINK_PAGES = 10


def _rows(value) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = list(value.values())
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def family_email_ids(email: dict[str, Any]) -> list[str]:
    """The email and its A/B variants and translations, main first."""
    ids = [str(email.get("id"))]
    for key in ("variantChildren", "translationChildren"):
        for row in _rows(email.get(key)):
            if str(row.get("id") or "").isdigit() and str(row["id"]) not in ids:
                ids.append(str(row["id"]))
    return ids


def _all_rows(client: MauticClient, table: str, filters) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for page in range(MAX_LINK_PAGES):
        batch, total = client.list_stat_rows(table, filters, start=page * STATS_PAGE_SIZE, limit=STATS_PAGE_SIZE)
        rows.extend(batch)
        if len(rows) >= total or not batch:
            return rows
    raise TemporaryMauticError(f"Mautic {table} has more rows than ECP reads at once")


def email_link_clicks(client: MauticClient, email_ids: list[str], names: dict[str, str] | None = None) -> dict[str, Any]:
    trackables = _all_rows(client, "channel_url_trackables", [("channel", "eq", "email"), ("channel_id", "in", ",".join(email_ids))])
    redirect_ids = sorted({str(row.get("redirect_id")) for row in trackables if str(row.get("redirect_id") or "").isdigit()})
    urls: dict[str, str] = {}
    if redirect_ids:
        for row in _all_rows(client, "page_redirects", [("id", "in", ",".join(redirect_ids))]):
            urls[str(row.get("id"))] = str(row.get("url") or "")

    links: dict[str, dict[str, Any]] = {}
    for row in trackables:
        url = urls.get(str(row.get("redirect_id")), "")
        if not url:
            continue
        link = links.setdefault(url, {"url": url, "clicks": 0, "uniqueClicks": 0, "byEmail": {}})
        hits, unique = int(row.get("hits") or 0), int(row.get("unique_hits") or 0)
        link["clicks"] += hits
        link["uniqueClicks"] += unique
        email_id = str(row.get("channel_id"))
        version = link["byEmail"].setdefault(email_id, {"emailId": email_id, "name": (names or {}).get(email_id, ""), "clicks": 0, "uniqueClicks": 0})
        version["clicks"] += hits
        version["uniqueClicks"] += unique
    rows = sorted(links.values(), key=lambda link: (-link["clicks"], link["url"]))
    for link in rows:
        link["byEmail"] = list(link["byEmail"].values())
    return {
        "emailIds": email_ids,
        "totalClicks": sum(link["clicks"] for link in rows),
        "links": rows,
    }


def _clicks_response(email: dict[str, Any]) -> Response:
    names = {str(email.get("id")): str(email.get("name") or "")}
    for key in ("variantChildren", "translationChildren"):
        for row in _rows(email.get(key)):
            names[str(row.get("id"))] = str(row.get("name") or "")
    try:
        data = email_link_clicks(MauticClient(), family_email_ids(email), names)
    except (TemporaryMauticError, PermanentMauticError):
        logger.warning("Link clicks of email %s could not be read", email.get("id"), exc_info=True)
        return Response({"detail": "Mautic could not return the link clicks. Try again.", "code": "mautic_error"},
                        status=status.HTTP_502_BAD_GATEWAY)
    return Response(data)


class NewsletterAdminTemplateLinkClicksView(APIView):
    """Clicks per tracked link of a template and its A/B variants and translations."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, template_id):
        if not str(template_id).isdigit():
            return Response({"detail": "Template links use a numeric Mautic ID.", "code": "invalid_template_id"},
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            email = MauticClient().get_email(template_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        return _clicks_response(email)


class NewsletterAdminCampaignLinkClicksView(APIView):
    """Clicks per tracked link of a broadcast and its versions."""

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, uuid):
        campaign = _get_campaign_or_404(uuid)
        email_id = str(campaign.mautic_email_id or "").strip()
        if not email_id:
            return Response({"emailIds": [], "totalClicks": 0, "links": []})
        try:
            email = MauticClient().get_email(email_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        return _clicks_response(email)


def _delivery_body(campaign, email: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "available": email is not None,
        "editable": email is not None and is_family_editable(campaign),
        **(normalize_delivery_options(email) if email is not None else {}),
    }


class NewsletterAdminCampaignDeliveryOptionsView(APIView):
    """GET or PATCH a broadcast's Reply-To, BCC, UTM tags, attachments and
    excluded segments.

    They live on the broadcast's Mautic email only, so they are available once
    the broadcast has been saved to Mautic, and change only while it is a draft.
    Its A/B variants and translations always share them.
    """

    permission_classes = [HasMarketingHubAccess]

    def get(self, request, uuid):
        campaign = _get_campaign_or_404(uuid)
        email_id = str(campaign.mautic_email_id or "").strip()
        if not email_id:
            return Response(_delivery_body(campaign, None))
        try:
            client = MauticClient()
            return Response(_delivery_body(campaign, with_excluded_segments(client, client.get_email(email_id))))
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)

    def patch(self, request, uuid):
        campaign = _get_campaign_or_404(uuid)
        email_id = str(campaign.mautic_email_id or "").strip()
        if not email_id:
            return Response({"detail": "Save the broadcast first: delivery options are set on its Mautic email.",
                             "code": "broadcast_not_synced"}, status=status.HTTP_409_CONFLICT)
        if not is_family_editable(campaign):
            return Response({"detail": "Delivery options can only be changed while the broadcast is a draft.",
                             "code": "broadcast_not_draft"}, status=status.HTTP_409_CONFLICT)
        data = request.data if hasattr(request.data, "get") else {}
        unknown = sorted(set(data.keys()) - set(DELIVERY_FIELDS))
        if unknown or not data:
            return Response({"detail": "Send replyToAddress, bccAddress, utmTags, assetAttachments and/or excludedLists.",
                             "code": "invalid_delivery_options"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            email = MauticClient().get_email(email_id)
            native = parse_delivery_options(
                data,
                known_assets=_known_assets() if "assetAttachments" in data else None,
                exclusions={"published": _segment_publish_states() if "excludedLists" in data else None,
                            "targets": [str(row.get("id")) for row in _rows(email.get("lists")) if row.get("id") is not None]},
            )
        except DeliveryOptionsError as exc:
            return Response({"detail": str(exc), "code": exc.code, "errors": {exc.field: str(exc)}}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        family = family_email_ids(email)
        for version_id in family:
            try:
                _, error_response = run_interactive_mutation(
                    request,
                    action=EMAIL_UPDATE,
                    resource="newsletter_campaign_delivery_options",
                    resource_id=version_id,
                    mutate=lambda client, version_id=version_id: client.update_email(version_id, {**native, "emailType": "list"}),
                    client_factory=MauticClient,
                    audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
                    detail="changed: " + ", ".join(sorted(native)),
                )
            except (TemporaryMauticError, PermanentMauticError) as exc:
                return _provider_error(exc)
            if error_response is not None:
                return error_response
        try:
            client = MauticClient()
            stored = with_excluded_segments(client, client.get_email(email_id))
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error(exc)
        problems = options_match(stored, native)
        if problems:
            return Response({"detail": "Mautic's saved email does not show the new " + ", ".join(problems) + ". Reload and check.",
                             "code": "delivery_options_mismatch", **_delivery_body(campaign, stored)},
                            status=status.HTTP_409_CONFLICT)
        return Response(_delivery_body(campaign, stored))


def _segment_publish_states() -> dict[str, bool] | None:
    """Every Mautic segment ID with whether it is published, or None when the
    list cannot be read whole."""
    data = MauticClient().list_segments(limit=500)
    rows = data.get("lists")
    rows = list(rows.values()) if isinstance(rows, dict) else rows if isinstance(rows, list) else []
    if int(data.get("total") or 0) > len(rows):
        return None
    return {str(row.get("id")): row.get("isPublished") in (True, 1, "1") for row in rows if isinstance(row, dict)}


def _known_assets() -> set[str] | None:
    """Every Mautic asset ID, or None when the list cannot be read whole."""
    data = MauticClient().list_assets(limit=100)
    rows = data.get("assets") or []
    if int(data.get("total") or 0) > len(rows):
        return None
    return {str(row.get("id")) for row in rows if isinstance(row, dict)}

