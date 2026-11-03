"""Email delivery options Mautic keeps on the email itself: Reply-To, BCC, the
UTM tags it adds to tracked links, file attachments (assets) and, for segment
emails (broadcasts) only, excluded segments: members of those are never sent
it. Mautic applies exclusions only when it picks a segment email's recipients,
so templates (sent by campaigns) do not take them.

Templates save them with the template. A broadcast's are set on its Mautic email
(and its A/B and translation versions) once the broadcast has one: ECP stores
none of them, so Mautic stays their only source.

Native facts (Mautic 7.1.3): ``utmTags`` is an object with utmSource,
utmMedium, utmCampaign and utmContent (read back as [] when none is set);
``assetAttachments`` takes asset IDs and reads back as asset objects; a form
PATCH leaves an omitted field unchanged, so clearing attachments sends an empty
value explicitly.
"""

from __future__ import annotations

import re
from typing import Any

from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email

FIELDS = ("replyToAddress", "utmTags", "assetAttachments", "bccAddress", "excludedLists")
UTM_KEYS = ("utmSource", "utmMedium", "utmCampaign", "utmContent")
UTM_LABELS = {"utmSource": "UTM source", "utmMedium": "UTM medium", "utmCampaign": "UTM campaign", "utmContent": "UTM content"}
UTM_MAX_LENGTH = 100
# Characters that would break or inject into the tracked link's query string are refused.
UTM_VALUE_RE = re.compile(r"^[A-Za-z0-9 ._~+\-|:/{}]*$")
MAX_ATTACHMENTS = 10
MAX_EXCLUDED_SEGMENTS = 20
ADDRESS_MAX_LENGTH = 191


class DeliveryOptionsError(ValueError):
    def __init__(self, message: str, *, field: str):
        super().__init__(message)
        self.code = "invalid_delivery_options"
        self.field = field


def _collection(value) -> list:
    if isinstance(value, dict):
        return list(value.values())
    return value if isinstance(value, list) else []


def normalize_delivery_options(email: dict[str, Any]) -> dict[str, Any]:
    utm = email.get("utmTags") if isinstance(email.get("utmTags"), dict) else {}
    attachments = []
    for row in _collection(email.get("assetAttachments")):
        asset_id = row.get("id") if isinstance(row, dict) else row
        if str(asset_id or "").isdigit():
            title = str(row.get("title") or "") if isinstance(row, dict) else ""
            attachments.append({"id": str(asset_id), "title": title or f"Asset {asset_id}"})
    excluded = []
    for row in _collection(email.get("excludedLists")):
        segment_id = row.get("id") if isinstance(row, dict) else row
        if str(segment_id or "").isdigit():
            name = str(row.get("name") or "") if isinstance(row, dict) else ""
            excluded.append({"id": str(segment_id), "name": name or f"Segment {segment_id}"})
    return {
        "replyToAddress": str(email.get("replyToAddress") or ""),
        "bccAddress": str(email.get("bccAddress") or ""),
        "utmTags": {key: str(utm.get(key) or "") for key in UTM_KEYS},
        "assetAttachments": attachments,
        "excludedLists": excluded,
    }


def with_excluded_segments(client, email: dict[str, Any]) -> dict[str, Any]:
    """The email with the segments it excludes, which Mautic's email API never
    returns. Raises the client's errors when they cannot be read."""
    if not isinstance(email, dict) or not email.get("id"):
        return email
    return {**email, "excludedLists": client.get_email_excluded_segments(email["id"])}


def _address(data, key: str, label: str) -> str:
    value = data.get(key)
    if value is not None and not isinstance(value, str):
        raise DeliveryOptionsError(f"{label} must be an email address.", field=key)
    value = (value or "").strip()
    if value:
        if len(value) > ADDRESS_MAX_LENGTH:
            raise DeliveryOptionsError(f"{label} must be {ADDRESS_MAX_LENGTH} characters or fewer.", field=key)
        try:
            validate_email(value)
        except DjangoValidationError:
            raise DeliveryOptionsError(f"{label} must be one valid email address.", field=key) from None
    return value


def parse_delivery_options(data, *, known_assets: set[str] | None = None, exclusions: dict[str, Any] | None = None) -> dict[str, Any]:
    """The native settings for the delivery options present in ``data``.

    ``exclusions`` allows excluded segments (broadcasts only): its
    ``published`` maps each segment ID to whether it is published (None when
    unknown; Mautic accepts published segments only) and ``targets`` holds the
    segments the email is sent to, which it cannot also exclude."""
    native: dict[str, Any] = {}
    if "replyToAddress" in data:
        native["replyToAddress"] = _address(data, "replyToAddress", "Reply-To")
    if "bccAddress" in data:
        native["bccAddress"] = _address(data, "bccAddress", "BCC")
    if "excludedLists" in data:
        if exclusions is None:
            raise DeliveryOptionsError("Excluded segments apply to broadcasts only.", field="excludedLists")
        value = data.get("excludedLists")
        if not isinstance(value, list) or len(value) > MAX_EXCLUDED_SEGMENTS:
            raise DeliveryOptionsError(f"Exclude up to {MAX_EXCLUDED_SEGMENTS} segments.", field="excludedLists")
        published, targets = exclusions.get("published"), set(exclusions.get("targets") or ())
        ids: list[str] = []
        for item in value:
            segment_id = str(item.get("id") if isinstance(item, dict) else item).strip()
            if isinstance(item, bool) or not segment_id.isdigit() or segment_id == "0":
                raise DeliveryOptionsError("Excluded segments are chosen from Mautic's segments.", field="excludedLists")
            if segment_id in targets:
                raise DeliveryOptionsError("A broadcast can't exclude a segment it is sent to.", field="excludedLists")
            if published is not None and published.get(segment_id) is not True:
                raise DeliveryOptionsError(f"Segment {segment_id} is unpublished or no longer exists; Mautic only excludes published segments.",
                                           field="excludedLists")
            if segment_id not in ids:
                ids.append(segment_id)
        native["excludedLists"] = ids
    if "utmTags" in data:
        tags = data.get("utmTags")
        if not isinstance(tags, dict) or set(tags) - set(UTM_KEYS):
            raise DeliveryOptionsError("UTM tags are utmSource, utmMedium, utmCampaign and utmContent.", field="utmTags")
        parsed = {}
        for key in UTM_KEYS:
            value = tags.get(key, "")
            if value is not None and not isinstance(value, str):
                raise DeliveryOptionsError(f"{UTM_LABELS[key]} must be text.", field="utmTags")
            value = (value or "").strip()
            if len(value) > UTM_MAX_LENGTH or not UTM_VALUE_RE.match(value):
                raise DeliveryOptionsError(
                    f"{UTM_LABELS[key]} may use letters, digits, spaces and . _ - + ~ | : / {{ }} (up to {UTM_MAX_LENGTH}).",
                    field="utmTags",
                )
            parsed[key] = value
        native["utmTags"] = parsed
    if "assetAttachments" in data:
        value = data.get("assetAttachments")
        if not isinstance(value, list) or len(value) > MAX_ATTACHMENTS:
            raise DeliveryOptionsError(f"Attach up to {MAX_ATTACHMENTS} assets.", field="assetAttachments")
        ids: list[str] = []
        for item in value:
            asset_id = str(item.get("id") if isinstance(item, dict) else item).strip()
            if isinstance(item, bool) or not asset_id.isdigit() or asset_id == "0":
                raise DeliveryOptionsError("Attachments are chosen from Mautic's assets.", field="assetAttachments")
            if known_assets is not None and asset_id not in known_assets:
                raise DeliveryOptionsError(f"Asset {asset_id} does not exist in Mautic.", field="assetAttachments")
            if asset_id not in ids:
                ids.append(asset_id)
        native["assetAttachments"] = ids
    return native


def options_match(email: dict[str, Any], native: dict[str, Any]) -> list[str]:
    """Delivery options in ``native`` that Mautic's saved email does not show."""
    stored = normalize_delivery_options(email)
    problems = []
    if "replyToAddress" in native and stored["replyToAddress"] != native["replyToAddress"]:
        problems.append("Reply-To")
    if "bccAddress" in native and stored["bccAddress"] != native["bccAddress"]:
        problems.append("BCC")
    if "excludedLists" in native and sorted(s["id"] for s in stored["excludedLists"]) != sorted(native["excludedLists"]):
        problems.append("excluded segments")
    if "utmTags" in native and stored["utmTags"] != {key: native["utmTags"].get(key, "") for key in UTM_KEYS}:
        problems.append("UTM tags")
    if "assetAttachments" in native and sorted(a["id"] for a in stored["assetAttachments"]) != sorted(native["assetAttachments"]):
        problems.append("attachments")
    return problems
