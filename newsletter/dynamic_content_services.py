"""Marketing Hub Dynamic Content (Mautic page blocks that change per visitor).

An item is shown either by rules (its slot name, filled for visitors whose
contact fields match its rules) or by a campaign ("Request dynamic content"
picks the default, "Push dynamic content" replaces it). Mautic owns the items;
ECP sends changes to the bridge as the admin's own Mautic user, which checks
them again (EcpBridgeDynamicContentApiController) and keeps the HTML content
the native API would strip. The checks here give clear, per-field errors early.

Rules are limited to what Mautic can check for a visitor: contact fields, with
the operators its matcher knows (any other one breaks the page for visitors).
"""

from __future__ import annotations

import json
import re
from typing import Any

from . import marketing_cache
from .mautic import MauticClient
from .mautic_category_services import category_choice
from .mautic_publish_window import PublishWindowError, parse_window
from .page_html_policy import find_active_content

# Keep in step with EcpBridgeDynamicContentApiController.
TYPES = ("html", "text")
OPERATORS = ("=", "!=", "gt", "gte", "lt", "lte", "empty", "!empty", "like", "!like", "in", "!in",
             "regexp", "!regexp", "startsWith", "endsWith", "contains")
LIST_OPERATORS = ("in", "!in")
EMPTY_OPERATORS = ("empty", "!empty")
SLOT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$")
NAME_MAX = 191
DESCRIPTION_MAX = 5000
CONTENT_MAX = 200000
MAX_RULES = 20
UTM_KEYS = ("utmSource", "utmMedium", "utmCampaign", "utmContent")
COPY_PREFIX = "Copy of "
_LANGUAGE_RE = re.compile(r"^[a-z]{2,3}([_-][A-Za-z]{2,4})?$")


class DynamicContentError(ValueError):
    def __init__(self, message: str, *, field: str = "", code: str = "invalid_dynamic_content", status_code: int = 400):
        super().__init__(message)
        self.field = field
        self.code = code
        self.status_code = status_code


def _flag(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


# Rules --------------------------------------------------------------------------


def rule_metadata(client: MauticClient | None = None) -> dict[str, Any]:
    """The segment filter metadata narrowed to what a Dynamic Content rule can
    use: contact fields (not behaviours, segments or tags) and the operators
    Mautic can check for a visitor."""
    client = client or MauticClient()
    metadata = marketing_cache.segment_filter_metadata(client, "")
    listed = marketing_cache.fields(client, "contact", limit=500)
    rows = listed.get("fields") if isinstance(listed, dict) else None
    rows = rows.values() if isinstance(rows, dict) else rows or []
    contact_fields = {str(row.get("alias") or "") for row in rows if isinstance(row, dict)}
    fields = []
    for field in metadata.get("fields") or []:
        if not isinstance(field, dict) or field.get("object") != "lead" or field.get("alias") not in contact_fields:
            continue
        operators = [op for op in field.get("operators") or [] if isinstance(op, dict) and op.get("value") in OPERATORS]
        if operators:
            fields.append({**field, "operators": operators})
    return {
        "objects": metadata.get("objects") or [],
        "operators": [op for op in metadata.get("operators") or [] if not isinstance(op, dict) or op.get("value") in OPERATORS],
        "glue": metadata.get("glue") or [],
        "fields": fields,
        "total": len(fields),
        "source": metadata.get("source"),
    }


def _rules(rows) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise DynamicContentError("Send the rules as a list.", field="filters")
    if len(rows) > MAX_RULES:
        raise DynamicContentError(f"Use at most {MAX_RULES} rules.", field="filters")
    rules = []
    for position, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            raise DynamicContentError(f"Rule {position} is not valid.", field="filters")
        field = str(row.get("field") or "").strip()
        operator = str(row.get("operator") or "")
        if not field:
            raise DynamicContentError(f"Rule {position}: choose a contact field.", field="filters")
        if operator not in OPERATORS:
            raise DynamicContentError(f"Rule {position}: this condition cannot be checked for visitors.", field="filters")
        value = row.get("filter", (row.get("properties") or {}).get("filter") if isinstance(row.get("properties"), dict) else None)
        if operator in EMPTY_OPERATORS:
            value = None
        elif operator in LIST_OPERATORS:
            value = [str(item).strip() for item in (value if isinstance(value, list) else [value]) if str(item or "").strip()]
            if not value:
                raise DynamicContentError(f"Rule {position}: choose at least one value.", field="filters")
        else:
            value = str(value if value is not None and not isinstance(value, (list, dict)) else "").strip()
            if not value:
                raise DynamicContentError(f"Rule {position}: enter a value.", field="filters")
            if operator in ("regexp", "!regexp"):
                try:
                    re.compile(value)
                except re.error:
                    raise DynamicContentError(f"Rule {position}: the pattern is not valid.", field="filters") from None
        rules.append({"glue": "and" if position == 1 else ("or" if row.get("glue") == "or" else "and"),
                      "field": field, "operator": operator, "filter": value})
    return rules


# Payload -------------------------------------------------------------------------


def bridge_form(data, *, current: dict[str, Any] | None = None, client=None) -> list[tuple[str, str]]:
    """The checked settings as form pairs for the bridge. ``current`` is the
    stored item on an update, where only the keys sent change."""
    if not hasattr(data, "get"):
        raise DynamicContentError("Send the Dynamic Content item as an object.", code="invalid_payload")
    creating = current is None
    pairs: list[tuple[str, str]] = []

    if creating or "name" in data:
        name = str(data.get("name") or "").strip()
        if not name:
            raise DynamicContentError("Give the Dynamic Content item a name.", field="name")
        if len(name) > NAME_MAX:
            raise DynamicContentError(f"The name can be at most {NAME_MAX} characters.", field="name")
        pairs.append(("name", name))
    if "description" in data:
        description = str(data.get("description") or "").strip()
        if len(description) > DESCRIPTION_MAX:
            raise DynamicContentError(f"The description can be at most {DESCRIPTION_MAX} characters.", field="description")
        pairs.append(("description", description))
    if creating or "type" in data:
        content_type = str(data.get("type") or "html")
        if content_type not in TYPES:
            raise DynamicContentError("Choose HTML or plain text.", field="type")
        pairs.append(("type", content_type))

    campaign_based = bool((current or {}).get("isCampaignBased"))
    if creating or "isCampaignBased" in data:
        campaign_based = _flag(data.get("isCampaignBased"))
        pairs.append(("isCampaignBased", "1" if campaign_based else "0"))
    slot = str((current or {}).get("slotName") or "")
    if "slotName" in data:
        slot = str(data.get("slotName") or "").strip()
        if slot and not SLOT_PATTERN.match(slot):
            raise DynamicContentError('Use letters, numbers, "-" and "_" only (up to 100), such as homepage-banner.', field="slotName")
        pairs.append(("slotName", slot))
    if not campaign_based and not slot:
        raise DynamicContentError("Content shown by rules needs a slot name: the place on the page it fills.", field="slotName")

    rule_count = len((current or {}).get("filters") or [])
    if "filters" in data:
        rules = _rules(data.get("filters"))
        rule_count = len(rules)
        pairs.append(("filters", json.dumps(rules)))
    if not campaign_based and rule_count == 0:
        raise DynamicContentError("Content shown by rules needs at least one rule.", field="filters")

    if "content" in data:
        content = str(data.get("content") or "")
        if len(content) > CONTENT_MAX:
            raise DynamicContentError("The content is too long.", field="content")
        active = find_active_content(content)
        if active:
            raise DynamicContentError(f"The content is shown on public pages, so it cannot contain {'; '.join(active)}.", field="content")
        if "{dwc=" in content:
            raise DynamicContentError("Dynamic Content cannot contain another {dwc=…} token.", field="content")
        pairs.append(("content", content))

    if "category" in data:
        raw = data.get("category")
        raw = raw.get("id") if isinstance(raw, dict) else raw
        try:
            category = category_choice(raw, "dynamicContent", client=client)
        except ValueError as exc:
            raise DynamicContentError(str(exc), field="category") from None
        pairs.append(("category", str(category or "")))
    if "isPublished" in data:
        pairs.append(("isPublished", "1" if _flag(data.get("isPublished")) else "0"))
    elif creating:
        pairs.append(("isPublished", "0"))
    try:
        window = parse_window(data, current)
    except PublishWindowError as exc:
        raise DynamicContentError(str(exc), field=exc.field) from None
    pairs.extend((key, value or "") for key, value in window.items())
    if "language" in data:
        language = str(data.get("language") or "").strip()
        if language and not _LANGUAGE_RE.match(language):
            raise DynamicContentError("Use a language code such as en or fr_FR.", field="language")
        pairs.append(("language", language or "en"))
    if isinstance(data.get("utmTags"), dict):
        for key in UTM_KEYS:
            if key in data["utmTags"]:
                value = str(data["utmTags"][key] or "").strip()
                if len(value) > NAME_MAX:
                    raise DynamicContentError(f"UTM values can be at most {NAME_MAX} characters.", field=key)
                pairs.append((f"utmTags[{key}]", value))

    if not creating and not pairs:
        raise DynamicContentError("Nothing to change.", code="no_changes")
    return pairs


def duplicate_payload(item: dict[str, Any]) -> dict[str, Any]:
    """Create settings for an unpublished copy of a stored item."""
    return {
        "name": f"{COPY_PREFIX}{item['name']}"[:NAME_MAX],
        "description": item.get("description") or "",
        "type": item.get("type") or "html",
        "isCampaignBased": bool(item.get("isCampaignBased")),
        "slotName": item.get("slotName") or "",
        "filters": item.get("filters") or [],
        "content": item.get("content") or "",
        "category": (item.get("category") or {}).get("id"),
        "language": item.get("language") or "en",
        "utmTags": item.get("utmTags") or {},
        "isPublished": False,
    }


def place_codes(item: dict[str, Any], base: str | None) -> dict[str, Any]:
    """How to place a rule-based item: the slot element (landing pages, and
    websites that load Mautic's tracking script), the page token, and that
    tracking script. Campaign-based items are placed by their campaign step."""
    slot = str(item.get("slotName") or "")
    if item.get("isCampaignBased") or not slot:
        return {"slot": None, "token": None, "tracking": _tracking_script(base)}
    return {
        "slot": f'<div data-slot="dwc" data-param-slot-name="{slot}">Default content for visitors who match no rule</div>',
        "token": f"{{dwc={slot}}}",
        "tracking": _tracking_script(base),
    }


def _tracking_script(base: str | None) -> str | None:
    if not base:
        return None
    return ("<script>\n(function(w,d,t,u,n,a,m){w['MauticTrackingObject']=n;\n"
            "w[n]=w[n]||function(){(w[n].q=w[n].q||[]).push(arguments)},a=d.createElement(t),\n"
            "m=d.getElementsByTagName(t)[0];a.async=1;a.src=u;m.parentNode.insertBefore(a,m)\n"
            f"}})(window,document,'script','{base}/mtc.js','mt');\nmt('send', 'pageview');\n</script>")
