"""Marketing Hub Focus Items (Mautic's website pop-ups and bars).

Mautic owns the Focus Items and renders them on any website that loads their
script, and on its landing pages through ``{focus=ID}``. ECP sends the settings
to the bridge as the admin's own Mautic user; the bridge checks them again
(EcpBridgeFocusApiController) before Mautic's API saves them, so the checks
here exist to give clear, per-field errors early.

A Focus Item runs on public websites, so only the builder ("basic") and the
rich-text editor are offered: raw HTML mode is refused, editor HTML may not run
code, custom CSS may not leave its <style> element and links must be http(s).
"""

from __future__ import annotations

import copy
import re
from typing import Any
from urllib.parse import urlsplit

from .mautic_category_services import category_choice
from .mautic_publish_window import PublishWindowError, parse_window
from .page_html_policy import find_active_content

# Keep in step with EcpBridgeFocusApiController.
TYPES = ("form", "notice", "link")
STYLES = ("bar", "modal", "notification", "page")
HTML_MODES = ("basic", "editor")
PLACEMENTS = {
    "bar": ("top", "bottom"),
    "modal": ("top", "middle", "bottom"),
    "notification": ("top_left", "top_right", "bottom_left", "bottom_right"),
    "page": (),
}
BAR_SIZES = ("large", "regular")
WHEN = ("immediately", "scroll_slight", "scroll_middle", "scroll_bottom", "leave")
FREQUENCY = ("everypage", "once", "q2min", "q15min", "hourly", "daily")
FONTS = (
    "Arial, Helvetica, sans-serif",
    "'Arial Black', Gadget, sans-serif",
    "'Arial Narrow', sans-serif",
    "Century Gothic, sans-serif",
    "Copperplate / Copperplate Gothic Light, sans-serif",
    "'Courier New', Courier, monospace",
    "Georgia, Serif",
    "Impact, Charcoal, sans-serif",
    "'Lucida Console', Monaco, monospace",
    "'Lucida Sans Unicode', 'Lucida Grande', sans-serif",
    "'Palatino Linotype', 'Book Antiqua', Palatino, serif",
    "Tahoma, Geneva, sans-serif",
    "'Times New Roman', Times, serif",
    "'Trebuchet MS', Helvetica, sans-serif",
    "Verdana, Geneva, sans-serif",
)
# Mautic's script reads these as on unless the stored value is empty, and its
# yes/no field stores "No" as 0, which is not empty: off must be stored as null,
# so it is sent as "".
FLAGS = ("animate", "link_activation", "stop_after_conversion", "stop_after_close")
BAR_FLAGS = ("allow_hide", "push_page", "sticky")
COLORS = ("primary", "text", "button", "button_text")
TEXTS = ("headline", "tagline", "link_text")
UTM_KEYS = ("utmSource", "utmMedium", "utmCampaign", "utmContent")
DEFAULT_PROPERTIES: dict[str, Any] = {
    "bar": {"allow_hide": 1, "push_page": 1, "sticky": 1, "size": "large", "placement": "top"},
    "modal": {"placement": "middle"},
    "notification": {"placement": "bottom_right"},
    "page": {},
    "animate": 1,
    "link_activation": 1,
    "colors": {"primary": "4e5d9d", "text": "ffffff", "button": "fdb933", "button_text": "000000"},
    "content": {"headline": "", "tagline": "", "link_text": "", "link_url": "", "link_new_window": 1,
                "font": FONTS[0], "css": ""},
    "when": "immediately",
    "timeout": "",
    "frequency": "everypage",
    "stop_after_conversion": 1,
    "stop_after_close": 0,
}
NAME_MAX = 191
TEXT_MAX = 255
DESCRIPTION_MAX = 5000
URL_MAX = 2048
CSS_MAX = 20000
EDITOR_MAX = 200000
COPY_PREFIX = "Copy of "
_HEX = re.compile(r"^[0-9a-fA-F]{6}$")


class FocusError(ValueError):
    def __init__(self, message: str, *, field: str = "", code: str = "invalid_focus", status_code: int = 400):
        super().__init__(message)
        self.field = field
        self.code = code
        self.status_code = status_code


# Reading ---------------------------------------------------------------------


def _flag(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _merged(defaults: dict[str, Any], stored) -> dict[str, Any]:
    merged = dict(defaults)
    for key, value in (stored or {}).items() if isinstance(stored, dict) else ():
        if isinstance(defaults.get(key), dict) and isinstance(value, dict):
            merged[key] = _merged(defaults[key], value)
        elif value is not None and key in defaults:
            merged[key] = value
    return merged


def _script_on(value) -> bool:
    """Twig's "is not empty": only null, "", false and [] are empty, so 0 is on.
    (Identity checks: in Python 0 == False.)"""
    return not (value is None or value is False or (isinstance(value, (str, list)) and len(value) == 0))


def _defaults(style: str | None) -> dict[str, Any]:
    """Mautic's defaults for a style. As in Mautic's editor, only a bar has white
    text: the other styles are white boxes."""
    defaults = copy.deepcopy(DEFAULT_PROPERTIES)
    if style != "bar":
        defaults["colors"]["text"] = "000000"
    return defaults


def _properties(stored) -> dict[str, Any]:
    """Stored properties over the defaults, with flags as booleans. FLAGS show
    what Mautic's script does: a stored 0 is on, a stored null is off."""
    raw = stored if isinstance(stored, dict) else {}
    properties = _merged(DEFAULT_PROPERTIES, raw)
    for key in FLAGS:
        properties[key] = _script_on(raw[key]) if key in raw else bool(DEFAULT_PROPERTIES[key])
    for key in BAR_FLAGS:
        properties["bar"][key] = _flag(properties["bar"].get(key))
    properties["content"]["link_new_window"] = _flag(properties["content"].get("link_new_window"))
    properties["timeout"] = "" if properties.get("timeout") in (None, "") else str(properties["timeout"])
    for key in TEXTS + ("link_url", "css"):
        properties["content"][key] = str(properties["content"].get(key) or "")
    return properties


def _ref(value, *name_keys: str) -> dict[str, Any] | None:
    if isinstance(value, dict) and value.get("id"):
        name = next((str(value[key]) for key in name_keys if value.get(key)), "")
        return {"id": int(value["id"]), "name": name}
    if str(value or "").isdigit() and int(value) > 0:
        return {"id": int(value), "name": ""}
    return None


def normalize_focus(focus: dict[str, Any], *, stats: dict[str, int] | None = None) -> dict[str, Any]:
    category = focus.get("category") if isinstance(focus.get("category"), dict) else None
    return {
        "id": int(focus["id"]),
        "name": str(focus.get("name") or ""),
        "description": str(focus.get("description") or ""),
        "type": str(focus.get("type") or ""),
        "style": str(focus.get("style") or ""),
        "htmlMode": str(focus.get("htmlMode") or "basic"),
        "editor": str(focus.get("editor") or ""),
        "website": str(focus.get("website") or ""),
        "form": _ref(focus.get("form"), "name", "alias"),
        "category": {"id": int(category["id"]), "title": str(category.get("title") or ""),
                     "color": str(category.get("color") or "")} if category and category.get("id") else None,
        "isPublished": _flag(focus.get("isPublished")),
        "publishUp": focus.get("publishUp") or None,
        "publishDown": focus.get("publishDown") or None,
        "properties": _properties(focus.get("properties")),
        "utmTags": {key: str((focus.get("utmTags") or {}).get(key) or "") for key in UTM_KEYS}
        if isinstance(focus.get("utmTags"), dict) else {key: "" for key in UTM_KEYS},
        "dateAdded": focus.get("dateAdded"),
        "dateModified": focus.get("dateModified"),
        "createdByUser": focus.get("createdByUser") or "",
        "modifiedByUser": focus.get("modifiedByUser") or "",
        "stats": stats,
    }


def focus_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = data.get("focus")
    rows = rows.values() if isinstance(rows, dict) else rows or []
    return [row for row in rows if isinstance(row, dict) and row.get("id") is not None]


def embed_codes(focus_id: int, base: str | None) -> dict[str, Any]:
    """The website script (Mautic's own embed code) and the landing page token."""
    script = (f'<script src="{base}/focus/{int(focus_id)}.js" type="text/javascript" charset="utf-8" async="async"></script>'
              if base else None)
    return {"script": script, "token": f"{{focus={int(focus_id)}}}"}


# Validation ------------------------------------------------------------------


def _http_url(value, field: str, message: str) -> str:
    url = str(value or "").strip()
    if not url:
        return ""
    parts = urlsplit(url)
    if (len(url) > URL_MAX or any(ch.isspace() or ord(ch) < 32 for ch in url) or parts.scheme.lower() not in ("http", "https")
            or not parts.hostname):
        raise FocusError(message, field=field)
    return url


def _choice(value, choices, field: str, message: str) -> str:
    value = str(value or "")
    if value not in choices:
        raise FocusError(message, field=field)
    return value


def _check_properties(data, style: str) -> list[tuple[str, str]]:
    """Form pairs for the properties sent (they are all sent from the editor)."""
    if not isinstance(data, dict):
        raise FocusError("Send the settings as an object.", field="properties")
    pairs: list[tuple[str, str]] = []
    style_data = data.get(style) if isinstance(data.get(style), dict) else {}
    if style == "bar":
        for key in BAR_FLAGS:
            if key in style_data:
                pairs.append((f"properties[bar][{key}]", "1" if _flag(style_data[key]) else "0"))
        if "size" in style_data:
            pairs.append(("properties[bar][size]", _choice(style_data["size"], BAR_SIZES, "size", "Choose a bar size.")))
    if PLACEMENTS[style] and "placement" in style_data:
        pairs.append((f"properties[{style}][placement]",
                       _choice(style_data["placement"], PLACEMENTS[style], "placement", "Choose where the Focus Item appears.")))
    for key in FLAGS:
        if key in data:
            pairs.append((f"properties[{key}]", "1" if _flag(data[key]) else ""))
    colors = data.get("colors") if isinstance(data.get("colors"), dict) else {}
    for key in COLORS:
        if key in colors:
            color = str(colors[key] or "").strip().lstrip("#")
            if not _HEX.match(color):
                raise FocusError("Colours must be 6-digit hex values such as 4E5D9D.", field=f"colors.{key}")
            pairs.append((f"properties[colors][{key}]", color.lower()))
    content = data.get("content") if isinstance(data.get("content"), dict) else {}
    for key in TEXTS:
        if key in content:
            text = str(content[key] or "").strip()
            if len(text) > TEXT_MAX:
                raise FocusError(f"This text can be at most {TEXT_MAX} characters.", field=key)
            pairs.append((f"properties[content][{key}]", text))
    if "link_url" in content:
        pairs.append(("properties[content][link_url]",
                      _http_url(content["link_url"], "link_url", "The button link must start with http:// or https://.")))
    if "link_new_window" in content:
        pairs.append(("properties[content][link_new_window]", "1" if _flag(content["link_new_window"]) else "0"))
    if "font" in content:
        pairs.append(("properties[content][font]", _choice(content["font"], FONTS, "font", "Choose one of the fonts.")))
    if "css" in content:
        css = str(content["css"] or "")
        if len(css) > CSS_MAX or "<" in css:
            raise FocusError(f'Custom CSS can be at most {CSS_MAX:,} characters and cannot contain "<".', field="css")
        pairs.append(("properties[content][css]", css))
    if "when" in data:
        pairs.append(("properties[when]", _choice(data["when"], WHEN, "when", "Choose when the Focus Item appears.")))
    if "timeout" in data:
        timeout = str(data["timeout"] if data["timeout"] is not None else "").strip()
        if timeout and (not timeout.isdigit() or int(timeout) > 3600):
            raise FocusError("The delay must be a whole number of seconds up to 3600.", field="timeout")
        pairs.append(("properties[timeout]", timeout))
    if "frequency" in data:
        pairs.append(("properties[frequency]", _choice(data["frequency"], FREQUENCY, "frequency", "Choose how often it appears.")))
    return pairs


def bridge_form(data, *, current: dict[str, Any] | None = None, client=None, preview: bool = False) -> list[tuple[str, str]]:
    """The checked settings as form pairs for the bridge. ``current`` is the
    stored (normalized) Focus Item on an update, where only the keys sent
    change; on create and preview every required field must be present."""
    if not hasattr(data, "get"):
        raise FocusError("Send the Focus Item as an object.", code="invalid_payload")
    creating = current is None
    pairs: list[tuple[str, str]] = []

    if not preview and (creating or "name" in data):
        name = str(data.get("name") or "").strip()
        if not name:
            raise FocusError("Give the Focus Item a name.", field="name")
        if len(name) > NAME_MAX:
            raise FocusError(f"The name can be at most {NAME_MAX} characters.", field="name")
        pairs.append(("name", name))
    if not preview and "description" in data:
        description = str(data.get("description") or "").strip()
        if len(description) > DESCRIPTION_MAX:
            raise FocusError(f"The description can be at most {DESCRIPTION_MAX} characters.", field="description")
        pairs.append(("description", description))

    focus_type = (current or {}).get("type")
    style = (current or {}).get("style")
    if creating or "type" in data:
        focus_type = _choice(data.get("type"), TYPES, "type", "Choose what the Focus Item does.")
        pairs.append(("type", focus_type))
    if creating or "style" in data:
        style = _choice(data.get("style"), STYLES, "style", "Choose how the Focus Item looks.")
        pairs.append(("style", style))

    if creating or "htmlMode" in data:
        mode = str(data.get("htmlMode") or "basic")
        if mode not in HTML_MODES:
            raise FocusError("Raw HTML Focus Items are not available here; use the builder or the editor.", field="htmlMode")
        pairs.append(("html_mode", mode))
    if "editor" in data:
        editor = str(data.get("editor") or "")
        if len(editor) > EDITOR_MAX:
            raise FocusError("The editor content is too long.", field="editor")
        active = find_active_content(editor)
        if active:
            raise FocusError(f"Focus Items run on public websites, so the content cannot contain {'; '.join(active)}.",
                             field="editor")
        pairs.append(("editor", editor))

    if "website" in data:
        pairs.append(("website", _http_url(data.get("website"), "website", "The website must start with http:// or https://.")))

    form_id = ((current or {}).get("form") or {}).get("id")
    if "form" in data:
        raw = data.get("form")
        raw = raw.get("id") if isinstance(raw, dict) else raw
        if raw in (None, "", 0, "0"):
            form_id = None
        elif str(raw).isdigit():
            form_id = int(raw)
        else:
            raise FocusError("Choose a published Form.", field="form")
        pairs.append(("form", str(form_id or "")))
    if focus_type == "form" and not form_id:
        raise FocusError("A Focus Item that collects data needs a published Form.", field="form")

    if not preview and "category" in data:
        raw = data.get("category")
        raw = raw.get("id") if isinstance(raw, dict) else raw
        try:
            category = category_choice(raw, "plugin:focus", client=client)
        except ValueError as exc:
            raise FocusError(str(exc), field="category") from None
        pairs.append(("category", str(category or "")))
    if not preview and "isPublished" in data:
        pairs.append(("isPublished", "1" if _flag(data.get("isPublished")) else "0"))
    elif creating and not preview:
        pairs.append(("isPublished", "0"))
    if not preview:
        try:
            window = parse_window(data, current)
        except PublishWindowError as exc:
            raise FocusError(str(exc), field=exc.field) from None
        pairs.extend((key, value or "") for key, value in window.items())

    if not preview and isinstance(data.get("utmTags"), dict):
        for key in UTM_KEYS:
            if key in data["utmTags"]:
                value = str(data["utmTags"][key] or "").strip()
                if len(value) > NAME_MAX:
                    raise FocusError(f"UTM values can be at most {NAME_MAX} characters.", field=key)
                pairs.append((f"utmTags[{key}]", value))

    if creating or preview:
        # Every setting is stored (and rendered), so the ones not sent take Mautic's defaults.
        sent = data.get("properties") if "properties" in data else {}
        if not isinstance(sent, dict):
            raise FocusError("Send the settings as an object.", field="properties")
        pairs.extend(_check_properties(_merged(_defaults(style), sent), style))
    elif "properties" in data:
        pairs.extend(_check_properties(data["properties"], style))

    if not creating and not pairs:
        raise FocusError("Nothing to change.", code="no_changes")
    return pairs


def duplicate_payload(focus: dict[str, Any]) -> dict[str, Any]:
    """Create settings for an unpublished copy of a normalized Focus Item."""
    name = f"{COPY_PREFIX}{focus['name']}"[:NAME_MAX]
    return {
        "name": name,
        "description": focus.get("description") or "",
        "type": focus["type"],
        "style": focus["style"],
        "htmlMode": focus["htmlMode"] if focus["htmlMode"] in HTML_MODES else "basic",
        "editor": focus.get("editor") or "",
        "website": focus.get("website") or "",
        "form": (focus.get("form") or {}).get("id"),
        "category": (focus.get("category") or {}).get("id"),
        "isPublished": False,
        "utmTags": focus.get("utmTags") or {},
        "properties": focus["properties"],
    }


PREVIEW_DOCUMENT = """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>
html,body{{margin:0;min-height:100%;}}
body{{background:#F3F5F8;font-family:Arial,Helvetica,sans-serif;min-height:520px;position:relative;}}
.ecp-site{{max-width:880px;margin:0 auto;padding:120px 24px 48px;}}
.ecp-site i{{display:block;height:14px;border-radius:7px;background:#DDE3EA;margin:0 0 14px;}}
</style></head>
<body><div class="ecp-site" aria-hidden="true"><i style="width:42%;height:22px"></i><i></i><i style="width:92%"></i>
<i style="width:84%"></i><i style="width:64%"></i><i></i><i style="width:76%"></i></div>
{content}
</body></html>"""


_SCRIPT_ELEMENT = re.compile(r"<script\b[^>]*>.*?</script\s*>", re.IGNORECASE | re.DOTALL)


def preview_document(html: str) -> str:
    """Mautic's preview markup over a placeholder page. It is shown in a frame
    that runs no script; the Form helpers Mautic adds are dropped as well."""
    return PREVIEW_DOCUMENT.format(content=_SCRIPT_ELEMENT.sub("", html))
