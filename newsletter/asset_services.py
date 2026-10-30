"""Marketing Hub assets (Mautic's downloadable files).

Mautic owns the assets. ECP sends uploads and remote links to the bridge as
the admin's own Mautic user; the bridge stores the file itself and checks its
content (EcpAssetPolicy), so ECP only gives early, clear errors here: the
extension and size against Mautic's own settings, and remote links that must
be public https addresses.

Admins download the stored file through ECP, which reads it from the bridge,
so their previews are not counted as downloads in Mautic.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from . import marketing_cache
from .mautic import MauticClient

TITLE_MAX = 191
DESCRIPTION_MAX = 5000
URL_MAX = 2048
_LANGUAGE_RE = re.compile(r"^[a-z]{2,3}([_-][A-Za-z]{2,4})?$")
_DATETIME_FORMATS = ("%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S")
_LOCAL_SUFFIXES = (".localhost", ".internal", ".local")


class AssetError(ValueError):
    def __init__(self, message: str, *, code: str = "invalid_asset", status_code: int = 400, field: str = ""):
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.field = field


def asset_config(client: MauticClient | None = None) -> dict[str, Any]:
    client = client or MauticClient()
    return marketing_cache.cached_value("asset-config", [], client.get_asset_config, ttl=marketing_cache.metadata_ttl())


def asset_categories(client: MauticClient | None = None) -> list[dict[str, Any]]:
    """Mautic categories for the asset bundle (and global ones), by title."""
    client = client or MauticClient()

    def build():
        data = client.list_categories(limit=500)
        rows = data.get("categories")
        rows = rows.values() if isinstance(rows, dict) else rows or []
        return sorted(
            ({"id": int(row["id"]), "title": str(row.get("title") or "")} for row in rows
             if isinstance(row, dict) and row.get("id") and str(row.get("bundle") or "") in ("asset", "global")
             and row.get("isPublished", True) not in (False, 0, "0")),
            key=lambda row: row["title"].lower(),
        )

    return marketing_cache.cached_value("asset-categories", [], build, ttl=marketing_cache.metadata_ttl())


# Validation ----------------------------------------------------------------------


def _flag(value) -> int:
    if isinstance(value, str):
        return 1 if value.strip().lower() in ("1", "true", "yes", "on") else 0
    return 1 if value else 0


def _when(value, field: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    for fmt in _DATETIME_FORMATS:
        try:
            return datetime.strptime(raw[:19], fmt).strftime("%Y-%m-%d %H:%M")
        except ValueError:
            continue
    raise AssetError("Use a date and time like 2026-11-01 09:00.", field=field)


def normalize_fields(data, *, creating: bool, categories: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """The asset fields to send. On update only the keys sent are changed."""
    if not hasattr(data, "get"):
        raise AssetError("Send the asset as an object.", code="invalid_payload")
    fields: dict[str, Any] = {}

    if creating or "title" in data:
        title = str(data.get("title") or "").strip()
        if not title:
            raise AssetError("Give the asset a title.", field="title")
        if len(title) > TITLE_MAX:
            raise AssetError(f"The title can be at most {TITLE_MAX} characters.", field="title")
        fields["title"] = title
    if "description" in data:
        description = str(data.get("description") or "").strip()
        if len(description) > DESCRIPTION_MAX:
            raise AssetError(f"The description can be at most {DESCRIPTION_MAX} characters.", field="description")
        fields["description"] = description
    if "language" in data:
        language = str(data.get("language") or "").strip()
        if language and not _LANGUAGE_RE.match(language):
            raise AssetError("Use a language code such as en or fr_FR.", field="language")
        fields["language"] = language or "en"
    elif creating:
        fields["language"] = "en"
    for key in ("isPublished", "disallow"):
        if key in data:
            fields[key] = _flag(data.get(key))
    if creating and "isPublished" not in fields:
        fields["isPublished"] = 0
    for key in ("publishUp", "publishDown"):
        if key in data:
            fields[key] = _when(data.get(key), key)
    if fields.get("publishUp") and fields.get("publishDown") and fields["publishDown"] <= fields["publishUp"]:
        raise AssetError("The unpublish date must be after the publish date.", field="publishDown")
    if "category" in data:
        raw = str(data.get("category") or "").strip()
        if raw:
            if not raw.isdigit() or (categories is not None and int(raw) not in {row["id"] for row in categories}):
                raise AssetError("Choose one of the asset categories.", field="category")
        fields["category"] = raw
    return fields


def check_upload(name: str, size: int, config: dict[str, Any]) -> str:
    """The lower-case extension, or an AssetError (the bridge also checks the content)."""
    clean = str(name or "").replace("\\", "/").split("/")[-1].strip()
    extension = clean.rsplit(".", 1)[-1].lower() if "." in clean else ""
    allowed = [str(item).lower() for item in config.get("allowedExtensions") or []]
    if not extension or extension not in allowed:
        raise AssetError(f"Files of this type cannot be uploaded. Allowed: {', '.join(allowed)}.", field="file")
    if size <= 0:
        raise AssetError("The file is empty.", field="file")
    max_mb = float(config.get("maxSizeMb") or 6)
    if size > int(max_mb * 1024 * 1024):
        raise AssetError(f"The file is larger than Mautic's limit of {max_mb:g} MB.", field="file")
    if len(clean) > 255:
        raise AssetError("The file name is too long.", field="file")
    return extension


def _public_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def _resolve(host: str) -> list[str]:
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
    except OSError:
        return []


def check_remote_url(url: str, *, resolve=_resolve) -> str:
    url = str(url or "").strip()
    if not url or len(url) > URL_MAX or any(ch.isspace() or ord(ch) < 32 for ch in url):
        raise AssetError("Enter a valid https:// link to the file.", field="remoteUrl")
    parts = urlsplit(url)
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise AssetError("Remote files must use an https:// link.", field="remoteUrl")
    if parts.username or parts.password:
        raise AssetError("Links with a user name or password are not allowed.", field="remoteUrl")
    try:
        port = parts.port
    except ValueError as exc:
        raise AssetError("Enter a valid https:// link to the file.", field="remoteUrl") from exc
    if port not in (None, 443):
        raise AssetError("Remote files must be on the standard https port.", field="remoteUrl")
    host = parts.hostname.lower()
    if host == "localhost" or host.endswith(_LOCAL_SUFFIXES):
        raise AssetError("The link must point to a public website.", field="remoteUrl")
    try:
        addresses = [str(ipaddress.ip_address(host))]
    except ValueError:
        addresses = resolve(host)
    if not addresses:
        raise AssetError("The website in the link could not be found.", field="remoteUrl")
    if not all(_public_address(address) for address in addresses):
        raise AssetError("The link must point to a public website.", field="remoteUrl")
    return url


# Template tokens -----------------------------------------------------------------


def asset_link_tokens(client: MauticClient, *, limit: int = 200) -> list[dict[str, str]]:
    """{assetlink=ID} tokens for published assets, for the email/page editors."""
    def build():
        # Only plain data is cached: a cache write that fails (an object that
        # cannot be pickled) would pause the whole marketing cache.
        data = client.list_assets(limit=min(limit, 100), status="published")
        rows = data.get("assets") if isinstance(data, dict) else None
        return [
            {"token": f"{{assetlink={int(row['id'])}}}", "label": str(row.get("title") or f"Asset {row['id']}"), "group": "Assets"}
            for row in rows if isinstance(row, dict) and str(row.get("id") or "").isdigit()
        ] if isinstance(rows, list) else []

    return marketing_cache.cached_value("asset-tokens", [limit], build, ttl=marketing_cache.list_ttl())
