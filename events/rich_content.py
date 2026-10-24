"""Allowlisted HTML for event descriptions; plain legacy descriptions are retained."""
from urllib.parse import urlparse
from html import unescape
from django.conf import settings

import nh3
from bs4 import BeautifulSoup


TAGS = {"p", "br", "strong", "em", "s", "h1", "h2", "h3", "h4", "ul", "ol", "li", "blockquote", "a", "img", "figure", "figcaption", "iframe", "table", "thead", "tbody", "tr", "th", "td"}
ATTRIBUTES = {"a": {"href", "class"}, "img": {"src", "alt", "title"}, "figure": {"class", "data-width"}, "iframe": {"src", "title", "allowfullscreen"}, "th": {"colspan", "rowspan"}, "td": {"colspan", "rowspan"}}


def plain_event_description(value):
    """Text for email, previews and integrations that do not render event HTML."""
    if not value or "<" not in value:
        return value or ""
    return unescape(BeautifulSoup(value, "html.parser").get_text(" ", strip=True))


def sanitize_event_description(value):
    if not value or "<" not in value:
        return value
    soup = BeautifulSoup(value, "html.parser")
    for tag in soup.find_all(True):
        if tag.name == "iframe":
            url = urlparse(tag.get("src", ""))
            if url.scheme != "https" or url.hostname not in {"www.youtube-nocookie.com", "www.youtube.com", "player.vimeo.com"} or not url.path.startswith(("/embed/", "/video/")):
                tag.decompose()
                continue
        if tag.name == "img":
            url = urlparse(tag.get("src", ""))
            local_upload = url.scheme == "http" and settings.DEBUG and url.hostname in {"localhost", "127.0.0.1"} and url.path.startswith("/media/event-content/")
            if not ((url.scheme == "https" and url.netloc) or (not url.scheme and not url.netloc and url.path.startswith("/media/event-content/")) or local_upload):
                tag.decompose()
                continue
        if tag.name == "figure":
            alignment = next((part for part in tag.get("class", []) if part in {"event-content-image--left", "event-content-image--center", "event-content-image--right"}), "event-content-image--center")
            tag["class"] = ["event-content-image", alignment]
            try:
                width = int(tag.get("data-width", "100"))
            except (TypeError, ValueError):
                width = 100
            tag["data-width"] = str(max(15, min(100, width)))
        if tag.name == "a":
            url = urlparse(tag.get("href", ""))
            if url.scheme not in {"https", "http", "mailto"} and not (not url.scheme and not url.netloc and (url.path.startswith("/") or (not url.path and url.fragment))):
                tag.attrs.pop("href", None)
            tag["rel"] = "noopener noreferrer"
            if tag.get("class") != ["event-cta"]:
                tag.attrs.pop("class", None)
            tag.attrs.pop("target", None)
    return nh3.clean(str(soup), tags=TAGS, attributes=ATTRIBUTES, url_schemes={"https", "http", "mailto"}, link_rel="noopener noreferrer")
