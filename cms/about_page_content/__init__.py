"""Approved content for the About page (cms.AboutPage), migrated from imaa-institute.org/about-us/.

``about.json`` holds the page's fields, statistics and ordered sections, the media list and
``content_sha256``; ``images/`` holds the media files (each with its SHA-256 in about.json).
The directory is deliberately not called ``media``: the repository's .gitignore ignores every
``media/`` directory, which would leave the files out of Git and of every deployment built
from it.

Consumers: ``manage.py import_about_page`` (any environment, reuses stored originals; see
docs/about-page-import-runbook.md) and ``manage.py populate_about_page`` (local only). Both are
explicit and preview by default. Nothing loads this content at runtime. Edit the page in Wagtail once it is populated; this file is the
migration source, not the live content.

Importable without Django settings.
"""

import hashlib
import json
import re
from html.parser import HTMLParser
from pathlib import Path

CONTENT_DIR = Path(__file__).resolve().parent
CONTENT_FILE = CONTENT_DIR / "about.json"
IMAGES_DIR = CONTENT_DIR / "images"
FORMAT_VERSION = 1

# Same rules as cms.about_blocks (kept here so this module needs no Django).
SAFE_URL_RE = re.compile(r"^(https?://[^\s]+|mailto:[^\s]+|tel:\+?[0-9][0-9 ()./-]*|/(?!/)[^\s]*)$", re.IGNORECASE)
RICH_TEXT_TAGS = {"p", "br", "strong", "b", "em", "i", "a", "ul", "ol", "li"}
SECTION_TYPES = {"accordion", "cta_band", "card_group", "testimonials", "logo_strip", "contact_callout", "offices"}
HASHED_FIELDS = (
    "format_version", "page", "title", "hero_title", "hero_subtitle", "hero_background_image", "intro_image",
    "intro_html", "stats", "mission_title", "mission_html", "features_title", "features", "sections",
    "seo_title", "search_description", "media",
)


class AboutContentError(ValueError):
    """The content file or its media is missing, malformed or does not match its hashes."""


def compute_content_hash(data):
    payload = {key: data[key] for key in HASHED_FIELDS}
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class _Markup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.hrefs, self.bad_attrs = set(), [], []

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag)
        for name, value in attrs:
            if tag == "a" and name == "href":
                self.hrefs.append(value or "")
            else:
                self.bad_attrs.append(f"{tag}[{name}]")


def rich_text_problems(html):
    parser = _Markup()
    parser.feed(html or "")
    problems = [f"tag <{tag}>" for tag in sorted(parser.tags - RICH_TEXT_TAGS)]
    problems += [f"attribute {attr}" for attr in parser.bad_attrs]
    problems += [f"link {href!r}" for href in parser.hrefs if not SAFE_URL_RE.match(href)]
    return problems


def iter_rich_text(data):
    """(location, html) for every rich-text value in the content."""
    yield "intro_html", data["intro_html"]
    yield "mission_html", data["mission_html"]
    for i, section in enumerate(data["sections"]):
        for key in ("text_html",):
            if key in section:
                yield f"sections[{i}].{key}", section[key]
        for j, item in enumerate(section.get("items", [])):
            for key in ("body_html", "quote_html"):
                if key in item:
                    yield f"sections[{i}].items[{j}].{key}", item[key]


def iter_urls(data):
    for i, section in enumerate(data["sections"]):
        button = section.get("button")
        if button:
            yield f"sections[{i}].button", button["url"]
        for j, card in enumerate(section.get("cards", [])):
            if card.get("link"):
                yield f"sections[{i}].cards[{j}].link", card["link"]["url"]
        for j, item in enumerate(section.get("items", [])):
            if item.get("url"):
                yield f"sections[{i}].items[{j}].url", item["url"]


def iter_media_keys(data):
    yield data["hero_background_image"]
    yield data["intro_image"]
    for section in data["sections"]:
        if section.get("image"):
            yield section["image"]
        for key in section.get("logos", []):
            yield key["image"] if isinstance(key, dict) else key
        for card in section.get("cards", []):
            if card.get("image"):
                yield card["image"]
        for item in section.get("items", []):
            if item.get("photo"):
                yield item["photo"]
        for office in section.get("offices", []):
            if office.get("image"):
                yield office["image"]


def load_about_content(*, verify_files=True):
    """Load and validate about.json (and, by default, every media file's hash)."""
    try:
        data = json.loads(CONTENT_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AboutContentError(f"Missing {CONTENT_FILE.name}.") from exc
    except json.JSONDecodeError as exc:
        raise AboutContentError(f"{CONTENT_FILE.name} is not valid JSON: {exc}") from exc

    if data.get("format_version") != FORMAT_VERSION:
        raise AboutContentError(f"Unsupported format_version {data.get('format_version')!r}.")
    missing = [key for key in HASHED_FIELDS if key not in data]
    if missing:
        raise AboutContentError(f"Missing fields: {missing}.")
    if compute_content_hash(data) != data.get("content_sha256"):
        raise AboutContentError("content_sha256 does not match the content; the file was edited without updating its hash.")

    media = {item["key"]: item for item in data["media"]}
    if len(media) != len(data["media"]):
        raise AboutContentError("Duplicate media keys.")
    unknown = sorted({key for key in iter_media_keys(data) if key not in media})
    if unknown:
        raise AboutContentError(f"Content refers to unlisted media: {unknown[:5]}")
    unused = sorted(set(media) - set(iter_media_keys(data)))
    if unused:
        raise AboutContentError(f"Media listed but not used: {unused[:5]}")
    if verify_files:
        for item in data["media"]:
            path = IMAGES_DIR / item["file"]
            if not path.is_file():
                raise AboutContentError(f"Missing media file images/{item['file']}.")
            if file_sha256(path) != item["sha256"]:
                raise AboutContentError(f"images/{item['file']} does not match its recorded sha256.")

    for location, html in iter_rich_text(data):
        problems = rich_text_problems(html)
        if problems:
            raise AboutContentError(f"{location}: not editor-compatible rich text: {problems[:3]}")
    for location, url in iter_urls(data):
        if not SAFE_URL_RE.match(url or ""):
            raise AboutContentError(f"{location}: unsafe or empty link {url!r}")
    for section in data["sections"]:
        if section.get("type") not in SECTION_TYPES:
            raise AboutContentError(f"Unknown section type {section.get('type')!r}.")
    if not 1 <= len(data["stats"]) <= 4:
        raise AboutContentError("Between one and four statistics are expected.")
    return data
