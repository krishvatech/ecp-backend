"""Approved content for the Contact Us page (cms.ContactPage), migrated from imaa-institute.org/contact-us/.

``contact.json`` holds the page texts, statistics and sections, the enquiry form's field rules and
country list (used by the page and by the submission endpoint), the media list and
``content_sha256``. The image binaries are NOT in Git (see cms/testimonials_content).
Importable without Django settings.
"""

import hashlib
import json
from functools import lru_cache
from pathlib import Path

from cms.team_page_content import SAFE_URL_RE, file_sha256, rich_text_problems

CONTENT_FILE = Path(__file__).resolve().parent / "contact.json"
FORMAT_VERSION = 1
HASHED_FIELDS = ("format_version", "page", "form", "media")


class ContactContentError(ValueError):
    """The content file or its media is missing, malformed or does not match its hashes."""


def compute_content_hash(data):
    payload = {key: data[key] for key in HASHED_FIELDS}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def iter_media_keys(data):
    page = data["page"]
    if page.get("form_image"):
        yield page["form_image"]
    for section in page["sections"]:
        for logo in section.get("logos", []):
            yield logo["image"]
        for card in section.get("cards", []):
            if card.get("image"):
                yield card["image"]
        for office in section.get("offices", []):
            if office.get("image"):
                yield office["image"]


def iter_urls(data):
    for i, section in enumerate(data["page"]["sections"]):
        if section.get("button"):
            yield f"sections[{i}].button", section["button"]["url"]
        for j, card in enumerate(section.get("cards", [])):
            if card.get("link"):
                yield f"sections[{i}].cards[{j}].link", card["link"]["url"]


def load_contact_content(*, images_dir=None):
    """Load and validate contact.json; with ``images_dir``, also every media file's SHA-256."""
    try:
        data = json.loads(CONTENT_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ContactContentError(f"Missing {CONTENT_FILE.name}.") from exc
    except json.JSONDecodeError as exc:
        raise ContactContentError(f"{CONTENT_FILE.name} is not valid JSON: {exc}") from exc
    if data.get("format_version") != FORMAT_VERSION:
        raise ContactContentError(f"Unsupported format_version {data.get('format_version')!r}.")
    missing = [key for key in HASHED_FIELDS if key not in data]
    if missing:
        raise ContactContentError(f"Missing fields: {missing}.")
    if compute_content_hash(data) != data.get("content_sha256"):
        raise ContactContentError("content_sha256 does not match the content; the file was edited without updating its hash.")
    countries = data["form"]["countries"]
    if len(countries) < 200 or len(set(countries)) != len(countries):
        raise ContactContentError("The country list is incomplete or has duplicates.")
    page = data["page"]
    for location in ("form_intro_html", "consent_html"):
        problems = rich_text_problems(page.get(location) or "")
        if problems:
            raise ContactContentError(f"{location}: not editor-compatible rich text: {problems[:3]}")
    if not (page.get("consent_html") or "").strip():
        raise ContactContentError("The consent text is required.")
    media = {m["key"]: m for m in data["media"]}
    used = set(iter_media_keys(data))
    if used - set(media) or set(media) - used:
        raise ContactContentError(f"Media list and content disagree: {sorted(used ^ set(media))[:5]}")
    too_long = [m["file"] for m in data["media"] if len(f"original_images/{m['file']}") > 100]
    if too_long:
        raise ContactContentError(f"Storage names longer than Wagtail's 100 characters: {too_long[:3]}")
    if images_dir is not None:
        for m in data["media"]:
            path = Path(images_dir) / m["file"]
            if not path.is_file() or file_sha256(path) != m["sha256"]:
                raise ContactContentError(f"{m['file']} is missing or does not match its recorded sha256.")
    for location, url in iter_urls(data):
        if not SAFE_URL_RE.match(url or ""):
            raise ContactContentError(f"{location}: unsafe or empty link {url!r}")
    return data


@lru_cache(maxsize=1)
def contact_form_rules():
    """The form's field limits and country list (cached; used by the submission endpoint)."""
    return load_contact_content()["form"]
