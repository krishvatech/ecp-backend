"""Approved content for the Testimonials page (cms.TestimonialsPage + Testimonial snippets), migrated
from imaa-institute.org/testimonials/ (77 WordPress ``testimonial`` posts).

``testimonials.json`` holds the page texts and sections, the programmes, every testimonial (one per
WordPress post, with its programmes and WordPress date), the media list and ``content_sha256``.
The image binaries are NOT in Git: production verifies the originals in storage
(``import_batch3_content``); ``batch3_media_transfer`` copies missing originals from a local
directory. Importable without Django settings.
"""

import hashlib
import json
from pathlib import Path

from cms.team_page_content import SAFE_URL_RE, file_sha256, rich_text_problems

CONTENT_FILE = Path(__file__).resolve().parent / "testimonials.json"
FORMAT_VERSION = 1
HASHED_FIELDS = ("format_version", "page", "programmes", "testimonials", "media")


class TestimonialsContentError(ValueError):
    """The content file or its media is missing, malformed or does not match its hashes."""


def compute_content_hash(data):
    payload = {key: data[key] for key in HASHED_FIELDS}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def iter_media_keys(data):
    for t in data["testimonials"]:
        if t.get("photo"):
            yield t["photo"]
    for section in data["page"]["sections"]:
        for logo in section.get("logos", []):
            yield logo["image"]
        for card in section.get("cards", []):
            if card.get("image"):
                yield card["image"]


def iter_urls(data):
    for t in data["testimonials"]:
        if t.get("url"):
            yield f"testimonials[{t['slug']}].url", t["url"]
    for i, section in enumerate(data["page"]["sections"]):
        if section.get("button"):
            yield f"sections[{i}].button", section["button"]["url"]
        for j, card in enumerate(section.get("cards", [])):
            if card.get("link"):
                yield f"sections[{i}].cards[{j}].link", card["link"]["url"]


def load_testimonials_content(*, images_dir=None):
    """Load and validate testimonials.json; with ``images_dir``, also every media file's SHA-256."""
    try:
        data = json.loads(CONTENT_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TestimonialsContentError(f"Missing {CONTENT_FILE.name}.") from exc
    except json.JSONDecodeError as exc:
        raise TestimonialsContentError(f"{CONTENT_FILE.name} is not valid JSON: {exc}") from exc
    if data.get("format_version") != FORMAT_VERSION:
        raise TestimonialsContentError(f"Unsupported format_version {data.get('format_version')!r}.")
    missing = [key for key in HASHED_FIELDS if key not in data]
    if missing:
        raise TestimonialsContentError(f"Missing fields: {missing}.")
    if compute_content_hash(data) != data.get("content_sha256"):
        raise TestimonialsContentError("content_sha256 does not match the content; the file was edited without updating its hash.")

    slugs = [p["slug"] for p in data["programmes"]]
    if len(set(slugs)) != len(slugs) or len({p["code"] for p in data["programmes"]}) != len(slugs):
        raise TestimonialsContentError("Duplicate programme codes or slugs.")
    items = data["testimonials"]
    for key in ("wordpress_id", "slug"):
        values = [t[key] for t in items]
        if len(set(values)) != len(values):
            raise TestimonialsContentError(f"Duplicate testimonial {key}s.")
    for t in items:
        if not t["name"].strip():
            raise TestimonialsContentError(f"{t['slug']}: missing name.")
        unknown = sorted(set(t["programmes"]) - set(slugs))
        if unknown:
            raise TestimonialsContentError(f"{t['slug']}: unknown programmes {unknown}.")
        problems = rich_text_problems(t["quote_html"])
        if problems:
            raise TestimonialsContentError(f"{t['slug']}: quote is not editor-compatible: {problems[:3]}")
        if not t["quote_html"].strip() and t.get("is_public", True):
            raise TestimonialsContentError(f"{t['slug']}: a public testimonial needs a quote.")

    media = {m["key"]: m for m in data["media"]}
    if len(media) != len(data["media"]):
        raise TestimonialsContentError("Duplicate media keys.")
    used = set(iter_media_keys(data))
    if used - set(media):
        raise TestimonialsContentError(f"Content refers to unlisted media: {sorted(used - set(media))[:5]}")
    if set(media) - used:
        raise TestimonialsContentError(f"Media listed but not used: {sorted(set(media) - used)[:5]}")
    too_long = [m["file"] for m in data["media"] if len(f"original_images/{m['file']}") > 100]
    if too_long:
        raise TestimonialsContentError(f"Storage names longer than Wagtail's 100 characters: {too_long[:3]}")
    if images_dir is not None:
        for m in data["media"]:
            path = Path(images_dir) / m["file"]
            if not path.is_file():
                raise TestimonialsContentError(f"Missing media file {m['file']} in {images_dir}.")
            if file_sha256(path) != m["sha256"]:
                raise TestimonialsContentError(f"{m['file']} does not match its recorded sha256.")
    for location, url in iter_urls(data):
        if not SAFE_URL_RE.match(url or ""):
            raise TestimonialsContentError(f"{location}: unsafe or empty link {url!r}")
    return data
