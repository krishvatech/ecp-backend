"""Approved content for the Our Team page, migrated from imaa-institute.org/our-team/.

``team.json`` holds the page texts and buttons, the programme filters, every faculty and staff
record (one per WordPress post, with all its programmes), the trailing sections shared with the
About page, the media list and ``content_sha256``; ``images/`` holds the media files (each with its
SHA-256 in team.json). Like cms/about_page_content, the directory is deliberately not called
``media``: the repository's .gitignore ignores every ``media/`` directory.

Consumer: ``manage.py populate_team_page`` (local, explicit, preview by default). Nothing loads
this content at runtime; once imported, the records are edited in Wagtail.

Importable without Django settings.
"""

import hashlib
import json
import re
from html.parser import HTMLParser
from pathlib import Path

CONTENT_DIR = Path(__file__).resolve().parent
CONTENT_FILE = CONTENT_DIR / "team.json"
IMAGES_DIR = CONTENT_DIR / "images"
FORMAT_VERSION = 1
MEMBER_TYPES = {"faculty", "staff"}

# Same rules as cms.about_blocks (kept here so this module needs no Django).
SAFE_URL_RE = re.compile(r"^(https?://[^\s]+|mailto:[^\s]+|tel:\+?[0-9][0-9 ()./-]*|/(?!/)[^\s]*)$", re.IGNORECASE)
RICH_TEXT_TAGS = {"p", "br", "strong", "b", "em", "i", "a", "ul", "ol", "li"}
HASHED_FIELDS = ("format_version", "page", "programmes", "members", "media")


class TeamContentError(ValueError):
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
    page = data["page"]
    yield "page.faculty_intro_html", page["faculty_intro_html"]
    yield "page.staff_intro_html", page["staff_intro_html"]
    for member in data["members"]:
        yield f"members[{member['slug']}].biography_html", member["biography_html"]


def iter_urls(data):
    page = data["page"]
    for name in ("hero_button", "staff_button"):
        yield f"page.{name}", page[name]["url"]
    for i, button in enumerate(page["faculty_buttons"]):
        yield f"page.faculty_buttons[{i}]", button["url"]
    for section in page["sections"]:
        for card in section.get("cards", []):
            if card.get("link"):
                yield f"sections.{section['type']}.cards", card["link"]["url"]
    for member in data["members"]:
        for name in ("linkedin_url", "profile_url"):
            if member[name]:
                yield f"members[{member['slug']}].{name}", member[name]


def iter_media_keys(data):
    for member in data["members"]:
        if member.get("photo"):
            yield member["photo"]
    for section in data["page"]["sections"]:
        for item in section.get("cards", []) + section.get("offices", []):
            if item.get("image"):
                yield item["image"]


def load_team_content(*, verify_files=True):
    """Load and validate team.json (and, by default, every media file's hash)."""
    try:
        data = json.loads(CONTENT_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TeamContentError(f"Missing {CONTENT_FILE.name}.") from exc
    except json.JSONDecodeError as exc:
        raise TeamContentError(f"{CONTENT_FILE.name} is not valid JSON: {exc}") from exc

    if data.get("format_version") != FORMAT_VERSION:
        raise TeamContentError(f"Unsupported format_version {data.get('format_version')!r}.")
    missing = [key for key in HASHED_FIELDS if key not in data]
    if missing:
        raise TeamContentError(f"Missing fields: {missing}.")
    if compute_content_hash(data) != data.get("content_sha256"):
        raise TeamContentError("content_sha256 does not match the content; the file was edited without updating its hash.")

    codes = [p["code"] for p in data["programmes"]]
    if len(set(codes)) != len(codes) or len({p["slug"] for p in data["programmes"]}) != len(codes):
        raise TeamContentError("Duplicate programme codes or slugs.")
    members = data["members"]
    for key in ("wordpress_id", "slug"):
        values = [m[key] for m in members]
        if len(set(values)) != len(values):
            raise TeamContentError(f"Duplicate member {key}s.")
    for member in members:
        if member["member_type"] not in MEMBER_TYPES:
            raise TeamContentError(f"{member['slug']}: unknown member_type {member['member_type']!r}.")
        if not member["name"].strip():
            raise TeamContentError(f"{member['slug']}: missing name.")
        unknown = sorted(set(member["programmes"]) - set(codes))
        if unknown:
            raise TeamContentError(f"{member['slug']}: unknown programmes {unknown}.")
        if member["linkedin_url"] and not member["linkedin_url"].startswith("https://"):
            raise TeamContentError(f"{member['slug']}: LinkedIn URL must be https.")

    media = {item["key"]: item for item in data["media"]}
    if len(media) != len(data["media"]):
        raise TeamContentError("Duplicate media keys.")
    used = set(iter_media_keys(data))
    if used - set(media):
        raise TeamContentError(f"Content refers to unlisted media: {sorted(used - set(media))[:5]}")
    if set(media) - used:
        raise TeamContentError(f"Media listed but not used: {sorted(set(media) - used)[:5]}")
    if verify_files:
        for item in data["media"]:
            path = IMAGES_DIR / item["file"]
            if not path.is_file():
                raise TeamContentError(f"Missing media file images/{item['file']}.")
            if file_sha256(path) != item["sha256"]:
                raise TeamContentError(f"images/{item['file']} does not match its recorded sha256.")

    for location, html in iter_rich_text(data):
        problems = rich_text_problems(html)
        if problems:
            raise TeamContentError(f"{location}: not editor-compatible rich text: {problems[:3]}")
    for location, url in iter_urls(data):
        if not SAFE_URL_RE.match(url or ""):
            raise TeamContentError(f"{location}: unsafe or empty link {url!r}")
    return data
