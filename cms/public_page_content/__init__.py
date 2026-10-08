"""Initial content for the public website's CMS StandardPages.

One JSON file per page, migrated from the client's WordPress site (imaa-institute.org).
Two consumers, deliberately without any runtime link between them:

* ``python manage.py setup_public_pages`` uses it as the initial title, body and SEO fields
  of pages it creates (existing pages are never touched);
* the Next.js frontend keeps byte-identical copies in
  ``Events-Community-Platform-Frontend/src/content/public-pages/`` and renders them only
  while a page is genuinely absent from the configured Wagtail Site
  (see docs/public-website-pages.md).

Every file carries ``content_sha256``, a hash of its content fields. Tests in both
repositories recompute it, so a copy edited without updating its hash fails that
repository's tests. The frontend tests also compare their copies with a sibling
``ecp-backend`` checkout when one is present, and the hash is printed by the setup command
and exposed on default pages (``data-content-sha256``), so the two copies can be compared
directly. After an intentional edit run ``python -m cms.public_page_content --update-hashes``
here and copy the files to the frontend. See README.md in this directory.

Bundled media (the References logo wall): files under ``media/`` listed in a page's ``media``
array, each with its SHA-256 and pixel size. A body line that shows one is exactly
``<img alt="…" class="richtext-image <format>" height="…" src="media:<key>" width="…">``.
The placeholder ``src`` is resolved by each consumer: the setup commands import the file into
the Wagtail image library and store a rich-text image embed in that format; the frontend
serves its byte-identical copy from ``public/public-pages/<key>``.

This module must stay importable without Django settings (the maintenance entry point and
the content tests use it directly).
"""

import hashlib
import json
import re
from dataclasses import dataclass
from html import unescape
from pathlib import Path

CONTENT_DIR = Path(__file__).resolve().parent
MEDIA_DIR = CONTENT_DIR / "media"
FORMAT_VERSION = 1

MEDIA_SRC_PREFIX = "media:"
MEDIA_KEY_RE = re.compile(r"^[a-z0-9-]+/[a-z0-9][a-z0-9-]*\.(?:png|jpg)$")
# One bundled image per body line, attributes in this exact order (both consumers parse it).
MEDIA_IMG_LINE_RE = re.compile(
    r'^<img alt="(?P<alt>[^"<>]*)" class="richtext-image (?P<format>[a-z][a-z-]*)" '
    r'height="(?P<height>[1-9][0-9]*)" src="media:(?P<key>[^"]+)" width="(?P<width>[1-9][0-9]*)">$'
)

# The pages in scope, in display order: (slug, title). Each page is a StandardPage that is a
# direct child of the public Wagtail Site's root HomePage, served at "/<slug>".
PUBLIC_PAGES = (
    ("frequently-asked-questions", "Frequently Asked Questions"),
    ("references", "References"),
    ("terms-and-conditions", "Terms and Conditions"),
    ("privacy-policy", "Privacy Policy"),
    ("imprint", "Imprint"),
)
PUBLIC_PAGE_SLUGS = tuple(slug for slug, _title in PUBLIC_PAGES)
PUBLIC_PAGE_TITLES = dict(PUBLIC_PAGES)

MIGRATED = "migrated"
NOT_MIGRATED = "not_migrated"
MIGRATION_STATUSES = (MIGRATED, NOT_MIGRATED)

# Unit separator between hashed fields: cannot occur in the content itself.
_HASH_FIELD_SEPARATOR = "\x1f"
_TAG_RE = re.compile(r"<[^>]+>")


class PublicPageContentError(ValueError):
    """A content file is missing, malformed or does not match its recorded hash."""


def _media_hash_lines(media):
    return "\n".join(
        f"{_media_value(item, 'key')}\t{_media_value(item, 'sha256')}\t"
        f"{_media_value(item, 'width')}\t{_media_value(item, 'height')}"
        for item in media
    )


def _media_value(item, name):
    return item[name] if isinstance(item, dict) else getattr(item, name)


def compute_content_hash(slug, title, seo_title, search_description, body_lines, media=()):
    """SHA-256 over the content fields. The frontend computes the same value (see its tests).

    Media (key, file SHA-256, width, height per item) is appended only when a page has media,
    so files without media keep their original hashes.
    """
    fields = [slug, title, seo_title, search_description, "\n".join(body_lines)]
    if media:
        fields.append(_media_hash_lines(media))
    payload = _HASH_FIELD_SEPARATOR.join(fields)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def content_path(slug):
    return CONTENT_DIR / f"{slug}.json"


@dataclass(frozen=True)
class MediaItem:
    """A bundled file (``media/<key>``) shown by a page body line."""

    key: str
    sha256: str
    width: int
    height: int
    company: str = ""
    alt_source: str = ""
    source_url: str = ""

    @property
    def path(self):
        return MEDIA_DIR / self.key

    @property
    def filename(self):
        return self.key.rsplit("/", 1)[-1]


@dataclass(frozen=True)
class MediaLine:
    """A body line that shows a bundled file: ``<img … src="media:<key>" …>``."""

    alt: str  # unescaped alt text
    format: str  # Wagtail rich-text image format name, e.g. "logo"
    key: str
    width: int
    height: int


def parse_media_line(line):
    """The :class:`MediaLine` for a bundled-image body line, ``None`` for any other line."""
    match = MEDIA_IMG_LINE_RE.match(line)
    if not match:
        return None
    return MediaLine(
        alt=unescape(match["alt"]),
        format=match["format"],
        key=match["key"],
        width=int(match["width"]),
        height=int(match["height"]),
    )


@dataclass(frozen=True)
class PublicPageContent:
    slug: str
    title: str
    seo_title: str
    search_description: str
    body_lines: tuple
    content_sha256: str
    migration_status: str
    source: dict
    migration_notes: tuple
    media: tuple = ()

    @property
    def body_html(self):
        return "\n".join(self.body_lines)

    @property
    def has_body(self):
        text = unescape(_TAG_RE.sub("", self.body_html)).replace("\xa0", " ")
        return bool(text.strip())

    @property
    def has_required_content(self):
        """Title and a non-empty body: the minimum for a page that may be published."""
        return bool(self.title.strip()) and self.has_body

    @property
    def has_media(self):
        return bool(self.media)

    @property
    def media_by_key(self):
        return {item.key: item for item in self.media}


def _require_str(data, key, path):
    value = data.get(key)
    if not isinstance(value, str):
        raise PublicPageContentError(f"{path.name}: '{key}' must be a string.")
    return value


def _load_media(data, body, path, *, verify_files):
    raw = data.get("media", [])
    if not isinstance(raw, list):
        raise PublicPageContentError(f"{path.name}: 'media' must be a list.")
    items = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise PublicPageContentError(f"{path.name}: every 'media' entry must be an object.")
        key, sha, width, height = (entry.get(name) for name in ("key", "sha256", "width", "height"))
        if not isinstance(key, str) or not MEDIA_KEY_RE.match(key):
            raise PublicPageContentError(f"{path.name}: invalid media key {key!r}.")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise PublicPageContentError(f"{path.name}: media {key}: 'sha256' must be 64 hex digits.")
        if not (isinstance(width, int) and isinstance(height, int) and width > 0 and height > 0):
            raise PublicPageContentError(f"{path.name}: media {key}: width and height must be positive integers.")
        optional = {name: entry.get(name, "") for name in ("company", "alt_source", "source_url")}
        if not all(isinstance(value, str) for value in optional.values()):
            raise PublicPageContentError(f"{path.name}: media {key}: company, alt_source and source_url must be strings.")
        items.append(MediaItem(key=key, sha256=sha, width=width, height=height, **optional))

    by_key = {item.key: item for item in items}
    if len(by_key) != len(items):
        raise PublicPageContentError(f"{path.name}: duplicate media keys.")

    referenced = set()
    for line in body:
        if MEDIA_SRC_PREFIX not in line:
            continue
        media_line = parse_media_line(line)
        if media_line is None:
            raise PublicPageContentError(
                f"{path.name}: a body line refers to bundled media but is not one canonical <img> line: {line[:120]!r}"
            )
        item = by_key.get(media_line.key)
        if item is None:
            raise PublicPageContentError(f"{path.name}: body refers to unlisted media {media_line.key!r}.")
        if (media_line.width, media_line.height) != (item.width, item.height):
            raise PublicPageContentError(f"{path.name}: media {item.key}: body size differs from the media entry.")
        referenced.add(item.key)
    unused = sorted(set(by_key) - referenced)
    if unused:
        raise PublicPageContentError(f"{path.name}: media listed but not used in the body: {unused[:5]}")

    if verify_files:
        for item in items:
            if not item.path.is_file():
                raise PublicPageContentError(f"{path.name}: missing media file media/{item.key}.")
            if file_sha256(item.path) != item.sha256:
                raise PublicPageContentError(
                    f"{path.name}: media/{item.key} does not match its recorded sha256. If the file was "
                    "replaced intentionally, run `python -m cms.public_page_content --update-hashes`."
                )
    return tuple(items)


def load_public_page_content(slug, *, verify_hash=True):
    """Load and validate the content file for ``slug``."""
    if slug not in PUBLIC_PAGE_SLUGS:
        raise PublicPageContentError(f"'{slug}' is not one of the supported public pages.")
    path = content_path(slug)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PublicPageContentError(f"Missing content file {path.name}.") from exc
    except json.JSONDecodeError as exc:
        raise PublicPageContentError(f"{path.name} is not valid JSON: {exc}") from exc

    if data.get("format_version") != FORMAT_VERSION:
        raise PublicPageContentError(f"{path.name}: unsupported format_version {data.get('format_version')!r}.")
    if _require_str(data, "slug", path) != slug:
        raise PublicPageContentError(f"{path.name}: 'slug' must be '{slug}'.")
    title = _require_str(data, "title", path)
    if title != PUBLIC_PAGE_TITLES[slug]:
        raise PublicPageContentError(f"{path.name}: 'title' must be '{PUBLIC_PAGE_TITLES[slug]}'.")
    seo_title = _require_str(data, "seo_title", path)
    search_description = _require_str(data, "search_description", path)
    body = data.get("body_html")
    if not isinstance(body, list) or not all(isinstance(line, str) for line in body):
        raise PublicPageContentError(f"{path.name}: 'body_html' must be a list of strings.")
    status = _require_str(data, "migration_status", path)
    if status not in MIGRATION_STATUSES:
        raise PublicPageContentError(f"{path.name}: 'migration_status' must be one of {MIGRATION_STATUSES}.")
    recorded = _require_str(data, "content_sha256", path)
    media = _load_media(data, body, path, verify_files=verify_hash)

    computed = compute_content_hash(slug, title, seo_title, search_description, body, media)
    if verify_hash and computed != recorded:
        raise PublicPageContentError(
            f"{path.name}: content_sha256 is {recorded} but the content hashes to {computed}. "
            "If the edit was intentional, run `python -m cms.public_page_content --update-hashes` "
            "and copy the file to the frontend (src/content/public-pages/)."
        )

    content = PublicPageContent(
        slug=slug,
        title=title,
        seo_title=seo_title,
        search_description=search_description,
        body_lines=tuple(body),
        content_sha256=recorded,
        migration_status=status,
        source=dict(data.get("source") or {}),
        migration_notes=tuple(data.get("migration_notes") or ()),
        media=media,
    )
    if status == MIGRATED and not content.has_required_content:
        raise PublicPageContentError(f"{path.name}: marked '{MIGRATED}' but has no body.")
    if status == NOT_MIGRATED and content.has_body:
        raise PublicPageContentError(f"{path.name}: marked '{NOT_MIGRATED}' but has a body.")
    return content


def load_all_public_page_content(*, verify_hash=True):
    return [load_public_page_content(slug, verify_hash=verify_hash) for slug in PUBLIC_PAGE_SLUGS]


def dump_content_file(data):
    """Canonical file formatting (2-space JSON, UTF-8, trailing newline). Both repos store these bytes."""
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
