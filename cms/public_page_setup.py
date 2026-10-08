"""Shared building blocks of the public page commands.

``manage.py setup_public_pages`` (create missing pages) and ``manage.py
populate_public_page_draft`` (fill an existing empty draft) use the same Site and root
checks, the same dry-run write guard, and the same handling of bundled media. The approved
content itself lives in ``cms.public_page_content`` (importable without Django).
"""

import re
from html import unescape

from django.core.files.images import ImageFile
from django.core.management.base import CommandError
from wagtail.images import get_image_model
from wagtail.images.formats import get_image_format
from wagtail.models import Collection
from wagtail.utils.file import hash_filelike

from cms.models import HomePage
from cms.public_page_content import parse_media_line
from cms.public_pages import PublicSiteConfigurationError, is_archived, resolve_public_site

MEDIA_COLLECTION_NAME = "Public website pages"

_TAG_RE = re.compile(r"<[^>]+>")


class DryRunWriteGuard:
    """Database execute wrapper: refuse every statement except SELECT."""

    def __call__(self, execute, sql, params, many, context):
        statement = sql.lstrip().split(None, 1)[0].upper() if sql and sql.strip() else ""
        if statement != "SELECT":
            raise CommandError(
                f"Dry run attempted a database write ({statement or 'empty statement'}); aborted, nothing was changed."
            )
        return execute(sql, params, many, context)


def resolve_site_and_root():
    """The public Site (same rules as the public API) and its root, which must be the HomePage."""
    try:
        site = resolve_public_site()
    except PublicSiteConfigurationError as exc:
        raise CommandError(f"Cannot choose the public Wagtail Site, nothing was changed: {exc}") from exc

    root = site.root_page.specific
    if not isinstance(root, HomePage) or is_archived(root):
        found = "an archived HomePage" if isinstance(root, HomePage) else f"{type(root).__name__}"
        candidates = [
            f"#{home.pk} '{home.title}' (slug '{home.slug}', {'live' if home.live else 'not live'})"
            for home in HomePage.objects.filter(cms_is_deleted=False).order_by("pk")
        ]
        hint = (
            f" HomePages in this database: {', '.join(candidates)}."
            if candidates
            else " This database has no HomePage; create the IMAA Connect HomePage in Wagtail first."
        )
        raise CommandError(
            f"The public Site '{site.hostname}:{site.port}' has root page #{root.pk} '{root.title}' "
            f"({found}), not the IMAA Connect HomePage. Set the Site's root page in "
            f"Wagtail > Settings > Sites (or CMS_PUBLIC_SITE_HOSTNAME) and run this again. "
            f"Nothing was changed.{hint}"
        )
    return site, root


def rich_text_is_empty(html):
    """True when rich text has no visible text and no embedded image or media."""
    html = html or ""
    if "<embed" in html or "<img" in html:
        return False
    text = unescape(_TAG_RE.sub("", html)).replace("\xa0", " ")
    return not text.strip()


# -- bundled media ----------------------------------------------------------------------


def _embed_attr(value):
    # Exactly the entities Wagtail's rich-text attribute parser decodes (wagtail.rich_text.rewriters).
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def media_file_hashes(content):
    """``{key: Wagtail file_hash}`` (SHA-1, as stored on Wagtail images) for each bundled file."""
    hashes = {}
    for item in content.media:
        with open(item.path, "rb") as fh:
            hashes[item.key] = hash_filelike(fh)
    return hashes


def find_media_images(content):
    """Images already in the Wagtail library for ``content``'s media, matched by file content.

    Returns ``({key: image}, [missing keys])``. Read-only.
    """
    if not content.media:
        return {}, []
    hashes = media_file_hashes(content)
    by_hash = {}
    for image in get_image_model().objects.filter(file_hash__in=set(hashes.values())).order_by("pk"):
        by_hash.setdefault(image.file_hash, image)
    found = {key: by_hash[file_hash] for key, file_hash in hashes.items() if file_hash in by_hash}
    missing = [item.key for item in content.media if item.key not in found]
    return found, missing


def media_collection():
    """The Wagtail collection for imported public-page media (created on first use)."""
    root = Collection.get_first_root_node()
    existing = Collection.objects.filter(
        path__startswith=root.path, depth=root.depth + 1, name=MEDIA_COLLECTION_NAME
    ).first()
    return existing or root.add_child(name=MEDIA_COLLECTION_NAME)


def import_media_images(content, progress=None):
    """Make sure every bundled file of ``content`` is a Wagtail image; reuse identical files.

    Returns ``({key: image}, number of images created)``. Writes files to the configured
    media storage, so call it only when applying. ``progress(done, total)`` is called while
    importing (uploads to remote storage take a while for the 258 References logos).
    """
    images, missing = find_media_images(content)
    if not missing:
        return images, 0
    collection = media_collection()
    image_model = get_image_model()
    for done, key in enumerate(missing, start=1):
        item = content.media_by_key[key]
        title = f"{item.company} logo" if item.company else item.filename.rsplit(".", 1)[0]
        image = image_model(title=title[:255], collection=collection)
        with open(item.path, "rb") as fh:
            image.file.save(item.filename, ImageFile(fh, name=item.filename), save=False)
        image._set_image_file_metadata()
        image.save()
        images[key] = image
        if progress:
            progress(done, len(missing))
    return images, len(missing)


def prepare_media_renditions(content, images, progress=None):
    """Create the renditions the page will show (one per image and rich-text format).

    Wagtail otherwise renders them on the first public request, which for a logo wall on
    remote storage can take longer than the request may. Existing renditions are reused.
    """
    lines = [line for line in (parse_media_line(raw) for raw in content.body_lines) if line is not None]
    for done, media_line in enumerate(lines, start=1):
        images[media_line.key].get_rendition(get_image_format(media_line.format).filter_spec)
        if progress:
            progress(done, len(lines))


def render_cms_body(content, images):
    """The body in Wagtail's rich-text storage format: each bundled image becomes an image embed
    in the line's format (for example ``logo``); every other line is stored as it is."""
    lines = []
    for line in content.body_lines:
        media_line = parse_media_line(line)
        if media_line is None:
            lines.append(line)
            continue
        image = images[media_line.key]
        lines.append(
            f'<embed alt="{_embed_attr(media_line.alt)}" embedtype="image" '
            f'format="{media_line.format}" id="{image.pk}"/>'
        )
    return "\n".join(lines)


def progress_printer(stdout, label, every=50):
    """A ``progress(done, total)`` callback that prints every ``every`` items and at the end."""

    def progress(done, total):
        if done == total or done % every == 0:
            stdout.write(f"  {label}: {done}/{total}")

    return progress


def describe_media_plan(content):
    """Operator text for the media a page needs, e.g. "258 logo images: 3 in the library, 255 to import"."""
    if not content.media:
        return ""
    found, missing = find_media_images(content)
    return (
        f"{len(content.media)} bundled images: {len(found)} already in the Wagtail image library, "
        f"{len(missing)} to import into the '{MEDIA_COLLECTION_NAME}' collection"
    )
