"""
Post-sync rewriting of imported Blog HTML (structural, never string replace):

  * inline images hosted on the configured WordPress site -> ECP storage URLs
    (srcset/sizes dropped once the image is migrated, so nothing points back
    to WordPress);
  * links to other imported WordPress Blog posts -> /blogs/<ecp-slug> (the
    Batch 2 reader route). Restricted/unimported targets keep their WordPress
    URL. Every other link is left alone.

The result always goes back through the importer's nh3 sanitiser.
Featured images follow the ownership policy in `sync_featured_image`.
"""
import logging
from collections import Counter
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from .media import MEDIA_PREFIX, MediaError, is_trusted_media_url, normalize_media_url
from .normalizer import classify_link, sanitize_html

logger = logging.getLogger(__name__)

BLOG_READER_PATH = "/blogs/"


def rewrite_inline_media(html, store, *, base_url, hosts, on_image=None):
    """Return (html, stats Counter, failures[list of dict]).

    `on_image(outcome)` is called once per image (for live progress).
    """
    stats, failures = Counter(), []

    def record(outcome):
        stats[outcome] += 1
        if on_image:
            on_image(outcome)

    soup = BeautifulSoup(html or "", "html.parser")
    changed = False
    for img in soup.find_all("img"):
        src = img.get("src") or ""
        if MEDIA_PREFIX in src:
            record("already_migrated")  # ECP storage URL (absolute S3 or relative /media/)
            continue
        url = normalize_media_url(src, base_url)
        if not url:
            continue
        stats["found"] += 1
        if not is_trusted_media_url(url, hosts):
            record("external")
            continue
        try:
            asset, downloaded = store.get_or_migrate(url)
        except MediaError as exc:
            failures.append({"url": url[:300], "code": exc.code, "message": exc.message[:200]})
            record("failed")
            continue
        record("migrated" if downloaded else "reused")
        img["src"] = store.url(asset)
        for stale in ("srcset", "sizes"):
            if img.has_attr(stale):
                del img[stale]
        changed = True
    if not changed:
        return html, stats, failures
    return sanitize_html(str(soup)), stats, failures


def blog_slug_mapping(posts, *, base_url, known_blog_slugs=()):
    """Map WordPress Blog slug -> ECP slug for imported posts (from wp_source_url)."""
    mapping = {}
    for wp_source_url, ecp_slug in posts:
        link = classify_link(wp_source_url, base_url, known_blog_slugs)
        if link.classification == "blog" and link.blog_slug:
            mapping[link.blog_slug] = ecp_slug
    return mapping


def rewrite_blog_links(html, mapping, *, base_url, restricted_slugs=(), known_blog_slugs=()):
    """Return (html, stats Counter). Only confidently identified Blog links change."""
    stats = Counter()
    soup = BeautifulSoup(html or "", "html.parser")
    changed = False
    restricted = set(restricted_slugs)
    for anchor in soup.find_all("a", href=True):
        link = classify_link(anchor["href"], base_url, known_blog_slugs)
        stats[f"class_{link.classification}"] += 1
        if link.classification != "blog":
            continue
        stats["blog_found"] += 1
        if link.blog_slug in mapping:
            fragment = urlsplit(anchor["href"]).fragment
            anchor["href"] = f"{BLOG_READER_PATH}{mapping[link.blog_slug]}" + (f"#{fragment}" if fragment else "")
            stats["rewritten"] += 1
            changed = True
        elif link.blog_slug in restricted:
            stats["restricted_target"] += 1
        else:
            stats["unresolved"] += 1
    if not changed:
        return html, stats
    return sanitize_html(str(soup)), stats


def sync_featured_image(blog, featured, store, *, hosts):
    """Apply the WordPress featured image to `blog` per the ownership policy.

    Returns (outcome, updates: dict of BlogPost fields to save, failure|None).
      * empty image, never imported      -> migrate and attach
      * importer-managed image, WP media changed -> migrate and attach the new one
      * importer-managed image, same WP media    -> unchanged (repointed if needed)
      * manual ECP image, or an imported image the admin removed -> left alone
      * featured image not on the configured WordPress host -> left external
    """
    current = blog.featured_image.name if blog.featured_image else ""
    managed = current.startswith(MEDIA_PREFIX)
    if featured is None or not featured.url:
        return "none", {}, None
    if current and not managed:
        return "ecp_owned", {}, None
    if not current and blog.wp_featured_media_id is not None:
        return "ecp_removed", {}, None
    url = normalize_media_url(featured.url, "")
    if not is_trusted_media_url(url, hosts):
        return "external", {}, None
    try:
        asset, downloaded = store.get_or_migrate(url)
    except MediaError as exc:
        return "failed", {}, {"url": url[:300], "code": exc.code, "message": exc.message[:200]}
    if current == asset.storage_name and blog.wp_featured_media_id == featured.wp_id:
        return "unchanged", {}, None
    return ("migrated" if downloaded else "reused"), {
        "featured_image": asset.storage_name,
        "wp_featured_media_id": featured.wp_id,
    }, None
