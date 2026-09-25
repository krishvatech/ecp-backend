"""
Raw WordPress post JSON -> NormalizedWordPressBlog. No database access.

Parsed once per post; everything downstream works from the normalized object.
"""
import logging
import re
from datetime import datetime, timezone as dt_timezone

from .formats import detect_source_format
from .normalizer import collapse, normalize_excerpt, normalize_wordpress_html, text_from_html
from .types import (
    FORMAT_MIXED,
    FORMAT_UNKNOWN,
    W_AUTHOR_NAME_MISSING,
    W_CANONICAL_MISSING,
    W_FEATURED_IMAGE_UNRESOLVED,
    W_MISSING_FEATURED_IMAGE,
    W_MIXED_CONTENT,
    W_SEO_DESCRIPTION_MISSING,
    W_SEO_DESCRIPTION_SUSPICIOUS,
    W_SEO_TITLE_MISSING,
    W_TAXONOMY_RESOLUTION_FAILED,
    W_UNKNOWN_CONTENT_FORMAT,
    FeaturedMedia,
    ImportWarning,
    NormalizedWordPressBlog,
    TermRef,
)

logger = logging.getLogger(__name__)


class WordPressPostParseError(ValueError):
    """The payload is not a usable WordPress post."""


def _rendered(value):
    if isinstance(value, dict):
        return value.get("rendered") or ""
    return value if isinstance(value, str) else ""


def parse_wp_datetime(gmt_value, local_value=None):
    """Parse WordPress `*_gmt` (naive UTC) into an aware UTC datetime."""
    for value, assume_utc in ((gmt_value, True), (local_value, False)):
        if not value or str(value).startswith("0000"):
            continue
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            continue
        if parsed.tzinfo is None:
            if not assume_utc:
                # Local site time without offset: unusable safely; keep looking.
                continue
            parsed = parsed.replace(tzinfo=dt_timezone.utc)
        return parsed.astimezone(dt_timezone.utc)
    return None


def _embedded_terms(payload):
    categories, tags = [], []
    for group in (payload.get("_embedded") or {}).get("wp:term") or []:
        if not isinstance(group, list):
            continue
        for term in group:
            if not isinstance(term, dict) or "id" not in term:
                continue
            if term.get("taxonomy") == "category":
                categories.append(term)
            elif term.get("taxonomy") == "post_tag":
                tags.append(term)
    return categories, tags


def _term_ref(term):
    name = text_from_html(term.get("name", ""))[:120]
    return TermRef(wp_id=int(term["id"]), name=name, slug=str(term.get("slug") or "")[:140])


def _resolve_terms(ids, embedded, taxonomy, client, warnings):
    ids = [int(i) for i in ids or [] if str(i).isdigit()]
    by_id = {int(t["id"]): t for t in embedded}
    if client is not None:
        client.remember_terms(taxonomy, embedded)
        missing = [i for i in ids if i not in by_id]
        if missing:
            try:
                by_id.update({k: v for k, v in client.get_terms(taxonomy, missing).items() if v})
            except Exception as exc:  # network errors must not kill the post parse
                logger.warning("WordPress %s lookup failed: %s", taxonomy, exc)
    refs = []
    for term_id in ids:
        term = by_id.get(term_id)
        if term and term.get("name"):
            refs.append(_term_ref(term))
        else:
            warnings.append(ImportWarning(W_TAXONOMY_RESOLUTION_FAILED, f"{taxonomy} {term_id}"))
    return refs


def _featured_media(payload, client, warnings):
    media_id = payload.get("featured_media") or 0
    try:
        media_id = int(media_id)
    except (TypeError, ValueError):
        media_id = 0
    if not media_id:
        warnings.append(ImportWarning(W_MISSING_FEATURED_IMAGE))
        return None, None
    media = None
    for item in (payload.get("_embedded") or {}).get("wp:featuredmedia") or []:
        if isinstance(item, dict) and item.get("id") == media_id and item.get("source_url"):
            media = item
            break
    if media is None and client is not None:
        media = client.get_media(media_id)
    if not media or not media.get("source_url"):
        warnings.append(ImportWarning(W_FEATURED_IMAGE_UNRESOLVED, str(media_id)))
        return media_id, None
    details = media.get("media_details") or {}
    return media_id, FeaturedMedia(
        wp_id=media_id,
        url=media.get("source_url", ""),
        alt=collapse(media.get("alt_text", "")),
        caption=text_from_html(_rendered(media.get("caption"))),
        mime_type=media.get("mime_type", ""),
        width=details.get("width") if isinstance(details.get("width"), int) else None,
        height=details.get("height") if isinstance(details.get("height"), int) else None,
    )


def _author_name(payload, yoast, client):
    """Display name: Yoast byline, then embedded author (if valid), then users endpoint."""
    misc = yoast.get("twitter_misc") if isinstance(yoast.get("twitter_misc"), dict) else {}
    for candidate in (misc.get("Written by"), yoast.get("author")):
        if isinstance(candidate, str) and collapse(candidate):
            return collapse(candidate)
    for author in (payload.get("_embedded") or {}).get("author") or []:
        if isinstance(author, dict) and author.get("name") and "code" not in author:
            return collapse(author["name"])
    author_id = payload.get("author")
    if client is not None and isinstance(author_id, int) and author_id > 0:
        return collapse(client.get_user_name(author_id))
    return ""


def parse_wordpress_post(payload, *, site_url="", client=None, known_blog_slugs=()):
    if not isinstance(payload, dict):
        raise WordPressPostParseError("post payload is not an object")
    try:
        wp_post_id = int(payload.get("id"))
    except (TypeError, ValueError):
        raise WordPressPostParseError("post has no numeric id")
    if wp_post_id <= 0:
        raise WordPressPostParseError("post has no numeric id")
    if "content" not in payload or "title" not in payload:
        raise WordPressPostParseError(f"post {wp_post_id} is missing title/content")

    warnings = []
    raw_html = _rendered(payload.get("content"))
    source_format = detect_source_format(raw_html)
    if source_format == FORMAT_MIXED:
        warnings.append(ImportWarning(W_MIXED_CONTENT))
    elif source_format == FORMAT_UNKNOWN:
        warnings.append(ImportWarning(W_UNKNOWN_CONTENT_FORMAT))

    yoast = payload.get("yoast_head_json") if isinstance(payload.get("yoast_head_json"), dict) else {}
    # Yoast returns HTML-escaped strings (e.g. "M&amp;A"); store plain text.
    seo_title = text_from_html(yoast.get("title") or "")[:255]
    seo_description = text_from_html(yoast.get("description") or "")
    canonical = (yoast.get("canonical") or "").strip()
    # A bare path/slug (no spaces) is a data-entry mistake, not a description.
    if seo_description and re.fullmatch(r"/?[\w\-/.]+", seo_description):
        warnings.append(ImportWarning(W_SEO_DESCRIPTION_SUSPICIOUS, seo_description[:80]))
        seo_description = ""
    if not seo_title:
        warnings.append(ImportWarning(W_SEO_TITLE_MISSING))
    if not seo_description:
        warnings.append(ImportWarning(W_SEO_DESCRIPTION_MISSING))
    if not canonical:
        warnings.append(ImportWarning(W_CANONICAL_MISSING))

    embedded_categories, embedded_tags = _embedded_terms(payload)
    categories = _resolve_terms(payload.get("categories"), embedded_categories, "categories", client, warnings)
    tags = _resolve_terms(payload.get("tags"), embedded_tags, "tags", client, warnings)
    featured_media_id, featured_media = _featured_media(payload, client, warnings)

    author_id = payload.get("author") if isinstance(payload.get("author"), int) and payload.get("author") > 0 else None
    author_name = _author_name(payload, yoast, client)
    if not author_name:
        warnings.append(ImportWarning(W_AUTHOR_NAME_MISSING, str(author_id or "")))

    content = normalize_wordpress_html(raw_html, source_format, site_url=site_url, known_blog_slugs=known_blog_slugs)

    return NormalizedWordPressBlog(
        wp_post_id=wp_post_id,
        status=str(payload.get("status") or ""),
        title=text_from_html(_rendered(payload.get("title"))),
        slug=str(payload.get("slug") or ""),
        excerpt=normalize_excerpt(_rendered(payload.get("excerpt"))),
        content=content,
        source_format=source_format,
        wp_author_id=author_id,
        wp_author_name=author_name,
        published_at=parse_wp_datetime(payload.get("date_gmt"), payload.get("date")),
        modified_at=parse_wp_datetime(payload.get("modified_gmt"), payload.get("modified")),
        featured_media_id=featured_media_id,
        featured_media=featured_media,
        categories=categories,
        tags=tags,
        seo_title=seo_title,
        seo_description=seo_description,
        source_canonical_url=canonical,
        source_url=str(payload.get("link") or ""),
        warnings=warnings,
    )
