"""
Safe WordPress public bbPress forum mapping/import helpers.

This module is intentionally separate from WordPress group sync. Public/separate
bbPress forums are not BuddyPress groups, so they have no member sync. Admins
must explicitly create/link a public Connect group before topics/replies import.
"""
from __future__ import annotations

import logging
from typing import Any, Dict
from urllib.parse import unquote, urlparse

from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone
from django.utils.html import strip_tags
from django.utils.text import slugify

from activity_feed.models import FeedItem
from users.wordpress_api import WordPressAPIClient
from .models import Group, WordPressForumSource
from .wordpress_group_sync import (
    _connect_user_for_wordpress_author,
    _fallback_actor_for_group,
    _group_ct,
    _import_wordpress_topic_replies,
    _int,
    _json_has_wordpress_bbpress_topic_id,
    _source_created_at_from_payload,
    _text,
    _topic_text,
    _wp_author_payload,
)

logger = logging.getLogger(__name__)


def _forum_group_slug(forum_payload: Dict[str, Any]) -> str:
    """Return BuddyPress group slug for /groups/<slug>/forum/ forum URLs."""
    url = str(forum_payload.get("url") or "")
    parts = [p for p in urlparse(url).path.strip("/").split("/") if p]
    if len(parts) >= 3 and parts[0] == "groups" and parts[-1] == "forum":
        return unquote(parts[1]).strip()
    return ""


def _forum_public_slug(forum_payload: Dict[str, Any]) -> str:
    """Return a stable slug for /forums/forum/<slug>/ public forums."""
    for key in ("slug", "name_slug", "post_name"):
        value = str(forum_payload.get(key) or "").strip()
        if value:
            return slugify(unquote(value))[:255]

    url = str(forum_payload.get("url") or "")
    parts = [p for p in urlparse(url).path.strip("/").split("/") if p]
    if parts:
        return slugify(unquote(parts[-1]))[:255]
    return ""


def _forum_description(forum_payload: Dict[str, Any]) -> str:
    raw = forum_payload.get("description") or forum_payload.get("content") or ""
    if isinstance(raw, dict):
        raw = raw.get("rendered") or raw.get("raw") or ""
    return strip_tags(str(raw or "")).strip()


def refresh_wordpress_public_forum_sources(*, max_pages: int = 100) -> Dict[str, int]:
    """
    Refresh public/separate bbPress forum catalog rows from WordPress.

    Group-connected forums under /groups/<slug>/forum/ are skipped here because
    those already import through the WordPressGroupSource Full Import flow.
    """
    client = WordPressAPIClient.for_group_sync()
    forums = client.get_all_imaa_connect_forum_content_forums(per_page=100, max_pages=max_pages)
    now = timezone.now()

    created = 0
    updated = 0
    skipped_group_forums = 0
    skipped_missing_id = 0

    for payload in forums:
        wp_forum_id = _int(payload.get("id"))
        if not wp_forum_id:
            skipped_missing_id += 1
            continue
        group_slug = _forum_group_slug(payload)
        if group_slug:
            skipped_group_forums += 1
            continue

        title = _text(payload.get("title") or payload.get("name")) or f"WordPress Forum {wp_forum_id}"
        defaults = {
            "title": title[:255],
            "slug": _forum_public_slug(payload)[:255],
            "description": _forum_description(payload),
            "status": str(payload.get("status") or "")[:50],
            "source_type": WordPressForumSource.SOURCE_TYPE_PUBLIC,
            "group_slug": "",
            "topic_count": max(_int(payload.get("topic_count")) or 0, 0),
            "reply_count": max(_int(payload.get("reply_count")) or 0, 0),
            "forum_url": str(payload.get("url") or "")[:200],
            "raw_payload": payload,
            "last_fetched_at": now,
        }
        _source, was_created = WordPressForumSource.objects.update_or_create(
            wp_forum_id=wp_forum_id,
            defaults=defaults,
        )
        if was_created:
            created += 1
        else:
            updated += 1

    return {
        "created": created,
        "updated": updated,
        "skipped_group_forums": skipped_group_forums,
        "skipped_missing_id": skipped_missing_id,
        "total": WordPressForumSource.objects.filter(source_type=WordPressForumSource.SOURCE_TYPE_PUBLIC).count(),
    }


def _unique_group_slug(base_slug: str, *, exclude_group_id: int | None = None) -> str:
    base = slugify(base_slug or "wordpress-forum")[:210].strip("-") or "wordpress-forum"
    slug = base
    i = 2
    qs = Group.all_objects.all()
    if exclude_group_id:
        qs = qs.exclude(pk=exclude_group_id)
    while qs.filter(slug=slug).exists():
        suffix = f"-{i}"
        slug = f"{base[:220 - len(suffix)]}{suffix}"
        i += 1
    return slug


def sync_wordpress_forum_source_to_connect_group(
    source: WordPressForumSource,
    *,
    actor,
) -> tuple[Group, bool]:
    """Create/update the public Connect group that receives one public forum."""
    if source.source_type != WordPressForumSource.SOURCE_TYPE_PUBLIC:
        raise ValueError("Only public/separate WordPress forum sources can use this sync flow.")
    if not actor or not getattr(actor, "is_authenticated", False):
        raise ValueError("An authenticated admin user is required to create a public forum group.")

    now = timezone.now()
    source_key = f"forum:{source.wp_forum_id}"
    group_name = source.title if source.title.startswith("Forum:") else f"Forum: {source.title}"
    description = source.description or f"Imported public WordPress forum: {source.title}"

    group = source.linked_group
    created = False
    if not group:
        group = Group.all_objects.filter(
            source=Group.SOURCE_WORDPRESS,
            source_group_id=source_key,
        ).first()

    defaults = {
        "name": group_name[:200],
        "description": description,
        "visibility": Group.VISIBILITY_PUBLIC,
        "join_policy": Group.JOIN_OPEN,
        "posts_comments_enabled": True,
        "posts_creation_restricted": False,
        "forum_enabled": True,
        "source": Group.SOURCE_WORDPRESS,
        "source_group_id": source_key,
        "source_slug": source.slug,
        "source_url": source.forum_url,
        "source_synced_at": now,
    }

    with transaction.atomic():
        if group:
            for key, value in defaults.items():
                setattr(group, key, value)
            if not group.slug:
                group.slug = _unique_group_slug(f"forum-{source.slug or source.wp_forum_id}", exclude_group_id=group.id)
            group.save()
        else:
            group = Group.objects.create(
                **defaults,
                slug=_unique_group_slug(f"forum-{source.slug or source.wp_forum_id}"),
                created_by=actor,
                owner=actor,
            )
            created = True

        source.sync_enabled = True
        source.linked_group = group
        source.last_synced_at = now
        source.save(update_fields=["sync_enabled", "linked_group", "last_synced_at", "updated_at"])

    return group, created


def import_wordpress_public_forum_source_content(
    source: WordPressForumSource,
    *,
    actor=None,
    dry_run: bool = False,
    max_pages: int = 100,
) -> Dict[str, int]:
    """
    Import one explicitly-linked public forum's topics/replies into its Connect group.

    This is additive and idempotent. It never deletes WordPress content, Connect
    groups, existing posts, existing comments, or users.
    """
    if source.source_type != WordPressForumSource.SOURCE_TYPE_PUBLIC:
        raise ValueError("Only public/separate WordPress forum sources can use this import flow.")
    if not source.linked_group_id:
        raise ValueError("Create/link a public Connect group before importing this forum.")

    group = source.linked_group
    fallback_actor = _fallback_actor_for_group(group, actor=actor)
    if not fallback_actor:
        fallback_actor = User.objects.filter(is_staff=True).order_by("id").first()
    if not fallback_actor:
        raise ValueError("Unable to resolve a fallback Connect user for imported forum content.")

    client = WordPressAPIClient.for_group_sync()
    group_ct = _group_ct()

    topics_processed = 0
    topics_imported = 0
    topics_skipped_existing = 0
    topics_skipped_empty = 0
    replies_processed = 0
    replies_imported = 0
    replies_skipped_existing = 0
    replies_skipped_empty = 0
    failed = 0

    try:
        topics = client.get_all_imaa_connect_forum_topics(source.wp_forum_id, per_page=100, max_pages=max_pages)
    except Exception as exc:  # pragma: no cover - network safety
        logger.exception("Unable to fetch WordPress bbPress topics for public forum %s: %s", source.wp_forum_id, exc)
        return {
            "wp_forum_id": source.wp_forum_id,
            "topics_processed": 0,
            "topics_imported": 0,
            "topics_skipped_existing": 0,
            "topics_skipped_empty": 0,
            "replies_processed": 0,
            "replies_imported": 0,
            "replies_skipped_existing": 0,
            "replies_skipped_empty": 0,
            "failed": 1,
            "dry_run": bool(dry_run),
        }

    for topic_payload in topics:
        topic_id = _int(topic_payload.get("id"))
        if not topic_id:
            failed += 1
            continue
        topics_processed += 1

        existing = FeedItem.objects.filter(group=group).filter(_json_has_wordpress_bbpress_topic_id(topic_id)).first()
        if existing:
            topics_skipped_existing += 1
            topic_item = existing
        else:
            text = _topic_text(topic_payload)
            if not text:
                topics_skipped_empty += 1
                continue

            source_created_at = _source_created_at_from_payload(topic_payload)
            author = _connect_user_for_wordpress_author(topic_payload, fallback_actor=fallback_actor)
            topic_title = _text(topic_payload.get("title"))
            topic_metadata = {
                "type": "text",
                "text": text,
                "group_id": group.id,
                "is_hidden": False,
                "is_deleted": False,
                "source": "wordpress",
                "source_system": "wordpress",
                "source_object_type": "bbpress_topic",
                "source_topic_id": str(topic_id),
                "wordpress_topic_id": str(topic_id),
                "wordpress_forum_id": str(source.wp_forum_id),
                "wordpress_forum_source_type": "public",
                "wordpress_public_forum_source_id": str(source.id),
                "wordpress_forum_title": source.title,
                "wordpress_forum_url": source.forum_url,
                "wordpress_topic_title": topic_title,
                "wordpress_user_id": str((_wp_author_payload(topic_payload) or {}).get("id") or ""),
                "wordpress_link": str(topic_payload.get("url") or ""),
                "wordpress_created_at": (source_created_at.isoformat() if source_created_at else str(topic_payload.get("date") or "")),
                "wordpress_last_active_time": str(topic_payload.get("last_active_time") or ""),
            }
            content_html = str(topic_payload.get("content_html") or "")
            if content_html and content_html != text:
                topic_metadata["wordpress_content_html"] = content_html

            if dry_run:
                topics_imported += 1
                topic_item = None
            else:
                try:
                    with transaction.atomic():
                        topic_item = FeedItem.objects.create(
                            community=group.community,
                            group=group,
                            event=None,
                            actor=author,
                            verb="posted",
                            target_content_type=group_ct,
                            target_object_id=group.id,
                            metadata=topic_metadata,
                        )
                        if source_created_at:
                            FeedItem.objects.filter(pk=topic_item.pk).update(created_at=source_created_at)
                    topics_imported += 1
                except Exception as exc:  # pragma: no cover - defensive import safety
                    failed += 1
                    logger.exception("Unable to import WordPress public bbPress topic %s: %s", topic_id, exc)
                    continue

        if topic_item is None:
            # In dry-run, count replies that WordPress would return even though no local topic exists yet.
            try:
                reply_payloads = client.get_all_imaa_connect_forum_topic_replies(topic_id, per_page=100, max_pages=max_pages)
                replies_processed += len(reply_payloads)
                replies_imported += len([r for r in reply_payloads if _text(r.get("content_text") or r.get("content_html") or r.get("content"))])
            except Exception:
                failed += 1
            continue

        reply_result = _import_wordpress_topic_replies(
            client=client,
            feed_item=topic_item,
            topic_payload=topic_payload,
            fallback_actor=fallback_actor,
            dry_run=dry_run,
            max_pages=max_pages,
        )
        replies_processed += int(reply_result.get("processed") or 0)
        replies_imported += int(reply_result.get("imported") or 0)
        replies_skipped_existing += int(reply_result.get("skipped_existing") or 0)
        replies_skipped_empty += int(reply_result.get("skipped_empty") or 0)
        failed += int(reply_result.get("failed") or 0)

    if not dry_run:
        source.last_imported_at = timezone.now()
        source.save(update_fields=["last_imported_at", "updated_at"])

    return {
        "wp_forum_id": source.wp_forum_id,
        "connect_group_id": group.id,
        "topics_processed": topics_processed,
        "topics_imported": topics_imported,
        "topics_skipped_existing": topics_skipped_existing,
        "topics_skipped_empty": topics_skipped_empty,
        "replies_processed": replies_processed,
        "replies_imported": replies_imported,
        "replies_skipped_existing": replies_skipped_existing,
        "replies_skipped_empty": replies_skipped_empty,
        "failed": failed,
        "dry_run": bool(dry_run),
    }
