"""WordPress IMAA BuddyPress group discovery sync.

Phase 1 intentionally imports only the WordPress group catalog into
WordPressGroupSource. Phase 2 can also create/update selected Connect Group rows.
"""

import html
import logging
import re
from datetime import timezone as datetime_timezone
from typing import Any, Dict, Iterable
from urllib.parse import unquote, urlparse

from django.contrib.auth.models import User
from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.html import strip_tags
from django.utils.text import slugify

from activity_feed.models import FeedItem
from engagements.models import Comment
from users.wordpress_api import WordPressAPIClient
from users.models import UserProfile
from .models import Group, GroupMembership, WordPressGroupSource

logger = logging.getLogger(__name__)


def _text(value: Any) -> str:
    """Normalize WordPress/BuddyPress text values that may be strings or rendered dicts."""
    if value is None:
        return ""
    if isinstance(value, dict):
        value = value.get("rendered") or value.get("raw") or value.get("plaintext") or ""
    value = html.unescape(strip_tags(str(value)))
    value = re.sub(r"\s+", " ", value).strip()
    return value


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _wp_datetime(value: Any):
    """Parse a WordPress REST datetime string into an aware Django datetime."""
    if not value:
        return None
    parsed = parse_datetime(str(value))
    if not parsed:
        return None
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone=datetime_timezone.utc)
    return parsed


def _json_has_wordpress_activity_id(activity_id: int) -> Q:
    """Match old/new metadata shapes and int/string JSON values for idempotency."""
    return (
        Q(metadata__source="wordpress", metadata__wordpress_activity_id=activity_id)
        | Q(metadata__source="wordpress", metadata__wordpress_activity_id=str(activity_id))
        | Q(metadata__source_activity_id=activity_id)
        | Q(metadata__source_activity_id=str(activity_id))
    )


def normalize_buddypress_group(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Map a BuddyPress REST group payload into our source table shape."""
    group_id = _int(payload.get("id") or payload.get("ID") or payload.get("group_id"))
    name = _text(payload.get("name") or payload.get("title"))
    slug = str(payload.get("slug") or "").strip()
    description = _text(
        payload.get("description")
        or payload.get("content")
        or payload.get("excerpt")
        or payload.get("description_raw")
    )
    status = str(payload.get("status") or payload.get("privacy") or "").strip().lower()
    member_count = _int(
        payload.get("total_member_count")
        or payload.get("members_count")
        or payload.get("member_count")
        or payload.get("count")
    )
    group_url = str(payload.get("link") or payload.get("permalink") or payload.get("url") or "").strip()

    return {
        "wp_group_id": group_id,
        "name": name or f"WordPress Group {group_id}",
        "slug": slug,
        "description": description,
        "status": status,
        "member_count": member_count,
        "group_url": group_url,
        "raw_payload": payload,
    }


def refresh_wordpress_group_sources(groups: Iterable[Dict[str, Any]] | None = None) -> Dict[str, int]:
    """
    Refresh discovered WordPress groups.

    Returns counters. Existing sync_enabled values are preserved so a refresh
    never disables an admin-selected group.
    """
    client = None
    if groups is None:
        # Use the dedicated IMAA group-sync WordPress configuration. Do not use
        # the existing WP_IMAA_* config here because that may already be used
        # for staging.manda.sg / MANDA sync.
        client = WordPressAPIClient.for_group_sync()
        groups = client.get_all_buddypress_groups()

    now = timezone.now()
    created = 0
    updated = 0
    skipped = 0

    for payload in groups:
        normalized = normalize_buddypress_group(payload)
        wp_group_id = normalized.get("wp_group_id")
        if not wp_group_id:
            skipped += 1
            logger.warning("Skipping WordPress group without ID: %s", payload)
            continue

        member_count = normalized["member_count"]
        if member_count == 0 and client is not None:
            # BuddyPress group list can return total_member_count=0 for private
            # groups even when the admin screen shows members. The members
            # endpoint exposes the real count in the X-WP-Total header.
            try:
                member_count = client.get_buddypress_group_member_count(wp_group_id)
            except Exception as exc:  # pragma: no cover - network safety
                logger.warning(
                    "Unable to fetch member count for WordPress group %s: %s",
                    wp_group_id,
                    exc,
                )

        defaults = {
            "name": normalized["name"],
            "slug": normalized["slug"],
            "description": normalized["description"],
            "status": normalized["status"],
            "member_count": member_count,
            "group_url": normalized["group_url"],
            "raw_payload": normalized["raw_payload"],
            "last_fetched_at": now,
        }
        _, was_created = WordPressGroupSource.objects.update_or_create(
            wp_group_id=wp_group_id,
            defaults=defaults,
        )
        if was_created:
            created += 1
        else:
            updated += 1

    return {"created": created, "updated": updated, "skipped": skipped}



def _visibility_from_status(status: str) -> str:
    """Map BuddyPress group privacy to the existing Connect visibility choices."""
    return Group.VISIBILITY_PUBLIC if str(status or "").lower() == "public" else Group.VISIBILITY_PRIVATE


def _join_policy_from_status(status: str) -> str:
    """Map BuddyPress privacy to a valid Connect join policy.

    Connect validation requires private groups to be invite-only. WordPress
    members are still synced directly into the linked group, so this does not
    block imported members from accessing their group.
    """
    status = str(status or "").lower()
    if status == "public":
        return Group.JOIN_OPEN
    return Group.JOIN_INVITE


def _unique_group_slug(base_value: str, wp_group_id: int, existing_group: Group | None = None) -> str:
    """Return a unique Connect group slug for a WordPress source group."""
    base = slugify(base_value or "") or f"wordpress-group-{wp_group_id}"
    base = base[:180].strip("-") or f"wordpress-group-{wp_group_id}"

    qs = Group.all_objects.all()
    if existing_group and existing_group.pk:
        qs = qs.exclude(pk=existing_group.pk)

    if not qs.filter(slug=base).exists():
        return base

    wp_slug = f"{base}-wp-{wp_group_id}"[:220].strip("-")
    if not qs.filter(slug=wp_slug).exists():
        return wp_slug

    for i in range(2, 1000):
        suffix = f"-wp-{wp_group_id}-{i}"
        candidate = f"{base[:220 - len(suffix)]}{suffix}".strip("-")
        if not qs.filter(slug=candidate).exists():
            return candidate

    raise ValueError(f"Unable to generate a unique slug for WordPress group {wp_group_id}")


def sync_wordpress_source_to_connect_group(source: WordPressGroupSource, *, actor) -> tuple[Group, bool]:
    """
    Create or update the existing Connect Group row for a selected WP group.

    Phase 2 only creates/updates the group shell. It does not create users or
    group memberships. Existing manual groups are never overwritten.
    """
    if not actor or not getattr(actor, "is_authenticated", False):
        raise ValueError("An authenticated admin user is required to sync a WordPress group.")

    now = timezone.now()
    source_group_id = str(source.wp_group_id)

    group = source.linked_group
    if not group:
        group = Group.all_objects.filter(
            source=Group.SOURCE_WORDPRESS,
            source_group_id=source_group_id,
        ).first()

    created = group is None

    raw = source.raw_payload or {}
    forum_enabled = bool(raw.get("enable_forum")) if isinstance(raw, dict) else False

    with transaction.atomic():
        if created:
            group = Group(
                name=source.name,
                slug=_unique_group_slug(source.slug or source.name, source.wp_group_id),
                description=source.description,
                visibility=_visibility_from_status(source.status),
                join_policy=_join_policy_from_status(source.status),
                forum_enabled=forum_enabled,
                source=Group.SOURCE_WORDPRESS,
                source_group_id=source_group_id,
                source_slug=source.slug or "",
                source_url=source.group_url or "",
                source_synced_at=now,
                created_by=actor,
                owner=actor,
            )
        else:
            group.name = source.name
            # Do not change an existing slug because local URLs may already be shared.
            if not group.slug:
                group.slug = _unique_group_slug(source.slug or source.name, source.wp_group_id, existing_group=group)
            group.description = source.description
            group.visibility = _visibility_from_status(source.status)
            group.join_policy = _join_policy_from_status(source.status)
            group.forum_enabled = forum_enabled
            group.source = Group.SOURCE_WORDPRESS
            group.source_group_id = source_group_id
            group.source_slug = source.slug or ""
            group.source_url = source.group_url or ""
            group.source_synced_at = now
            if group.owner_id is None:
                group.owner = actor
            if group.created_by_id is None:
                group.created_by = actor

        group.save()

        source.linked_group = group
        source.sync_enabled = True
        source.last_synced_at = now
        source.save(update_fields=["linked_group", "sync_enabled", "last_synced_at", "updated_at"])

    return group, created


def sync_enabled_wordpress_sources_to_connect_groups(*, actor) -> Dict[str, int]:
    """Create/update Connect groups for all WordPress sources marked sync_enabled."""
    created = 0
    updated = 0
    failed = 0

    qs = WordPressGroupSource.objects.filter(sync_enabled=True).select_related("linked_group").order_by("name")
    for source in qs:
        try:
            _, was_created = sync_wordpress_source_to_connect_group(source, actor=actor)
        except Exception as exc:  # pragma: no cover - defensive sync logging
            failed += 1
            logger.exception("Unable to sync WordPress group %s into Connect: %s", source.wp_group_id, exc)
            continue
        if was_created:
            created += 1
        else:
            updated += 1

    return {"created": created, "updated": updated, "failed": failed}



def _extract_wp_member_id(member_payload: Dict[str, Any]) -> int:
    return _int(
        member_payload.get("id")
        or member_payload.get("ID")
        or member_payload.get("user_id")
        or member_payload.get("member_id")
    )


def _extract_email(*payloads: Dict[str, Any]) -> str:
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        for key in ("email", "user_email", "email_address"):
            value = payload.get(key)
            if isinstance(value, str) and "@" in value:
                return value.strip().lower()
        # Some custom WP endpoints expose email in meta/acf.
        for parent_key in ("meta", "acf", "profile", "user"):
            nested = payload.get(parent_key)
            if isinstance(nested, dict):
                for key in ("email", "user_email", "email_address"):
                    value = nested.get(key)
                    if isinstance(value, str) and "@" in value:
                        return value.strip().lower()
    return ""


def _extract_username(*payloads: Dict[str, Any], wp_user_id: int = 0) -> str:
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        for key in ("username", "user_login", "slug", "mention_name", "login"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return f"wp_{wp_user_id}" if wp_user_id else "wordpress_user"


def _extract_name(member_payload: Dict[str, Any], full_user_payload: Dict[str, Any] | None = None) -> tuple[str, str, str]:
    full_user_payload = full_user_payload or {}
    display_name = _text(
        full_user_payload.get("name")
        or full_user_payload.get("display_name")
        or member_payload.get("name")
        or member_payload.get("display_name")
    )

    first_name = _text(full_user_payload.get("first_name") or member_payload.get("first_name"))
    last_name = _text(full_user_payload.get("last_name") or member_payload.get("last_name"))

    # BuddyPress member payload often stores first/last names in xprofile groups.
    if not first_name or not last_name:
        xprofile = member_payload.get("xprofile") or {}
        for group in xprofile.get("groups", []) if isinstance(xprofile, dict) else []:
            for field in group.get("fields", []) if isinstance(group, dict) else []:
                field_name = str(field.get("name") or "").lower()
                value = field.get("value") if isinstance(field, dict) else None
                raw_value = ""
                if isinstance(value, dict):
                    raw_value = _text(value.get("raw") or value.get("rendered"))
                else:
                    raw_value = _text(value)
                if raw_value and "first name" in field_name and not first_name:
                    first_name = raw_value
                if raw_value and "last name" in field_name and not last_name:
                    last_name = raw_value

    if display_name and (not first_name or not last_name):
        parts = display_name.split()
        if not first_name and parts:
            first_name = parts[0]
        if not last_name and len(parts) > 1:
            last_name = " ".join(parts[1:])

    if not display_name:
        display_name = " ".join([p for p in [first_name, last_name] if p]).strip()

    return display_name, first_name, last_name


def _extract_avatar_url(*payloads: Dict[str, Any]) -> str:
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        avatar_urls = payload.get("avatar_urls") or {}
        if isinstance(avatar_urls, dict):
            for key in ("full", "96", "thumb", "48", "24"):
                value = avatar_urls.get(key)
                if isinstance(value, str) and value.strip():
                    url = html.unescape(value.strip())
                    if url.startswith("//"):
                        url = f"https:{url}"
                    return url
    return ""


def _membership_role_from_member(member_payload: Dict[str, Any]) -> str:
    # Custom IMAA endpoint returns role as: member/admin/mod.
    explicit_role = str(member_payload.get("role") or "").strip().lower()
    if explicit_role in {"admin", "administrator", "group_admin", "group-admin"}:
        return GroupMembership.ROLE_ADMIN
    if explicit_role in {"mod", "moderator", "group_mod", "group-mod"}:
        return GroupMembership.ROLE_MODERATOR

    if member_payload.get("is_admin"):
        return GroupMembership.ROLE_ADMIN
    if member_payload.get("is_mod"):
        return GroupMembership.ROLE_MODERATOR
    return GroupMembership.ROLE_MEMBER


def _membership_status_from_member(member_payload: Dict[str, Any]) -> str:
    if member_payload.get("is_banned"):
        return GroupMembership.STATUS_BANNED
    # The BuddyPress endpoint returns confirmed members for this route. If the
    # flag is explicitly false, keep it pending instead of incorrectly granting access.
    if member_payload.get("is_confirmed") is False:
        return GroupMembership.STATUS_PENDING
    return GroupMembership.STATUS_ACTIVE


def _unique_username(base_value: str, wp_user_id: int) -> str:
    fallback = f"wp-{wp_user_id}" if wp_user_id else "wordpress-user"
    base = (slugify(base_value or "") or fallback).replace("-", "_")[:140]
    if not base:
        base = f"wp_{wp_user_id}" if wp_user_id else "wordpress_user"
    username = base
    i = 2
    while User.objects.filter(username=username).exists():
        suffix = f"_{i}"
        username = f"{base[:150 - len(suffix)]}{suffix}"
        i += 1
    return username


def _get_or_create_connect_user_from_wordpress_member(
    member_payload: Dict[str, Any],
    full_user_payload: Dict[str, Any] | None = None,
) -> tuple[User | None, bool, str]:
    """
    Find/create a local Connect user for a WordPress member.

    Users created by group sync intentionally receive an unusable password and
    no Cognito temporary password. Login is handled later by IMAA SSO -> Cognito
    -> Connect email linking.
    """
    full_user_payload = full_user_payload or {}
    wp_user_id = _extract_wp_member_id(member_payload) or _int(full_user_payload.get("id"))
    email = _extract_email(full_user_payload, member_payload)
    if not email:
        return None, False, "missing_email"

    display_name, first_name, last_name = _extract_name(member_payload, full_user_payload)
    username = _extract_username(full_user_payload, member_payload, wp_user_id=wp_user_id)
    avatar_url = _extract_avatar_url(full_user_payload, member_payload)

    user = None
    is_new = False
    if wp_user_id:
        profile = UserProfile.objects.filter(wordpress_id=wp_user_id).select_related("user").first()
        if profile:
            user = profile.user

    if user is None:
        user = User.objects.filter(email__iexact=email).first()

    existing_profile = getattr(user, "profile", None) if user is not None else None

    if user is None:
        user = User(
            username=_unique_username(username, wp_user_id),
            email=email,
            first_name=first_name[:150],
            last_name=last_name[:150],
            is_active=True,
        )
        # These users are pre-provisioned from WordPress group sync so they can
        # later login via IMAA SSO/Cognito and be linked by verified email.
        # Do not send normal registration welcome emails and do not run default
        # new-user onboarding during this background sync.
        user._skip_new_user_onboarding = True
        user._skip_welcome_email = True
        user.set_unusable_password()
        user.save()
        is_new = True
    else:
        changed = False
        if email and not user.email:
            user.email = email
            changed = True
        if first_name and not user.first_name:
            user.first_name = first_name[:150]
            changed = True
        if last_name and not user.last_name:
            user.last_name = last_name[:150]
            changed = True
        # A group sync may reactivate an account only when its local lifecycle
        # status is still active/under-review. It must never override an admin
        # soft delete, suspension, fake-account block, or memorialization.
        can_sync_reactivate = (
            existing_profile is None
            or existing_profile.profile_status not in UserProfile.ACCESS_BLOCKED_STATUSES
        )
        if not user.is_active and can_sync_reactivate:
            user.is_active = True
            changed = True
        if changed:
            user.save(update_fields=["email", "first_name", "last_name", "is_active"])

    profile, _ = UserProfile.objects.get_or_create(user=user)
    profile_changed = False
    if wp_user_id and profile.wordpress_id != wp_user_id:
        profile.wordpress_id = wp_user_id
        profile_changed = True
    if email and profile.wordpress_email != email:
        profile.wordpress_email = email
        profile_changed = True
    if username and profile.wordpress_username != username:
        profile.wordpress_username = username
        profile_changed = True
    if display_name and not profile.full_name:
        profile.full_name = display_name
        profile_changed = True
    if avatar_url and profile.wordpress_avatar_url != avatar_url:
        profile.wordpress_avatar_url = avatar_url
        profile_changed = True
    if profile.wordpress_sync_status != UserProfile.WORDPRESS_SYNC_STATUS_SYNCED:
        profile.wordpress_sync_status = UserProfile.WORDPRESS_SYNC_STATUS_SYNCED
        profile_changed = True
    profile.wordpress_synced_at = timezone.now()
    profile_changed = True
    if profile_changed:
        profile.save()

    return user, is_new, "ok"


def _wp_joined_at_from_member_payload(payload: Dict[str, Any]):
    """Extract a WordPress/BuddyPress membership date from common payload shapes."""
    if not isinstance(payload, dict):
        return None

    direct_keys = (
        "joined_at",
        "joined_date",
        "date_joined",
        "date_modified",
        "membership_date",
        "member_since",
    )
    for key in direct_keys:
        parsed = _wp_datetime(payload.get(key))
        if parsed:
            return parsed

    for nested_key in ("membership", "group_membership", "member"):
        nested = payload.get(nested_key)
        if isinstance(nested, dict):
            parsed = _wp_joined_at_from_member_payload(nested)
            if parsed:
                return parsed

    return None


def _set_earliest_join_date(join_dates: dict[str, Any], wp_user_id: Any, joined_at: Any) -> None:
    wp_user_id = _int(wp_user_id)
    if not wp_user_id or not joined_at:
        return
    key = str(wp_user_id)
    existing = join_dates.get(key)
    if existing is None or joined_at < existing:
        join_dates[key] = joined_at


def _wordpress_join_dates_by_user_id(
    client: WordPressAPIClient,
    wp_group_id: int,
    *,
    member_payloads: Iterable[Dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Return the best known WordPress group join date for each WordPress user.

    Priority is:
    1. joined_at/date_modified fields returned by the existing custom members
       endpoint: /wp-json/imaa-connect/v1/groups/<group_id>/members;
    2. BuddyPress joined_group activity fallback.

    The activity fallback is incomplete for older/admin/imported members, so the
    existing WordPress members endpoint should include joined_at for fully
    accurate dates.
    """
    join_dates: dict[str, Any] = {}

    for payload in member_payloads or []:
        if not isinstance(payload, dict):
            continue
        wp_user_id = _extract_wp_member_id(payload)
        _set_earliest_join_date(join_dates, wp_user_id, _wp_joined_at_from_member_payload(payload))

    try:
        joined_rows = client.get_all_buddypress_group_activity(
            wp_group_id,
            activity_type="joined_group",
            per_page=100,
            max_pages=100,
        )
    except Exception as exc:  # pragma: no cover - network safety
        logger.warning("Unable to fetch WordPress join-date activity for group %s: %s", wp_group_id, exc)
        joined_rows = []

    for row in joined_rows:
        if not isinstance(row, dict):
            continue
        joined_at = _wp_datetime(row.get("date_gmt") or row.get("date"))
        _set_earliest_join_date(join_dates, row.get("user_id"), joined_at)

    return join_dates


def _connect_user_for_wordpress_user_id(wp_user_id: int):
    if not wp_user_id:
        return None
    profile = UserProfile.objects.filter(wordpress_id=wp_user_id).select_related("user").first()
    return profile.user if profile else None


def import_wordpress_source_group_content(
    source: WordPressGroupSource,
    *,
    actor=None,
    dry_run: bool = False,
    max_pages: int = 100,
) -> Dict[str, int]:
    """
    Import BuddyPress group activity posts into the linked IMAA Connect group.

    This is intentionally additive and idempotent:
    - only BuddyPress ``activity_update`` rows are imported as Connect posts;
    - existing Connect posts/users/memberships are never deleted;
    - the same WordPress activity id is never imported twice;
    - missing authors fall back to the admin/group owner instead of blocking import.
    """
    if not source.linked_group_id:
        if not actor:
            raise ValueError("This WordPress source is not linked to a Connect group yet.")
        sync_wordpress_source_to_connect_group(source, actor=actor)
        source.refresh_from_db()

    group = source.linked_group
    if not group:
        raise ValueError("Unable to resolve linked Connect group for this WordPress source.")

    client = WordPressAPIClient.for_group_sync()
    activities = client.get_all_buddypress_group_activity(
        source.wp_group_id,
        activity_type="activity_update",
        per_page=100,
        max_pages=max_pages,
    )

    group_ct = ContentType.objects.get_for_model(Group)
    imported = 0
    skipped_existing = 0
    skipped_empty = 0
    skipped_wrong_group = 0
    failed = 0

    fallback_actor = None
    if actor and getattr(actor, "is_authenticated", False):
        fallback_actor = actor
    elif group.owner_id:
        fallback_actor = group.owner
    elif group.created_by_id:
        fallback_actor = group.created_by

    for activity in activities:
        wp_activity_id = _int(activity.get("id"))
        wp_group_id = _int(activity.get("primary_item_id"))
        if not wp_activity_id:
            failed += 1
            continue
        if wp_group_id and wp_group_id != int(source.wp_group_id):
            skipped_wrong_group += 1
            continue

        if FeedItem.objects.filter(group=group).filter(_json_has_wordpress_activity_id(wp_activity_id)).exists():
            skipped_existing += 1
            continue

        content_html = ""
        content_payload = activity.get("content")
        if isinstance(content_payload, dict):
            content_html = str(content_payload.get("rendered") or "")
        else:
            content_html = str(content_payload or "")
        content_text = _text(content_payload)
        if not content_text:
            skipped_empty += 1
            continue

        author = _connect_user_for_wordpress_user_id(_int(activity.get("user_id"))) or fallback_actor
        source_created_at = _wp_datetime(activity.get("date_gmt") or activity.get("date"))
        metadata = {
            "type": "text",
            "text": content_text,
            "group_id": group.id,
            "is_hidden": False,
            "is_deleted": False,
            "source": "wordpress",
            "source_system": "wordpress",
            "source_object_type": "buddypress_activity",
            "source_activity_type": str(activity.get("type") or "activity_update"),
            "source_activity_id": str(wp_activity_id),
            "wordpress_activity_id": str(wp_activity_id),
            "wordpress_group_id": str(source.wp_group_id),
            "wordpress_user_id": str(activity.get("user_id") or ""),
            "wordpress_link": str(activity.get("link") or ""),
            "wordpress_title": _text(activity.get("title")),
            "wordpress_created_at": (source_created_at.isoformat() if source_created_at else str(activity.get("date") or "")),
        }
        if content_html and content_html != content_text:
            metadata["wordpress_content_html"] = content_html

        if dry_run:
            imported += 1
            continue

        try:
            with transaction.atomic():
                item = FeedItem.objects.create(
                    community=group.community,
                    group=group,
                    event=None,
                    actor=author,
                    verb="posted",
                    target_content_type=group_ct,
                    target_object_id=group.id,
                    metadata=metadata,
                )
                if source_created_at:
                    FeedItem.objects.filter(pk=item.pk).update(created_at=source_created_at)
            imported += 1
        except Exception as exc:  # pragma: no cover - defensive import safety
            failed += 1
            logger.exception(
                "Unable to import WordPress activity %s for group %s: %s",
                wp_activity_id,
                source.wp_group_id,
                exc,
            )

    return {
        "processed": len(activities),
        "imported": imported,
        "skipped_existing": skipped_existing,
        "skipped_empty": skipped_empty,
        "skipped_wrong_group": skipped_wrong_group,
        "failed": failed,
        "dry_run": bool(dry_run),
    }


def import_enabled_wordpress_source_group_content(*, actor=None, dry_run: bool = False) -> Dict[str, int]:
    """Import BuddyPress group posts for all enabled/linked WordPress sources."""
    totals = {
        "groups_processed": 0,
        "groups_failed": 0,
        "processed": 0,
        "imported": 0,
        "skipped_existing": 0,
        "skipped_empty": 0,
        "skipped_wrong_group": 0,
        "failed": 0,
        "dry_run": bool(dry_run),
    }
    qs = WordPressGroupSource.objects.filter(sync_enabled=True).select_related("linked_group").order_by("name")
    for source in qs:
        if not source.linked_group_id:
            continue
        try:
            result = import_wordpress_source_group_content(source, actor=actor, dry_run=dry_run)
        except Exception as exc:  # pragma: no cover - defensive sync logging
            totals["groups_failed"] += 1
            logger.exception("Unable to import WordPress content for group %s: %s", source.wp_group_id, exc)
            continue
        totals["groups_processed"] += 1
        for key in ("processed", "imported", "skipped_existing", "skipped_empty", "skipped_wrong_group", "failed"):
            totals[key] += int(result.get(key) or 0)
    return totals



def _json_has_wordpress_comment_id(comment_id: int) -> Q:
    """Match source metadata for imported WordPress/BuddyPress comments/replies."""
    return (
        Q(metadata__source="wordpress", metadata__wordpress_comment_id=comment_id)
        | Q(metadata__source="wordpress", metadata__wordpress_comment_id=str(comment_id))
        | Q(metadata__source="wordpress", metadata__wordpress_activity_comment_id=comment_id)
        | Q(metadata__source="wordpress", metadata__wordpress_activity_comment_id=str(comment_id))
        | Q(metadata__source="wordpress", metadata__wordpress_bbpress_reply_id=comment_id)
        | Q(metadata__source="wordpress", metadata__wordpress_bbpress_reply_id=str(comment_id))
    )


def _json_has_wordpress_bbpress_topic_id(topic_id: int) -> Q:
    """Match old/new metadata shapes for imported WordPress bbPress topics."""
    return (
        Q(metadata__source="wordpress", metadata__source_object_type="bbpress_topic", metadata__wordpress_topic_id=topic_id)
        | Q(metadata__source="wordpress", metadata__source_object_type="bbpress_topic", metadata__wordpress_topic_id=str(topic_id))
        | Q(metadata__source="wordpress", metadata__source_object_type="bbpress_topic", metadata__source_topic_id=topic_id)
        | Q(metadata__source="wordpress", metadata__source_object_type="bbpress_topic", metadata__source_topic_id=str(topic_id))
    )


def _source_created_at_from_payload(payload: Dict[str, Any]):
    return _wp_datetime(payload.get("date_gmt") or payload.get("date") or payload.get("created_at"))


def _wp_author_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    author = payload.get("author") if isinstance(payload, dict) else None
    return author if isinstance(author, dict) else {}


def _connect_user_for_wordpress_author(payload: Dict[str, Any], *, fallback_actor=None):
    """Resolve/create a Connect user from a WordPress author payload when email is available."""
    author_payload = _wp_author_payload(payload)
    if author_payload:
        user, _created, reason = _get_or_create_connect_user_from_wordpress_member(author_payload, author_payload)
        if user:
            return user
        if reason != "missing_email":
            logger.warning("Unable to resolve WordPress author for imported content: %s", reason)
    return fallback_actor


def _fallback_actor_for_group(group: Group, actor=None):
    if actor and getattr(actor, "is_authenticated", False):
        return actor
    if group.owner_id:
        return group.owner
    if group.created_by_id:
        return group.created_by
    return User.objects.filter(is_staff=True).order_by("id").first()


def _feed_item_ct():
    return ContentType.objects.get_for_model(FeedItem)


def _group_ct():
    return ContentType.objects.get_for_model(Group)


def _create_imported_comment(
    *,
    feed_item: FeedItem,
    user,
    text: str,
    metadata: Dict[str, Any],
    created_at=None,
    parent: Comment | None = None,
) -> Comment:
    comment = Comment.objects.create(
        content_type=_feed_item_ct(),
        object_id=feed_item.id,
        user=user,
        text=text,
        parent=parent,
        metadata=metadata,
    )
    if created_at:
        Comment.objects.filter(pk=comment.pk).update(created_at=created_at, updated_at=created_at)
    return comment


def import_wordpress_group_activity_comments_for_source(
    source: WordPressGroupSource,
    *,
    actor=None,
    dry_run: bool = False,
    max_pages: int = 100,
) -> Dict[str, int]:
    """
    Import BuddyPress comments for already-imported WordPress group activity posts.

    This is additive and idempotent. It never deletes/updates WordPress, Connect
    users, memberships, posts, or existing non-WordPress comments.
    """
    if not source.linked_group_id:
        raise ValueError("This WordPress source is not linked to a Connect group yet.")

    group = source.linked_group
    if not group:
        raise ValueError("Unable to resolve linked Connect group for this WordPress source.")

    client = WordPressAPIClient.for_group_sync()
    fallback_actor = _fallback_actor_for_group(group, actor=actor)
    if not fallback_actor:
        raise ValueError("Unable to resolve a fallback Connect user for imported WordPress comments.")

    feeditem_ct = _feed_item_ct()
    posts = FeedItem.objects.filter(
        group=group,
        metadata__source="wordpress",
        metadata__source_object_type="buddypress_activity",
        is_deleted=False,
    ).order_by("id")

    posts_processed = 0
    comments_processed = 0
    comments_imported = 0
    skipped_existing = 0
    skipped_empty = 0
    failed = 0

    for item in posts:
        metadata = item.metadata or {}
        activity_id = _int(metadata.get("wordpress_activity_id") or metadata.get("source_activity_id"))
        if not activity_id:
            continue
        posts_processed += 1
        try:
            comments = client.get_all_imaa_connect_group_activity_comments(
                activity_id,
                per_page=100,
                max_pages=max_pages,
            )
        except Exception as exc:  # pragma: no cover - network safety
            failed += 1
            logger.exception("Unable to fetch WordPress activity comments for %s: %s", activity_id, exc)
            continue

        for payload in comments:
            wp_comment_id = _int(payload.get("id"))
            if not wp_comment_id:
                failed += 1
                continue
            comments_processed += 1
            if Comment.objects.filter(content_type=feeditem_ct, object_id=item.id).filter(_json_has_wordpress_comment_id(wp_comment_id)).exists():
                skipped_existing += 1
                continue

            text = _text(payload.get("content_text") or payload.get("content_html") or payload.get("content"))
            if not text:
                skipped_empty += 1
                continue

            parent = None
            parent_wp_id = _int(payload.get("parent_id"))
            if parent_wp_id:
                parent = Comment.objects.filter(
                    content_type=feeditem_ct,
                    object_id=item.id,
                ).filter(_json_has_wordpress_comment_id(parent_wp_id)).first()

            source_created_at = _source_created_at_from_payload(payload)
            author = _connect_user_for_wordpress_author(payload, fallback_actor=fallback_actor)
            comment_metadata = {
                "source": "wordpress",
                "source_system": "wordpress",
                "source_object_type": "buddypress_activity_comment",
                "wordpress_comment_id": str(wp_comment_id),
                "wordpress_activity_comment_id": str(wp_comment_id),
                "wordpress_root_activity_id": str(payload.get("root_activity_id") or activity_id),
                "wordpress_parent_comment_id": str(parent_wp_id or ""),
                "wordpress_group_id": str(source.wp_group_id),
                "wordpress_user_id": str((_wp_author_payload(payload) or {}).get("id") or ""),
                "wordpress_link": str(payload.get("primary_link") or ""),
                "wordpress_created_at": (source_created_at.isoformat() if source_created_at else str(payload.get("date") or "")),
            }
            content_html = str(payload.get("content_html") or "")
            if content_html and content_html != text:
                comment_metadata["wordpress_content_html"] = content_html

            if dry_run:
                comments_imported += 1
                continue

            try:
                with transaction.atomic():
                    _create_imported_comment(
                        feed_item=item,
                        user=author,
                        text=text,
                        parent=parent,
                        metadata=comment_metadata,
                        created_at=source_created_at,
                    )
                comments_imported += 1
            except Exception as exc:  # pragma: no cover - defensive import safety
                failed += 1
                logger.exception("Unable to import WordPress activity comment %s: %s", wp_comment_id, exc)

    return {
        "posts_processed": posts_processed,
        "comments_processed": comments_processed,
        "comments_imported": comments_imported,
        "skipped_existing": skipped_existing,
        "skipped_empty": skipped_empty,
        "failed": failed,
        "dry_run": bool(dry_run),
    }


def import_enabled_wordpress_group_activity_comments(*, actor=None, dry_run: bool = False) -> Dict[str, int]:
    """Import BuddyPress activity comments for all enabled/linked WordPress sources."""
    totals = {
        "groups_processed": 0,
        "groups_failed": 0,
        "posts_processed": 0,
        "comments_processed": 0,
        "comments_imported": 0,
        "skipped_existing": 0,
        "skipped_empty": 0,
        "failed": 0,
        "dry_run": bool(dry_run),
    }
    qs = WordPressGroupSource.objects.filter(sync_enabled=True, linked_group__isnull=False).select_related("linked_group").order_by("name")
    for source in qs:
        try:
            result = import_wordpress_group_activity_comments_for_source(source, actor=actor, dry_run=dry_run)
        except Exception as exc:  # pragma: no cover - defensive sync logging
            totals["groups_failed"] += 1
            logger.exception("Unable to import WordPress activity comments for group %s: %s", source.wp_group_id, exc)
            continue
        totals["groups_processed"] += 1
        for key in ("posts_processed", "comments_processed", "comments_imported", "skipped_existing", "skipped_empty", "failed"):
            totals[key] += int(result.get(key) or 0)
    return totals


def _forum_group_slug(forum_payload: Dict[str, Any]) -> str:
    url = str(forum_payload.get("url") or "")
    parsed_path = unquote(urlparse(url).path or "")
    match = re.search(r"/groups/([^/]+)/forum/?", parsed_path)
    if match:
        return match.group(1).strip()
    return ""


def _source_for_forum_payload(forum_payload: Dict[str, Any]) -> WordPressGroupSource | None:
    """Map a WordPress group forum to its already-linked WordPressGroupSource."""
    group_slug = _forum_group_slug(forum_payload)
    if not group_slug:
        return None
    return (
        WordPressGroupSource.objects.filter(
            slug=group_slug,
            sync_enabled=True,
            linked_group__isnull=False,
        )
        .select_related("linked_group")
        .first()
    )


def _topic_text(topic_payload: Dict[str, Any]) -> str:
    title = _text(topic_payload.get("title"))
    body = _text(topic_payload.get("content_text") or topic_payload.get("content_html") or topic_payload.get("content"))
    if title and body and title.lower() not in body.lower():
        return f"{title}\n\n{body}".strip()
    return body or title


def _import_wordpress_topic_replies(
    *,
    client: WordPressAPIClient,
    feed_item: FeedItem,
    topic_payload: Dict[str, Any],
    fallback_actor,
    dry_run: bool,
    max_pages: int,
) -> Dict[str, int]:
    topic_id = _int(topic_payload.get("id"))
    feeditem_ct = _feed_item_ct()
    processed = 0
    imported = 0
    skipped_existing = 0
    skipped_empty = 0
    failed = 0

    try:
        replies = client.get_all_imaa_connect_forum_topic_replies(topic_id, per_page=100, max_pages=max_pages)
    except Exception as exc:  # pragma: no cover - network safety
        logger.exception("Unable to fetch WordPress bbPress replies for topic %s: %s", topic_id, exc)
        return {"processed": 0, "imported": 0, "skipped_existing": 0, "skipped_empty": 0, "failed": 1}

    for payload in replies:
        reply_id = _int(payload.get("id"))
        if not reply_id:
            failed += 1
            continue
        processed += 1
        if Comment.objects.filter(content_type=feeditem_ct, object_id=feed_item.id).filter(_json_has_wordpress_comment_id(reply_id)).exists():
            skipped_existing += 1
            continue

        text = _text(payload.get("content_text") or payload.get("content_html") or payload.get("content"))
        if not text:
            skipped_empty += 1
            continue

        parent = None
        parent_wp_id = _int(payload.get("reply_to"))
        if parent_wp_id:
            parent = Comment.objects.filter(content_type=feeditem_ct, object_id=feed_item.id).filter(_json_has_wordpress_comment_id(parent_wp_id)).first()

        source_created_at = _source_created_at_from_payload(payload)
        author = _connect_user_for_wordpress_author(payload, fallback_actor=fallback_actor)
        comment_metadata = {
            "source": "wordpress",
            "source_system": "wordpress",
            "source_object_type": "bbpress_reply",
            "wordpress_comment_id": str(reply_id),
            "wordpress_bbpress_reply_id": str(reply_id),
            "wordpress_topic_id": str(topic_id),
            "wordpress_forum_id": str(payload.get("forum_id") or topic_payload.get("forum_id") or ""),
            "wordpress_parent_reply_id": str(parent_wp_id or ""),
            "wordpress_user_id": str((_wp_author_payload(payload) or {}).get("id") or ""),
            "wordpress_link": str(payload.get("url") or ""),
            "wordpress_created_at": (source_created_at.isoformat() if source_created_at else str(payload.get("date") or "")),
        }
        content_html = str(payload.get("content_html") or "")
        if content_html and content_html != text:
            comment_metadata["wordpress_content_html"] = content_html

        if dry_run:
            imported += 1
            continue

        try:
            with transaction.atomic():
                _create_imported_comment(
                    feed_item=feed_item,
                    user=author,
                    text=text,
                    parent=parent,
                    metadata=comment_metadata,
                    created_at=source_created_at,
                )
            imported += 1
        except Exception as exc:  # pragma: no cover - defensive import safety
            failed += 1
            logger.exception("Unable to import WordPress bbPress reply %s: %s", reply_id, exc)

    return {
        "processed": processed,
        "imported": imported,
        "skipped_existing": skipped_existing,
        "skipped_empty": skipped_empty,
        "failed": failed,
    }


def import_wordpress_forum_content(
    *,
    actor=None,
    dry_run: bool = False,
    group_forums_only: bool = True,
    max_forums: int | None = None,
    max_pages: int = 100,
) -> Dict[str, int]:
    """
    Import mapped WordPress bbPress group forum topics and replies.

    By default this imports only forums whose URL is under /groups/<slug>/forum/
    and whose slug matches an enabled, linked WordPressGroupSource. Public/global
    /forums/forum/<slug>/ forums are skipped until an explicit mapping decision is
    made, avoiding accidental content placement in the wrong Connect group.
    """
    client = WordPressAPIClient.for_group_sync()
    forums = client.get_all_imaa_connect_forum_content_forums(per_page=100, max_pages=max_pages)
    if max_forums is not None:
        forums = forums[: max(0, int(max_forums))]

    group_ct = _group_ct()
    processed_forums = 0
    skipped_unmapped_forums = 0
    skipped_public_forums = 0
    topics_processed = 0
    topics_imported = 0
    topics_skipped_existing = 0
    topics_skipped_empty = 0
    replies_processed = 0
    replies_imported = 0
    replies_skipped_existing = 0
    replies_skipped_empty = 0
    failed = 0

    for forum_payload in forums:
        forum_id = _int(forum_payload.get("id"))
        if not forum_id:
            failed += 1
            continue
        if group_forums_only and not _forum_group_slug(forum_payload):
            skipped_public_forums += 1
            continue
        source = _source_for_forum_payload(forum_payload)
        if not source or not source.linked_group_id:
            skipped_unmapped_forums += 1
            continue

        group = source.linked_group
        fallback_actor = _fallback_actor_for_group(group, actor=actor)
        if not fallback_actor:
            failed += 1
            continue
        processed_forums += 1

        try:
            topics = client.get_all_imaa_connect_forum_topics(forum_id, per_page=100, max_pages=max_pages)
        except Exception as exc:  # pragma: no cover - network safety
            failed += 1
            logger.exception("Unable to fetch WordPress bbPress topics for forum %s: %s", forum_id, exc)
            continue

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
                    "wordpress_forum_id": str(forum_id),
                    "wordpress_forum_title": _text(forum_payload.get("title")),
                    "wordpress_forum_url": str(forum_payload.get("url") or ""),
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
                        logger.exception("Unable to import WordPress bbPress topic %s: %s", topic_id, exc)
                        continue

            if topic_item is None:
                # Dry-run can still count replies without a local feed item.
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

    return {
        "processed_forums": processed_forums,
        "skipped_unmapped_forums": skipped_unmapped_forums,
        "skipped_public_forums": skipped_public_forums,
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
        "group_forums_only": bool(group_forums_only),
    }


def sync_wordpress_source_members(source: WordPressGroupSource, *, actor=None) -> Dict[str, int]:
    """
    Sync members for one enabled WordPress group into existing GroupMembership.

    Phase 3 creates local users only when an email is available from the WP API.
    It does not create Cognito temp-password users and does not touch WordPress.
    """
    if not source.linked_group_id:
        if not actor:
            raise ValueError("This WordPress source is not linked to a Connect group yet.")
        sync_wordpress_source_to_connect_group(source, actor=actor)
        source.refresh_from_db()

    group = source.linked_group
    if not group:
        raise ValueError("Unable to resolve linked Connect group for this WordPress source.")

    client = WordPressAPIClient.for_group_sync()
    now = timezone.now()
    # Use the custom read-only WordPress endpoint because the standard
    # BuddyPress members endpoint does not expose email, and the standard
    # /wp/v2/users/<id>?context=edit route is not available on IMAA.
    # Endpoint: /wp-json/imaa-connect/v1/groups/<group_id>/members
    members = client.get_all_imaa_connect_group_members(source.wp_group_id)
    join_dates_by_wp_user_id = _wordpress_join_dates_by_user_id(
        client,
        source.wp_group_id,
        member_payloads=members,
    )

    processed_wp_ids: set[str] = set()
    users_created = 0
    users_existing = 0
    memberships_created = 0
    memberships_updated = 0
    skipped_missing_email = 0
    failed = 0

    for member_payload in members:
        wp_user_id = _extract_wp_member_id(member_payload)
        if not wp_user_id:
            failed += 1
            logger.warning("Skipping WordPress group member without user ID: %s", member_payload)
            continue

        user, is_new, reason = _get_or_create_connect_user_from_wordpress_member(
            member_payload,
            member_payload,
        )
        if not user:
            if reason == "missing_email":
                skipped_missing_email += 1
            else:
                failed += 1
            continue

        if is_new:
            users_created += 1
        else:
            users_existing += 1

        processed_wp_ids.add(str(wp_user_id))
        role = _membership_role_from_member(member_payload)
        member_status = _membership_status_from_member(member_payload)

        membership, created = GroupMembership.objects.get_or_create(
            group=group,
            user=user,
            defaults={
                "role": role,
                "status": member_status,
                "source": GroupMembership.SOURCE_WORDPRESS,
                "source_user_id": str(wp_user_id),
                "source_synced_at": now,
                "joined_at": join_dates_by_wp_user_id.get(str(wp_user_id)) or now,
                "invited_by": actor if actor and getattr(actor, "is_authenticated", False) else None,
                "left_at": None,
            },
        )
        if created:
            memberships_created += 1
        else:
            changed_fields = []
            if membership.role != role:
                membership.role = role
                changed_fields.append("role")
            if membership.status != member_status:
                membership.status = member_status
                changed_fields.append("status")
            if membership.source != GroupMembership.SOURCE_WORDPRESS:
                membership.source = GroupMembership.SOURCE_WORDPRESS
                changed_fields.append("source")
            if membership.source_user_id != str(wp_user_id):
                membership.source_user_id = str(wp_user_id)
                changed_fields.append("source_user_id")
            wp_joined_at = join_dates_by_wp_user_id.get(str(wp_user_id))
            if wp_joined_at and (not membership.joined_at or wp_joined_at < membership.joined_at):
                membership.joined_at = wp_joined_at
                changed_fields.append("joined_at")
            if membership.left_at is not None:
                membership.left_at = None
                changed_fields.append("left_at")
            membership.source_synced_at = now
            changed_fields.append("source_synced_at")
            if changed_fields:
                membership.save(update_fields=list(dict.fromkeys(changed_fields)))
            memberships_updated += 1

    # WordPress/Moodle sync is intentionally non-destructive. If a source group
    # no longer returns a user, keep the existing Connect user and membership
    # untouched. This preserves community access/history and makes subsequent
    # syncs additive: existing users remain, newly found users are added.
    marked_inactive = 0
    preserved_missing_remote = 0
    if processed_wp_ids:
        preserved_missing_remote = GroupMembership.objects.filter(
            group=group,
            source=GroupMembership.SOURCE_WORDPRESS,
        ).exclude(source_user_id__in=processed_wp_ids).count()

    source.last_members_synced_at = now
    source.member_count = len(processed_wp_ids) if processed_wp_ids else source.member_count
    source.save(update_fields=["last_members_synced_at", "member_count", "updated_at"])

    return {
        "users_created": users_created,
        "users_existing": users_existing,
        "memberships_created": memberships_created,
        "memberships_updated": memberships_updated,
        "marked_inactive": marked_inactive,
        "preserved_missing_remote": preserved_missing_remote,
        "skipped_missing_email": skipped_missing_email,
        "failed": failed,
        "processed": len(processed_wp_ids),
        "remote_members": len(members),
    }


def sync_enabled_wordpress_source_members(*, actor=None) -> Dict[str, int]:
    """Sync members for all enabled WordPress sources that already have/produce a Connect group."""
    totals = {
        "groups_processed": 0,
        "groups_failed": 0,
        "users_created": 0,
        "users_existing": 0,
        "memberships_created": 0,
        "memberships_updated": 0,
        "marked_inactive": 0,
        "preserved_missing_remote": 0,
        "skipped_missing_email": 0,
        "failed": 0,
        "processed": 0,
        "remote_members": 0,
    }
    qs = WordPressGroupSource.objects.filter(sync_enabled=True).select_related("linked_group").order_by("name")
    for source in qs:
        try:
            result = sync_wordpress_source_members(source, actor=actor)
        except Exception as exc:  # pragma: no cover - defensive sync logging
            totals["groups_failed"] += 1
            logger.exception("Unable to sync members for WordPress group %s: %s", source.wp_group_id, exc)
            continue
        totals["groups_processed"] += 1
        for key in (
            "users_created",
            "users_existing",
            "memberships_created",
            "memberships_updated",
            "marked_inactive",
            "preserved_missing_remote",
            "skipped_missing_email",
            "failed",
            "processed",
            "remote_members",
        ):
            totals[key] += int(result.get(key) or 0)
    return totals
