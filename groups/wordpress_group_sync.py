"""WordPress IMAA BuddyPress group discovery sync.

Phase 1 intentionally imports only the WordPress group catalog into
WordPressGroupSource. Phase 2 can also create/update selected Connect Group rows.
"""

import html
import logging
import re
from typing import Any, Dict, Iterable

from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone
from django.utils.html import strip_tags
from django.utils.text import slugify

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

    qs = Group.objects.all()
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
        group = Group.objects.filter(
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
        if not user.is_active:
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
            if membership.left_at is not None:
                membership.left_at = None
                changed_fields.append("left_at")
            membership.source_synced_at = now
            changed_fields.append("source_synced_at")
            if changed_fields:
                membership.save(update_fields=list(dict.fromkeys(changed_fields)))
            memberships_updated += 1

    marked_inactive = 0
    if processed_wp_ids:
        stale_qs = GroupMembership.objects.filter(
            group=group,
            source=GroupMembership.SOURCE_WORDPRESS,
        ).exclude(source_user_id__in=processed_wp_ids)
        marked_inactive = stale_qs.exclude(status=GroupMembership.STATUS_INACTIVE).update(
            status=GroupMembership.STATUS_INACTIVE,
            left_at=now,
            source_synced_at=now,
        )

    source.last_members_synced_at = now
    source.member_count = len(processed_wp_ids) if processed_wp_ids else source.member_count
    source.save(update_fields=["last_members_synced_at", "member_count", "updated_at"])

    return {
        "users_created": users_created,
        "users_existing": users_existing,
        "memberships_created": memberships_created,
        "memberships_updated": memberships_updated,
        "marked_inactive": marked_inactive,
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
            "skipped_missing_email",
            "failed",
            "processed",
            "remote_members",
        ):
            totals[key] += int(result.get(key) or 0)
    return totals
