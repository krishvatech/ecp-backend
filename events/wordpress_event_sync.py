"""
WordPress Events Calendar → Django Event sync service.

One-way sync: WordPress is the source of truth.
Handles create, update, and cancel operations.
"""
import logging
import re
import html
from datetime import datetime
from typing import Optional, Tuple, Dict, Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.utils.text import slugify
from django.utils.dateparse import parse_datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .models import Event, EventParticipant
from community.models import Community

User = get_user_model()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Field Extraction Helpers
# ---------------------------------------------------------------------------

def _strip_html_tags(html_str: str) -> str:
    """Remove all HTML tags; preserve line breaks as newlines."""
    if not html_str:
        return ""
    html_str = re.sub(r"<br\s*/?>", "\n", html_str, flags=re.IGNORECASE)
    html_str = re.sub(r"<[^>]+>", "", html_str)
    return html.unescape(html_str).strip()


def _clean_title(wp_event: Dict[str, Any]) -> str:
    """Extract and clean event title."""
    title_obj = wp_event.get("title", {})
    if isinstance(title_obj, dict):
        raw = title_obj.get("rendered", "") or title_obj.get("raw", "")
    else:
        raw = str(title_obj or "")
    return _strip_html_tags(raw) or f"WordPress Event {wp_event.get('id')}"


def _clean_description(wp_event: Dict[str, Any]) -> str:
    """Extract description; keep HTML but sanitize."""
    desc_obj = wp_event.get("description", {})
    if isinstance(desc_obj, dict):
        return desc_obj.get("rendered", "") or desc_obj.get("raw", "")
    return str(desc_obj or "")


def _normalize_timezone(tz_name: str) -> str:
    """
    Normalize timezone string to valid IANA zone.
    Handles non-standard formats like "UTC+5:30" → "Asia/Kolkata".
    """
    if not tz_name:
        return "UTC"

    tz_name = tz_name.strip()

    # Check if already valid IANA timezone
    try:
        ZoneInfo(tz_name)
        return tz_name
    except (ZoneInfoNotFoundError, Exception):
        pass

    # Try to map UTC offset patterns (UTC+5:30, UTC-8:00, etc.)
    offset_match = re.match(r"UTC([+-])(\d{1,2}):?(\d{2})?", tz_name, re.IGNORECASE)
    if offset_match:
        sign = offset_match.group(1)
        hours = int(offset_match.group(2))
        minutes = int(offset_match.group(3) or 0)

        # Map common UTC offsets to IANA zones
        offset_key = f"{sign}{hours}:{minutes:02d}"
        timezone_map = {
            "+0:00": "UTC",
            "+1:00": "Europe/Berlin",
            "+2:00": "Europe/Helsinki",
            "+3:00": "Europe/Moscow",
            "+3:30": "Asia/Tehran",
            "+4:00": "Asia/Dubai",
            "+4:30": "Asia/Kabul",
            "+5:00": "Asia/Karachi",
            "+5:30": "Asia/Kolkata",
            "+5:45": "Asia/Kathmandu",
            "+6:00": "Asia/Dhaka",
            "+6:30": "Asia/Yangon",
            "+7:00": "Asia/Bangkok",
            "+8:00": "Asia/Singapore",
            "+9:00": "Asia/Tokyo",
            "+9:30": "Australia/Adelaide",
            "+10:00": "Australia/Sydney",
            "+10:30": "Australia/Adelaide",
            "+11:00": "Pacific/Guadalcanal",
            "+12:00": "Pacific/Fiji",
            "-4:00": "America/New_York",
            "-5:00": "America/Chicago",
            "-6:00": "America/Denver",
            "-7:00": "America/Los_Angeles",
            "-8:00": "America/Anchorage",
        }

        if offset_key in timezone_map:
            tz = timezone_map[offset_key]
            logger.info(f"Normalized timezone '{tz_name}' → '{tz}'")
            return tz

    logger.warning(f"Unknown timezone '{tz_name}', using UTC")
    return "UTC"


def _parse_event_datetime(date_str: str, tz_name: str) -> Optional[datetime]:
    """
    Parse The Events Calendar date string ("2026-05-01 09:00:00") into a
    timezone-aware datetime. Normalizes non-standard timezone formats.
    Falls back to UTC if timezone is invalid.
    """
    if not date_str:
        return None
    try:
        # TEC format: "2026-05-01 09:00:00" (no timezone suffix)
        naive_dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        # Try ISO format as fallback
        naive_dt = parse_datetime(date_str)
        if naive_dt is None:
            return None

    # Normalize timezone string
    normalized_tz = _normalize_timezone(tz_name)
    tz = ZoneInfo(normalized_tz)

    return naive_dt.replace(tzinfo=tz)


def _map_status(wp_status: str) -> Optional[str]:
    """
    Map WordPress post status to Django event status.
    Returns None if the event should be skipped (not synced).
    """
    mapping = {
        "publish": "published",
        "private": "published",   # restricted access on WP side; still visible here
        "trash": "cancelled",
        # draft, pending, future → skip (return None)
    }
    return mapping.get(wp_status)


def _map_format(wp_event: Dict[str, Any]) -> str:
    """Infer event format from venue data."""
    venue = wp_event.get("venue", {})
    if not venue:
        return "virtual"
    venue_name = (venue.get("venue") or "").lower()
    address = venue.get("address", "")
    if any(kw in venue_name for kw in ("online", "virtual", "remote", "zoom", "teams")):
        return "virtual"
    if address:
        return "in_person"
    return "virtual"


def _map_location(wp_event: Dict[str, Any]) -> str:
    """Build a location string from venue data."""
    venue = wp_event.get("venue", {})
    if not venue:
        return ""
    parts = [
        venue.get("venue", ""),
        venue.get("address", ""),
        venue.get("city", ""),
        venue.get("country", ""),
    ]
    return ", ".join(p for p in parts if p).strip(", ")


def _map_price(wp_event: Dict[str, Any]) -> Tuple[float, bool, str]:
    """
    Returns (price, is_free, price_label).

    Price label priority:
    1. Custom label from cost_details['label']
    2. Non-numeric text in cost field (e.g., "By application only")
    3. Empty if cost is purely numeric
    """
    cost = wp_event.get("cost", "") or ""
    cost_details = wp_event.get("cost_details", {}) or {}
    cost_description = wp_event.get("cost_description", "") or ""

    # Extract numeric value from cost
    numeric_str = re.sub(r"[^\d.]", "", cost)
    try:
        price = float(numeric_str) if numeric_str else 0.0
    except ValueError:
        price = 0.0

    is_free = price == 0.0

    # Determine price_label - check multiple sources
    price_label = ""

    # 1. Check if cost_details has a label field (from WordPress Events Calendar)
    if isinstance(cost_details, dict) and cost_details.get("label"):
        price_label = str(cost_details["label"]).strip()

    # 2. Check if cost field contains non-numeric text
    elif cost.strip() and cost.strip() != numeric_str:
        price_label = str(cost).strip()

    # 3. Check cost_description field as fallback
    elif cost_description.strip():
        price_label = str(cost_description).strip()

    return price, is_free, price_label


def _map_category(wp_event: Dict[str, Any]) -> str:
    """Extract first category name."""
    cats = wp_event.get("categories", []) or []
    if cats and isinstance(cats[0], dict):
        return cats[0].get("name", "")
    return ""


# ---------------------------------------------------------------------------
# User Profile Enrichment
# ---------------------------------------------------------------------------

def _enrich_user_profile(profile, creator: Dict[str, Any]) -> None:
    """
    Opportunistically populate UserProfile WordPress fields from creator data
    without overwriting existing values. This ensures the UserProfile.wordpress_id
    linkage is established even for users created before WP sync existed.

    Args:
        profile: UserProfile instance to enrich
        creator: Dict with keys: wp_user_id, email, name, login
    """
    updated_fields = []

    wp_user_id = creator.get("wp_user_id")
    if wp_user_id and int(wp_user_id) > 0 and not profile.wordpress_id:
        profile.wordpress_id = int(wp_user_id)
        updated_fields.append("wordpress_id")

    creator_email = (creator.get("email") or "").strip()
    if creator_email and not profile.wordpress_email:
        profile.wordpress_email = creator_email
        updated_fields.append("wordpress_email")

    creator_login = (creator.get("login") or "").strip()
    if creator_login and not profile.wordpress_username:
        profile.wordpress_username = creator_login
        updated_fields.append("wordpress_username")

    if updated_fields:
        profile.wordpress_synced_at = timezone.now()
        updated_fields.append("wordpress_synced_at")
        try:
            profile.save(update_fields=updated_fields)
            logger.debug(
                f"Enriched UserProfile for user_id={profile.user_id} "
                f"with WP fields: {updated_fields}"
            )
        except Exception as e:
            logger.warning(f"Failed to enrich UserProfile for user_id={profile.user_id}: {e}")


# ---------------------------------------------------------------------------
# Event Creator Resolution (Dynamic - Uses WordPress User + Organizer Fallback)
# ---------------------------------------------------------------------------

def _resolve_event_creator(wp_event: Dict[str, Any] = None) -> Optional[User]:
    """
    Resolve the Django User to assign as event creator/host.

    Priority order (most reliable first):
    1. creator.wp_user_id → UserProfile.wordpress_id (direct WP account match)
    2. creator.email → User.email (fallback if WP ID not synced yet)
    3. organizer[0].email → User.email (legacy fallback from organizer list)
    4. settings.WP_SYNC_SERVICE_ACCOUNT_ID (static configured fallback)
    5. First superuser in DB (last resort)

    When a match is found via creator block, opportunistically enriches UserProfile
    if wordpress_id / wordpress_email / wordpress_username are not yet set.

    Returns: Django User object or None
    """
    from users.models import UserProfile

    # ---- Strategy 1 & 2: creator block from webhook (logged-in WP user) ----
    creator = wp_event.get("creator") if wp_event else None
    if creator and isinstance(creator, dict):
        wp_user_id = creator.get("wp_user_id")
        creator_email = (creator.get("email") or "").strip().lower()

        # Strategy 1: match by WordPress user ID (most reliable)
        if wp_user_id and int(wp_user_id) > 0:
            try:
                profile = UserProfile.objects.select_related("user").get(
                    wordpress_id=int(wp_user_id)
                )
                user = profile.user
                logger.info(
                    f"Resolved event creator via wp_user_id={wp_user_id} "
                    f"-> Django user_id={user.id}"
                )
                _enrich_user_profile(profile, creator)
                return user
            except UserProfile.DoesNotExist:
                logger.debug(
                    f"No UserProfile found with wordpress_id={wp_user_id}; "
                    f"trying email fallback"
                )

        # Strategy 2: match by creator email
        if creator_email:
            try:
                users = User.objects.filter(email__iexact=creator_email)
                if users.count() > 1:
                    logger.warning(
                        f"Multiple Django users share creator email '{creator_email}'; "
                        f"using first match"
                    )
                user = users.first()
                if user:
                    logger.info(
                        f"Resolved event creator via creator.email='{creator_email}' "
                        f"-> Django user_id={user.id}"
                    )
                    # Opportunistic enrichment
                    try:
                        profile = user.profile
                        _enrich_user_profile(profile, creator)
                    except Exception:
                        pass
                    return user
                else:
                    logger.debug(
                        f"Creator email '{creator_email}' not found in Django users"
                    )
            except Exception as e:
                logger.warning(f"Error matching creator email: {e}")

    # ---- Strategy 3: organizer email match (legacy) ----
    if wp_event:
        organizers = wp_event.get("organizer", []) or []
        if organizers and isinstance(organizers[0], dict):
            organizer_email = organizers[0].get("email", "")
            if organizer_email:
                try:
                    user = User.objects.get(email=organizer_email)
                    logger.info(
                        f"Resolved event creator via organizer email '{organizer_email}' "
                        f"-> Django user_id={user.id}"
                    )
                    return user
                except User.DoesNotExist:
                    logger.debug(
                        f"Organizer email '{organizer_email}' not found in Django"
                    )
                except User.MultipleObjectsReturned:
                    user = User.objects.filter(email=organizer_email).first()
                    logger.warning(
                        f"Multiple users match organizer email '{organizer_email}'; "
                        f"using user_id={user.id}"
                    )
                    return user

    # ---- Strategy 4: static service account (configured fallback) ----
    user_id = getattr(settings, "WP_SYNC_SERVICE_ACCOUNT_ID", None)
    if user_id:
        try:
            user = User.objects.get(id=int(user_id))
            logger.debug(
                f"Using configured service account (user_id={user_id}) as event creator"
            )
            return user
        except User.DoesNotExist:
            logger.warning(
                f"Configured service account user_id={user_id} not found"
            )

    # ---- Strategy 5: superuser fallback ----
    superuser = User.objects.filter(is_superuser=True).first()
    if superuser:
        logger.info(f"Using superuser (user_id={superuser.id}) as event creator (last resort)")
        return superuser

    logger.error(
        "Could not resolve event creator — no creator match, no organizer match, "
        "no service account, no superuser"
    )
    return None


# Backward-compatibility alias
_get_service_account_user = _resolve_event_creator


def _get_default_community() -> Optional[Community]:
    """
    Return the community to assign synced events to.
    Reads WP_SYNC_DEFAULT_COMMUNITY_ID from settings.
    """
    community_id = getattr(settings, "WP_SYNC_DEFAULT_COMMUNITY_ID", None)
    if not community_id:
        logger.error("WP_SYNC_DEFAULT_COMMUNITY_ID not configured")
        return None
    try:
        return Community.objects.get(id=int(community_id))
    except Community.DoesNotExist:
        logger.error(f"Default community {community_id} not found")
        return None


# ---------------------------------------------------------------------------
# Core Sync Service
# ---------------------------------------------------------------------------

class WordPressEventSyncService:
    """
    Sync WordPress events to Django Event model.
    Writes directly to ORM — no HTTP API calls to self.
    """

    def sync_from_wp_data(self, wp_event: Dict[str, Any]) -> Tuple[Optional[Event], str]:
        """
        Create or update a Django Event from a WP event dict.

        Returns: (event_instance, action) where action is "created", "updated",
                 "cancelled", "skipped", or "error".
        """
        wp_id = wp_event.get("id")
        if not wp_id:
            logger.error("WP event data missing 'id'")
            return None, "error"

        # Debug: log available fields
        logger.info(f"WP event {wp_id} received fields: {list(wp_event.keys())}")
        logger.info(f"WP event {wp_id} full data: {wp_event}")

        # Try both "status" and "post_status" field names (tribe/v1 API uses post_status)
        wp_status = wp_event.get("status") or wp_event.get("post_status", "")
        django_status = _map_status(wp_status)

        if django_status is None:
            logger.info(f"WP event {wp_id} has status '{wp_status}' — skipping sync")
            return None, "skipped"

        # Fetch or initialize the Event
        try:
            event = Event.objects.get(wordpress_event_id=wp_id)
            is_new = False
        except Event.DoesNotExist:
            event = None
            is_new = True

        # Handle cancellation
        if django_status == "cancelled":
            if event:
                return self._cancel_event(event, wp_id)
            # If not in DB yet, don't create a cancelled event
            logger.info(f"WP event {wp_id} is trashed and not in DB; no-op")
            return None, "skipped"

        # Guard: don't overwrite manually locked events
        if event and event.wp_sync_locked:
            logger.info(f"Event {event.id} (WP {wp_id}) is sync-locked; skipping update")
            return event, "skipped"

        # Check for no-op: if WP hasn't changed since last sync
        # Compare wordpress_synced_at vs WP's modified field
        wp_modified_str = wp_event.get("modified") or wp_event.get("modified_gmt")
        if event and event.wordpress_synced_at and wp_modified_str:
            try:
                wp_modified = parse_datetime(wp_modified_str)
                if wp_modified is None:
                    # Try alternative format
                    wp_modified = parse_datetime(wp_modified_str.replace(" ", "T") + "Z")
                if wp_modified and event.wordpress_synced_at >= wp_modified:
                    logger.debug(f"WP event {wp_id} not modified since last sync; skipping")
                    return event, "skipped"
            except Exception as e:
                logger.warning(f"Failed to parse WP modified date: {e}")

        # Map fields
        # Dynamically determine creator: prefer WP organizer, fall back to configured account or superuser
        service_user = _resolve_event_creator(wp_event)
        community = _get_default_community()

        if not service_user or not community:
            return None, "error"

        tz_name = wp_event.get("timezone", "UTC") or "UTC"
        # Normalize timezone to valid IANA zone for both datetime parsing and storage
        normalized_tz = _normalize_timezone(tz_name)
        start_dt = _parse_event_datetime(wp_event.get("start_date", ""), tz_name)
        end_dt = _parse_event_datetime(wp_event.get("end_date", ""), tz_name)
        price, is_free, price_label = _map_price(wp_event)

        fields = {
            "title": _clean_title(wp_event),
            "description": _clean_description(wp_event),
            "start_time": start_dt,
            "end_time": end_dt,
            "timezone": normalized_tz,
            "status": django_status,
            "format": _map_format(wp_event),
            "location": _map_location(wp_event),
            "category": _map_category(wp_event),
            "price": price,
            "is_free": is_free,
            "price_label": price_label,
            "wordpress_event_id": wp_id,
            "wordpress_event_url": wp_event.get("url", ""),
            "wordpress_synced_at": timezone.now(),
            "wordpress_sync_status": "synced",
        }

        if is_new:
            fields["community"] = community
            fields["created_by"] = service_user
            # status starts as "published" (created events are always published)
            fields["status"] = "published"
            event = Event(**fields)
            event.save()
            logger.info(f"Created Event {event.id} from WP event {wp_id}")
            self._sync_roles(event, wp_event, resolved_creator=service_user)
            self._register_creator(event, service_user)
            self._download_image_if_needed(event, wp_event)
            return event, "created"
        else:
            for field, value in fields.items():
                # Don't overwrite community or created_by on updates
                if field not in ("community", "created_by"):
                    setattr(event, field, value)
            event.save(update_fields=list(f for f in fields.keys() if f not in ("community", "created_by")))
            logger.info(f"Updated Event {event.id} from WP event {wp_id}")
            self._sync_roles(event, wp_event, resolved_creator=service_user)
            self._register_creator(event, service_user)
            return event, "updated"

    def _cancel_event(self, event: Event, wp_id: int) -> Tuple[Event, str]:
        """Cancel an event that was deleted in WordPress."""
        event.status = "cancelled"
        event.is_live = False
        event.cancelled_at = timezone.now()
        event.cancellation_message = "Event removed on WordPress"
        event.wordpress_sync_status = "synced"
        event.wordpress_synced_at = timezone.now()
        event.save(
            update_fields=[
                "status", "is_live", "cancelled_at", "cancellation_message",
                "wordpress_sync_status", "wordpress_synced_at"
            ]
        )
        logger.info(f"Cancelled Event {event.id} (WP {wp_id} trashed)")
        return event, "cancelled"

    def _sync_roles(self, event: Event, wp_event: Dict[str, Any], resolved_creator: Optional[User] = None):
        """
        Sync hosts and speakers from WordPress organizers to EventParticipant.

        If resolved_creator is provided and differs from the first organizer,
        the resolved creator becomes the host and first organizer is demoted to speaker.
        """
        organizers = wp_event.get("organizer", []) or []
        organizer_user_ids_assigned = []

        for i, org in enumerate(organizers):
            role = "host" if i == 0 else "speaker"
            email = org.get("email", "")
            name = org.get("organizer", "")

            # Try to match to existing Django user
            user = None
            if email:
                user = User.objects.filter(email=email).first()

            if user:
                organizer_user_ids_assigned.append(user.id)
                EventParticipant.objects.update_or_create(
                    event=event,
                    user=user,
                    defaults={
                        "role": role,
                        "participant_type": "staff"
                    }
                )
                logger.debug(f"Synced EventParticipant {user.id} as {role} for event {event.id}")
            else:
                # Guest participant (no Django account)
                EventParticipant.objects.update_or_create(
                    event=event,
                    guest_name=name,
                    participant_type="guest",
                    defaults={
                        "role": role,
                        "guest_email": email
                    }
                )
                logger.debug(f"Synced guest EventParticipant '{name}' as {role} for event {event.id}")

        # ---- Handle resolved_creator ----
        if resolved_creator and resolved_creator.id not in organizer_user_ids_assigned:
            # Creator is not in organizer list — assign as host
            # If organizer list is non-empty, demote existing host to speaker (staff or guest)
            if organizers:
                # Find and demote all current hosts (both staff and guest)
                host_participants = EventParticipant.objects.filter(
                    event=event, role="host"
                )
                for host_participant in host_participants:
                    host_participant.role = "speaker"
                    host_participant.save(update_fields=["role"])
                    user_id = host_participant.user_id or f"guest:{host_participant.guest_name}"
                    logger.debug(f"Demoted EventParticipant {user_id} from host to speaker")
            else:
                # Organizer list is now empty — clean up old organizer-synced participants
                # Remove all staff participants except the resolved creator
                EventParticipant.objects.filter(
                    event=event,
                    participant_type="staff"
                ).exclude(user=resolved_creator).delete()
                # Also remove any guest organizer participants (no user_id)
                EventParticipant.objects.filter(
                    event=event,
                    participant_type="guest",
                    user__isnull=True
                ).delete()
                logger.debug(f"Cleaned up old organizer participants for event {event.id}")

            # Set resolved_creator as host
            EventParticipant.objects.update_or_create(
                event=event,
                user=resolved_creator,
                defaults={
                    "role": "host",
                    "participant_type": "staff"
                }
            )
            logger.info(
                f"Synced resolved creator (user_id={resolved_creator.id}) as host for event {event.id}"
            )

    def _register_creator(self, event: Event, creator: User) -> None:
        """
        Auto-register event creator as a participant (status=registered, admission=admitted).
        Creator is the host, so they're automatically admitted to the event.
        """
        if not creator:
            return

        from .models import EventRegistration

        try:
            registration, created = EventRegistration.objects.update_or_create(
                event=event,
                user=creator,
                defaults={
                    "status": "registered",
                    "admission_status": "admitted",
                    "was_ever_admitted": True,
                }
            )
            if created:
                logger.info(
                    f"Auto-registered creator (user_id={creator.id}) for event {event.id}"
                )
            else:
                logger.debug(
                    f"Updated registration for creator (user_id={creator.id}) on event {event.id}"
                )
        except Exception as e:
            logger.warning(f"Failed to register creator for event {event.id}: {e}")

    def _download_image_if_needed(self, event: Event, wp_event: Dict[str, Any]):
        """
        Download and save event image from WordPress.
        Only on initial creation to avoid re-downloading on every update.
        """
        if not getattr(settings, "WP_SYNC_IMAGE_DOWNLOAD", True):
            return

        try:
            image = wp_event.get("image", {}) or {}
            image_url = image.get("url") if isinstance(image, dict) else None

            if not image_url:
                logger.debug(f"No image URL for WP event {wp_event.get('id')}")
                return

            from django.core.files.base import ContentFile
            import requests

            resp = requests.get(image_url, timeout=10)
            resp.raise_for_status()

            # Derive filename from URL
            filename = image_url.split("/")[-1] or f"event-{event.id}.jpg"
            event.preview_image.save(filename, ContentFile(resp.content), save=True)
            logger.info(f"Downloaded image for event {event.id} from {image_url}")
        except Exception as e:
            logger.warning(f"Failed to download image for event {event.id}: {e}")


# Singleton instance
_sync_service = None


def get_wordpress_event_sync_service() -> WordPressEventSyncService:
    """Get or create the singleton sync service."""
    global _sync_service
    if _sync_service is None:
        _sync_service = WordPressEventSyncService()
    return _sync_service
