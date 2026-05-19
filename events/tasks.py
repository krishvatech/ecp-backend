from celery import shared_task
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from django.db import transaction
from .models import Event, EventRegistration
import requests
import logging

logger = logging.getLogger('events')
IDLE_TIMEOUT_MINUTES = 15


def build_networking_meeting_url(meeting):
    """
    Build the complete companion page URL for a networking meeting.

    Args:
        meeting: NetworkingMeeting instance

    Returns:
        Full URL to the companion page meetings tab with meeting ID
        e.g., http://localhost:5173/events/my-event/companion?tab=meetings&meeting=123
    """
    frontend_url = getattr(settings, 'FRONTEND_URL', '').rstrip('/')
    if not frontend_url:
        # Fallback to http://localhost:5173 if not configured
        frontend_url = 'http://localhost:5173'

    event_slug = meeting.event.slug if meeting.event and hasattr(meeting.event, 'slug') else str(meeting.event_id)
    return f"{frontend_url}/events/{event_slug}/companion?tab=meetings&meeting={meeting.id}"


def run_saleor_mutation(query, variables=None):
    url = settings.SALEOR_API_URL
    token = settings.SALEOR_APP_TOKEN
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {"query": query, "variables": variables}
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=15)
        response.raise_for_status()
        result = response.json()
        if "errors" in result:
            logger.error(f"Saleor GraphQL Errors: {result['errors']}")
            return None
        return result.get("data")
    except Exception as e:
        logger.error(f"Saleor Request Failed: {e}")
        return None

@shared_task
def sync_event_to_saleor(event_id):
    """
    Push ECP Event to Saleor as a Product + Variant.
    """
    try:
        event = Event.objects.get(id=event_id)
    except Event.DoesNotExist:
        return f"Event {event_id} not found."

    if event.status != "published":
        return f"Event {event_id} is not published."

    # 1. Ensure Product exists or create it
    product_id = event.saleor_product_id
    if not product_id:
        # Create Product
        mutation = """
        mutation CreateProduct($input: ProductCreateInput!) {
            productCreate(input: $input) {
                product {
                    id
                }
                errors {
                    field
                    message
                }
            }
        }
        """
        variables = {
            "input": {
                "name": event.title,
                "description": event.description or "",
                "productType": "UHJvZHVjdFR5cGU6MQ==", # Default type (need to verify this ID in local Saleor)
                "category": "Q2F0ZWdvcnk6MQ==",   # Default category (need to verify)
            }
        }
        data = run_saleor_mutation(mutation, variables)
        if data and data.get("productCreate", {}).get("product"):
            product_id = data["productCreate"]["product"]["id"]
            event.saleor_product_id = product_id
            event.save(update_fields=["saleor_product_id"])
        else:
            return f"Failed to create Saleor product for event {event_id}"

    # 2. Upsert Variant
    variant_id = event.saleor_variant_id
    if not variant_id:
        mutation = """
        mutation CreateVariant($input: ProductVariantCreateInput!) {
            productVariantCreate(input: $input) {
                productVariant {
                    id
                }
                errors {
                    field
                    message
                }
            }
        }
        """
        variables = {
            "input": {
                "product": product_id,
                "name": "Standard Ticket",
                "stocks": [{"warehouse": "V2FyZWhvdXNlOjE=", "quantity": 1000}], # Warehouse ID
                "attributes": [],
            }
        }
        data = run_saleor_mutation(mutation, variables)
        if data and data.get("productVariantCreate", {}).get("productVariant"):
            variant_id = data["productVariantCreate"]["productVariant"]["id"]
            event.saleor_variant_id = variant_id
            event.save(update_fields=["saleor_variant_id"])

    # 3. Update Pricing and Channel Listing
    if product_id:
        # Assign to channel
        mutation = """
        mutation UpdateChannelListing($id: ID!, $input: ProductChannelListingUpdateInput!) {
            productChannelListingUpdate(id: $id, input: $input) {
                errors {
                    field
                    message
                }
            }
        }
        """
        variables = {
            "id": product_id,
            "input": {
                "updateChannels": [{
                    "channelId": "Q2hhbm5lbDox", # Default channel ID
                    "isPublished": True,
                    "visibleInListings": True,
                }]
            }
        }
        run_saleor_mutation(mutation, variables)

        # Update Variant Price
        if variant_id:
            mutation = """
            mutation UpdateVariantListing($id: ID!, $input: [ProductVariantChannelListingAddInput!]!) {
                productVariantChannelListingUpdate(id: $id, input: $input) {
                    errors {
                        field
                        message
                    }
                }
            }
            """
            variables = {
                "id": variant_id,
                "input": [{
                    "channelId": "Q2hhbm5lbDox",
                    "price": str(event.price),
                }]
            }
            run_saleor_mutation(mutation, variables)

    return f"Successfully synced event {event_id} to Saleor."

@shared_task
def example_cleanup_task() -> str:
    """Return a string with the current timestamp to verify Celery runs."""
    return f"Cleanup ran at {timezone.now().isoformat()}"


def _end_event_from_system(event, reason: str) -> None:
    event.status = "ended"
    event.is_live = False
    event.live_ended_at = timezone.now()
    event.ended_by_host = False
    event.save(update_fields=["status", "is_live", "live_ended_at", "ended_by_host", "updated_at"])

    try:
        from .views import _stop_rtk_recording_for_event
        _stop_rtk_recording_for_event(event)
    except Exception:
        pass

    # 📢 Broadcast meeting end to all participants via WebSocket (system-initiated)
    try:
        from asgiref.sync import async_to_sync
        from channels.layers import get_channel_layer
        from django.utils import timezone as django_timezone
        from datetime import timedelta

        channel_layer = get_channel_layer()
        lounge_available = event.lounge_enabled_after
        lounge_closing_time = None
        if lounge_available:
            lounge_closing_time = (event.live_ended_at + timedelta(minutes=event.lounge_after_buffer)).isoformat()

        async_to_sync(channel_layer.group_send)(
            f"event_{event.id}",
            {
                "type": "meeting_ended",
                "event_id": event.id,
                "ended_at": event.live_ended_at.isoformat(),
                "lounge_available": lounge_available,
                "lounge_closing_time": lounge_closing_time
            }
        )
    except Exception as e:
        logger.warning(f"Failed to broadcast meeting_ended to event {event.id}: {e}")

    logger.info("Ended event %s (%s)", event.id, reason)

    # 📧 Send follow-up emails to guests immediately
    try:
        send_guest_followup_task.apply_async(
            args=[event.id],
            countdown=0  # Send immediately, not after 24 hours
        )
        logger.info(f"Scheduled follow-up email task for event {event.id}")
    except Exception as e:
        logger.warning(f"Failed to schedule follow-up email task for event {event.id}: {e}")


@shared_task
def enforce_event_end_conditions() -> dict:
    """
    End events when:
      - No participants (including host) are present for 15 continuous minutes.
      - Host is absent and official end time has been reached.
      - Official end time (+ social lounge time if enabled) has passed AND no participants
        are in any room for 60 minutes after the close time.
    """
    now = timezone.now()
    qs = Event.objects.filter(is_live=True, status="live")
    ended = 0

    for event in qs:
        # Condition 1: Idle timeout (no participants for 15 minutes)
        if event.idle_started_at and now - event.idle_started_at >= timedelta(minutes=IDLE_TIMEOUT_MINUTES):
            _end_event_from_system(event, "idle_timeout")
            ended += 1
            continue

        # Condition 2: Scheduled end time reached
        # ✅ MODIFIED: Auto-end when official end_time arrives, regardless of host status
        # This ensures the meeting ends at the scheduled time and triggers lounge display (if enabled)
        if event.end_time and now >= event.end_time:
            _end_event_from_system(event, "scheduled_end_time")
            ended += 1
            continue

        # Condition 3: Post-close buffer timeout (60 minutes after close time with no participants)
        if event.end_time:
            # Calculate the cutoff time
            if event.lounge_enabled_after:
                # If lounge is enabled, cutoff is: end_time + lounge_after_buffer + 60 minutes
                lounge_closing_time = event.end_time + timedelta(minutes=event.lounge_after_buffer)
                cutoff_time = lounge_closing_time + timedelta(minutes=60)
            else:
                # If lounge is not enabled, cutoff is: end_time + 60 minutes
                cutoff_time = event.end_time + timedelta(minutes=60)

            # Check if cutoff time has been reached
            if now >= cutoff_time:
                # Check if there are any participants online in any room
                participants_online = EventRegistration.objects.filter(
                    event_id=event.id,
                    is_online=True,
                ).exists()

                # Auto-end if no participants
                if not participants_online:
                    reason = "post_close_buffer_timeout"
                    if event.lounge_enabled_after:
                        reason = f"post_lounge_timeout_{event.lounge_after_buffer}min_lounge"
                    _end_event_from_system(event, reason)
                    ended += 1

    return {"checked": qs.count(), "ended": ended}


# ============================================================================
# Phase 3: Speed Networking - Live Score Recalculation
# ============================================================================

@shared_task
def recalculate_stale_matches():
    """
    Periodic task (every 5 minutes) to recalculate matches with outdated configs.

    When admin updates matching criteria (config_version increments), all active/pending
    matches are marked with config_version=0. This task finds those matches and
    recalculates their scores using the updated algorithm.

    Benefits:
    - ✅ Matches always reflect current criteria
    - ✅ Historical records preserved (last_recalculated_at tracked)
    - ✅ No manual intervention needed
    - ✅ Transparent to users
    """
    from django.db.models import F
    from .models import SpeedNetworkingMatch, SpeedNetworkingSession
    from .speed_networking_views import _build_user_profiles_bulk, _calculate_match_probability, _get_criteria_config
    from .criteria_matching_engine import CriteriaBasedMatchingEngine

    try:
        # Find stale matches: config_version < session.config_version
        stale_matches = SpeedNetworkingMatch.objects.filter(
            config_version__lt=F('session__config_version'),  # Config outdated
            status__in=['ACTIVE', 'PENDING'],
            session__status='ACTIVE'
        )[:100]  # Process in batches of 100

        if not stale_matches.exists():
            logger.info("[RECALC] No stale matches found")
            return {"recalculated": 0, "status": "no_stale_matches"}

        recalculated_count = 0
        error_count = 0

        for match in stale_matches:
            try:
                # Rebuild profiles using bulk loading
                profiles = _build_user_profiles_bulk([match.participant_1.id, match.participant_2.id])

                if match.participant_1.id not in profiles or match.participant_2.id not in profiles:
                    logger.warning(f"[RECALC] Could not build profiles for match {match.id}")
                    error_count += 1
                    continue

                profile_a = profiles[match.participant_1.id]
                profile_b = profiles[match.participant_2.id]

                # Get current config
                config = _get_criteria_config(match.session)
                engine = CriteriaBasedMatchingEngine(match.session, config)

                # Recalculate score
                score, breakdown, is_valid = engine.calculate_combined_score(profile_a, profile_b)

                # Update match with new values
                match.match_score = score
                match.match_breakdown = breakdown
                match.match_probability = _calculate_match_probability(score)
                match.config_version = match.session.config_version
                match.last_recalculated_at = timezone.now()
                match.save()

                recalculated_count += 1
                logger.info(
                    f"[RECALC] Match {match.id}: {score:.1f} → {match.match_probability:.1f}% "
                    f"(v{match.session.config_version})"
                )

            except Exception as e:
                error_count += 1
                logger.error(f"[RECALC] Failed to recalculate match {match.id}: {e}")
                continue

        logger.info(
            f"[RECALC] Completed: {recalculated_count} recalculated, {error_count} errors"
        )

        return {
            "recalculated": recalculated_count,
            "errors": error_count,
            "status": "success"
        }

    except Exception as e:
        logger.error(f"[RECALC] Task failed: {e}")
        return {"status": "failed", "error": str(e)}


# ============================================================================
# Break Mode - Auto-End Break Timer
# ============================================================================

@shared_task(bind=True, max_retries=3)
def auto_end_break(self, event_id):
    """
    Auto-end a break when its timer expires.
    Called via apply_async with countdown=break_duration_seconds + 30.

    This task is idempotent:
    - If break was already manually ended, it silently no-ops (break_started_at=None)
    - If meeting was ended, it clears the break state

    ✅ BUGFIX: When break ends, remove all users from social lounge so they return to main room.
    """
    try:
        with transaction.atomic():
            from .models import LoungeParticipant, BreakoutJoiner

            event = Event.objects.select_for_update().get(id=event_id)

            # Idempotency check: if break already ended manually, no-op
            if not event.is_on_break:
                logger.info(f"[AUTO_END_BREAK] Event {event_id}: break already ended manually")
                return {"skipped": True, "reason": "break_already_ended"}

            # Verify the meeting is still live
            if not event.is_live:
                logger.info(f"[AUTO_END_BREAK] Event {event_id}: meeting is no longer live")
                event.is_on_break = False
                event.break_started_at = None
                event.break_celery_task_id = None
                event.save(update_fields=["is_on_break", "break_started_at", "break_celery_task_id", "updated_at"])
                return {"skipped": True, "reason": "meeting_not_live"}

            # End the break
            lounge_enabled_during = event.lounge_enabled_during
            event.is_on_break = False
            event.break_started_at = None
            event.break_celery_task_id = None

            # ✅ BUGFIX: Clear lounge when break ends
            # Remove all participants from lounge tables so they return to main room
            lounge_count = LoungeParticipant.objects.filter(
                table__event_id=event_id
            ).delete()[0]
            logger.info(f"[AUTO_END_BREAK] Removed {lounge_count} participants from lounge tables")

            # ✅ Clear breakout_rooms_active flag
            event.breakout_rooms_active = False

            # ✅ Expire waiting late joiners
            BreakoutJoiner.objects.filter(
                event_id=event_id,
                status='waiting'
            ).update(status='expired')

            event.save(update_fields=[
                "is_on_break", "break_started_at", "break_celery_task_id",
                "breakout_rooms_active", "updated_at"
            ])

        logger.info(f"[AUTO_END_BREAK] Event {event_id}: break auto-ended with cleanup")

        # Broadcast break_ended via WebSocket to all participants
        try:
            from asgiref.sync import async_to_sync
            from channels.layers import get_channel_layer

            # ✅ Get updated lounge state for frontend so UI refreshes immediately
            lounge_state = _build_lounge_state_sync(event_id)

            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f"event_{event_id}",
                {
                    "type": "break_ended",
                    "event_id": event_id,
                    "lounge_enabled_during": lounge_enabled_during,
                    "lounge_state": lounge_state,  # ✅ Include updated lounge state
                }
            )
        except Exception as e:
            logger.warning(f"Failed to broadcast break_ended for event {event_id}: {e}")

        return {"ok": True, "event_id": event_id}

    except Event.DoesNotExist:
        logger.error(f"[AUTO_END_BREAK] Event {event_id} not found")
        return {"error": "event_not_found"}

    except Exception as exc:
        logger.exception(f"[AUTO_END_BREAK] Task failed for event {event_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)


def _build_lounge_state_sync(event_id):
    """
    ✅ Helper function: Build current lounge state for broadcasting.
    Used to include updated lounge state in WebSocket messages so frontend can refresh UI.
    Returns list of table states with current participants.
    """
    from .models import LoungeTable, LoungeParticipant

    try:
        tables = LoungeTable.objects.filter(event_id=event_id).prefetch_related('participants__user')
        state = []
        for t in tables:
            participants = {}
            for p in t.participants.all():
                profile = getattr(p.user, "profile", None)
                img = getattr(profile, "user_image", None) if profile else None
                if not img:
                    img = getattr(p.user, "avatar", None) or getattr(profile, "avatar", None) if profile else None
                avatar_url = ""
                if img:
                    try:
                        avatar_url = img.url
                    except Exception:
                        avatar_url = str(img) if img else ""
                participants[str(p.seat_index)] = {
                    "user_id": p.user.id,
                    "username": p.user.username,
                    "full_name": f"{p.user.first_name} {p.user.last_name}".strip() or p.user.username,
                    "avatar_url": avatar_url,
                }
            icon_url = ""
            if getattr(t, "icon", None):
                try:
                    icon_url = t.icon.url
                except Exception:
                    icon_url = ""
            state.append({
                "id": t.id,
                "name": t.name,
                "category": t.category,
                "max_seats": t.max_seats,
                "rtk_meeting_id": t.rtk_meeting_id,
                "icon_url": icon_url,
                "participants": participants
            })
        return state
    except Exception as e:
        logger.warning(f"[LOUNGE_STATE] Failed to build lounge state for event {event_id}: {e}")
        return []

@shared_task
def send_event_cancelled_task(event_id):
    """
    Background task to send event cancellation emails to all participants.
    """
    from .models import Event
    from users.email_utils import send_event_cancelled_email

    try:
        event = Event.objects.select_related('recommended_event').get(id=event_id)
        if event.status != "cancelled":
            return f"Event {event_id} is not cancelled. Aborting emails."

        send_event_cancelled_email(event)
        return f"Successfully sent cancellation emails for event {event_id}."
    except Event.DoesNotExist:
        return f"Event {event_id} not found."
    except Exception as e:
        logger.error(f"Failed to send cancellation emails for event {event_id}: {e}")
        return str(e)


@shared_task(bind=True, max_retries=3)
def send_replay_notifications_task(self, event_id):
    """
    Send contextual replay notifications to registrants based on attendance.

    Categorizes registrants as:
    - No-show: joined_live=False -> "You missed the webinar"
    - Partial: joined_live=True, duration < 80% of event duration -> "Parts you missed"
    - Full: joined_live=True, duration >= 80% -> skip (they saw it all)

    Creates both in-app Notification records AND sends emails.
    Idempotent: checks replay_notifications_sent_at before sending.
    """
    from .models import EventRegistration, SessionAttendance
    from friends.models import Notification
    from users.email_utils import send_replay_noshow_email, send_replay_partial_email
    from django.db.models import Sum

    try:
        event = Event.objects.get(id=event_id)
    except Event.DoesNotExist:
        logger.error(f"[REPLAY_NOTIFY] Event {event_id} not found")
        return {"error": "event_not_found"}

    # Idempotency guard: do not resend if already sent
    if event.replay_notifications_sent_at is not None:
        logger.info(f"[REPLAY_NOTIFY] Skipping event {event_id}: already sent at {event.replay_notifications_sent_at}")
        return {"skipped": True, "reason": "already_sent"}

    if not event.replay_available or not event.recording_url:
        logger.warning(f"[REPLAY_NOTIFY] Event {event_id}: replay not available yet, aborting")
        return {"skipped": True, "reason": "replay_not_available"}

    # Calculate event duration in seconds
    event_duration_seconds = None
    if event.start_time and event.end_time:
        delta = event.end_time - event.start_time
        event_duration_seconds = delta.total_seconds()

    # Build a lookup: user_id -> total duration_seconds across all sessions for this event
    attendance_map = {}
    if event_duration_seconds and event_duration_seconds > 0:
        attendances = (
            SessionAttendance.objects
            .filter(session__event_id=event_id)
            .values('user_id')
            .annotate(total_seconds=Sum('duration_seconds'))
        )
        attendance_map = {a['user_id']: a['total_seconds'] for a in attendances}

    registrations = EventRegistration.objects.filter(
        event=event,
        status__in=["registered", "cancellation_requested"],
    ).select_related("user")

    threshold = 0.8 * (event_duration_seconds or 0)

    noshow_count = 0
    partial_count = 0
    full_count = 0
    frontend_base = getattr(settings, 'FRONTEND_URL', '')
    event_url = f"{frontend_base}/events/{event.slug}/"

    try:
        with transaction.atomic():
            for reg in registrations:
                user = reg.user
                if not user:
                    continue

                total_seconds = attendance_map.get(user.id, 0)

                # Determine category
                if not reg.joined_live:
                    category = "noshow"
                elif event_duration_seconds and event_duration_seconds > 0 and total_seconds >= threshold:
                    category = "full"
                else:
                    # joined_live=True but either no duration data or < 80%
                    # Edge case: joined_live=True but NO SessionAttendance record
                    # -> treat as partial (they joined but we have no duration)
                    category = "partial"

                if category == "full":
                    full_count += 1
                    continue  # Skip full attendees

                # Build notification title/description
                if category == "noshow":
                    notif_title = f"Recording available: {event.title}"
                    notif_desc = "You missed the live session. Watch the full recording now."
                    send_replay_noshow_email(user, event)
                    noshow_count += 1
                else:  # partial
                    notif_title = f"Catch up on {event.title}"
                    notif_desc = "You left early. The full recording is now available."
                    send_replay_partial_email(user, event)
                    partial_count += 1

                # Create in-app notification
                Notification.objects.create(
                    recipient=user,
                    actor=event.created_by,  # Set actor to event creator so it shows their name
                    kind="event",
                    title=notif_title,
                    description=notif_desc,
                    data={
                        "event_id": event.id,
                        "event_slug": event.slug,
                        "event_url": event_url,
                        "notification_type": "replay_available",
                        "attendance_category": category,
                    },
                )

            # Mark notifications as sent (prevents duplicate sends)
            Event.objects.filter(pk=event_id).update(
                replay_notifications_sent_at=timezone.now()
            )

        logger.info(
            f"[REPLAY_NOTIFY] Event {event_id}: sent to {noshow_count} no-shows, "
            f"{partial_count} partial attendees; skipped {full_count} full attendees"
        )
        return {
            "ok": True,
            "noshow": noshow_count,
            "partial": partial_count,
            "full_skipped": full_count,
        }

    except Exception as exc:
        logger.exception(f"[REPLAY_NOTIFY] Task failed for event {event_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def execute_lounge_transition(self, event_id, transition, user_ids):
    """
    Celery task to execute lounge participant transitions after countdown delay.

    Args:
        event_id: Event.id to transition participants for
        transition: "to_main_room" or "to_waiting_room"
        user_ids: List of user IDs to transition

    Executes the same transition logic as synchronous version but delayed.
    """
    try:
        from .views import _execute_lounge_transition
        _execute_lounge_transition(event_id, transition, user_ids)
        return f"✅ Lounge transition complete: event={event_id}, transition={transition}, users={len(user_ids)}"
    except Exception as exc:
        logger.exception(f"❌ Lounge transition failed: event={event_id}, transition={transition}: {exc}")
        # Retry up to max_retries times with exponential backoff
        raise self.retry(exc=exc, countdown=5)


@shared_task(name="events.poll_wordpress_events")
def poll_wordpress_events():
    """
    Celery beat task: poll WordPress for events modified in last 30 minutes.

    Safety net for missed webhooks. Syncs all recently modified WordPress events
    to the Django platform.

    Configured to run every 15 minutes via CELERY_BEAT_SCHEDULE.
    """
    if not getattr(settings, "WP_SYNC_ENABLED", True):
        logger.info("WordPress event sync is disabled (WP_SYNC_ENABLED=False)")
        return

    try:
        from datetime import timedelta
        from .wordpress_event_api import get_wordpress_event_client
        from .wordpress_event_sync import get_wordpress_event_sync_service

        # Poll for events modified in the last 30 minutes
        from_dt = (timezone.now() - timedelta(minutes=30)).isoformat()

        logger.info(f"Polling WordPress events modified after {from_dt}")

        client = get_wordpress_event_client()
        events = client.list_recently_modified_events(after=from_dt)

        if not events:
            logger.debug("No recently modified WordPress events found")
            return {"status": "ok", "synced_count": 0}

        service = get_wordpress_event_sync_service()
        synced_count = 0

        for wp_event in events:
            wp_id = wp_event.get("id")
            event, action = service.sync_from_wp_data(wp_event)
            if action in ("created", "updated", "cancelled"):
                synced_count += 1
                logger.info(f"Synced WP event {wp_id}: {action}")

        logger.info(f"WordPress event polling complete: synced {synced_count} events")
        return {"status": "ok", "synced_count": synced_count}

    except Exception as e:
        logger.error(f"Failed to poll WordPress events: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}


@shared_task(name="events.send_guest_followup_task")
def send_guest_followup_task(event_id):
    """
    Celery task: Send follow-up emails to guest attendees post-event.

    Scheduled to run 24 hours after an event ends.
    Sends encouraging emails to guests who attended but haven't registered yet,
    highlighting benefits like access to past events, certificates, and personalized dashboard.

    Args:
        event_id: ID of the event that ended

    Returns:
        dict: {"status": "ok", "emails_sent": int} or {"status": "error", "error": str}
    """
    try:
        from .models import GuestAttendee, Event
        from users.email_utils import send_guest_followup_email

        # Get the event
        try:
            event = Event.objects.get(pk=event_id)
        except Event.DoesNotExist:
            logger.warning(f"[SendGuestFollowup] Event {event_id} not found")
            return {"status": "error", "error": "Event not found"}

        # Find guests who should receive follow-up email
        # - Not yet registered (converted_user is None)
        # - Haven't received follow-up yet (follow_up_sent_at is None)
        # - Verified their email (email_verified is True)
        # - Actually attended the event (joined_live is True)
        guests = GuestAttendee.objects.filter(
            event=event,
            converted_user__isnull=True,  # Not yet registered
            follow_up_sent_at__isnull=True,  # Haven't received follow-up yet
            email_verified=True,  # Verified their email
            joined_live=True,  # Actually attended
        )

        emails_sent = 0
        for guest in guests:
            try:
                signup_url = f"{getattr(settings, 'FRONTEND_URL', 'https://app.example.com')}/signup?prefill_email={guest.email}"

                email_sent = send_guest_followup_email(
                    to_email=guest.email,
                    guest_name=guest.first_name,
                    event_title=event.title,
                    signup_url=signup_url,
                )

                if email_sent:
                    # Mark email as sent
                    guest.follow_up_sent_at = timezone.now()
                    guest.save(update_fields=["follow_up_sent_at"])
                    emails_sent += 1
                    logger.info(f"[SendGuestFollowup] Sent follow-up email to {guest.email} for event {event.id}")
                else:
                    logger.warning(f"[SendGuestFollowup] Failed to send email to {guest.email}")

            except Exception as e:
                logger.warning(f"[SendGuestFollowup] Error sending email to guest {guest.id}: {e}")
                continue

        logger.info(f"[SendGuestFollowup] Completed for event {event.id}: {emails_sent} emails sent")
        return {"status": "ok", "emails_sent": emails_sent}

    except Exception as e:
        logger.error(f"[SendGuestFollowup] Task failed: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}


@shared_task(bind=True, max_retries=3)
def send_event_starting_soon_task(self, event_id):
    """
    Celery task: Send "Event starts in 1 hour" reminders to all registered users.

    Scheduled to run exactly 1 hour before event start time.
    Idempotent: checks starting_soon_notifications_sent_at before sending.

    Args:
        event_id: ID of the event

    Returns:
        dict: {"status": "ok", "emails_sent": int} or {"status": "error", "error": str}
    """
    from .models import Event, EventRegistration
    from users.email_utils import send_event_starting_soon_email

    try:
        event = Event.objects.get(id=event_id)
    except Event.DoesNotExist:
        logger.error(f"[EVENT_STARTING_SOON] Event {event_id} not found")
        return {"error": "event_not_found"}

    # Idempotency guard: do not resend if already sent
    if event.starting_soon_notifications_sent_at is not None:
        logger.info(f"[EVENT_STARTING_SOON] Skipping event {event_id}: already sent at {event.starting_soon_notifications_sent_at}")
        return {"skipped": True, "reason": "already_sent"}

    # Get all registered users
    registrations = EventRegistration.objects.filter(
        event=event,
        status__in=["registered", "cancellation_requested"]
    ).select_related("user")

    emails_sent = 0

    try:
        with transaction.atomic():
            for reg in registrations:
                user = reg.user
                if not user or not user.email:
                    continue

                if send_event_starting_soon_email(user, event):
                    emails_sent += 1
                    logger.info(f"[EVENT_STARTING_SOON] Sent reminder to {user.email} for event {event.id}")
                else:
                    logger.warning(f"[EVENT_STARTING_SOON] Failed to send email to {user.email}")

            # Mark notifications as sent (prevents duplicate sends)
            Event.objects.filter(pk=event_id).update(
                starting_soon_notifications_sent_at=timezone.now()
            )

        logger.info(f"[EVENT_STARTING_SOON] Event {event_id}: sent {emails_sent} reminders")
        return {"status": "ok", "emails_sent": emails_sent}

    except Exception as exc:
        logger.exception(f"[EVENT_STARTING_SOON] Task failed for event {event_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, max_retries=3)
def send_event_join_confirmation_task(self, event_id, user_id):
    """
    Celery task: Send "Thanks for joining" confirmation email when user joins live event.

    Called immediately when user joins the live meeting via WebSocket connection.
    Non-critical: fails silently if event/user not found.

    Args:
        event_id: ID of the event
        user_id: ID of the user who joined

    Returns:
        dict: {"status": "ok"} or {"status": "skipped"}
    """
    from django.contrib.auth import get_user_model
    from .models import Event
    from users.email_utils import send_event_join_confirmation_email

    User = get_user_model()

    try:
        event = Event.objects.get(id=event_id)
        user = User.objects.get(id=user_id)
    except (Event.DoesNotExist, User.DoesNotExist):
        logger.warning(f"[JOIN_CONFIRMATION] Event {event_id} or User {user_id} not found")
        return {"status": "skipped", "reason": "not_found"}

    try:
        if send_event_join_confirmation_email(user, event):
            logger.info(f"[JOIN_CONFIRMATION] Sent confirmation to {user.email} for event {event.id}")
            return {"status": "ok"}
        else:
            logger.warning(f"[JOIN_CONFIRMATION] Failed to send email to {user.email}")
            return {"status": "failed", "reason": "email_send_failed"}
    except Exception as exc:
        logger.warning(f"[JOIN_CONFIRMATION] Error: {exc}")
        # Don't retry for this non-critical task
        return {"status": "error", "error": str(exc)}


@shared_task(bind=True, max_retries=3)
def send_replay_expiring_soon_task(self, event_id):
    """
    Celery task: Send "Replay expires in 2 days" alerts to all registered users.

    Scheduled to run 2 days before replay expiration (when replay_availability_duration allows).
    Idempotent: checks replay_expiring_notifications_sent_at before sending.

    Args:
        event_id: ID of the event

    Returns:
        dict: {"status": "ok", "emails_sent": int} or {"status": "error", "error": str}
    """
    from .models import Event, EventRegistration
    from users.email_utils import send_replay_expiring_soon_email

    try:
        event = Event.objects.get(id=event_id)
    except Event.DoesNotExist:
        logger.error(f"[REPLAY_EXPIRING] Event {event_id} not found")
        return {"error": "event_not_found"}

    # Idempotency guard: do not resend if already sent
    if event.replay_expiring_notifications_sent_at is not None:
        logger.info(f"[REPLAY_EXPIRING] Skipping event {event_id}: already sent at {event.replay_expiring_notifications_sent_at}")
        return {"skipped": True, "reason": "already_sent"}

    # Check if replay is available and has expiration info
    if not event.replay_available or not event.replay_availability_duration:
        logger.warning(f"[REPLAY_EXPIRING] Event {event_id}: replay not available or no expiration info")
        return {"skipped": True, "reason": "no_replay_expiration"}

    # Get all registered users
    registrations = EventRegistration.objects.filter(
        event=event,
        status__in=["registered", "cancellation_requested"]
    ).select_related("user")

    emails_sent = 0
    expiration_date = timezone.now() + timedelta(days=2)

    try:
        with transaction.atomic():
            for reg in registrations:
                user = reg.user
                if not user or not user.email:
                    continue

                if send_replay_expiring_soon_email(user, event, expiration_date):
                    emails_sent += 1
                    logger.info(f"[REPLAY_EXPIRING] Sent alert to {user.email} for event {event.id}")
                else:
                    logger.warning(f"[REPLAY_EXPIRING] Failed to send email to {user.email}")

            # Mark notifications as sent (prevents duplicate sends)
            Event.objects.filter(pk=event_id).update(
                replay_expiring_notifications_sent_at=timezone.now()
            )

        logger.info(f"[REPLAY_EXPIRING] Event {event_id}: sent {emails_sent} expiration alerts")
        return {"status": "ok", "emails_sent": emails_sent}

    except Exception as exc:
        logger.exception(f"[REPLAY_EXPIRING] Task failed for event {event_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True)
def scheduled_send_event_starting_soon_reminders(self):
    """
    Scheduled task: Find all events starting within the next hour and send reminders.

    Runs every 5 minutes via Celery Beat.
    Finds events that:
    - Start between now and 1 hour from now
    - Haven't had reminders sent yet (starting_soon_notifications_sent_at is None)

    Returns:
        dict: {"status": "ok", "events_processed": int, "total_emails": int}
    """
    from .models import Event

    now = timezone.now()
    one_hour_later = now + timedelta(hours=1)

    # Find events starting in the next hour that haven't sent reminders yet
    events_needing_reminders = Event.objects.filter(
        start_time__gte=now,
        start_time__lte=one_hour_later,
        starting_soon_notifications_sent_at__isnull=True,
        status='published'
    )

    events_processed = 0
    total_emails_sent = 0

    for event in events_needing_reminders:
        try:
            result = send_event_starting_soon_task.apply(args=[event.id])
            if result.successful():
                data = result.get()
                if data and data.get('status') == 'ok':
                    emails_sent = data.get('emails_sent', 0)
                    total_emails_sent += emails_sent
                    events_processed += 1
                    logger.info(f"[SCHEDULER] Processed event {event.id} ({event.title}): {emails_sent} emails")
        except Exception as e:
            logger.error(f"[SCHEDULER] Failed to process event {event.id}: {e}")

    logger.info(f"[SCHEDULER] Scheduled reminder task complete: {events_processed} events, {total_emails_sent} emails sent")
    return {"status": "ok", "events_processed": events_processed, "total_emails": total_emails_sent}


@shared_task(bind=True)
def scheduled_send_replay_expiring_alerts(self):
    """
    Scheduled task: Find all events with replays expiring within 2 days and send alerts.

    Runs every 5 minutes via Celery Beat.
    Finds events that:
    - Have replay_available = True
    - Replay expires within 2 days from now
    - Haven't had expiration alerts sent yet (replay_expiring_notifications_sent_at is None)

    Returns:
        dict: {"status": "ok", "events_processed": int, "total_emails": int}
    """
    from .models import Event

    now = timezone.now()
    two_days_later = now + timedelta(days=2)

    # Find events with replays expiring within 2 days that haven't sent alerts yet
    events_with_expiring_replays = Event.objects.filter(
        replay_available=True,
        replay_availability_duration__isnull=False,
        replay_expiring_notifications_sent_at__isnull=True,
        status='published'
    )

    events_processed = 0
    total_emails_sent = 0

    for event in events_with_expiring_replays:
        # Calculate replay expiration date
        if event.end_time and event.replay_availability_duration:
            replay_expiration = event.end_time + event.replay_availability_duration

            # Check if replay expires within 2 days
            if now <= replay_expiration <= two_days_later:
                try:
                    result = send_replay_expiring_soon_task.apply(args=[event.id])
                    if result.successful():
                        data = result.get()
                        if data and data.get('status') == 'ok':
                            emails_sent = data.get('emails_sent', 0)
                            total_emails_sent += emails_sent
                            events_processed += 1
                            logger.info(f"[SCHEDULER] Processed replay expiration for event {event.id} ({event.title}): {emails_sent} emails")
                except Exception as e:
                    logger.error(f"[SCHEDULER] Failed to process replay expiration for event {event.id}: {e}")


# ============================================================================
# NETWORKING MEETING EMAIL NOTIFICATIONS
# ============================================================================

@shared_task
def send_networking_meeting_request_email(meeting_id):
    """
    Send email to recipient when meeting request is created.
    Called immediately when meeting is created.
    """
    from events.models import NetworkingMeeting
    from users.email_utils import send_template_email, format_event_time_for_email, get_support_email

    try:
        meeting = NetworkingMeeting.objects.get(id=meeting_id)
        recipient = meeting.recipient
        requester = meeting.requester
        event = meeting.event

        logger.info(f"[NETWORKING_EMAIL_DEBUG] send_networking_meeting_request_email start: meeting_id={meeting_id}, recipient={recipient}, requester={requester}")

        if not recipient or not recipient.user or not recipient.user.email:
            logger.warning(f"[NETWORKING_EMAIL_DEBUG] Missing recipient/email for meeting {meeting_id}")
            return False

        # Format meeting time in event's timezone
        import pytz
        event_tz = pytz.timezone(event.timezone) if event.timezone else timezone.get_default_timezone()
        meeting_start_tz = meeting.start_time.astimezone(event_tz)
        meeting_end_tz = meeting.end_time.astimezone(event_tz)

        companion_url = build_networking_meeting_url(meeting)

        ctx = {
            "app_name": "IMAA Connect",
            "first_name": recipient.user.first_name or recipient.user.username or "there",
            "requester_name": requester.user.get_full_name() or requester.user.username,
            "requester_company": requester.user.profile.company if hasattr(requester.user, 'profile') else None,
            "requester_job_title": requester.user.profile.job_title if hasattr(requester.user, 'profile') else None,
            "event_title": event.title,
            "meeting_date": meeting_start_tz.strftime("%B %d, %Y"),
            "meeting_time": meeting_start_tz.strftime("%I:%M %p").lstrip('0'),
            "duration_minutes": meeting.duration_minutes,
            "message": meeting.message or "",
            "companion_url": companion_url,
            "meeting_url": companion_url,  # For backwards compatibility
            "support_email": get_support_email(),
        }

        logger.info(f"[NETWORKING_EMAIL_DEBUG] Attempting to send networking_meeting_request to {recipient.user.email}")
        result = send_template_email(
            template_key="networking_meeting_request",
            to_email=recipient.user.email,
            context=ctx,
            subject_override=f"1:1 Meeting Request from {requester.user.get_full_name() or requester.user.username} at {event.title}",
            fail_silently=True,
            event=event,
        )
        logger.info(f"[NETWORKING_EMAIL_DEBUG] send_template_email returned: {result}")
        return result
    except Exception as e:
        logger.error(f"[NETWORKING_EMAIL_ERROR] Failed to send networking meeting request email for meeting {meeting_id}: {e}", exc_info=True)
        return False


@shared_task
def send_networking_meeting_accepted_email(meeting_id):
    """Send email to both parties when meeting is accepted."""
    from events.models import NetworkingMeeting
    from users.email_utils import send_template_email, get_support_email

    try:
        meeting = NetworkingMeeting.objects.get(id=meeting_id)
        event = meeting.event
        requester = meeting.requester
        recipient = meeting.recipient

        if not (requester and requester.user and requester.user.email and recipient and recipient.user and recipient.user.email):
            return False

        import pytz
        event_tz = pytz.timezone(event.timezone) if event.timezone else timezone.get_default_timezone()
        meeting_start_tz = meeting.start_time.astimezone(event_tz)

        companion_url = build_networking_meeting_url(meeting)

        base_ctx = {
            "app_name": "IMAA Connect",
            "event_title": event.title,
            "meeting_date": meeting_start_tz.strftime("%B %d, %Y"),
            "meeting_time": meeting_start_tz.strftime("%I:%M %p").lstrip('0'),
            "duration_minutes": meeting.duration_minutes,
            "table_number": meeting.table.name if meeting.table else None,
            "reminder_minutes": event.networking_settings.reminder_minutes_before if hasattr(event, 'networking_settings') else 15,
            "companion_url": companion_url,
            "meeting_url": companion_url,  # For backwards compatibility
            "support_email": get_support_email(),
        }

        # Send to requester
        ctx_requester = {**base_ctx, "first_name": requester.user.first_name or requester.user.username or "there", "other_party_name": recipient.user.get_full_name() or recipient.user.username}
        send_template_email(
            template_key="networking_meeting_accepted",
            to_email=requester.user.email,
            context=ctx_requester,
            subject_override=f"Meeting Confirmed: {recipient.user.get_full_name() or recipient.user.username} at {event.title}",
            fail_silently=True,
            event=event,
        )

        # Send to recipient
        ctx_recipient = {**base_ctx, "first_name": recipient.user.first_name or recipient.user.username or "there", "other_party_name": requester.user.get_full_name() or requester.user.username}
        send_template_email(
            template_key="networking_meeting_accepted",
            to_email=recipient.user.email,
            context=ctx_recipient,
            subject_override=f"Meeting Confirmed: {requester.user.get_full_name() or requester.user.username} at {event.title}",
            fail_silently=True,
            event=event,
        )

        return True
    except Exception as e:
        logger.error(f"Failed to send networking meeting accepted emails for meeting {meeting_id}: {e}")
        return False


@shared_task
def send_networking_meeting_declined_email(meeting_id):
    """Send email to requester when meeting is declined."""
    from events.models import NetworkingMeeting
    from users.email_utils import send_template_email, get_support_email

    try:
        meeting = NetworkingMeeting.objects.get(id=meeting_id)
        requester = meeting.requester
        recipient = meeting.recipient
        event = meeting.event

        if not requester or not requester.user or not requester.user.email:
            return False

        import pytz
        event_tz = pytz.timezone(event.timezone) if event.timezone else timezone.get_default_timezone()
        meeting_start_tz = meeting.start_time.astimezone(event_tz)

        companion_url = build_networking_meeting_url(meeting)
        frontend_url = getattr(settings, 'FRONTEND_URL', '').rstrip('/') or 'http://localhost:5173'
        directory_url = f"{frontend_url}/events/{event.slug}/companion?tab=directory"

        ctx = {
            "app_name": "IMAA Connect",
            "first_name": requester.user.first_name or requester.user.username or "there",
            "other_party_name": recipient.user.get_full_name() or recipient.user.username,
            "event_title": event.title,
            "meeting_date": meeting_start_tz.strftime("%B %d, %Y"),
            "meeting_time": meeting_start_tz.strftime("%I:%M %p").lstrip('0'),
            "duration_minutes": meeting.duration_minutes,
            "companion_url": directory_url,
            "directory_url": directory_url,
            "support_email": get_support_email(),
        }

        return send_template_email(
            template_key="networking_meeting_declined",
            to_email=requester.user.email,
            context=ctx,
            subject_override=f"Meeting Request Declined: {recipient.user.get_full_name() or recipient.user.username} at {event.title}",
            fail_silently=True,
            event=event,
        )
    except Exception as e:
        logger.error(f"Failed to send networking meeting declined email for meeting {meeting_id}: {e}")
        return False


@shared_task
def send_networking_meeting_suggested_email(meeting_id):
    """Send email to other party when meeting time is suggested."""
    from events.models import NetworkingMeeting
    from users.email_utils import send_template_email, get_support_email

    try:
        meeting = NetworkingMeeting.objects.get(id=meeting_id)
        event = meeting.event
        requester = meeting.requester
        recipient = meeting.recipient

        if not (requester and requester.user and requester.user.email and recipient and recipient.user and recipient.user.email):
            return False

        import pytz
        event_tz = pytz.timezone(event.timezone) if event.timezone else timezone.get_default_timezone()

        companion_url = build_networking_meeting_url(meeting)

        base_ctx = {
            "app_name": "IMAA Connect",
            "event_title": event.title,
            "duration_minutes": meeting.duration_minutes,
            "companion_url": companion_url,
            "meeting_url": companion_url,  # For backwards compatibility
            "support_email": get_support_email(),
        }

        # For suggested status, show the proposed time
        if meeting.start_time:
            suggested_start = meeting.start_time.astimezone(event_tz)
            base_ctx["suggested_date"] = suggested_start.strftime("%B %d, %Y")
            base_ctx["suggested_time"] = suggested_start.strftime("%I:%M %p").lstrip('0')

        # Send to recipient (the one receiving the suggestion)
        ctx_recipient = {**base_ctx, "first_name": recipient.user.first_name or recipient.user.username or "there", "other_party_name": requester.user.get_full_name() or requester.user.username, "suggestion_message": meeting.message or ""}
        send_template_email(
            template_key="networking_meeting_suggested",
            to_email=recipient.user.email,
            context=ctx_recipient,
            subject_override=f"Alternative Time Suggested: {requester.user.get_full_name() or requester.user.username} at {event.title}",
            fail_silently=True,
            event=event,
        )

        return True
    except Exception as e:
        logger.error(f"Failed to send networking meeting suggested email for meeting {meeting_id}: {e}")
        return False


@shared_task
def send_networking_meeting_cancelled_email(meeting_id):
    """Send email to both parties when meeting is cancelled."""
    from events.models import NetworkingMeeting
    from users.email_utils import send_template_email, get_support_email

    try:
        meeting = NetworkingMeeting.objects.get(id=meeting_id)
        event = meeting.event
        requester = meeting.requester
        recipient = meeting.recipient

        if not (requester and requester.user and requester.user.email and recipient and recipient.user and recipient.user.email):
            return False

        import pytz
        event_tz = pytz.timezone(event.timezone) if event.timezone else timezone.get_default_timezone()
        meeting_start_tz = meeting.start_time.astimezone(event_tz)

        frontend_url = getattr(settings, 'FRONTEND_URL', '').rstrip('/') or 'http://localhost:5173'
        directory_url = f"{frontend_url}/events/{event.slug}/companion?tab=directory"

        base_ctx = {
            "app_name": "IMAA Connect",
            "event_title": event.title,
            "meeting_date": meeting_start_tz.strftime("%B %d, %Y"),
            "meeting_time": meeting_start_tz.strftime("%I:%M %p").lstrip('0'),
            "duration_minutes": meeting.duration_minutes,
            "companion_url": directory_url,
            "directory_url": directory_url,
            "support_email": get_support_email(),
        }

        # Send to requester
        ctx_requester = {**base_ctx, "first_name": requester.user.first_name or requester.user.username or "there", "other_party_name": recipient.user.get_full_name() or recipient.user.username}
        send_template_email(
            template_key="networking_meeting_cancelled",
            to_email=requester.user.email,
            context=ctx_requester,
            subject_override=f"Meeting Cancelled: {recipient.user.get_full_name() or recipient.user.username} at {event.title}",
            fail_silently=True,
            event=event,
        )

        # Send to recipient
        ctx_recipient = {**base_ctx, "first_name": recipient.user.first_name or recipient.user.username or "there", "other_party_name": requester.user.get_full_name() or requester.user.username}
        send_template_email(
            template_key="networking_meeting_cancelled",
            to_email=recipient.user.email,
            context=ctx_recipient,
            subject_override=f"Meeting Cancelled: {requester.user.get_full_name() or requester.user.username} at {event.title}",
            fail_silently=True,
            event=event,
        )

        return True
    except Exception as e:
        logger.error(f"Failed to send networking meeting cancelled emails for meeting {meeting_id}: {e}")
        return False


@shared_task
def send_networking_meeting_reminder_email(meeting_id):
    """
    Send reminder email X minutes before meeting starts.
    Called by scheduled task that runs every minute.
    Re-checks meeting status before sending - if not ACCEPTED, does not send.
    """
    from events.models import NetworkingMeeting
    from users.email_utils import send_template_email, get_support_email

    try:
        meeting = NetworkingMeeting.objects.get(id=meeting_id)

        # Safety check: only send reminder for ACCEPTED meetings
        if meeting.status != 'accepted':
            logger.info(f"Skipping reminder for meeting {meeting_id}: status is {meeting.status}, not accepted")
            return False

        event = meeting.event
        requester = meeting.requester
        recipient = meeting.recipient

        if not (requester and requester.user and requester.user.email and recipient and recipient.user and recipient.user.email):
            return False

        import pytz
        event_tz = pytz.timezone(event.timezone) if event.timezone else timezone.get_default_timezone()
        meeting_start_tz = meeting.start_time.astimezone(event_tz)

        companion_url = build_networking_meeting_url(meeting)

        reminder_minutes = event.networking_settings.reminder_minutes_before if hasattr(event, 'networking_settings') else 15

        base_ctx = {
            "app_name": "IMAA Connect",
            "event_title": event.title,
            "meeting_date": meeting_start_tz.strftime("%B %d, %Y"),
            "meeting_time": meeting_start_tz.strftime("%I:%M %p").lstrip('0'),
            "duration_minutes": meeting.duration_minutes,
            "reminder_minutes": reminder_minutes,
            "table_number": meeting.table.name if meeting.table else None,
            "location": meeting.table.location_note if meeting.table and meeting.table.location_note else None,
            "companion_url": companion_url,
            "event_url": companion_url,  # For backwards compatibility
            "support_email": get_support_email(),
        }

        # Send to requester
        ctx_requester = {**base_ctx, "first_name": requester.user.first_name or requester.user.username or "there", "other_party_name": recipient.user.get_full_name() or recipient.user.username}
        send_template_email(
            template_key="networking_meeting_reminder",
            to_email=requester.user.email,
            context=ctx_requester,
            subject_override=f"Reminder: Meeting with {recipient.user.get_full_name() or recipient.user.username} in {reminder_minutes} minutes",
            fail_silently=True,
            event=event,
        )

        # Send to recipient
        ctx_recipient = {**base_ctx, "first_name": recipient.user.first_name or recipient.user.username or "there", "other_party_name": requester.user.get_full_name() or requester.user.username}
        send_template_email(
            template_key="networking_meeting_reminder",
            to_email=recipient.user.email,
            context=ctx_recipient,
            subject_override=f"Reminder: Meeting with {requester.user.get_full_name() or requester.user.username} in {reminder_minutes} minutes",
            fail_silently=True,
            event=event,
        )

        return True
    except Exception as e:
        logger.error(f"Failed to send networking meeting reminder email for meeting {meeting_id}: {e}")
        return False


@shared_task
def schedule_networking_meeting_reminders():
    """
    Scheduled task that runs every minute to find meetings starting soon.
    Sends reminder emails X minutes before meeting start time.
    """
    from events.models import NetworkingMeeting
    from datetime import datetime
    from django.utils import timezone

    try:
        now = timezone.now()
        reminders_sent = 0

        # Get all ACCEPTED meetings
        meetings = NetworkingMeeting.objects.filter(status='accepted')

        for meeting in meetings:
            if not meeting.event or not hasattr(meeting.event, 'networking_settings'):
                continue

            settings = meeting.event.networking_settings
            reminder_minutes = settings.reminder_minutes_before

            # Calculate the time window for sending reminders
            # Send reminder when: start_time - now == reminder_minutes (within 1-2 minute tolerance)
            time_until_meeting = (meeting.start_time - now).total_seconds() / 60

            # Check if we're in the reminder window (within 2 minutes of target time)
            if reminder_minutes - 2 <= time_until_meeting <= reminder_minutes + 1:
                send_networking_meeting_reminder_email.delay(meeting.id)
                reminders_sent += 1

        logger.info(f"Scheduled networking meeting reminders: {reminders_sent} reminders queued")
        return {"reminders_sent": reminders_sent}

    except Exception as e:
        logger.error(f"Failed to schedule networking meeting reminders: {e}")
        return {"error": str(e)}


# ============================================================================
# PARTICIPANT INFORMATION FORM REMINDER TASKS
# ============================================================================

@shared_task(bind=True, max_retries=3)
def send_form_reminder_task(self, assignment_id):
    """
    Celery task to send reminder email for incomplete form assignment.
    Retries up to 3 times with exponential backoff.
    """
    from events.models import PostAcceptanceFormAssignment, PostAcceptanceReminderLog
    from events.services.post_acceptance_forms import send_form_reminder_email

    try:
        assignment = PostAcceptanceFormAssignment.objects.get(id=assignment_id)

        # Don't send if already completed
        if assignment.status == PostAcceptanceFormAssignment.STATUS_COMPLETED:
            logger.info(f"Skipping reminder for assignment {assignment_id} - already completed")
            return

        # Don't send if lapsed
        if assignment.status == PostAcceptanceFormAssignment.STATUS_LAPSED:
            logger.info(f"Skipping reminder for assignment {assignment_id} - form lapsed")
            return

        # Send the reminder email
        result = send_form_reminder_email(assignment)

        if result:
            # Update reminder counter
            assignment.reminders_sent += 1
            assignment.last_reminder_sent_at = timezone.now()
            assignment.save(update_fields=['reminders_sent', 'last_reminder_sent_at'])

            # Log reminder sent
            PostAcceptanceReminderLog.objects.create(
                assignment=assignment,
                reminder_number=assignment.reminders_sent,
                sent_at=timezone.now()
            )

            logger.info(f"Reminder {assignment.reminders_sent} sent for assignment {assignment_id}")
            return {"status": "sent", "reminder_number": assignment.reminders_sent}
        else:
            raise Exception("send_form_reminder_email returned False")

    except PostAcceptanceFormAssignment.DoesNotExist:
        logger.error(f"Assignment {assignment_id} not found for reminder task")
        return

    except Exception as exc:
        logger.error(f"Error sending form reminder for assignment {assignment_id}: {str(exc)}")
        # Retry with exponential backoff: 60s, 120s, 240s
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task
def schedule_form_reminders():
    """
    Scheduled task to find incomplete form assignments approaching deadline.
    Sends reminders:
    - 14 days before deadline (first reminder)
    - 3 days before deadline (second reminder)
    - 24 hours before deadline (optional third reminder)
    """
    from events.models import PostAcceptanceFormAssignment
    from datetime import datetime, timedelta
    from django.utils import timezone

    try:
        now = timezone.now()
        reminder_window_start = now
        reminder_window_end = now + timedelta(days=1)  # Check daily
        reminders_scheduled = 0

        # Find incomplete assignments with deadline approaching in next 14+ days
        # Skip opted-out or cancelled registrations
        # TODO: Add opt_out_automated_communication field to EventRegistration when available
        assignments = PostAcceptanceFormAssignment.objects.filter(
            status__in=[
                PostAcceptanceFormAssignment.STATUS_NOT_STARTED,
                PostAcceptanceFormAssignment.STATUS_IN_PROGRESS
            ],
            deadline__gte=reminder_window_start,
            deadline__lte=reminder_window_end + timedelta(days=14),
            event_registration__attendee_status='confirmed',
            event_registration__status='registered'
        ).select_related('event', 'event_registration')

        for assignment in assignments:
            days_until_deadline = (assignment.deadline - now).days

            # Send first reminder 14 days before (13-15 day window for daily check)
            if 13 <= days_until_deadline <= 15 and assignment.reminders_sent == 0:
                send_form_reminder_task.delay(assignment.id)
                reminders_scheduled += 1
                logger.info(f"Scheduled first reminder (14d) for assignment {assignment.id}")

            # Send second reminder 3 days before (2-4 day window for daily check)
            elif 2 <= days_until_deadline <= 4 and assignment.reminders_sent == 1:
                send_form_reminder_task.delay(assignment.id)
                reminders_scheduled += 1
                logger.info(f"Scheduled second reminder (3d) for assignment {assignment.id}")

            # Optional third reminder 24 hours before is disabled by default
            # Uncomment below to enable 24-hour reminders
            # elif 0 <= days_until_deadline <= 1 and assignment.reminders_sent >= 2:
            #     send_form_reminder_task.delay(assignment.id)
            #     reminders_scheduled += 1
            #     logger.info(f"Scheduled optional third reminder (24h) for assignment {assignment.id}")

        logger.info(f"Form reminder scheduler: {reminders_scheduled} reminders queued")
        return {"reminders_scheduled": reminders_scheduled}

    except Exception as e:
        logger.error(f"Failed to schedule form reminders: {e}")
        return {"error": str(e)}


@shared_task
def mark_lapsed_form_assignments():
    """
    Scheduled task to mark assignments as lapsed when deadline passes.
    Runs daily to check all incomplete assignments.
    """
    from events.models import PostAcceptanceFormAssignment
    from django.utils import timezone

    try:
        now = timezone.now()
        marked_lapsed = 0

        # Find incomplete assignments past deadline
        lapsed_assignments = PostAcceptanceFormAssignment.objects.filter(
            status__in=[
                PostAcceptanceFormAssignment.STATUS_NOT_STARTED,
                PostAcceptanceFormAssignment.STATUS_IN_PROGRESS
            ],
            deadline__lt=now
        )

        for assignment in lapsed_assignments:
            assignment.status = PostAcceptanceFormAssignment.STATUS_LAPSED
            assignment.save(update_fields=['status'])
            marked_lapsed += 1

            logger.info(f"Marked assignment {assignment.id} as lapsed")

        logger.info(f"Marked {marked_lapsed} assignments as lapsed")
        return {"marked_lapsed": marked_lapsed}

    except Exception as e:
        logger.error(f"Failed to mark lapsed form assignments: {e}")
        return {"error": str(e)}


@shared_task
def purge_expired_form_data():
    """
    Scheduled task to purge restricted form data 30 days after event ends.
    Removes emergency contact, medical/accessibility, and dietary information.
    Keeps non-sensitive attendance and registration data.
    Respects retention flags if any.
    """
    from events.models import Event, PostAcceptanceFormSubmission, PostAcceptanceFormAnswer
    from django.utils import timezone
    from datetime import timedelta

    try:
        now = timezone.now()
        thirty_days_ago = now - timedelta(days=30)
        purged_count = 0
        restricted_fields = {
            # Emergency contact
            'emergency_contact_name',
            'emergency_contact_phone',
            'emergency_contact_relationship',
            'emergency_contact_relationship_other',
            # Medical and accessibility
            'accessibility_needs_detail',
            'mobility_seating_requirements',
            'medical_info_emergency',
            # Dietary
            'food_allergies',
            'food_allergies_other',
            'dietary_restrictions',
            'dietary_restrictions_other',
            'food_notes'
        }

        # Find events that ended more than 30 days ago
        old_events = Event.objects.filter(
            end_time__lt=thirty_days_ago,
            status__in=['ended', 'completed']
        )

        logger.info(f"Found {old_events.count()} events eligible for restricted data purge")

        for event in old_events:
            # Get all completed submissions for Participant Information forms only
            submissions = PostAcceptanceFormSubmission.objects.filter(
                assignment__event=event,
                assignment__status='completed',
                assignment__form_type='participant_information'
            )

            for submission in submissions:
                # Delete restricted answer fields
                deleted = submission.answers.filter(
                    question_key__in=restricted_fields
                ).delete()

                if deleted[0] > 0:
                    purged_count += deleted[0]
                    logger.info(
                        f"Purged {deleted[0]} restricted fields from "
                        f"submission {submission.id} for event {event.id}"
                    )

        if purged_count > 0:
            logger.info(
                f"AUDIT: Purge completed - action=purge_restricted, "
                f"events_processed={old_events.count()}, "
                f"restricted_fields_removed={purged_count}, "
                f"form_type=participant_information, "
                f"timestamp={timezone.now().isoformat()}"
            )
        else:
            logger.info(f"Purge expired form data: No restricted fields to purge")

        return {"purged_fields": purged_count}

    except Exception as e:
        logger.error(f"Failed to purge expired form data: {e}", exc_info=True)
        return {"error": str(e)}
