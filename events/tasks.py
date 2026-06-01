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
def sync_event_to_saleor_async(event_id):
    """
    Async background task to sync an event to Saleor.
    Runs in Celery worker, not in request cycle.
    """
    try:
        event = Event.objects.get(id=event_id)
        from .saleor_sync import sync_event_to_saleor_sync
        sync_event_to_saleor_sync(event)
        logger.info(f"Successfully synced event {event.id} ({event.title}) to Saleor (async)")
    except Event.DoesNotExist:
        logger.warning(f"Event {event_id} not found for Saleor sync")
    except Exception as e:
        logger.error(f"Failed to sync event {event_id} to Saleor (async): {e}")


@shared_task
def delete_event_from_saleor_async(event_id):
    """
    Async background task to delete an event from Saleor.
    Runs in Celery worker, not in request cycle.
    """
    try:
        event = Event.objects.get(id=event_id)
        from .saleor_sync import delete_event_from_saleor
        delete_event_from_saleor(event)
        logger.info(f"Successfully deleted event {event.id} from Saleor (async)")
    except Event.DoesNotExist:
        logger.warning(f"Event {event_id} not found for Saleor deletion")
    except Exception as e:
        logger.error(f"Failed to delete event {event_id} from Saleor (async): {e}")


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
# FORM ASSIGNMENT EMAIL TASK
# ============================================================================

@shared_task(bind=True, max_retries=2)
def send_form_assignment_email_task(self, assignment_id):
    """
    Async task to send form assignment notification email.
    Non-blocking - form creation continues even if email fails.

    Args:
        assignment_id: ID of PostAcceptanceFormAssignment

    Returns:
        dict: {'status': 'sent'|'failed', 'reason': str}
    """
    try:
        from events.models import PostAcceptanceFormAssignment
        from events.services.post_acceptance_forms import send_form_assignment_email

        assignment = PostAcceptanceFormAssignment.objects.select_related(
            'event', 'event_registration', 'event_registration__user', 'form_template'
        ).get(id=assignment_id)

        # Send form assignment email
        result = send_form_assignment_email(assignment)
        if result:
            logger.info(
                f"Sent {assignment.form_type} form assignment email to {assignment.event_registration.user.email}"
            )
            return {'status': 'sent', 'reason': 'success'}
        else:
            logger.warning(
                f"Failed to send {assignment.form_type} form assignment email to {assignment.event_registration.user.email}"
            )
            raise Exception("send_form_assignment_email returned False")

    except PostAcceptanceFormAssignment.DoesNotExist:
        logger.error(f"PostAcceptanceFormAssignment {assignment_id} not found")
        return {'status': 'failed', 'reason': 'not_found'}
    except Exception as e:
        logger.error(
            f"Error sending form assignment email for assignment {assignment_id}: {e}",
            exc_info=True
        )
        # Retry with exponential backoff
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


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
    Sends reminders with role/module-based cadence:

    Participant Information (default):
    - 14 days before deadline (first reminder)
    - 3 days before deadline (second reminder)

    Promotional Profile (speaker/moderator/host emphasis):
    - Day 0 (initial - already sent on creation)
    - Day 3 before deadline
    - Day 5 before deadline
    - Day 7 before deadline
    - Optional escalation (24 hours)
    """
    from events.models import PostAcceptanceFormAssignment, PostAcceptanceFormTemplate
    from datetime import datetime, timedelta
    from django.utils import timezone

    try:
        now = timezone.now()
        reminder_window_start = now
        reminder_window_end = now + timedelta(days=1)  # Check daily
        reminders_scheduled = 0

        # Find incomplete assignments with deadline approaching in next 14+ days
        # Skip opted-out registrations if field exists
        # Use select_related + prefetch_related to prevent N+1 queries on user lookups
        assignments = PostAcceptanceFormAssignment.objects.filter(
            status__in=[
                PostAcceptanceFormAssignment.STATUS_NOT_STARTED,
                PostAcceptanceFormAssignment.STATUS_IN_PROGRESS
            ],
            deadline__gte=reminder_window_start,
            deadline__lte=reminder_window_end + timedelta(days=14),
            event_registration__attendee_status='confirmed',
            event_registration__status='registered'
        ).select_related(
            'event', 'event_registration', 'form_template'
        ).prefetch_related(
            'event_registration__user'
        )

        for assignment in assignments:
            form_type = assignment.form_type

            # Get reminder schedule and calculate days
            if form_type == 'promotional_profile':
                reminder_schedule = _get_promotional_profile_reminder_schedule(assignment)
                # For promotional profiles, use creation_at-based schedule
                days_for_comparison = (now - assignment.created_at).days
                reference_point = "creation"
            else:
                # Default participant_information schedule
                reminder_schedule = _get_participant_information_reminder_schedule(assignment)
                # For participant_information, use deadline-based schedule
                days_for_comparison = (assignment.deadline - now).days
                reference_point = "deadline"

            # Check if reminder should be sent now
            for reminder_day, reminder_count in reminder_schedule:
                # Allow 1-day tolerance window for matching
                if (reminder_day - 1 <= days_for_comparison <= reminder_day + 1 and
                    assignment.reminders_sent == reminder_count):
                    send_form_reminder_task.delay(assignment.id)
                    reminders_scheduled += 1
                    logger.info(
                        f"Scheduled reminder #{reminder_count + 1} ({reminder_day}d from {reference_point}) "
                        f"for {form_type} assignment {assignment.id}"
                    )
                    break  # Only send one reminder per day

        logger.info(f"Form reminder scheduler: {reminders_scheduled} reminders queued")
        return {"reminders_scheduled": reminders_scheduled}

    except Exception as e:
        logger.error(f"Failed to schedule form reminders: {e}")
        return {"error": str(e)}


def _get_participant_information_reminder_schedule(assignment):
    """
    Get reminder schedule for Participant Information forms.

    Default schedule:
    - Day 14: First reminder
    - Day 3: Second reminder

    Returns:
        list: [(days_until_deadline, reminders_sent_threshold), ...]
    """
    return [
        (14, 0),  # Send when 14 days before and no reminders sent yet
        (3, 1),   # Send when 3 days before and 1 reminder already sent
    ]


def _get_promotional_profile_reminder_schedule(assignment):
    """
    Get reminder schedule for Promotional Profile forms.

    Schedule based on days since assignment creation:
    - Day 0: Initial email sent on creation
    - Day 3: First reminder
    - Day 5: Second reminder
    - Day 7: Third reminder

    Note: This uses creation_at-based schedule, not deadline-based.
    The calling code should check days_since_created instead of days_until_deadline.

    Returns:
        list: [(days_since_created, reminders_sent_threshold), ...]
    """
    return [
        (3, 0),  # First reminder 3 days after creation
        (5, 1),  # Second reminder 5 days after creation
        (7, 2),  # Third reminder 7 days after creation
    ]


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
                # Skip purging if registration has retention requirement
                registration = submission.assignment.event_registration
                if registration.restricted_data_retention_required:
                    logger.info(
                        f"Skipping purge for submission {submission.id} - "
                        f"retention required. Reason: {registration.restricted_data_retention_reason}"
                    )
                    continue

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
@shared_task(name="events.tasks.manage_live_meeting_asg_capacity")
def manage_live_meeting_asg_capacity():
    """
    Runs every few minutes.
    Handles scheduled, upcoming, active, early-start, and late-registration load.
    """
    from django.core.cache import cache
    from events.services.live_meeting_capacity import scale_asg_if_needed

    lock_key = "live_meeting_asg_capacity_manager_lock"

    if not cache.add(lock_key, "1", timeout=240):
        logger.info("[ASG_CAPACITY] Skipped: another task is already running")
        return {"status": "locked"}

    try:
        return scale_asg_if_needed(
            reason="celery_live_meeting_capacity_manager",
            scale_down_allowed=True,
        )
    except Exception as exc:
        logger.exception("[ASG_CAPACITY] Failed to manage ASG capacity: %s", exc)
        return {"status": "error", "error": str(exc)}
    finally:
        cache.delete(lock_key)


# ============================================================================
# Saleor Auto-Sync Tasks (run automatically via Celery Beat every 30 minutes)
# ============================================================================
#
# Resilience strategy when Saleor is down:
#   1. Retry up to 3 times with exponential backoff: 1 min → 5 min → 15 min
#   2. Circuit breaker: after 5 consecutive task failures across any sync type,
#      all Saleor sync tasks are paused for 30 minutes automatically, then resume.
#   3. After all retries exhausted, log CRITICAL so monitoring/Sentry picks it up.

from django.core.cache import cache

from .saleor_sync import (
    sync_channels_from_saleor,
    sync_warehouses_from_saleor,
    sync_shipping_zones_from_saleor,
    sync_product_types_from_saleor,
    sync_staff_users_from_saleor,
    sync_permission_groups_from_saleor,
)

_CIRCUIT_BREAKER_KEY = "saleor_circuit_open"
_FAILURE_COUNT_KEY = "saleor_sync_failure_count"
_CIRCUIT_OPEN_SECONDS = 30 * 60   # pause sync for 30 minutes when tripped
_CIRCUIT_TRIP_THRESHOLD = 5       # consecutive failures before circuit opens

# Exponential backoff delays (seconds) for retries 1, 2, 3
_RETRY_DELAYS = [60, 300, 900]


def _is_circuit_open():
    return cache.get(_CIRCUIT_BREAKER_KEY, False)


def _record_saleor_failure():
    """Increment the failure counter; trip the circuit breaker when threshold hit."""
    count = cache.get(_FAILURE_COUNT_KEY, 0) + 1
    cache.set(_FAILURE_COUNT_KEY, count, timeout=_CIRCUIT_OPEN_SECONDS)
    if count >= _CIRCUIT_TRIP_THRESHOLD:
        cache.set(_CIRCUIT_BREAKER_KEY, True, timeout=_CIRCUIT_OPEN_SECONDS)
        logger.critical(
            "[SALEOR_SYNC] Circuit breaker OPENED — Saleor appears to be down. "
            "All Saleor sync tasks paused for 30 minutes."
        )


def _record_saleor_success():
    """Reset failure counter and close circuit breaker on any success."""
    was_open = cache.get(_CIRCUIT_BREAKER_KEY, False)
    cache.delete(_CIRCUIT_BREAKER_KEY)
    cache.delete(_FAILURE_COUNT_KEY)
    if was_open:
        logger.info("[SALEOR_SYNC] Circuit breaker CLOSED — Saleor is back online.")


def _run_saleor_sync_task(self, label, sync_fn):
    """
    Shared wrapper for all 6 Saleor sync tasks.
    Handles circuit breaker check, retry with exponential backoff, and success/failure tracking.
    """
    if _is_circuit_open():
        logger.warning(f"[SALEOR_SYNC] Circuit open — skipping {label} sync.")
        return {"status": "skipped", "reason": "circuit_open"}

    try:
        synced_ids = sync_fn()
        _record_saleor_success()
        logger.info(f"[SALEOR_SYNC] {label} synced: {len(synced_ids)}")
        return {"status": "ok", "synced": len(synced_ids)}

    except Exception as e:
        retry_number = self.request.retries          # 0-based current attempt
        retries_left = self.max_retries - retry_number

        if retries_left > 0:
            delay = _RETRY_DELAYS[min(retry_number, len(_RETRY_DELAYS) - 1)]
            logger.warning(
                f"[SALEOR_SYNC] {label} sync failed (attempt {retry_number + 1}/"
                f"{self.max_retries + 1}). Retrying in {delay}s. Error: {e}"
            )
            raise self.retry(exc=e, countdown=delay)

        # All retries exhausted
        _record_saleor_failure()
        logger.critical(
            f"[SALEOR_SYNC] {label} sync FAILED after {self.max_retries + 1} attempts. "
            f"Error: {e}"
        )
        return {"status": "failed", "error": str(e)}


@shared_task(bind=True, max_retries=3)
def auto_sync_saleor_channels(self):
    return _run_saleor_sync_task(self, "Channels", sync_channels_from_saleor)


@shared_task(bind=True, max_retries=3)
def auto_sync_saleor_warehouses(self):
    return _run_saleor_sync_task(self, "Warehouses", sync_warehouses_from_saleor)


@shared_task(bind=True, max_retries=3)
def auto_sync_saleor_shipping_zones(self):
    return _run_saleor_sync_task(self, "Shipping zones", sync_shipping_zones_from_saleor)


@shared_task(bind=True, max_retries=3)
def auto_sync_saleor_product_types(self):
    return _run_saleor_sync_task(self, "Product types", sync_product_types_from_saleor)


@shared_task(bind=True, max_retries=3)
def auto_sync_saleor_staff_users(self):
    return _run_saleor_sync_task(self, "Staff users", sync_staff_users_from_saleor)


@shared_task(bind=True, max_retries=3)
def auto_sync_saleor_permission_groups(self):
    return _run_saleor_sync_task(self, "Permission groups", sync_permission_groups_from_saleor)


# ============================================================================
# Phase 4: RTK Cleanup Tasks (Async, Non-Blocking)
# ============================================================================
# Move slow RTK API cleanup out of user-facing request paths.
# Tasks are idempotent: handle case where RTK participant already deleted.

@shared_task(bind=True, max_retries=3)
def cleanup_rtk_participant_task(self, meeting_id, participant_id):
    """
    Async cleanup task to remove a participant from RTK meeting.
    Called when user leaves lounge or disconnects.

    Idempotent: if participant already deleted, logs warning and exits safely.

    Args:
        meeting_id: RTK meeting UUID
        participant_id: RTK participant UUID

    Returns:
        dict: {'status': 'deleted'|'already_deleted'|'failed', 'reason': str}
    """
    import requests as requests_lib
    from django.conf import settings

    try:
        rtk_api_base = getattr(settings, 'RTK_API_BASE', 'https://api.realtime.cloudflare.com/v2')
        rtk_auth_header = getattr(settings, 'RTK_AUTH_HEADER', '')

        if not rtk_auth_header:
            logger.error(f"[RTK_CLEANUP] RTK_AUTH_HEADER not configured")
            return {'status': 'failed', 'reason': 'auth_header_missing'}

        # Call RTK API to delete the participant
        url = f"{rtk_api_base}/meetings/{meeting_id}/participants/{participant_id}"
        headers = {
            "Authorization": rtk_auth_header,
            "Content-Type": "application/json",
        }

        try:
            response = requests_lib.delete(url, headers=headers, timeout=5)

            # 404 = participant already deleted (idempotent success)
            if response.status_code == 404:
                logger.info(f"[RTK_CLEANUP] Participant {participant_id} already deleted from meeting {meeting_id}")
                return {'status': 'already_deleted', 'reason': 'not_found'}

            # 204 = success (no content)
            if response.status_code == 204:
                logger.info(f"[RTK_CLEANUP] Successfully deleted participant {participant_id} from meeting {meeting_id}")
                return {'status': 'deleted', 'reason': 'success'}

            # Unexpected status code
            logger.warning(f"[RTK_CLEANUP] Unexpected status {response.status_code} deleting participant {participant_id}: {response.text}")
            raise Exception(f"Unexpected status {response.status_code}")

        except requests_lib.Timeout:
            logger.warning(f"[RTK_CLEANUP] Timeout deleting participant {participant_id} from meeting {meeting_id}")
            raise
        except requests_lib.RequestException as e:
            logger.warning(f"[RTK_CLEANUP] Request failed deleting participant {participant_id}: {e}")
            raise

    except Exception as exc:
        retry_count = self.request.retries
        if retry_count < self.max_retries:
            logger.warning(f"[RTK_CLEANUP] Retrying delete (attempt {retry_count + 1}/{self.max_retries + 1}): {exc}")
            # Exponential backoff: 5s → 10s → 20s
            delay = 5 * (2 ** retry_count)
            raise self.retry(exc=exc, countdown=delay)
        else:
            logger.error(f"[RTK_CLEANUP] Failed to delete participant {participant_id} after {self.max_retries + 1} attempts: {exc}")
            return {'status': 'failed', 'reason': 'max_retries_exceeded'}


@shared_task(bind=True, max_retries=3)
def cleanup_rtk_participant_by_client_id_task(self, meeting_id, client_specific_id):
    """
    Async cleanup task to remove a participant from RTK meeting by client ID.
    Used when participant's participant_id is not known, but client_specific_id is.

    Idempotent: if participant already deleted, logs warning and exits safely.

    Args:
        meeting_id: RTK meeting UUID
        client_specific_id: Client-specific ID (user_id or participant reference)

    Returns:
        dict: {'status': 'deleted'|'already_deleted'|'failed'|'not_found', 'reason': str}
    """
    import requests as requests_lib
    from django.conf import settings

    try:
        rtk_api_base = getattr(settings, 'RTK_API_BASE', 'https://api.realtime.cloudflare.com/v2')
        rtk_auth_header = getattr(settings, 'RTK_AUTH_HEADER', '')

        if not rtk_auth_header:
            logger.error(f"[RTK_CLEANUP] RTK_AUTH_HEADER not configured")
            return {'status': 'failed', 'reason': 'auth_header_missing'}

        # First, fetch the meeting to find the participant by client_specific_id
        url = f"{rtk_api_base}/meetings/{meeting_id}"
        headers = {
            "Authorization": rtk_auth_header,
            "Content-Type": "application/json",
        }

        try:
            response = requests_lib.get(url, headers=headers, timeout=5)

            if response.status_code != 200:
                logger.warning(f"[RTK_CLEANUP] Failed to fetch meeting {meeting_id}: {response.status_code}")
                return {'status': 'failed', 'reason': 'fetch_meeting_failed'}

            meeting_data = response.json()
            participants = meeting_data.get('participants', [])

            # Find participant by client_specific_id
            participant_id = None
            for p in participants:
                if p.get('client_specific_id') == client_specific_id or p.get('id') == client_specific_id:
                    participant_id = p.get('id')
                    break

            if not participant_id:
                logger.info(f"[RTK_CLEANUP] Participant with client_id {client_specific_id} not found in meeting {meeting_id}")
                return {'status': 'not_found', 'reason': 'participant_not_in_meeting'}

            # Now delete the participant by ID
            delete_url = f"{rtk_api_base}/meetings/{meeting_id}/participants/{participant_id}"
            delete_response = requests_lib.delete(delete_url, headers=headers, timeout=5)

            # 204 = success
            if delete_response.status_code == 204:
                logger.info(f"[RTK_CLEANUP] Successfully deleted participant (client_id={client_specific_id}) from meeting {meeting_id}")
                return {'status': 'deleted', 'reason': 'success'}

            # 404 = participant already deleted (idempotent)
            if delete_response.status_code == 404:
                logger.info(f"[RTK_CLEANUP] Participant (client_id={client_specific_id}) already deleted from meeting {meeting_id}")
                return {'status': 'already_deleted', 'reason': 'not_found'}

            logger.warning(f"[RTK_CLEANUP] Unexpected status {delete_response.status_code} deleting participant: {delete_response.text}")
            raise Exception(f"Unexpected status {delete_response.status_code}")

        except requests_lib.Timeout:
            logger.warning(f"[RTK_CLEANUP] Timeout cleaning up client_id {client_specific_id} from meeting {meeting_id}")
            raise
        except requests_lib.RequestException as e:
            logger.warning(f"[RTK_CLEANUP] Request failed cleaning up client_id {client_specific_id}: {e}")
            raise

    except Exception as exc:
        retry_count = self.request.retries
        if retry_count < self.max_retries:
            logger.warning(f"[RTK_CLEANUP] Retrying cleanup (attempt {retry_count + 1}/{self.max_retries + 1}): {exc}")
            delay = 5 * (2 ** retry_count)
            raise self.retry(exc=exc, countdown=delay)
        else:
            logger.error(f"[RTK_CLEANUP] Failed to cleanup client_id {client_specific_id} after {self.max_retries + 1} attempts: {exc}")
            return {'status': 'failed', 'reason': 'max_retries_exceeded'}


@shared_task(bind=True, max_retries=2)
def cleanup_rtk_user_on_disconnect_task(self, user_id, event_id, meeting_ids):
    """
    Async cleanup task for user disconnect from WebSocket.
    Removes user from multiple RTK meetings across lounge/breakout rooms.

    Called from consumers.py _finalize_disconnect after grace period.
    Idempotent: handles case where user already removed or meeting doesn't exist.

    Args:
        user_id: User ID (string, used as client_specific_id)
        event_id: Event ID (for logging context)
        meeting_ids: List of RTK meeting UUIDs to clean from

    Returns:
        dict: {'status': 'ok', 'removed': int, 'reason': str}
    """
    import requests as requests_lib
    from django.conf import settings

    rtk_api_base = getattr(settings, 'RTK_API_BASE', 'https://api.realtime.cloudflare.com/v2')
    rtk_auth_header = getattr(settings, 'RTK_AUTH_HEADER', '')

    if not rtk_auth_header:
        logger.error(f"[RTK_CLEANUP] RTK_AUTH_HEADER not configured")
        return {'status': 'failed', 'reason': 'auth_header_missing'}

    removed = 0
    failed_meetings = []

    for meeting_id in meeting_ids:
        try:
            logger.info(f"[RTK_DISCONNECT_CLEANUP] Checking meeting {meeting_id} for user {user_id}")
            headers = {
                "Authorization": rtk_auth_header,
                "Content-Type": "application/json",
            }

            # Fetch all participants in this meeting
            resp = requests_lib.get(
                f"{rtk_api_base}/meetings/{meeting_id}/participants",
                headers=headers,
                params={"limit": 100},
                timeout=10,
            )

            if not resp.ok:
                logger.warning(f"[RTK_DISCONNECT_CLEANUP] Failed to fetch participants from meeting {meeting_id}: {resp.status_code}")
                failed_meetings.append(meeting_id)
                continue

            participants = resp.json().get("data", [])

            # Find and remove user from this meeting
            for p in participants:
                cid = p.get("client_specific_id") or p.get("custom_participant_id")
                if cid == str(user_id):
                    pid = p.get("id")
                    if pid:
                        logger.info(f"[RTK_DISCONNECT_CLEANUP] Removing participant {pid} from meeting {meeting_id}")
                        del_resp = requests_lib.delete(
                            f"{rtk_api_base}/meetings/{meeting_id}/participants/{pid}",
                            headers=headers,
                            timeout=5,
                        )
                        if del_resp.status_code in (204, 404):  # 204=deleted, 404=already gone
                            removed += 1
                            logger.info(f"[RTK_DISCONNECT_CLEANUP] Successfully removed participant from meeting {meeting_id}")
                        else:
                            logger.warning(f"[RTK_DISCONNECT_CLEANUP] Failed to remove participant: {del_resp.status_code}")
                            failed_meetings.append(meeting_id)
                    break

        except requests_lib.Timeout:
            logger.warning(f"[RTK_DISCONNECT_CLEANUP] Timeout processing meeting {meeting_id}")
            failed_meetings.append(meeting_id)
        except Exception as e:
            logger.error(f"[RTK_DISCONNECT_CLEANUP] Error processing meeting {meeting_id}: {e}")
            failed_meetings.append(meeting_id)

    logger.info(f"[RTK_DISCONNECT_CLEANUP] Event {event_id}: Removed {removed} participants for user {user_id}")

    if failed_meetings:
        # Retry if we had failures
        if self.request.retries < self.max_retries:
            logger.warning(f"[RTK_DISCONNECT_CLEANUP] Retrying failed meetings: {failed_meetings}")
            delay = 30 * (2 ** self.request.retries)  # 30s, 60s
            raise self.retry(exc=Exception(f"Some meetings failed: {failed_meetings}"), countdown=delay)

    return {'status': 'ok', 'removed': removed, 'failed_count': len(failed_meetings)}


# Phase 13: Application decision email tasks (async, non-blocking)

@shared_task(bind=True, max_retries=2)
def send_application_acceptance_email_task(self, track_application_id):
    """
    Async task to send acceptance email for a track application.
    Non-blocking - errors are logged but don't fail the acceptance.

    Args:
        track_application_id: ID of EventApplicationTrackApplication

    Returns:
        dict: {'status': 'sent'|'skipped'|'failed', 'reason': str}
    """
    try:
        from events.models import EventApplicationTrackApplication
        from events.services.communication import send_application_decision_email

        track_app = EventApplicationTrackApplication.objects.select_related(
            'application', 'track', 'track__event'
        ).get(id=track_application_id)

        # Check opt-out flag
        if track_app.application.opt_out_automated_communication:
            logger.info(f"Skipping acceptance email for {track_app.application.email} - opted out")
            return {'status': 'skipped', 'reason': 'opted_out'}

        # Send acceptance email
        result = send_application_decision_email(track_app, 'accepted')
        if result:
            logger.info(f"Sent acceptance email to {track_app.application.email}")
            return {'status': 'sent', 'reason': 'success'}
        else:
            logger.warning(f"Failed to send acceptance email to {track_app.application.email}")
            raise Exception("send_application_decision_email returned False")

    except EventApplicationTrackApplication.DoesNotExist:
        logger.error(f"TrackApplication {track_application_id} not found")
        return {'status': 'failed', 'reason': 'not_found'}
    except Exception as e:
        logger.error(f"Error sending acceptance email for track app {track_application_id}: {e}", exc_info=True)
        # Retry with exponential backoff
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=2)
def send_application_decline_email_task(self, track_application_id):
    """
    Async task to send decline email for a track application.
    Non-blocking - errors are logged but don't fail the decline decision.

    Args:
        track_application_id: ID of EventApplicationTrackApplication

    Returns:
        dict: {'status': 'sent'|'skipped'|'failed', 'reason': str}
    """
    try:
        from events.models import EventApplicationTrackApplication
        from events.services.communication import send_application_decision_email

        track_app = EventApplicationTrackApplication.objects.select_related(
            'application', 'track', 'track__event'
        ).get(id=track_application_id)

        # Check opt-out flag
        if track_app.application.opt_out_automated_communication:
            logger.info(f"Skipping decline email for {track_app.application.email} - opted out")
            return {'status': 'skipped', 'reason': 'opted_out'}

        # Send decline email
        result = send_application_decision_email(track_app, 'declined')
        if result:
            logger.info(f"Sent decline email to {track_app.application.email}")
            return {'status': 'sent', 'reason': 'success'}
        else:
            logger.warning(f"Failed to send decline email to {track_app.application.email}")
            raise Exception("send_application_decision_email returned False")

    except EventApplicationTrackApplication.DoesNotExist:
        logger.error(f"TrackApplication {track_application_id} not found")
        return {'status': 'failed', 'reason': 'not_found'}
    except Exception as e:
        logger.error(f"Error sending decline email for track app {track_application_id}: {e}", exc_info=True)
        # Retry with exponential backoff
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=2)
def send_application_waitlist_email_task(self, track_application_id):
    """
    Async task to send waitlist email for a track application.
    Non-blocking - errors are logged but don't fail the waitlist decision.

    Args:
        track_application_id: ID of EventApplicationTrackApplication

    Returns:
        dict: {'status': 'sent'|'skipped'|'failed', 'reason': str}
    """
    try:
        from events.models import EventApplicationTrackApplication
        from events.services.communication import send_application_decision_email

        track_app = EventApplicationTrackApplication.objects.select_related(
            'application', 'track', 'track__event'
        ).get(id=track_application_id)

        # Check opt-out flag
        if track_app.application.opt_out_automated_communication:
            logger.info(f"Skipping waitlist email for {track_app.application.email} - opted out")
            return {'status': 'skipped', 'reason': 'opted_out'}

        # Send waitlist email
        result = send_application_decision_email(track_app, 'waitlisted')
        if result:
            logger.info(f"Sent waitlist email to {track_app.application.email}")
            return {'status': 'sent', 'reason': 'success'}
        else:
            logger.warning(f"Failed to send waitlist email to {track_app.application.email}")
            raise Exception("send_application_decision_email returned False")

    except EventApplicationTrackApplication.DoesNotExist:
        logger.error(f"TrackApplication {track_application_id} not found")
        return {'status': 'failed', 'reason': 'not_found'}
    except Exception as e:
        logger.error(f"Error sending waitlist email for track app {track_application_id}: {e}", exc_info=True)
        # Retry with exponential backoff
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


# ============================================================================
# Phase 6: Redis-based WebSocket Presence Sync
# ============================================================================
# Periodic task to sync Redis presence data to database for reporting/admin.
# Real-time presence updates happen in Redis (no DB writes during connect/disconnect).
# This task periodically updates EventRegistration.is_online from Redis state.

@shared_task(name="events.sync_redis_presence_to_db")
def sync_redis_presence_to_db():
    """
    Periodic task (every 5-10 minutes) to sync Redis presence to database.

    Redis tracks real-time presence to avoid DB writes during WebSocket storms.
    This task periodically updates EventRegistration.is_online so admin/reporting
    can see who's online without querying Redis directly.

    Returns:
        dict: {'status': 'ok', 'synced_events': int} or {'status': 'error', 'error': str}
    """
    try:
        from events.models import Event
        from events.redis_presence import RedisPresenceManager

        # Find all live events
        live_events = Event.objects.filter(is_live=True).values_list('id', flat=True)

        synced_count = 0
        for event_id in live_events:
            try:
                result = RedisPresenceManager.sync_presence_to_db(event_id)
                if result.get('status') == 'success':
                    synced_count += 1
                else:
                    logger.warning(f"[SYNC_PRESENCE] Failed to sync event {event_id}: {result.get('error')}")
            except Exception as e:
                logger.error(f"[SYNC_PRESENCE] Error syncing event {event_id}: {e}")

        logger.info(f"[SYNC_PRESENCE] Completed: synced {synced_count} live events")
        return {'status': 'ok', 'synced_events': synced_count}

    except Exception as e:
        logger.error(f"[SYNC_PRESENCE] Task failed: {e}", exc_info=True)
        return {'status': 'error', 'error': str(e)}

