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
                "dyte_meeting_id": t.dyte_meeting_id,
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
