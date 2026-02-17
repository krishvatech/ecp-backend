from celery import shared_task
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
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
