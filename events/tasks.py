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
    """
    now = timezone.now()
    qs = Event.objects.filter(is_live=True, status="live")
    ended = 0

    for event in qs:
        if event.idle_started_at and now - event.idle_started_at >= timedelta(minutes=IDLE_TIMEOUT_MINUTES):
            _end_event_from_system(event, "idle_timeout")
            ended += 1
            continue

        if event.end_time and now >= event.end_time:
            host_online = EventRegistration.objects.filter(
                event_id=event.id,
                user_id=event.created_by_id,
                is_online=True,
            ).exists()
            if not host_online:
                _end_event_from_system(event, "host_absent_end_time")
                ended += 1

    return {"checked": qs.count(), "ended": ended}
