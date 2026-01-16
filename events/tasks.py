from celery import shared_task
from django.conf import settings
from .models import Event
import requests
import logging

logger = logging.getLogger('events')

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
