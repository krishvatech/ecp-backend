import requests
import json
import logging
from django.conf import settings
from django.contrib.auth.models import User
from django.utils import timezone
from .models import Event
from community.models import Community

logger = logging.getLogger(__name__)

def sync_event_to_saleor_sync(event):
    """
    Synchronously creates/updates a Saleor Product for the given Event.
    All prices are synced in USD (US Dollar) via the global-events channel.

    Channel Mapping:
    - global-events → USD
    """
    saleor_url = getattr(settings, "SALEOR_API_URL", None)
    saleor_token = getattr(settings, "SALEOR_APP_TOKEN", None)
    # Use configured channel slug from settings (global-events for USD currency)
    channel_slug = getattr(settings, "SALEOR_CHANNEL_SLUG", "global-events") 

    if not saleor_url or not saleor_token:
        logger.warning("Skipping Saleor event sync: Settings missing.")
        return

    # Skip sync for free events (don't create products)
    if event.is_free and not event.saleor_product_id:
        logger.info(f"Skipping Saleor sync for FREE event {event.id}: {event.title}")
        return

    headers = {
        "Authorization": f"Bearer {saleor_token}",
        "Content-Type": "application/json"
    }

    # 1. Get or Create Dependencies
    category_id = _get_or_create_category(saleor_url, headers, "Events")
    logger.info(f"DEBUG: Category 'Events' ID: {category_id}")
    if not category_id:
        logger.error("Could not resolve Saleor Category 'Events'")
        return

    product_type_id = _get_or_create_product_type(saleor_url, headers, "Event Ticket")
    # Fallbacks ...
    if not product_type_id:
        logger.warning("Could not resolve 'Event Ticket', trying 'Simple'...")
        product_type_id = _get_existing_product_type(saleor_url, headers, "Simple")
    if not product_type_id:
        logger.warning("Could not resolve 'Simple', trying 'Default Type'...")
        product_type_id = _get_existing_product_type(saleor_url, headers, "Default Type")
    
    logger.info(f"DEBUG: Product Type ID used: {product_type_id}")

    if not product_type_id:
        logger.error("Could not resolve any ProductType. Sync Aborted.")
        return

    # 2. Extract Event Data
    # For slug, we ensure unique in Saleor by re-using event slug
    product_slug = event.slug
    price_amount = float(event.price) if event.price else 0.0

    logger.info(f"🔄 SALEOR SYNC START | Event: {event.title} | Price: {event.currency} {price_amount} | Channel: {channel_slug}")

    # 3. Create or Update Product
    if not event.saleor_product_id:
        logger.info(f"➕ Creating NEW product for event {event.id} | Price: {event.currency} {price_amount}")
        _create_product_in_saleor(event, saleor_url, headers, category_id, product_type_id, channel_slug)
    else:
        logger.info(f"🔄 Updating EXISTING product {event.saleor_product_id} | Price: {event.currency} {price_amount}")
        _update_product_in_saleor(event, saleor_url, headers, channel_slug)

    logger.info(f"✅ SALEOR SYNC COMPLETE | Event: {event.title}")


def _create_product_in_saleor(event, url, headers, cat_id, type_id, channel):
    mutation = """
    mutation CreateProduct($input: ProductCreateInput!) {
      productCreate(input: $input) {
        product { id }
        errors { field message }
      }
    }
    """
    variables = {
        "input": {
            "name": event.title,
            "slug": event.slug,
            "category": cat_id,
            "productType": type_id,
            "description": json_description(event.description or ""),
        }
    }
    
    try:
        r = requests.post(url, json={"query": mutation, "variables": variables}, headers=headers)
        data = r.json()
        logger.info(f"DEBUG: productCreate response: {data}") # DEBUG
        
        prod_data = data.get("data", {}).get("productCreate", {})
        errors = prod_data.get("errors", [])
        
        if errors:
            logger.error(f"Saleor Product Create Errors: {errors}")
            return

        product_id = prod_data.get("product", {}).get("id")
        if product_id:
            logger.info(f"DEBUG: Created Product ID: {product_id}")
            # Save ID immediately
            event.saleor_product_id = product_id
            event.save(update_fields=["saleor_product_id"])
            
            # 1. Channel Listing (publish product FIRST so variant can have price)
            _update_product_channel_listing(url, headers, product_id, channel)

            # 2. Create Variant
            _create_variant(event, url, headers, product_id, channel)
            
    except Exception as e:
        logger.error(f"Exc creating product: {e}")

def _update_product_in_saleor(event, url, headers, channel):
    logger.info(f"📝 UPDATING Product in Saleor: {event.title} (Event ID: {event.id})")
    mutation = """
    mutation UpdateProduct($id: ID!, $input: ProductInput!) {
      productUpdate(id: $id, input: $input) {
        product { id }
        errors { field message }
      }
    }
    """
    variables = {
        "id": event.saleor_product_id,
        "input": {
            "name": event.title,
            "description": json_description(event.description or "")
        }
    }

    try:
        r = requests.post(url, json={"query": mutation, "variables": variables}, headers=headers)
        logger.info(f"DEBUG: productUpdate response: {r.json()}")
    except Exception as e:
        logger.error(f"Exc updating product: {e}")

    # For now, we prioritize price update on the variant
    if event.saleor_variant_id:
        logger.info(f"💰 UPDATING Price on Variant: {event.saleor_variant_id} | Event: {event.title}")
        _update_variant_price(event, url, headers, event.saleor_variant_id, channel)

        # Also update stock if max_participants changed
        logger.info(f"📦 UPDATING Stock: {event.max_participants or 'Unlimited (999999)'} | Variant: {event.saleor_variant_id}")
        _create_or_update_stock(event, url, headers, event.saleor_variant_id)
    else:
        logger.warning(f"⚠️  No variant ID found for event {event.id}. Price and stock not updated.")

def _create_variant(event, url, headers, product_id, channel):
    mutation = """
    mutation CreateVariant($input: ProductVariantCreateInput!) {
      productVariantCreate(input: $input) {
        productVariant { id }
        errors { field message }
      }
    }
    """
    # SKU = EVENT-{ID}
    sku = f"EVENT-{event.id}"
    price_val = float(event.price) if event.price else 0.0

    variables = {
        "input": {
            "product": product_id,
            "sku": sku,
            "attributes": [] # Required by some Saleor configs even if empty
        }
    }

    try:
        r = requests.post(url, json={"query": mutation, "variables": variables}, headers=headers)
        data = r.json()
        logger.info(f"DEBUG: productVariantCreate response: {data}") # DEBUG

        var_data = data.get("data", {}).get("productVariantCreate", {})
        errors = var_data.get("errors", [])
        if errors:
            logger.error(f"❌ Variant Create Errors: {errors}")
            return

        variant_id = var_data.get("productVariant", {}).get("id")
        if variant_id:
             logger.info(f"✅ Created Variant ID: {variant_id} | SKU: {sku}")
             event.saleor_variant_id = variant_id
             event.save(update_fields=["saleor_variant_id"])
             logger.info(f"💰 Setting Price: {event.currency} {price_val} | Variant: {variant_id} | Channel: {channel}")
             _update_variant_channel_listing(event, url, headers, variant_id, channel)

             # Set stock based on max_participants
             logger.info(f"📦 Setting Stock: {event.max_participants or 'Unlimited (999999)'} | Variant: {variant_id}")
             _create_or_update_stock(event, url, headers, variant_id)

    except Exception as e:
        logger.error(f"❌ Exception creating variant: {e}")

def _update_product_channel_listing(url, headers, product_id, channel):
    mutation = """
    mutation UpdateProductChannel($id: ID!, $input: ProductChannelListingUpdateInput!) {
      productChannelListingUpdate(id: $id, input: $input) {
        errors { field message }
      }
    }
    """
    variables = {
        "id": product_id,
        "input": {
            "updateChannels": [{
                "channelId": channel,
                "isPublished": True,
                "isAvailableForPurchase": True
            }]
        }
    }
    # Note: channelId expects ID or Slug? Usually ID in strict API, but slug works in some versions or via separate lookup.
    # To be safe, we might need to fetch Channel ID by slug 'default-channel'. 
    # For this snippet, assuming slug works or we'd fetch ID. 
    # *FIX*: Saleor usually requires Channel ID. Let's assume user has default channel.
    
    # Hack: Try to fetch channel ID for slug first
    channel_id = _get_channel_id(url, headers, channel)
    if not channel_id:
         return 

    variables["input"]["updateChannels"][0]["channelId"] = channel_id

    try:
        requests.post(url, json={"query": mutation, "variables": variables}, headers=headers)
    except:
        pass

def _update_variant_channel_listing(event, url, headers, variant_id, channel):
    channel_id = _get_channel_id(url, headers, channel)
    if not channel_id:
        logger.warning(f"Channel '{channel}' not found in Saleor. Price sync FAILED for event {event.id}")
        return

    # Fix: Schema expects a LIST of inputs directly based on error message
    mutation = """
    mutation UpdateVariantChannel($id: ID!, $input: [ProductVariantChannelListingAddInput!]!) {
      productVariantChannelListingUpdate(id: $id, input: $input) {
        errors { field message }
      }
    }
    """
    price_val = float(event.price) if event.price else 0.0
    variables = {
        "id": variant_id,
        "input": [{
            "channelId": channel_id,
            "price": price_val,
            "costPrice": price_val
        }]
    }
    try:
        r = requests.post(url, json={"query": mutation, "variables": variables}, headers=headers)
        response_data = r.json()
        errors = response_data.get("data", {}).get("productVariantChannelListingUpdate", {}).get("errors", [])

        if errors:
            logger.error(f"❌ PRICE SYNC FAILED for Event {event.id}: {errors}")
        else:
            logger.info(f"✅ PRICE SET to {event.currency} {price_val} | Event: {event.title} (ID: {event.id}) | Channel: {channel}")
            logger.info(f"DEBUG: updateVariantChannel response: {response_data}")
    except Exception as e:
        logger.error(f"❌ Exception updating variant channel price for Event {event.id}: {e}")


def _update_variant_price(event, url, headers, variant_id, channel):
    # Same as listing update
    _update_variant_channel_listing(event, url, headers, variant_id, channel)


# --- Helpers ---

def _get_channel_id(url, headers, slug):
    query = """
    query Channels {
      channels {
        id
        slug
      }
    }
    """
    try:
        r = requests.post(url, json={"query": query}, headers=headers)
        if r.status_code == 200:
            for ch in r.json().get("data", {}).get("channels", []):
                if ch["slug"] == slug:
                    return ch["id"]
    except:
        pass
    return None

def _get_or_create_category(url, headers, name):
    # check existing
    query = """
    query Cats($search: String) {
      categories(filter: {search: $search}, first: 1) {
        edges { node { id name } }
      }
    }
    """
    try:
        r = requests.post(url, json={"query": query, "variables": {"search": name}}, headers=headers)
        edges = r.json().get("data", {}).get("categories", {}).get("edges", [])
        if edges:
            return edges[0]["node"]["id"]
    except:
        pass
        
    # create
    mutation = """
    mutation CreateCat($name: String!) {
      categoryCreate(input: {name: $name, slug: $name}) {
        category { id }
      }
    }
    """
    try:
        r = requests.post(url, json={"query": mutation, "variables": {"name": name}}, headers=headers)
        return r.json().get("data", {}).get("categoryCreate", {}).get("category", {}).get("id")
    except:
        return None

def _get_or_create_product_type(url, headers, name):
    # check existing
    query = """
    query Types($search: String) {
      productTypes(filter: {search: $search}, first: 1) {
        edges { node { id name } }
      }
    }
    """
    try:
        r = requests.post(url, json={"query": query, "variables": {"search": name}}, headers=headers)
        edges = r.json().get("data", {}).get("productTypes", {}).get("edges", [])
        if edges:
            return edges[0]["node"]["id"]
    except:
        pass
        
    # create (Requires knowing 'kind'. assume NORMAL)
    mutation = """
    mutation CreateType($name: String!) {
      productTypeCreate(input: {name: $name, slug: $name, hasVariants: false, isShippingRequired: false}) {
        productType { id }
      }
    }
    """
    # Note: If hasVariants=True, slightly more complex, but we set false logic above to simplify, 
    # actually we need variants for price. set hasVariants=True.
    
    mutation = """
    mutation CreateType($name: String!) {
      productTypeCreate(input: {name: $name, slug: $name, hasVariants: true, isShippingRequired: false}) {
        productType { id }
      }
    }
    """

    try:
        r = requests.post(url, json={"query": mutation, "variables": {"name": name}}, headers=headers)
        r_json = r.json()
        data = r_json.get("data", {}).get("productTypeCreate", {})
        errors = data.get("errors", [])
        if errors:
            logger.error(f"Error creating ProductType '{name}': {errors}")
            return None
            
        return data.get("productType", {}).get("id")
    except Exception as e:
        logger.error(f"Exception creating ProductType '{name}': {e}")
        return None

def _get_existing_product_type(url, headers, name):
    # Pure lookup - no creation
    query = """
    query Types($search: String) {
      productTypes(filter: {search: $search}, first: 1) {
        edges { node { id name } }
      }
    }
    """
    try:
        r = requests.post(url, json={"query": query, "variables": {"search": name}}, headers=headers)
        edges = r.json().get("data", {}).get("productTypes", {}).get("edges", [])
        if edges:
            return edges[0]["node"]["id"]
    except:
        pass
    return None

def _get_or_create_warehouse(url, headers):
    """Get default warehouse or create one if it doesn't exist."""
    # Try to fetch existing warehouses
    query = """
    query Warehouses {
      warehouses(first: 1) {
        edges { node { id name } }
      }
    }
    """
    try:
        r = requests.post(url, json={"query": query}, headers=headers)
        warehouses = r.json().get("data", {}).get("warehouses", {}).get("edges", [])
        if warehouses:
            warehouse_id = warehouses[0]["node"]["id"]
            logger.info(f"DEBUG: Found existing warehouse ID: {warehouse_id}")
            return warehouse_id
    except Exception as e:
        logger.warning(f"Error fetching warehouses: {e}")

    # If no warehouse exists, create one
    mutation = """
    mutation CreateWarehouse($name: String!, $slug: String!) {
      warehouseCreate(input: {name: $name, slug: $slug}) {
        warehouse { id }
        errors { field message }
      }
    }
    """
    try:
        r = requests.post(url, json={"query": mutation, "variables": {"name": "Default", "slug": "default"}}, headers=headers)
        warehouse_id = r.json().get("data", {}).get("warehouseCreate", {}).get("warehouse", {}).get("id")
        if warehouse_id:
            logger.info(f"DEBUG: Created warehouse ID: {warehouse_id}")
            return warehouse_id
    except Exception as e:
        logger.error(f"Error creating warehouse: {e}")

    return None

def _create_or_update_stock(event, url, headers, variant_id):
    """
    Update stock for event variant using productVariantStocksUpdate mutation.
    Saleor 3.22.x uses this mutation for stock management.
    - max_participants = quantity in Saleor
    - NULL = 999999 (practically unlimited)
    """
    warehouse_id = _get_or_create_warehouse(url, headers)
    if not warehouse_id:
        logger.error(f"❌ STOCK SYNC FAILED: Could not get warehouse for event {event.id}")
        return

    # Determine stock quantity
    stock_qty = event.max_participants if event.max_participants else 999999

    # Use productVariantStocksUpdate mutation (Saleor 3.22.x)
    mutation_update = """
    mutation UpdateVariantStocks($variantId: ID!, $stocks: [StockInput!]!) {
      productVariantStocksUpdate(variantId: $variantId, stocks: $stocks) {
        productVariant { id }
        errors { field message }
      }
    }
    """

    try:
        variables = {
            "variantId": variant_id,
            "stocks": [
                {
                    "warehouse": warehouse_id,
                    "quantity": stock_qty
                }
            ]
        }
        r = requests.post(url, json={"query": mutation_update, "variables": variables}, headers=headers)
        response_data = r.json()
        logger.info(f"DEBUG: productVariantStocksUpdate response: {response_data}")

        # Check for GraphQL errors
        graphql_errors = response_data.get("errors", [])
        if graphql_errors:
            logger.error(f"❌ GraphQL Error updating stock: {graphql_errors}")
            return

        stock_data = response_data.get("data", {}).get("productVariantStocksUpdate", {})
        errors = stock_data.get("errors", [])

        if errors:
            logger.error(f"❌ STOCK UPDATE ERROR: {errors}")
            return

        variant_result = stock_data.get("productVariant", {})
        if variant_result.get("id"):
            logger.info(f"✅ STOCK SET | Qty: {stock_qty} units | Variant: {variant_id} | Warehouse: {warehouse_id}")
            return

        logger.warning(f"⚠️  Unexpected response structure: {stock_data}")

    except Exception as e:
        logger.error(f"❌ Exception updating stock: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")

def delete_event_from_saleor(event):
    """
    Deletes the Saleor product associated with the event.
    Called when platform admin permanently deletes an event.
    """
    saleor_url = getattr(settings, "SALEOR_API_URL", None)
    saleor_token = getattr(settings, "SALEOR_APP_TOKEN", None)

    if not saleor_url or not saleor_token:
        logger.warning(f"Skipping Saleor event deletion: Settings missing for event {event.id}")
        return

    if not event.saleor_product_id:
        logger.info(f"Event {event.id} has no Saleor product, nothing to delete.")
        return

    headers = {
        "Authorization": f"Bearer {saleor_token}",
        "Content-Type": "application/json"
    }

    mutation = """
    mutation DeleteProduct($id: ID!) {
      productDelete(id: $id) {
        errors { field message }
      }
    }
    """
    variables = {"id": event.saleor_product_id}

    try:
        logger.info(f"🗑️  Deleting Saleor product {event.saleor_product_id} for event {event.id}")
        r = requests.post(saleor_url, json={"query": mutation, "variables": variables}, headers=headers)
        response_data = r.json()

        errors = response_data.get("data", {}).get("productDelete", {}).get("errors", [])
        if errors:
            logger.error(f"❌ Failed to delete Saleor product {event.saleor_product_id}: {errors}")
        else:
            logger.info(f"✅ Successfully deleted Saleor product {event.saleor_product_id} for event {event.id}")
            # Clear the IDs so event deletion record doesn't reference old Saleor product
            event.saleor_product_id = None
            event.saleor_variant_id = None
            event.save(update_fields=["saleor_product_id", "saleor_variant_id"])
    except Exception as e:
        logger.error(f"❌ Exception deleting Saleor product for event {event.id}: {e}")


def json_description(text):
    # Saleor 3.x description is JSON (EditorJS style)
    # MUST return a string, not a dict object for the GraphQL variable if the schema expects JSONScalar
    # But usually ProductCreateInput description is JSONString.

    data = {
        "time": 1600000000000,
        "blocks": [{"type": "paragraph", "data": {"text": text}}],
        "version": "2.18.0"
    }
    return json.dumps(data)


def extract_text_from_json_description(json_desc):
    """
    Extracts plain text from Saleor's EditorJS-style JSON description.
    """
    if not json_desc:
        return ""
    
    try:
        if isinstance(json_desc, str):
            data = json.loads(json_desc)
        else:
            data = json_desc
            
        blocks = data.get("blocks", [])
        text_parts = []
        for block in blocks:
            if block.get("type") == "paragraph":
                text = block.get("data", {}).get("text", "")
                if text:
                    text_parts.append(text)
            # Add more block types if needed (header, list, etc.)
            
        return "\n".join(text_parts)
    except Exception as e:
        logger.warning(f"Failed to parse Saleor description JSON: {e}")
        return str(json_desc)


def _fetch_full_product_from_saleor(product_id):
    """
    Fetch complete product details from Saleor API including variants, pricing, and stock.
    Called when webhook payload has incomplete data.
    """
    saleor_url = getattr(settings, "SALEOR_API_URL", None)
    saleor_token = getattr(settings, "SALEOR_APP_TOKEN", None)

    if not saleor_url or not saleor_token:
        logger.warning("Cannot fetch full product: Saleor settings missing")
        return None

    headers = {
        "Authorization": f"Bearer {saleor_token}",
        "Content-Type": "application/json"
    }

    query = """
    query GetProduct($id: ID!) {
      product(id: $id) {
        id
        name
        slug
        description
        variants {
          id
          sku
          channelListings {
            channel {
              slug
            }
            price {
              amount
            }
          }
          stocks {
            quantity
          }
        }
      }
    }
    """

    try:
        r = requests.post(saleor_url, json={"query": query, "variables": {"id": product_id}}, headers=headers)
        data = r.json()
        product = data.get("data", {}).get("product")
        if product:
            logger.info(f"✅ Fetched full product data from Saleor for {product_id}")
            return product
        else:
            errors = data.get("errors", [])
            logger.error(f"❌ GraphQL error fetching product: {errors}")
            return None
    except Exception as e:
        logger.error(f"❌ Exception fetching product from Saleor: {e}")
        return None


def sync_event_from_saleor_data(product_data):
    """
    Creates or updates an Event in ECP from Saleor product data.
    If webhook data is incomplete (no channel listings), fetch full product from Saleor API.
    """
    if not isinstance(product_data, dict):
        logger.error(f"Saleor product data is not a dict: {type(product_data)}")
        return None, "error"

    saleor_id = product_data.get("id")
    if not saleor_id:
        logger.error(f"Saleor product data missing ID. Data keys: {list(product_data.keys())}")
        return None, "error"

    name = product_data.get("name")
    slug = product_data.get("slug")
    description_json = product_data.get("description")
    description_text = extract_text_from_json_description(description_json)

    # Resolve variants and price
    variants = product_data.get("variants", [])

    # If webhook has no variants or empty channel listings, fetch full product data
    has_pricing = any(
        v.get("channelListings")
        for v in variants
    ) if variants else False

    if not has_pricing and variants:
        logger.info(f"🔄 Webhook missing pricing data, fetching full product from Saleor...")
        full_product = _fetch_full_product_from_saleor(saleor_id)
        if full_product:
            product_data = full_product
            variants = product_data.get("variants", [])
        else:
            logger.warning(f"⚠️  Could not fetch full product, using incomplete webhook data")
    variant_id = None
    price = 0.0
    max_participants = None

    if variants:
        # For simplicity, we take the first variant
        variant = variants[0]
        variant_id = variant.get("id")
        logger.info(f"DEBUG: Variant data keys: {list(variant.keys())}")

        # Extract price from channel listings
        channel_listings = variant.get("channelListings", [])
        logger.info(f"DEBUG: Channel listings found: {len(channel_listings)}")

        if channel_listings:
            # 1. Try to find the exact configured channel (global-events = USD)
            target_channel = getattr(settings, "SALEOR_CHANNEL_SLUG", "global-events")
            listing = next((l for l in channel_listings if l.get("channel", {}).get("slug") == target_channel), None)

            # 2. If not found, just take the first one that has a price
            if not listing:
                listing = next((l for l in channel_listings if l.get("price")), channel_listings[0] if channel_listings else None)

            if listing:
                price_data = listing.get("price")
                if price_data:
                    price = float(price_data.get("amount", 0.0))
                    logger.info(f"✅ PRICE EXTRACTED: ${price} from channel '{target_channel}'")
                else:
                    logger.warning(f"⚠️  No price data in listing: {listing}")
            else:
                logger.warning(f"⚠️  Channel '{target_channel}' not found in listings. Available channels: {[l.get('channel', {}).get('slug') for l in channel_listings]}")
        else:
            logger.warning(f"⚠️  No channel listings in variant. Webhook may not include pricing data.")

        # Extract stock/max_participants
        stocks = variant.get("stocks", [])
        if stocks:
            max_participants = stocks[0].get("quantity")
            logger.info(f"DEBUG: Max participants set to: {max_participants}")

    # Fetch or create event
    try:
        event = Event.objects.get(saleor_product_id=saleor_id)
        is_new = False
    except Event.DoesNotExist:
        event = Event(saleor_product_id=saleor_id)
        is_new = True

    # Default associations
    if is_new:
        # Use default community (ID 1)
        try:
            community_id = getattr(settings, "WP_SYNC_DEFAULT_COMMUNITY_ID", 1)
            event.community = Community.objects.get(id=community_id)
        except Community.DoesNotExist:
            logger.error(f"Default community {community_id} not found for Saleor sync")
            return None, "error"

        # Use first superuser as creator
        creator = User.objects.filter(is_superuser=True).first()
        if not creator:
            logger.error("No superuser found to assign as creator for Saleor sync")
            return None, "error"
        event.created_by = creator
        event.status = "published" # Synced events from Saleor are assumed published

    # Update fields
    event.title = name
    if slug:
        event.slug = slug
    event.description = description_text
    event.price = price
    event.is_free = (price == 0.0)
    event.max_participants = max_participants
    event.saleor_variant_id = variant_id
    
    # Placeholder for timing if not provided by Saleor (Events in ECP need start/end)
    if not event.start_time:
        event.start_time = timezone.now() + timezone.timedelta(days=7)
    if not event.end_time:
        event.end_time = event.start_time + timezone.timedelta(hours=1)

    event.skip_saleor_sync = True
    event.save()

    action = "created" if is_new else "updated"
    logger.info(f"{'✅' if price > 0 else '⚠️ '} {action.capitalize()} Event {event.id} | Title: {event.title} | Price: ${event.price} {event.currency} | Max Participants: {event.max_participants} | Format: {event.format}")
    return event, action
