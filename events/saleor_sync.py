import requests
import json
import logging
import time
from django.conf import settings
from django.contrib.auth.models import User
from django.utils import timezone
from .models import Event
from community.models import Community

logger = logging.getLogger(__name__)

CURRENCY_NAMES = {
    "USD": "US Dollar", "EUR": "Euro", "GBP": "British Pound",
    "CHF": "Swiss Franc", "INR": "Indian Rupee", "AED": "UAE Dirham",
    "SGD": "Singapore Dollar", "AUD": "Australian Dollar", "CAD": "Canadian Dollar",
}
COMMON_CURRENCIES = ["USD", "EUR", "GBP", "CHF", "INR", "AED", "SGD", "AUD", "CAD"]

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

    # 3. Verify / Correct Linkage via SKU
    # Saleor SKUs (EVENT-{id}) are our unique anchor. 
    # If the local saleor_product_id is missing or out of sync, we fix it.
    sku = f"EVENT-{event.id}"
    existing_variant = _get_variant_by_sku(saleor_url, headers, sku)
    
    if existing_variant:
        v_id = existing_variant["id"]
        p_id = existing_variant["product"]["id"]
        if event.saleor_product_id != p_id or event.saleor_variant_id != v_id:
            logger.info(f"🔗 Re-linking Event {event.id} to existing Saleor Product {p_id} (Variant {v_id}) via SKU {sku}")
            
            # If we had a different product ID, it's likely a duplicate from a failed previous sync
            if event.saleor_product_id and event.saleor_product_id != p_id:
                logger.info(f"🗑️ Cleaning up redundant Saleor product {event.saleor_product_id}")
                _delete_product_by_id(saleor_url, headers, event.saleor_product_id)

            event.saleor_product_id = p_id
            event.saleor_variant_id = v_id
            event.save(update_fields=["saleor_product_id", "saleor_variant_id"])

    # 4. Create or Update Product
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

    # Ensure product is in channel
    _update_product_channel_listing(url, headers, event.saleor_product_id, channel)

    # Ensure variant exists
    if not event.saleor_variant_id:
        logger.info(f"➕ Variant missing for product {event.saleor_product_id}, creating one...")
        _create_variant(event, url, headers, event.saleor_product_id, channel)
    else:
        logger.info(f"💰 UPDATING Price on Variant: {event.saleor_variant_id} | Event: {event.title}")
        _update_variant_price(event, url, headers, event.saleor_variant_id, channel)

        # Also update stock if max_participants changed
        logger.info(f"📦 UPDATING Stock: {event.max_participants or 'Unlimited (999999)'} | Variant: {event.saleor_variant_id}")
        _create_or_update_stock(event, url, headers, event.saleor_variant_id)

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
            # Check for SKU collision
            is_sku_error = any(e.get('field') == 'sku' and 'already exists' in e.get('message', '').lower() for e in errors)
            if is_sku_error:
                logger.info(f"ℹ️ SKU {sku} already exists. Fetching existing variant...")
                existing_variant = _get_variant_by_sku(url, headers, sku)
                if existing_variant:
                    v_id = existing_variant["id"]
                    p_id = existing_variant["product"]["id"]
                    
                    if p_id == product_id:
                        logger.info(f"✅ SKU belongs to CURRENT product. Using Variant {v_id}")
                        event.saleor_variant_id = v_id
                        event.save(update_fields=["saleor_variant_id"])
                        _update_variant_channel_listing(event, url, headers, v_id, channel)
                        _create_or_update_stock(event, url, headers, v_id)
                        return
                    else:
                        logger.error(f"❌ SKU COLLISION: {sku} belongs to DIFFERENT product {p_id}")
            
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
        r = requests.post(url, json={"query": mutation, "variables": variables}, headers=headers)
        data = r.json()
        errors = data.get("data", {}).get("productChannelListingUpdate", {}).get("errors", [])
        if errors:
            logger.error(f"❌ Product Channel Update Errors for {product_id}: {errors}")
        else:
            logger.info(f"✅ Product {product_id} listed in channel {channel}")
    except Exception as e:
        logger.error(f"❌ Exception in product channel update: {e}")

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
        else:
            logger.error(f"❌ Error fetching channels: {r.status_code} {r.text}")
    except Exception as e:
        logger.error(f"❌ Exception fetching channels: {e}")
    return None

def _get_variant_by_sku(url, headers, sku):
    query = """
    query GetVariantBySku($sku: String!) {
      productVariant(sku: $sku) {
        id
        sku
        product { id }
      }
    }
    """
    try:
        r = requests.post(url, json={"query": query, "variables": {"sku": sku}}, headers=headers)
        return r.json().get("data", {}).get("productVariant")
    except:
        return None

def _delete_product_by_id(url, headers, product_id):
    mutation = """
    mutation DeleteProduct($id: ID!) {
      productDelete(id: $id) {
        errors { field message }
      }
    }
    """
    try:
        requests.post(url, json={"query": mutation, "variables": {"id": product_id}}, headers=headers)
    except:
        pass

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

    # create using modern Saleor schema (no hasVariants, use kind instead)
    mutation = """
    mutation CreateType($name: String!) {
      productTypeCreate(input: {name: $name, slug: $name, kind: NORMAL, isShippingRequired: false}) {
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
    price = None
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
        event = None
        if slug:
            event = Event.objects.filter(slug=slug).first()
            if event:
                logger.info(f"🔗 Matched existing Event {event.id} by slug '{slug}' for Saleor product {saleor_id}")
                event.saleor_product_id = saleor_id
        if event is None:
            event = Event(saleor_product_id=saleor_id)
            is_new = True
        else:
            is_new = False

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
    if price is not None:
        event.price = price
        event.is_free = (price == 0.0)
    else:
        logger.info(
            f"ℹ️ No pricing found in Saleor webhook for product {saleor_id}; keeping existing price "
            f"{event.price} and is_free={event.is_free}"
        )
    if max_participants is not None:
        event.max_participants = max_participants
    if variant_id:
        event.saleor_variant_id = variant_id
    
    # Placeholder for timing if not provided by Saleor (Events in ECP need start/end)
    if not event.start_time:
        event.start_time = timezone.now() + timezone.timedelta(days=7)
    if not event.end_time:
        event.end_time = event.start_time + timezone.timedelta(hours=1)

    event.skip_saleor_sync = True
    event.save()

    action = "created" if is_new else "updated"
    price_status = event.price if event.price is not None else 0
    logger.info(f"{'✅' if price_status > 0 else '⚠️ '} {action.capitalize()} Event {event.id} | Title: {event.title} | Price: ${event.price} {event.currency} | Max Participants: {event.max_participants} | Format: {event.format}")
    return event, action

# ============================================================
# ============ Channel, Warehouse, Shipping Zone Sync ========
# ============================================================

def call_saleor_gql(query, variables=None):
    """Generic helper to call Saleor GraphQL API."""
    saleor_url = getattr(settings, "SALEOR_API_URL", None)
    saleor_token = getattr(settings, "SALEOR_APP_TOKEN", None)
    if not saleor_url or not saleor_token:
        raise Exception("Saleor configuration missing")
    
    headers = {
        "Authorization": f"Bearer {saleor_token}",
        "Content-Type": "application/json"
    }
    try:
        r = requests.post(saleor_url, json={"query": query, "variables": variables}, headers=headers, timeout=20)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.HTTPError as e:
        try:
            error_body = r.json()
            logger.error(f"Saleor GQL Error Response: {error_body}")
        except:
            logger.error(f"Saleor GQL Error Body: {r.text}")
        raise
    except Exception as e:
        logger.error(f"Error calling Saleor GQL: {e}")
        raise

def get_saleor_channel_options():
    """Fetch shop options (countries, currencies) from Saleor and combine with local warehouses/shipping zones."""
    query = """
    query SaleorShopOptions {
      shop {
        countries {
          code
          country
        }
        channelCurrencies
      }
    }
    """
    data = call_saleor_gql(query)
    shop = data.get("data", {}).get("shop", {})

    countries = [{"code": c["code"], "country": c["country"]} for c in shop.get("countries", [])]

    saleor_currencies = shop.get("channelCurrencies", [])
    all_codes = list(dict.fromkeys(saleor_currencies + COMMON_CURRENCIES))
    currencies = [{"code": c, "label": f"{c} - {CURRENCY_NAMES.get(c, c)}"} for c in all_codes]

    from .models import SaleorWarehouse, SaleorShippingZone
    warehouses = list(SaleorWarehouse.objects.values("id", "saleor_id", "name", "slug"))
    shipping_zones = list(SaleorShippingZone.objects.values("id", "saleor_id", "name", "channel_ids"))

    return {
        "countries": countries,
        "currencies": currencies,
        "warehouses": warehouses,
        "shipping_zones": shipping_zones,
    }

def get_warehouse_options():
    """Fetch shop countries from Saleor and combine with local shipping zones for warehouse creation."""
    query = """
    query SaleorWarehouseOptions {
      shop {
        countries {
          code
          country
        }
      }
    }
    """
    try:
        data = call_saleor_gql(query)
        shop = data.get("data", {}).get("shop", {})
        countries = [{"code": c["code"], "country": c["country"]} for c in shop.get("countries", [])]

        from .models import SaleorShippingZone
        shipping_zones = list(SaleorShippingZone.objects.values("id", "saleor_id", "name", "warehouse_ids"))

        return {
            "countries": countries,
            "shipping_zones": shipping_zones,
        }
    except Exception as e:
        logger.error(f"Error fetching warehouse options: {e}")
        raise

def sync_channels_from_saleor():
    """Fetch all channels from Saleor and update local DB."""
    query = """
    query Channels {
      channels {
        id
        name
        slug
        currencyCode
        isActive
        defaultCountry {
          code
        }
        countries {
          code
        }
        warehouses {
          id
        }
        stockSettings {
          allocationStrategy
        }
      }
    }
    """
    try:
        data = call_saleor_gql(query)
        channels = data.get("data", {}).get("channels", [])
        synced_ids = []

        from .models import SaleorChannel
        for ch in channels:
            stock_settings = ch.get("stockSettings", {}) or {}
            allocation_strategy = stock_settings.get("allocationStrategy", "PRIORITIZE_SORTING_ORDER")

            obj, _ = SaleorChannel.objects.update_or_create(
                saleor_id=ch["id"],
                defaults={
                    "name": ch["name"],
                    "slug": ch["slug"],
                    "currency": ch["currencyCode"],
                    "is_active": ch["isActive"],
                    "default_country": ch.get("defaultCountry", {}).get("code") if ch.get("defaultCountry") else None,
                    "countries": [c["code"] for c in ch.get("countries", [])],
                    "warehouse_ids": [w["id"] for w in ch.get("warehouses", [])],
                    "allocation_strategy": allocation_strategy,
                }
            )
            synced_ids.append(obj.saleor_id)

        # Delete records that no longer exist in Saleor
        SaleorChannel.objects.exclude(saleor_id__in=synced_ids).delete()
        return synced_ids
    except Exception as e:
        logger.error(f"Error syncing Saleor channels: {e}")
        raise

def sync_warehouses_from_saleor():
    """Fetch all warehouses from Saleor with pagination and update local DB."""
    query = """
    query Warehouses($after: String) {
      warehouses(first: 100, after: $after) {
        pageInfo {
          hasNextPage
          endCursor
        }
        edges {
          node {
            id
            name
            slug
            email
            isPrivate
            clickAndCollectOption
            address {
              companyName
              streetAddress1
              streetAddress2
              city
              postalCode
              countryArea
              phone
              country {
                code
                country
              }
            }
            shippingZones(first: 100) {
              edges {
                node {
                  id
                }
              }
            }
          }
        }
      }
    }
    """
    try:
        synced_ids = []
        has_next = True
        after = None

        from .models import SaleorWarehouse
        while has_next:
            data = call_saleor_gql(query, {"after": after})
            wh_data = data.get("data", {}).get("warehouses", {})
            edges = wh_data.get("edges", [])

            for edge in edges:
                node = edge["node"]
                addr = node.get("address") or {}
                country = addr.get("country") or {}

                obj, _ = SaleorWarehouse.objects.update_or_create(
                    saleor_id=node["id"],
                    defaults={
                        "name": node["name"],
                        "slug": node["slug"],
                        "email": node.get("email"),
                        "company_name": addr.get("companyName"),
                        "street_address_1": addr.get("streetAddress1"),
                        "street_address_2": addr.get("streetAddress2"),
                        "city": addr.get("city"),
                        "country": country.get("country"),
                        "country_code": country.get("code"),
                        "postal_code": addr.get("postalCode"),
                        "country_area": addr.get("countryArea"),
                        "phone": addr.get("phone"),
                        "click_and_collect": node.get("clickAndCollectOption", "disabled").lower(),
                        "is_private": node.get("isPrivate", False),
                        "is_active": True,
                        "shipping_zone_ids": [edge["node"]["id"] for edge in node.get("shippingZones", {}).get("edges", [])],
                    }
                )
                synced_ids.append(obj.saleor_id)
            
            page_info = wh_data.get("pageInfo", {})
            has_next = page_info.get("hasNextPage")
            after = page_info.get("endCursor")

        # Delete records that no longer exist in Saleor
        SaleorWarehouse.objects.exclude(saleor_id__in=synced_ids).delete()
        return synced_ids
    except Exception as e:
        logger.error(f"Error syncing Saleor warehouses: {e}")
        raise

def sync_shipping_zones_from_saleor():
    """Fetch all shipping zones from Saleor with pagination and update local DB."""
    query = """
    query ShippingZones($after: String) {
      shippingZones(first: 100, after: $after) {
        pageInfo {
          hasNextPage
          endCursor
        }
        edges {
          node {
            id
            name
            description
            default
            countries {
              code
            }
            warehouses {
              id
            }
            channels {
              id
            }
            shippingMethods {
              id
              name
              type
              minimumDeliveryDays
              maximumDeliveryDays
              channelListings {
                channel {
                  id
                  slug
                }
                price {
                  amount
                  currency
                }
                minimumOrderPrice {
                  amount
                  currency
                }
                maximumOrderPrice {
                  amount
                  currency
                }
              }
            }
          }
        }
      }
    }
    """
    try:
        synced_ids = []
        has_next = True
        after = None
        
        from .models import SaleorShippingZone
        while has_next:
            data = call_saleor_gql(query, {"after": after})
            sz_data = data.get("data", {}).get("shippingZones", {})
            edges = sz_data.get("edges", [])
            
            for edge in edges:
                node = edge["node"]
                
                obj, _ = SaleorShippingZone.objects.update_or_create(
                    saleor_id=node["id"],
                    defaults={
                        "name": node["name"],
                        "description": node.get("description") or "",
                        "is_default": node.get("default", False),
                        "countries": [c["code"] for c in node.get("countries", [])],
                        "warehouse_ids": [w["id"] for w in node.get("warehouses", [])],
                        "channel_ids": [c["id"] for c in node.get("channels", [])],
                        "shipping_methods": node.get("shippingMethods", []),
                        "is_active": True,
                    }
                )
                synced_ids.append(obj.saleor_id)
            
            page_info = sz_data.get("pageInfo", {})
            has_next = page_info.get("hasNextPage")
            after = page_info.get("endCursor")

        # Delete records that no longer exist in Saleor
        SaleorShippingZone.objects.exclude(saleor_id__in=synced_ids).delete()
        return synced_ids
    except Exception as e:
        logger.error(f"Error syncing Saleor shipping zones: {e}")
        raise

def sync_product_types_from_saleor():
    """Fetch all product types from Saleor and update local DB."""
    query = """
    query ProductTypes {
      productTypes(first: 100, sortBy: { field: NAME, direction: ASC }) {
        edges {
          node {
            id
            name
            slug
            kind
            isShippingRequired
            taxClass {
              id
              name
            }
            productAttributes {
              id
              name
              slug
            }
            assignedVariantAttributes {
              attribute {
                id
                name
                slug
              }
            }
            metadata {
              key
              value
            }
            privateMetadata {
              key
              value
            }
          }
        }
      }
    }
    """
    try:
        data = call_saleor_gql(query)
        product_types_data = data.get("data", {}).get("productTypes", {}).get("edges", [])
        synced_ids = []

        from .models import SaleorProductType
        for edge in product_types_data:
            node = edge["node"]
            tax_class = node.get("taxClass") or {}

            obj, _ = SaleorProductType.objects.update_or_create(
                saleor_id=node["id"],
                defaults={
                    "name": node["name"],
                    "slug": node["slug"],
                    "kind": node["kind"],
                    "is_shipping_required": node.get("isShippingRequired", False),
                    "tax_class_id": tax_class.get("id"),
                    "tax_class_name": tax_class.get("name"),
                    "product_attribute_ids": [a["id"] for a in node.get("productAttributes", [])],
                    "variant_attribute_ids": [a["attribute"]["id"] for a in node.get("assignedVariantAttributes", [])],
                    "metadata": {m["key"]: m["value"] for m in node.get("metadata", [])},
                    "private_metadata": {m["key"]: m["value"] for m in node.get("privateMetadata", [])},
                }
            )
            synced_ids.append(obj.saleor_id)

        SaleorProductType.objects.exclude(saleor_id__in=synced_ids).delete()
        return synced_ids
    except Exception as e:
        logger.error(f"Error syncing Saleor product types: {e}")
        raise


def create_product_type_in_saleor(data):
    """Create a product type in Saleor."""
    mutation = """
    mutation ProductTypeCreate($input: ProductTypeInput!) {
      productTypeCreate(input: $input) {
        productType {
          id
          name
          slug
          kind
          isShippingRequired
          taxClass {
            id
            name
          }
        }
        errors {
          field
          code
          message
        }
      }
    }
    """
    input_data = {
        "name": data.get("name"),
        "slug": data.get("slug"),
        "kind": data.get("kind", "NORMAL"),
        "isShippingRequired": data.get("is_shipping_required", False),
    }
    if data.get("tax_class_id"):
        input_data["taxClass"] = data.get("tax_class_id")

    return call_saleor_gql(mutation, {"input": input_data})


def update_product_type_in_saleor(saleor_id, data):
    """Update a product type in Saleor."""
    mutation = """
    mutation ProductTypeUpdate($id: ID!, $input: ProductTypeInput!) {
      productTypeUpdate(id: $id, input: $input) {
        productType {
          id
          name
          slug
          kind
          isShippingRequired
          taxClass {
            id
            name
          }
        }
        errors {
          field
          code
          message
        }
      }
    }
    """
    input_data = {}
    if "name" in data:
        input_data["name"] = data["name"]
    if "slug" in data:
        input_data["slug"] = data["slug"]
    if "kind" in data:
        input_data["kind"] = data["kind"]
    if "is_shipping_required" in data:
        input_data["isShippingRequired"] = data["is_shipping_required"]
    if "tax_class_id" in data and data["tax_class_id"]:
        input_data["taxClass"] = data["tax_class_id"]

    return call_saleor_gql(mutation, {"id": saleor_id, "input": input_data})


def delete_product_type_in_saleor(saleor_id):
    """Delete a product type from Saleor."""
    mutation = """
    mutation ProductTypeDelete($id: ID!) {
      productTypeDelete(id: $id) {
        productType {
          id
          name
        }
        errors {
          field
          code
          message
        }
      }
    }
    """
    return call_saleor_gql(mutation, {"id": saleor_id})


def get_product_type_options():
    """Fetch tax classes from Saleor and return with product type kinds."""
    query = """
    query ProductTypeOptions {
      taxClasses(first: 100) {
        edges {
          node {
            id
            name
          }
        }
      }
    }
    """
    try:
        data = call_saleor_gql(query)
        tax_classes_data = data.get("data", {}).get("taxClasses", {}).get("edges", [])
        tax_classes = [
            {"id": edge["node"]["id"], "name": edge["node"]["name"]}
            for edge in tax_classes_data
        ]
    except Exception as e:
        logger.error(f"Error fetching tax classes: {e}")
        tax_classes = []

    return {
        "tax_classes": tax_classes,
        "product_type_kinds": [
            {"value": "NORMAL", "label": "Regular product type"},
            {"value": "GIFT_CARD", "label": "Gift card product type"},
        ],
    }

# Mutations

def get_shipping_zone_options():
    """
    Fetch countries from Saleor GraphQL and combine with local channels/warehouses.
    Used by the shipping zone create/edit form.
    """
    query = """
    query SaleorShippingZoneOptions {
      shop {
        countries {
          code
          country
        }
      }
    }
    """
    try:
        data = call_saleor_gql(query)
        shop = data.get("data", {}).get("shop", {})
        countries = [{"code": c["code"], "country": c["country"]} for c in shop.get("countries", [])]
    except Exception as e:
        logger.error(f"Error fetching countries from Saleor: {e}")
        countries = []

    from .models import SaleorChannel, SaleorWarehouse
    channels = list(SaleorChannel.objects.values("id", "saleor_id", "name", "slug", "currency", "is_active"))
    warehouses = list(SaleorWarehouse.objects.values("id", "saleor_id", "name", "slug", "is_active"))

    return {
        "countries": countries,
        "channels": channels,
        "warehouses": warehouses,
    }


def create_shipping_zone_in_saleor(data):
    """Create a shipping zone in Saleor with full field support."""
    mutation = """
    mutation ShippingZoneCreate($input: ShippingZoneCreateInput!) {
      shippingZoneCreate(input: $input) {
        shippingZone {
          id
          name
          description
          default
          countries {
            code
          }
          warehouses {
            id
            name
          }
          channels {
            id
            slug
          }
        }
        errors {
          field
          code
          message
          channels
          warehouses
        }
      }
    }
    """
    is_default = data.get("is_default", False)
    # If default zone, countries can be empty
    countries = [] if is_default else data.get("countries", [])

    input_data = {
        "name": data.get("name"),
        "description": data.get("description", ""),
        "countries": countries,
        "default": is_default,
        "addChannels": data.get("channel_ids", []),
        "addWarehouses": data.get("warehouse_ids", []),
    }
    # Remove None values to avoid sending nulls
    input_data = {k: v for k, v in input_data.items() if v is not None}
    return call_saleor_gql(mutation, {"input": input_data})


def update_shipping_zone_in_saleor(saleor_id, data):
    """Update a shipping zone in Saleor with add/remove channels and warehouses support."""
    mutation = """
    mutation ShippingZoneUpdate($id: ID!, $input: ShippingZoneUpdateInput!) {
      shippingZoneUpdate(id: $id, input: $input) {
        shippingZone {
          id
          name
          description
          default
          countries {
            code
          }
          warehouses {
            id
            name
          }
          channels {
            id
            slug
          }
        }
        errors {
          field
          code
          message
          channels
          warehouses
        }
      }
    }
    """
    is_default = data.get("is_default", False)
    # If default zone, countries should be empty
    countries = [] if is_default else data.get("countries", [])

    input_data = {
        "name": data.get("name"),
        "description": data.get("description", ""),
        "countries": countries,
        "default": is_default,
    }

    # Only include add/remove if explicitly provided in the payload
    if "add_channel_ids" in data and data["add_channel_ids"] is not None:
        input_data["addChannels"] = data["add_channel_ids"]
    if "remove_channel_ids" in data and data["remove_channel_ids"] is not None:
        input_data["removeChannels"] = data["remove_channel_ids"]
    if "add_warehouse_ids" in data and data["add_warehouse_ids"] is not None:
        input_data["addWarehouses"] = data["add_warehouse_ids"]
    if "remove_warehouse_ids" in data and data["remove_warehouse_ids"] is not None:
        input_data["removeWarehouses"] = data["remove_warehouse_ids"]

    # Remove None values
    input_data = {k: v for k, v in input_data.items() if v is not None}
    return call_saleor_gql(mutation, {"id": saleor_id, "input": input_data})


def delete_shipping_zone_in_saleor(saleor_id):
    """Delete a shipping zone from Saleor."""
    mutation = """
    mutation ShippingZoneDelete($id: ID!) {
      shippingZoneDelete(id: $id) {
        shippingZone {
          id
          name
        }
        errors {
          field
          code
          message
        }
      }
    }
    """
    return call_saleor_gql(mutation, {"id": saleor_id})

def create_warehouse_in_saleor(request_data):
    mutation = """
    mutation WarehouseCreate($input: WarehouseCreateInput!) {
      warehouseCreate: createWarehouse(input: $input) {
        warehouse {
          id
          name
          slug
          email
          externalReference
          address {
            companyName
            streetAddress1
            streetAddress2
            city
            postalCode
            countryArea
            phone
            country {
              code
              country
            }
          }
        }
        errors {
          field
          code
          message
        }
      }
    }
    """
    # Build WarehouseCreateInput (does NOT support isPrivate, clickAndCollectOption, or shippingZones)
    address_input = {
        "country": (request_data.get("country_code") or "US").upper()[:2],
        "streetAddress1": request_data.get("street_address_1"),
        "city": request_data.get("city"),
    }
    if request_data.get("company_name"):
        address_input["companyName"] = request_data["company_name"]
    if request_data.get("street_address_2"):
        address_input["streetAddress2"] = request_data["street_address_2"]
    if request_data.get("postal_code"):
        address_input["postalCode"] = request_data["postal_code"]
    if request_data.get("country_area"):
        address_input["countryArea"] = request_data["country_area"]
    if request_data.get("phone"):
        address_input["phone"] = request_data["phone"]

    # Add skipValidation to address
    address_input["skipValidation"] = True

    input_data = {
        "name": request_data.get("name"),
        "slug": request_data.get("slug"),
        "email": request_data.get("email") or "",
        "address": address_input,
    }

    result = call_saleor_gql(mutation, {"input": input_data})

    # Extract warehouse ID if creation succeeded
    result_data = result.get("data", {}) or {}
    create_result = result_data.get("warehouseCreate", {}) or {}
    wh_node = create_result.get("warehouse") or {}
    wh_id = wh_node.get("id")

    if wh_id:
        # Step 2: Update isPrivate and clickAndCollectOption
        update_data = {}
        if "is_private" in request_data:
            update_data["is_private"] = request_data["is_private"]
        if "click_and_collect" in request_data:
            update_data["click_and_collect"] = request_data["click_and_collect"]
        if update_data:
            try:
                update_warehouse_in_saleor(wh_id, update_data)
            except Exception as e:
                logger.warning(f"Failed to update warehouse settings after creation: {e}")

        # Step 3: Assign shipping zones if provided
        shipping_zone_ids = request_data.get("shipping_zone_ids", [])
        if shipping_zone_ids:
            try:
                assign_warehouse_shipping_zones(wh_id, shipping_zone_ids)
            except Exception as e:
                logger.warning(f"Failed to assign shipping zones to warehouse: {e}")

    return result

def update_warehouse_in_saleor(saleor_id, data):
    mutation = """
    mutation WarehouseUpdate($id: ID!, $input: WarehouseUpdateInput!) {
      warehouseUpdate: updateWarehouse(id: $id, input: $input) {
        warehouse {
          id
          name
          slug
          email
          isPrivate
          clickAndCollectOption
          address {
            companyName
            streetAddress1
            streetAddress2
            city
            postalCode
            phone
            country {
              code
              country
            }
          }
        }
        errors {
          field
          code
          message
        }
      }
    }
    """
    input_data = {}

    # Only include non-null fields
    if "name" in data and data["name"] is not None:
        input_data["name"] = data["name"]
    if "slug" in data and data["slug"] is not None:
        input_data["slug"] = data["slug"]
    if "email" in data and data["email"] is not None:
        input_data["email"] = data["email"]

    # Build address only if any address fields are present
    address_input = {}
    if "company_name" in data and data["company_name"] is not None:
        address_input["companyName"] = data["company_name"]
    if "street_address_1" in data and data["street_address_1"] is not None:
        address_input["streetAddress1"] = data["street_address_1"]
    if "street_address_2" in data and data["street_address_2"] is not None:
        address_input["streetAddress2"] = data["street_address_2"]
    if "city" in data and data["city"] is not None:
        address_input["city"] = data["city"]
    if "postal_code" in data and data["postal_code"] is not None:
        address_input["postalCode"] = data["postal_code"]
    if "country_area" in data and data["country_area"] is not None:
        address_input["countryArea"] = data["country_area"]
    if "country_code" in data and data["country_code"] is not None:
        address_input["country"] = data["country_code"].upper()[:2]
    if "phone" in data and data["phone"] is not None:
        address_input["phone"] = data["phone"]

    if address_input:
        address_input["skipValidation"] = True
        input_data["address"] = address_input

    if "is_private" in data:
        input_data["isPrivate"] = data["is_private"]
    if "click_and_collect" in data:
        input_data["clickAndCollectOption"] = data["click_and_collect"].upper()

    return call_saleor_gql(mutation, {"id": saleor_id, "input": input_data})

def delete_warehouse_in_saleor(saleor_id):
    mutation = """
    mutation WarehouseDelete($id: ID!) {
      warehouseDelete: deleteWarehouse(id: $id) {
        errors {
          field
          code
          message
        }
      }
    }
    """
    return call_saleor_gql(mutation, {"id": saleor_id})

def assign_warehouse_shipping_zones(saleor_id, shipping_zone_ids):
    """Assign shipping zones to a warehouse."""
    mutation = """
    mutation AssignWarehouseShippingZone($id: ID!, $shippingZoneIds: [ID!]!) {
      assignWarehouseShippingZone(id: $id, shippingZoneIds: $shippingZoneIds) {
        warehouse {
          id
        }
        errors {
          field
          code
          message
        }
      }
    }
    """
    return call_saleor_gql(mutation, {"id": saleor_id, "shippingZoneIds": shipping_zone_ids})

def unassign_warehouse_shipping_zones(saleor_id, shipping_zone_ids):
    """Unassign shipping zones from a warehouse."""
    mutation = """
    mutation UnassignWarehouseShippingZone($id: ID!, $shippingZoneIds: [ID!]!) {
      unassignWarehouseShippingZone(id: $id, shippingZoneIds: $shippingZoneIds) {
        warehouse {
          id
        }
        errors {
          field
          code
          message
        }
      }
    }
    """
    return call_saleor_gql(mutation, {"id": saleor_id, "shippingZoneIds": shipping_zone_ids})

def create_channel_in_saleor(data):
    mutation = """
    mutation ChannelCreate($input: ChannelCreateInput!) {
      channelCreate(input: $input) {
        channel {
          id
          name
          slug
          isActive
          currencyCode
          defaultCountry {
            code
            country
          }
          warehouses {
            id
            name
            slug
          }
        }
        errors {
          field
          code
          message
        }
      }
    }
    """
    input_data = {
        "name": data.get("name"),
        "slug": data.get("slug"),
        "currencyCode": data.get("currency"),
        "isActive": data.get("is_active", True),
        "defaultCountry": data.get("default_country"),
        "addWarehouses": data.get("warehouse_ids", []),
        "addShippingZones": data.get("shipping_zone_ids", []),
    }
    if data.get("allocation_strategy"):
        input_data["stockSettings"] = {
            "allocationStrategy": data.get("allocation_strategy")
        }
    return call_saleor_gql(mutation, {"input": input_data})

def update_channel_in_saleor(saleor_id, data):
    mutation = """
    mutation ChannelUpdate($id: ID!, $input: ChannelUpdateInput!) {
      channelUpdate(id: $id, input: $input) {
        channel {
          id
          name
          slug
          isActive
          defaultCountry {
            code
            country
          }
          warehouses {
            id
            name
            slug
          }
        }
        errors {
          field
          code
          message
        }
      }
    }
    """
    input_data = {
        "name": data.get("name"),
        "slug": data.get("slug"),
        "isActive": data.get("is_active", True),
        "defaultCountry": data.get("default_country"),
    }
    if data.get("add_warehouse_ids"):
        input_data["addWarehouses"] = data["add_warehouse_ids"]
    if data.get("remove_warehouse_ids"):
        input_data["removeWarehouses"] = data["remove_warehouse_ids"]
    if data.get("add_shipping_zone_ids"):
        input_data["addShippingZones"] = data["add_shipping_zone_ids"]
    if data.get("remove_shipping_zone_ids"):
        input_data["removeShippingZones"] = data["remove_shipping_zone_ids"]
    if data.get("allocation_strategy"):
        input_data["stockSettings"] = {
            "allocationStrategy": data["allocation_strategy"]
        }
    return call_saleor_gql(mutation, {"id": saleor_id, "input": input_data})

def delete_channel_in_saleor(saleor_id, destination_channel_id=None):
    mutation = """
    mutation ChannelDelete($id: ID!, $input: ChannelDeleteInput) {
      channelDelete(id: $id, input: $input) {
        channel {
          id
          name
        }
        errors {
          field
          code
          message
        }
      }
    }
    """
    variables = {"id": saleor_id, "input": None}
    if destination_channel_id:
        variables["input"] = {"channelId": destination_channel_id}
    return call_saleor_gql(mutation, variables)
