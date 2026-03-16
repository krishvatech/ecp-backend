import requests
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def sync_event_to_saleor_sync(event):
    """
    Synchronously creates/updates a Saleor Product for the given Event.
    All prices are synced in SGD (Singapore Dollar).
    """
    saleor_url = getattr(settings, "SALEOR_API_URL", None)
    saleor_token = getattr(settings, "SALEOR_APP_TOKEN", None)
    # Use configured channel slug from settings (sgd-channel for SGD currency)
    channel_slug = getattr(settings, "SALEOR_CHANNEL_SLUG", "default-channel") 

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

import json
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
