"""Saleor checkout/order helpers for ECP offline/manual payment flow.

This module intentionally does not use Stripe. It creates an unpaid Saleor
order from the ECP cart, then lets an admin/finance user mark that Saleor
order as paid after bank/manual payment is received.
"""
import logging
from decimal import Decimal

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


class SaleorCheckoutError(Exception):
    """Raised when Saleor checkout/order API returns an error."""


def _saleor_headers():
    token = (getattr(settings, "SALEOR_APP_TOKEN", "") or "").strip()
    if not token:
        raise SaleorCheckoutError("SALEOR_APP_TOKEN is not configured.")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def saleor_graphql(query, variables=None, timeout=30):
    """Run a Saleor GraphQL operation and return the `data` object."""
    saleor_url = getattr(settings, "SALEOR_API_URL", "")
    if not saleor_url:
        raise SaleorCheckoutError("SALEOR_API_URL is not configured.")

    response = requests.post(
        saleor_url,
        json={"query": query, "variables": variables or {}},
        headers=_saleor_headers(),
        timeout=timeout,
    )
    try:
        payload = response.json()
    except ValueError as exc:
        raise SaleorCheckoutError(f"Saleor returned non-JSON response: HTTP {response.status_code}") from exc

    if response.status_code >= 400:
        raise SaleorCheckoutError(f"Saleor HTTP {response.status_code}: {payload}")

    if payload.get("errors"):
        raise SaleorCheckoutError(f"Saleor GraphQL errors: {payload['errors']}")

    return payload.get("data") or {}


def _raise_saleor_errors(operation_name, errors):
    cleaned = [e for e in (errors or []) if e]
    if cleaned:
        raise SaleorCheckoutError(f"{operation_name} failed: {cleaned}")


def _event_is_paid(event, item=None):
    """Treat non-free events or positive-priced cart lines as paid checkout lines."""
    if getattr(event, "is_free", False):
        return False
    if item is not None and Decimal(str(getattr(item, "line_total", 0) or 0)) > 0:
        return True
    return Decimal(str(getattr(event, "price", 0) or 0)) > 0 or bool(getattr(event, "saleor_variant_id", None))


def build_saleor_lines_from_order(order):
    """Return Saleor checkout lines for paid items in an ECP cart/order."""
    lines = []
    missing = []

    for item in order.items.select_related("event").all():
        event = item.event
        if not _event_is_paid(event, item):
            continue
        if not event.saleor_variant_id:
            missing.append({"event_id": event.id, "title": event.title})
            continue
        lines.append({"variantId": event.saleor_variant_id, "quantity": int(item.quantity or 1)})

    if missing:
        raise SaleorCheckoutError(
            "Some paid events are not linked to Saleor variants: "
            + ", ".join(f"#{m['event_id']} {m['title']}" for m in missing)
        )

    if not lines:
        raise SaleorCheckoutError("No paid Saleor checkout lines found in cart.")

    return lines


def create_saleor_checkout(order, email, metadata=None, billing_address=None):
    """Create Saleor checkout for paid cart lines."""
    channel_slug = getattr(settings, "SALEOR_CHANNEL_SLUG", "default-channel")
    lines = build_saleor_lines_from_order(order)

    mutation = """
    mutation CreateCheckout($input: CheckoutCreateInput!) {
      checkoutCreate(input: $input) {
        checkout {
          id
          token
          totalPrice { gross { amount currency } }
        }
        errors { field message code }
      }
    }
    """
    checkout_input = {
        "channel": channel_slug,
        "email": email,
        "lines": lines,
        "metadata": metadata or [],
    }

    # Saleor requires billing address before checkout can be converted
    # into an unpaid order using orderCreateFromCheckout.
    if billing_address:
        checkout_input["billingAddress"] = billing_address

    variables = {"input": checkout_input}
    data = saleor_graphql(mutation, variables)
    result = data.get("checkoutCreate") or {}
    _raise_saleor_errors("checkoutCreate", result.get("errors"))
    checkout = result.get("checkout")
    if not checkout or not checkout.get("id"):
        raise SaleorCheckoutError("checkoutCreate did not return checkout.id")
    return checkout


def create_saleor_order_from_checkout(checkout_id, order, payment_method="bank_transfer"):
    """Convert a Saleor checkout into an unpaid Saleor order."""
    mutation = """
    mutation CreateOrderFromCheckout(
      $id: ID!,
      $removeCheckout: Boolean!,
      $metadata: [MetadataInput!],
      $privateMetadata: [MetadataInput!]
    ) {
      orderCreateFromCheckout(
        id: $id,
        removeCheckout: $removeCheckout,
        metadata: $metadata,
        privateMetadata: $privateMetadata
      ) {
        order {
          id
          number
          status
          paymentStatus
          total { gross { amount currency } }
        }
        errors { field message code }
      }
    }
    """
    variables = {
        "id": checkout_id,
        "removeCheckout": True,
        "metadata": [
            {"key": "payment_method", "value": payment_method},
            {"key": "source", "value": "ecp_offline_checkout"},
        ],
        "privateMetadata": [
            {"key": "ecp_order_id", "value": str(order.id)},
            {"key": "ecp_user_id", "value": str(order.user_id)},
        ],
    }
    data = saleor_graphql(mutation, variables)
    result = data.get("orderCreateFromCheckout") or {}
    _raise_saleor_errors("orderCreateFromCheckout", result.get("errors"))
    saleor_order = result.get("order")
    if not saleor_order or not saleor_order.get("id"):
        raise SaleorCheckoutError("orderCreateFromCheckout did not return order.id")
    return saleor_order


def mark_saleor_order_paid(saleor_order_id, transaction_reference=""):
    """Mark an unpaid Saleor order as paid after manual/offline payment."""
    mutation = """
    mutation OrderMarkAsPaid($id: ID!, $transactionReference: String) {
      orderMarkAsPaid(id: $id, transactionReference: $transactionReference) {
        order { id number status paymentStatus }
        errors { field message code }
      }
    }
    """
    variables = {
        "id": saleor_order_id,
        "transactionReference": transaction_reference or None,
    }
    data = saleor_graphql(mutation, variables)
    result = data.get("orderMarkAsPaid") or {}
    _raise_saleor_errors("orderMarkAsPaid", result.get("errors"))
    return result.get("order") or {}


def fetch_saleor_order(saleor_order_id):
    """Fetch enough Saleor order data to create invoice/registration records."""
    query = """
    query GetSaleorOrder($id: ID!) {
      order(id: $id) {
        id
        number
        userEmail
        created
        status
        paymentStatus
        total { net { amount currency } gross { amount currency } tax { amount currency } }
        metadata { key value }
        privateMetadata { key value }
        lines {
          id
          productName
          variantName
          quantity
          unitPrice { gross { amount currency } net { amount currency } tax { amount currency } }
          totalPrice { gross { amount currency } net { amount currency } tax { amount currency } }
          variant { id sku product { id name } }
        }
      }
    }
    """
    data = saleor_graphql(query, {"id": saleor_order_id})
    order = data.get("order")
    if not order:
        raise SaleorCheckoutError(f"Saleor order not found: {saleor_order_id}")
    return order
