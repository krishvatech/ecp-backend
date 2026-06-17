"""Saleor checkout/order helpers for offline/manual-payment event orders."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Dict, Iterable, List, Optional

from django.conf import settings
from django.db import transaction
from django.db.models import F
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from events.models import EventRegistration
from events.services.post_acceptance_forms import is_online_event, trigger_post_acceptance_forms
from events.saleor_sync import call_saleor_gql
from .models import Order, OrderAddress

logger = logging.getLogger("orders.saleor_checkout")


class SaleorCheckoutError(Exception):
    """Raised when Saleor checkout/order creation fails."""

    def __init__(self, message: str, *, errors: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message)
        self.errors = errors or []


@dataclass(frozen=True)
class SaleorOrderResult:
    checkout_id: str
    order_id: str
    order_number: str
    total_gross: Decimal
    currency: str
    raw_order: Dict[str, Any]


def _money_amount(value: Optional[Dict[str, Any]]) -> Decimal:
    if not value:
        return Decimal("0.00")
    return Decimal(str(value.get("amount") or "0.00"))


def _errors_from(payload: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    return payload.get("data", {}).get(key, {}).get("errors") or []


def _raise_saleor_errors(action: str, errors: List[Dict[str, Any]]):
    if not errors:
        return
    message = "; ".join(
        f"{e.get('field') or 'general'}: {e.get('message') or e.get('code') or 'Unknown error'}"
        for e in errors
    )
    raise SaleorCheckoutError(f"Saleor {action} failed: {message}", errors=errors)



def _nonempty(value: Any, fallback: str = "") -> str:
    text = str(value or "").strip()
    return text if text else fallback


def _split_customer_name(user) -> tuple[str, str]:
    profile = getattr(user, "profile", None)
    full_name = _nonempty(getattr(profile, "full_name", "")) if profile else ""
    full_name = full_name or _nonempty(getattr(user, "get_full_name", lambda: "")())
    full_name = full_name or _nonempty(getattr(user, "username", ""), "Customer")
    parts = full_name.split()
    if not parts:
        return "Customer", "Customer"
    if len(parts) == 1:
        return parts[0][:256], "Customer"
    return parts[0][:256], " ".join(parts[1:])[:256]


def _saved_billing_address_for_user(user) -> Optional[OrderAddress]:
    return (
        OrderAddress.objects
        .filter(user=user, address_type="billing")
        .order_by("-is_default", "-updated_at")
        .first()
    )


def _checkout_billing_address_for_user(user) -> Dict[str, Any]:
    """
    Saleor requires a billing address before checkoutComplete creates an order,
    even for unpaid/manual orders. Prefer the user's saved billing address from
    the Cart -> Addresses UI, then fall back to stable configurable defaults.
    """
    saved_address = _saved_billing_address_for_user(user)
    if saved_address:
        return saved_address.to_saleor_address(user=user)

    first_name, last_name = _split_customer_name(user)
    country = _nonempty(getattr(settings, "SALEOR_DEFAULT_BILLING_COUNTRY", "US"), "US").upper()[:2]
    address = {
        "firstName": first_name,
        "lastName": last_name,
        "companyName": _nonempty(getattr(settings, "SALEOR_DEFAULT_BILLING_COMPANY", "")),
        "streetAddress1": _nonempty(
            getattr(settings, "SALEOR_DEFAULT_BILLING_STREET_ADDRESS1", ""),
            "Offline Event Registration",
        ),
        "streetAddress2": _nonempty(getattr(settings, "SALEOR_DEFAULT_BILLING_STREET_ADDRESS2", "")),
        "city": _nonempty(getattr(settings, "SALEOR_DEFAULT_BILLING_CITY", ""), "N/A"),
        "postalCode": _nonempty(getattr(settings, "SALEOR_DEFAULT_BILLING_POSTAL_CODE", ""), "00000"),
        "country": country,
        "countryArea": _nonempty(getattr(settings, "SALEOR_DEFAULT_BILLING_COUNTRY_AREA", ""), "State"),
        "phone": _nonempty(getattr(settings, "SALEOR_DEFAULT_BILLING_PHONE", "")),
        "skipValidation": True,
    }
    # Empty optional fields can trigger address validation errors in some Saleor
    # versions, so send only values we actually have.
    return {key: value for key, value in address.items() if value not in ("", None)}

def _paid_items(cart: Order):
    return [item for item in cart.items.select_related("event") if not item.event.is_free]


def _free_items(cart: Order):
    return [item for item in cart.items.select_related("event") if item.event.is_free]


def validate_cart_for_saleor(cart: Order):
    missing = []
    for item in _paid_items(cart):
        if not item.event.saleor_variant_id:
            missing.append({"event_id": item.event_id, "title": item.event.title})
    if missing:
        raise ValidationError({
            "detail": "Some paid cart events are not synced to Saleor variants yet.",
            "missing_saleor_variants": missing,
        })


def create_saleor_unpaid_order_from_cart(cart: Order, user) -> SaleorOrderResult:
    """
    Create an unpaid Saleor order from the ECP cart.

    Requires the Saleor channel to allow unpaid orders. If the channel does not allow
    unpaid orders, Saleor will return a payment/transaction coverage error.
    """
    validate_cart_for_saleor(cart)
    channel_slug = getattr(settings, "SALEOR_CHANNEL_SLUG", "default-channel")
    if not channel_slug:
        raise SaleorCheckoutError("SALEOR_CHANNEL_SLUG is not configured")

    paid_items = _paid_items(cart)
    if not paid_items:
        raise SaleorCheckoutError("Cart has no paid Saleor items")

    lines = []
    for item in paid_items:
        lines.append({
            "variantId": item.event.saleor_variant_id,
            "quantity": int(item.quantity),
            "metadata": [
                {"key": "ecp_event_id", "value": str(item.event_id)},
                {"key": "ecp_order_item_id", "value": str(item.id)},
            ],
        })

    checkout_mutation = """
    mutation EcpCheckoutCreate($input: CheckoutCreateInput!) {
      checkoutCreate(input: $input) {
        checkout {
          id
          token
          email
          totalPrice { gross { amount currency } }
          lines { id quantity variant { id sku product { id name } } }
        }
        errors { field message code }
      }
    }
    """
    checkout_variables = {
        "input": {
            "channel": channel_slug,
            "email": user.email,
            "billingAddress": _checkout_billing_address_for_user(user),
            "lines": lines,
            "metadata": [
                {"key": "ecp_order_id", "value": str(cart.id)},
                {"key": "ecp_user_id", "value": str(user.id)},
                {"key": "ecp_payment_method", "value": "manual_offline"},
            ],
            "privateMetadata": [
                {"key": "ecp_order_id", "value": str(cart.id)},
                {"key": "ecp_user_id", "value": str(user.id)},
            ],
        }
    }
    checkout_response = call_saleor_gql(checkout_mutation, checkout_variables)
    _raise_saleor_errors("checkoutCreate", _errors_from(checkout_response, "checkoutCreate"))

    checkout = checkout_response.get("data", {}).get("checkoutCreate", {}).get("checkout")
    if not checkout or not checkout.get("id"):
        raise SaleorCheckoutError("Saleor checkoutCreate returned no checkout")

    complete_mutation = """
    mutation EcpCheckoutComplete($id: ID!, $metadata: [MetadataInput!]) {
      checkoutComplete(id: $id, metadata: $metadata) {
        order {
          id
          number
          isPaid
          paymentStatus
          chargeStatus
          total { gross { amount currency } }
          lines { quantity variant { id sku product { id name } } }
        }
        confirmationNeeded
        confirmationData
        errors { field message code }
      }
    }
    """
    complete_variables = {
        "id": checkout["id"],
        "metadata": [
            {"key": "ecp_order_id", "value": str(cart.id)},
            {"key": "ecp_user_id", "value": str(user.id)},
            {"key": "ecp_payment_method", "value": "manual_offline"},
        ],
    }
    complete_response = call_saleor_gql(complete_mutation, complete_variables)
    errors = _errors_from(complete_response, "checkoutComplete")
    if errors:
        messages = "; ".join((e.get("message") or e.get("code") or "Unknown error") for e in errors)
        help_text = (
            " Ensure the Saleor channel allows unpaid orders and the checkout has valid "
            "billing data. For physical products, a shipping method is also required."
        )
        raise SaleorCheckoutError(
            f"Saleor checkoutComplete failed: {messages}.{help_text}",
            errors=errors,
        )

    order = complete_response.get("data", {}).get("checkoutComplete", {}).get("order")
    if not order or not order.get("id"):
        raise SaleorCheckoutError("Saleor checkoutComplete returned no order")

    gross = order.get("total", {}).get("gross") or {}
    return SaleorOrderResult(
        checkout_id=checkout["id"],
        order_id=order["id"],
        order_number=str(order.get("number") or ""),
        total_gross=_money_amount(gross),
        currency=str(gross.get("currency") or cart.currency or "USD").upper(),
        raw_order=order,
    )


def _create_or_update_registration(event, user, *, attendee_status: str, payment_reference: str = "", actor=None):
    initial_admission_status = "waiting" if event.waiting_room_enabled else "admitted"
    registration, created = EventRegistration.objects.get_or_create(
        event=event,
        user=user,
        defaults={
            "status": "registered",
            "attendee_status": attendee_status,
            "admission_status": initial_admission_status,
            "payment_reference": payment_reference,
        },
    )

    should_trigger_forms = False
    if created:
        if not registration.badge_labels.exists():
            participant_badge = event.get_or_create_participant_badge()
            registration.badge_labels.add(participant_badge)
        event.__class__.objects.filter(pk=event.pk).update(attending_count=F("attending_count") + 1)
        should_trigger_forms = attendee_status == "confirmed"
    else:
        update_fields = []
        if attendee_status == "confirmed" and registration.attendee_status != "confirmed":
            registration.attendee_status = "confirmed"
            registration.status = "registered"
            registration.marked_paid_at = timezone.now()
            registration.marked_paid_by = actor if getattr(actor, "is_authenticated", False) else None
            update_fields += ["attendee_status", "status", "marked_paid_at", "marked_paid_by"]
            should_trigger_forms = True
        elif attendee_status == "payment_pending" and registration.attendee_status != "confirmed":
            registration.attendee_status = "payment_pending"
            registration.status = "registered"
            update_fields += ["attendee_status", "status"]

        if payment_reference and registration.payment_reference != payment_reference:
            registration.payment_reference = payment_reference
            update_fields.append("payment_reference")
        if update_fields:
            registration.save(update_fields=list(dict.fromkeys(update_fields)))

    if should_trigger_forms and not is_online_event(event):
        def queue_forms():
            try:
                trigger_post_acceptance_forms(registration)
            except Exception as exc:
                logger.error("Failed to trigger forms for registration %s: %s", registration.id, exc, exc_info=True)
        transaction.on_commit(queue_forms)

    return registration, created


def create_pending_registrations_for_order(order: Order, *, payment_reference: str):
    """Create pending registrations for paid items and confirmed registrations for free items."""
    for item in order.items.select_related("event"):
        attendee_status = "confirmed" if item.event.is_free else "payment_pending"
        _create_or_update_registration(
            item.event,
            order.user,
            attendee_status=attendee_status,
            payment_reference=payment_reference,
        )


def confirm_registrations_for_saleor_order(order_data: Dict[str, Any], *, actor=None, payment_reference: str = "") -> int:
    """Confirm local registrations using Saleor order line variants."""
    email = order_data.get("userEmail") or order_data.get("email")
    if not email:
        return 0
    from django.contrib.auth import get_user_model
    from events.models import Event

    user = get_user_model().objects.filter(email__iexact=email).first()
    if not user:
        logger.warning("No local user for Saleor order email %s", email)
        return 0

    count = 0
    for line in order_data.get("lines") or []:
        variant = line.get("variant") or {}
        variant_id = variant.get("id")
        if not variant_id:
            continue
        event = Event.objects.filter(saleor_variant_id=variant_id).first()
        if not event:
            logger.warning("No local event for Saleor variant %s", variant_id)
            continue
        _create_or_update_registration(
            event,
            user,
            attendee_status="confirmed",
            payment_reference=payment_reference or order_data.get("id", ""),
            actor=actor,
        )
        count += 1
    return count


def mark_saleor_order_paid(saleor_order_id: str, transaction_reference: str = "") -> Dict[str, Any]:
    mutation = """
    mutation EcpOrderMarkAsPaid($id: ID!, $transactionReference: String) {
      orderMarkAsPaid(id: $id, transactionReference: $transactionReference) {
        order {
          id
          number
          userEmail
          isPaid
          paymentStatus
          chargeStatus
          total { gross { amount currency } net { amount currency } tax { amount currency } }
          lines {
            id
            productName
            variantName
            quantity
            taxRate
            unitPrice { net { amount currency } tax { amount currency } gross { amount currency } }
            totalPrice { net { amount currency } tax { amount currency } gross { amount currency } }
            variant { id sku product { id name } }
          }
        }
        errors { field message code }
      }
    }
    """
    response = call_saleor_gql(mutation, {"id": saleor_order_id, "transactionReference": transaction_reference or None})
    errors = _errors_from(response, "orderMarkAsPaid")
    _raise_saleor_errors("orderMarkAsPaid", errors)
    order = response.get("data", {}).get("orderMarkAsPaid", {}).get("order")
    if not order:
        raise SaleorCheckoutError("Saleor orderMarkAsPaid returned no order")
    return order


def fetch_saleor_order(order_id: str) -> Dict[str, Any]:
    query = """
    query EcpSaleorOrder($id: ID!) {
      order(id: $id) {
        id
        number
        userEmail
        isPaid
        paymentStatus
        chargeStatus
        total { net { amount currency } tax { amount currency } gross { amount currency } }
        invoices { id number url status }
        user { id email }
        lines {
          id
          productName
          variantName
          productSku
          quantity
          taxRate
          unitPrice { net { amount currency } tax { amount currency } gross { amount currency } }
          totalPrice { net { amount currency } tax { amount currency } gross { amount currency } }
          variant { id sku product { id name } }
        }
      }
    }
    """
    response = call_saleor_gql(query, {"id": order_id})
    order = response.get("data", {}).get("order")
    if not order:
        raise SaleorCheckoutError(f"Saleor order not found: {order_id}")
    return order
