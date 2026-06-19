"""Billing-address synchronization helpers for ECP ↔ Saleor.

ECP remains the primary place where members manage their billing address.
The helpers in this module keep Saleor's customer address book in sync when
possible, but never make checkout fail only because Saleor address-book sync is
temporarily unavailable. Checkout still sends the billing address directly to
Saleor order creation.
"""
import logging
from typing import Dict, Optional

from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone

from .models import BillingAddress
from .saleor_checkout import SaleorCheckoutError, saleor_graphql

logger = logging.getLogger(__name__)


class SaleorAddressSyncError(Exception):
    """Raised for Saleor customer-address sync failures."""


def _profile(user):
    try:
        return user.profile
    except Exception:
        return None


def _get_profile_saleor_customer_id(user) -> str:
    profile = _profile(user)
    value = getattr(profile, "saleor_customer_id", "") if profile else ""
    if value in {None, "", "synced_existing_unknown_id"}:
        return ""
    return str(value)


def _set_profile_saleor_customer_id(user, saleor_user_id: str):
    profile = _profile(user)
    if profile and saleor_user_id:
        profile.saleor_customer_id = saleor_user_id
        profile.save(update_fields=["saleor_customer_id"])


def _first_last_name(user):
    first_name = (getattr(user, "first_name", "") or "").strip()
    last_name = (getattr(user, "last_name", "") or "").strip()
    if first_name or last_name:
        return first_name or "Customer", last_name or "Customer"

    profile = _profile(user)
    full_name = (getattr(profile, "full_name", "") if profile else "") or ""
    parts = full_name.strip().split()
    if parts:
        return parts[0], " ".join(parts[1:]) or "Customer"

    email_name = (getattr(user, "email", "") or getattr(user, "username", "") or "Customer").split("@", 1)[0]
    return email_name or "Customer", "Customer"


def _raise_saleor_errors(operation, errors):
    cleaned = [e for e in (errors or []) if e]
    if cleaned:
        raise SaleorAddressSyncError(f"{operation} failed: {cleaned}")


def _find_saleor_user_by_email(email: str) -> str:
    if not email:
        return ""

    query = """
    query FindCustomer($email: String!) {
      customers(first: 1, filter: {search: $email}) {
        edges { node { id email } }
      }
      staffUsers(first: 1, filter: {search: $email}) {
        edges { node { id email } }
      }
    }
    """
    data = saleor_graphql(query, {"email": email})
    for key in ("customers", "staffUsers"):
        for edge in (((data.get(key) or {}).get("edges")) or []):
            node = edge.get("node") or {}
            if (node.get("email") or "").lower() == email.lower():
                return node.get("id") or ""
    return ""


def _create_saleor_customer_for_user(user) -> str:
    first_name, last_name = _first_last_name(user)
    mutation = """
    mutation CreateCustomer($input: UserCreateInput!) {
      customerCreate(input: $input) {
        user { id email }
        errors { field message code }
      }
    }
    """
    variables = {
        "input": {
            "email": user.email,
            "firstName": first_name,
            "lastName": last_name,
            "isActive": True,
        }
    }
    data = saleor_graphql(mutation, variables)
    result = data.get("customerCreate") or {}
    _raise_saleor_errors("customerCreate", result.get("errors"))
    created = result.get("user") or {}
    return created.get("id") or ""


def ensure_saleor_customer_for_user(user) -> str:
    """Return a Saleor user/customer ID for a Django user, creating if needed."""
    if not getattr(settings, "SALEOR_ENABLED", False):
        raise SaleorAddressSyncError("Saleor integration is disabled.")
    if not getattr(user, "email", ""):
        raise SaleorAddressSyncError("User email is required for Saleor customer sync.")

    existing = _get_profile_saleor_customer_id(user)
    if existing:
        return existing

    found = _find_saleor_user_by_email(user.email)
    if not found:
        found = _create_saleor_customer_for_user(user)

    if not found:
        raise SaleorAddressSyncError(f"Could not create/find Saleor customer for {user.email}")

    _set_profile_saleor_customer_id(user, found)
    return found


def sync_billing_address_to_saleor(address: BillingAddress, source="ecp") -> bool:
    """Create/update the current default billing address in Saleor.

    Returns True on successful Saleor sync. On failure, saves sync_status and
    error on BillingAddress, logs the failure, and returns False so user-facing
    address save can still succeed locally.
    """
    if not getattr(settings, "SALEOR_ENABLED", False):
        address.mark_saleor_sync_failed("Saleor integration is disabled.", status="skipped", source=source)
        return False

    try:
        saleor_user_id = address.saleor_user_id or ensure_saleor_customer_for_user(address.user)
        saleor_input = address.to_saleor_input()

        if address.saleor_address_id:
            mutation = """
            mutation UpdateAddress($id: ID!, $input: AddressInput!) {
              addressUpdate(id: $id, input: $input) {
                address { id }
                errors { field message code }
              }
            }
            """
            data = saleor_graphql(mutation, {"id": address.saleor_address_id, "input": saleor_input})
            result = data.get("addressUpdate") or {}
            _raise_saleor_errors("addressUpdate", result.get("errors"))
            saleor_address_id = ((result.get("address") or {}).get("id")) or address.saleor_address_id
        else:
            mutation = """
            mutation CreateAddress($userId: ID!, $input: AddressInput!) {
              addressCreate(userId: $userId, input: $input) {
                address { id }
                errors { field message code }
              }
            }
            """
            data = saleor_graphql(mutation, {"userId": saleor_user_id, "input": saleor_input})
            result = data.get("addressCreate") or {}
            _raise_saleor_errors("addressCreate", result.get("errors"))
            saleor_address_id = ((result.get("address") or {}).get("id")) or ""

        if not saleor_address_id:
            raise SaleorAddressSyncError("Saleor address mutation did not return address.id")

        address.mark_saleor_sync_success(saleor_user_id=saleor_user_id, saleor_address_id=saleor_address_id, source=source)
        return True
    except Exception as exc:
        logger.warning("Could not sync billing address %s to Saleor: %s", address.id, exc, exc_info=True)
        address.mark_saleor_sync_failed(exc, source=source)
        return False


def saleor_address_to_ecp_payload(address_data: Dict) -> Dict:
    """Map a Saleor Address object/payload into BillingAddress model fields."""
    return {
        "first_name": address_data.get("firstName") or address_data.get("first_name") or "Customer",
        "last_name": address_data.get("lastName") or address_data.get("last_name") or "Customer",
        "company_name": address_data.get("companyName") or address_data.get("company_name") or "",
        "street_address_1": address_data.get("streetAddress1") or address_data.get("street_address_1") or "",
        "street_address_2": address_data.get("streetAddress2") or address_data.get("street_address_2") or "",
        "city": address_data.get("city") or "",
        "postal_code": address_data.get("postalCode") or address_data.get("postal_code") or "",
        "country": (address_data.get("country") or {}).get("code") if isinstance(address_data.get("country"), dict) else (address_data.get("country") or ""),
        "country_area": address_data.get("countryArea") or address_data.get("country_area") or "",
        "phone": address_data.get("phone") or "",
    }


def apply_saleor_address_webhook_payload(payload: Dict) -> Optional[BillingAddress]:
    """Best-effort Saleor ADDRESS_UPDATED/CREATED sync into ECP current address.

    This updates only the user's current default billing address. It never
    changes order/invoice snapshots.
    """
    address_data = payload.get("address") or payload.get("data") or payload
    if not isinstance(address_data, dict):
        return None

    saleor_address_id = address_data.get("id") or payload.get("addressId") or ""
    saleor_user = (
        payload.get("user")
        or payload.get("customer")
        or address_data.get("user")
        or address_data.get("customer")
        or {}
    )
    saleor_user_id = saleor_user.get("id") or payload.get("userId") or address_data.get("userId") or ""
    email = saleor_user.get("email") or payload.get("email") or address_data.get("email") or ""

    address = None
    if saleor_address_id:
        address = BillingAddress.objects.filter(saleor_address_id=saleor_address_id).first()

    if not address and saleor_user_id:
        address = BillingAddress.objects.filter(saleor_user_id=saleor_user_id).first()

    user = None
    if address:
        user = address.user
    elif email:
        User = get_user_model()
        user = User.objects.filter(email__iexact=email).first()

    if not user:
        return None

    values = saleor_address_to_ecp_payload(address_data)
    values["country"] = (values.get("country") or "").upper()[:2]
    if not values["street_address_1"] or not values["city"] or not values["postal_code"] or not values["country"]:
        logger.info("Ignoring incomplete Saleor address webhook payload: %s", payload)
        return address

    values.update({
        "saleor_user_id": saleor_user_id or (address.saleor_user_id if address else ""),
        "saleor_address_id": saleor_address_id or (address.saleor_address_id if address else ""),
        "saleor_sync_status": "synced",
        "saleor_sync_error": "",
        "saleor_last_synced_at": timezone.now(),
        "last_sync_source": "saleor",
    })
    address, _ = BillingAddress.objects.update_or_create(user=user, defaults=values)
    return address
