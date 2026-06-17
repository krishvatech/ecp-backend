# orders/views.py
from django.conf import settings
from django.db import transaction
from django.db.models import F, Sum
from django.utils import timezone
from rest_framework import permissions, status
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import BillingAddress, Order, OrderItem
from .serializers import BillingAddressSerializer, OrderSerializer, OrderItemSerializer
from .saleor_checkout import (
    SaleorCheckoutError,
    create_saleor_checkout,
    create_saleor_order_from_checkout,
    mark_saleor_order_paid,
    _event_is_paid,
)
from events.models import Event, EventRegistration

def _is_guest_user(user) -> bool:
    return bool(getattr(user, "is_guest", False))

def get_open_cart(user):
    if _is_guest_user(user):
        raise PermissionDenied("Cart is unavailable for guest users.")
    cart, _ = Order.objects.get_or_create(user=user, status="cart")
    return cart

class CartView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        cart = get_open_cart(request.user)
        return Response(OrderSerializer(cart, context={"request": request}).data)

class CartCount(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        if _is_guest_user(request.user):
            return Response({"count": 0})
        cart = get_open_cart(request.user)
        count = cart.items.aggregate(n=Sum("quantity"))["n"] or 0
        return Response({"count": count})

class CartItems(APIView):
    permission_classes = [permissions.IsAuthenticated]

    # add/increment
    def post(self, request):
        event_id = request.data.get("event_id")
        qty = int(request.data.get("quantity", 1))
        if not event_id or qty < 1:
            return Response({"detail": "event_id and quantity required"},
                            status=status.HTTP_400_BAD_REQUEST)

        cart = get_open_cart(request.user)
        item, created = OrderItem.objects.get_or_create(
            order=cart, event_id=event_id,
            defaults={"quantity": qty}
        )
        if not created:
            item.quantity = F("quantity") + qty
            item.save(update_fields=["quantity"])
            item.refresh_from_db()

        return Response(OrderItemSerializer(item).data, status=status.HTTP_201_CREATED)

class CartClear(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        cart = get_open_cart(request.user)
        deleted = cart.items.count()
        cart.items.all().delete()
        # reset totals
        cart.subtotal = 0
        cart.total = 0
        cart.save(update_fields=["subtotal", "total"])
        return Response({"ok": True, "cleared": deleted})


class CartItemDetail(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, pk):
        cart = get_open_cart(request.user)
        try:
            item = cart.items.get(pk=pk)
        except OrderItem.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        qty = int(request.data.get("quantity", item.quantity))
        if qty < 1:
            item.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)

        item.quantity = qty
        item.save(update_fields=["quantity"])
        return Response(OrderItemSerializer(item).data)

    def delete(self, request, pk):
        cart = get_open_cart(request.user)
        try:
            item = cart.items.get(pk=pk)
        except OrderItem.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        item.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class OrderList(APIView):
    """
    GET /api/orders/  -> list user's previous orders (excluding current cart)
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        qs = (
            Order.objects
            .filter(user=request.user, status__in=["pending", "paid"])  # pending manual payments + paid orders
            .order_by("-created_at")                  # newest first
        )
        serializer = OrderSerializer(qs, many=True, context={"request": request})
        return Response(serializer.data)


def _user_can_mark_order_paid(user, order):
    """Staff/superusers can mark any order paid; event creators can mark their own event orders."""
    if bool(getattr(user, "is_staff", False)) or bool(getattr(user, "is_superuser", False)):
        return True
    return order.items.filter(event__created_by=user).exists()


def _build_saleor_billing_address(user, request_data):
    """Build a minimal Saleor billing address for offline invoice checkout.

    The frontend can send a billing_address object. If it does not, we use
    safe fallback values so Saleor can convert checkout into an unpaid order.
    """
    billing = request_data.get("billing_address") or {}

    if not isinstance(billing, dict):
        billing = {}

    get_full_name = getattr(user, "get_full_name", None)
    full_name = (
        billing.get("name")
        or billing.get("full_name")
        or (get_full_name() if callable(get_full_name) else "")
        or getattr(user, "email", "")
        or "Customer"
    ).strip()

    name_parts = full_name.split()
    first_name = (
        billing.get("first_name")
        or billing.get("firstName")
        or (name_parts[0] if name_parts else "Customer")
    )
    last_name = (
        billing.get("last_name")
        or billing.get("lastName")
        or (" ".join(name_parts[1:]) if len(name_parts) > 1 else "Customer")
    )

    address = {
        "firstName": str(first_name or "Customer")[:256],
        "lastName": str(last_name or "Customer")[:256],
        "streetAddress1": str(
            billing.get("street")
            or billing.get("streetAddress1")
            or "Billing address not provided"
        )[:256],
        "city": str(billing.get("city") or "N/A")[:256],
        "postalCode": str(
            billing.get("postal_code")
            or billing.get("postalCode")
            or "00000"
        )[:20],
        "country": str(billing.get("country") or "CH").upper(),
    }

    optional_fields = {
        "companyName": billing.get("company") or billing.get("companyName"),
        "streetAddress2": billing.get("streetAddress2"),
        "countryArea": billing.get("country_area") or billing.get("countryArea"),
        "phone": billing.get("phone"),
    }
    for key, value in optional_fields.items():
        if value:
            address[key] = str(value)

    return address


def _register_order_events(order):
    """Create/update event registrations after checkout/order creation.

    Paid event registrations stay payment_pending until finance/admin marks the
    related order as paid. Free items in the same cart are confirmed immediately.
    """
    created_ids = []
    for item in order.items.select_related("event").all():
        event = item.event

        if event.max_participants is not None:
            current_count = event.registrations.filter(status="registered").count()
            already_registered = event.registrations.filter(user=order.user, status="registered").exists()
            if not already_registered and current_count >= event.max_participants:
                raise ValueError(f"Event '{event.title}' is full.")

        is_paid_line = _event_is_paid(event, item)
        initial_attendee_status = "payment_pending" if is_paid_line else "confirmed"
        initial_admission_status = "waiting" if event.waiting_room_enabled else "admitted"

        registration, was_created = EventRegistration.objects.get_or_create(
            user=order.user,
            event=event,
            defaults={
                "attendee_status": initial_attendee_status,
                "admission_status": initial_admission_status,
            },
        )

        updates = []
        if registration.attendee_status != initial_attendee_status:
            registration.attendee_status = initial_attendee_status
            updates.append("attendee_status")
        if registration.status != "registered":
            registration.status = "registered"
            updates.append("status")
        if updates:
            registration.save(update_fields=updates)

        if was_created:
            if not registration.badge_labels.exists():
                participant_badge = event.get_or_create_participant_badge()
                registration.badge_labels.add(participant_badge)
            Event.objects.filter(pk=event.pk).update(attending_count=F("attending_count") + 1)
            created_ids.append(event.id)

    return created_ids


def _billing_payload_from_request(raw):
    """Normalize frontend/API billing address payload into BillingAddress fields."""
    if not isinstance(raw, dict):
        return {}
    full_name = (raw.get("name") or raw.get("full_name") or "").strip()
    parts = full_name.split()
    return {
        "first_name": raw.get("first_name") or raw.get("firstName") or (parts[0] if parts else ""),
        "last_name": raw.get("last_name") or raw.get("lastName") or (" ".join(parts[1:]) if len(parts) > 1 else ""),
        "company_name": raw.get("company_name") or raw.get("companyName") or raw.get("company") or "",
        "street_address_1": raw.get("street_address_1") or raw.get("streetAddress1") or raw.get("street") or "",
        "street_address_2": raw.get("street_address_2") or raw.get("streetAddress2") or "",
        "city": raw.get("city") or "",
        "postal_code": raw.get("postal_code") or raw.get("postalCode") or "",
        "country": (raw.get("country") or "").strip().upper(),
        "country_area": raw.get("country_area") or raw.get("countryArea") or "",
        "phone": raw.get("phone") or "",
    }


def _initial_billing_address_for_user(user):
    get_full_name = getattr(user, "get_full_name", None)
    full_name = (get_full_name() if callable(get_full_name) else "") or getattr(user, "email", "") or ""
    parts = full_name.split()
    return {
        "first_name": parts[0] if parts else "",
        "last_name": " ".join(parts[1:]) if len(parts) > 1 else "",
        "company_name": "",
        "street_address_1": "",
        "street_address_2": "",
        "city": "",
        "postal_code": "",
        "country": getattr(settings, "DEFAULT_BILLING_COUNTRY", "CH"),
        "country_area": "",
        "phone": "",
    }


def _get_valid_saleor_billing_address(user, request_data):
    """Return Saleor billingAddress input from request data or saved user address.

    Production-safe rule: no fake fallback address. A real user/superuser must
    either save an address first or send billing_address in the checkout request.
    Saleor then performs final country-specific validation.
    """
    request_billing = request_data.get("billing_address") if isinstance(request_data, dict) else None
    save_address = bool(request_data.get("save_billing_address", False)) if isinstance(request_data, dict) else False

    if isinstance(request_billing, dict) and any(str(v or "").strip() for v in request_billing.values()):
        payload = _billing_payload_from_request(request_billing)
        serializer = BillingAddressSerializer(data=payload)
        serializer.is_valid(raise_exception=True)
        if save_address:
            BillingAddress.objects.update_or_create(user=user, defaults=serializer.validated_data)
        return serializer.to_saleor_input()

    saved = getattr(user, "billing_address", None)
    if saved:
        return saved.to_saleor_input()

    raise ValueError("Billing address is required before checkout. Please add your billing address in the Addresses tab.")


class BillingAddressView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        address = getattr(request.user, "billing_address", None)
        if address:
            return Response(BillingAddressSerializer(address).data)
        return Response(_initial_billing_address_for_user(request.user))

    def post(self, request):
        payload = _billing_payload_from_request(request.data or {})
        serializer = BillingAddressSerializer(data=payload)
        serializer.is_valid(raise_exception=True)
        address, _ = BillingAddress.objects.update_or_create(
            user=request.user,
            defaults=serializer.validated_data,
        )
        return Response(BillingAddressSerializer(address).data, status=status.HTTP_200_OK)

    def patch(self, request):
        return self.post(request)


class CheckoutView(APIView):
    """
    Legacy route kept for compatibility, but now uses the safe manual/offline
    checkout flow instead of marking the cart paid immediately.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        return OfflineCheckoutView().post(request)


class OfflineCheckoutView(APIView):
    """
    POST /api/orders/offline-checkout/

    Creates an unpaid Saleor order from the current cart and marks local
    registration(s) as payment_pending. No Stripe/card payment is used.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        if not getattr(settings, "SALEOR_ENABLED", False):
            return Response({"detail": "Saleor integration is disabled."}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        cart = get_open_cart(request.user)
        if not cart.items.exists():
            return Response({"detail": "Cart is empty."}, status=status.HTTP_400_BAD_REQUEST)

        payment_method = (request.data.get("payment_method") or getattr(settings, "DEFAULT_PAYMENT_METHOD", "bank_transfer")).strip()
        if not payment_method:
            payment_method = "bank_transfer"

        cart.recalc()

        try:
            billing_address = _get_valid_saleor_billing_address(request.user, request.data)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as exc:
            return Response({"detail": "Billing address is invalid.", "errors": getattr(exc, "detail", str(exc))}, status=status.HTTP_400_BAD_REQUEST)

        try:
            checkout = create_saleor_checkout(
                cart,
                email=request.user.email,
                metadata=[
                    {"key": "ecp_user_id", "value": str(request.user.id)},
                    {"key": "payment_method", "value": payment_method},
                ],
                billing_address=billing_address,
            )
            saleor_order = create_saleor_order_from_checkout(
                checkout_id=checkout["id"],
                order=cart,
                payment_method=payment_method,
            )
        except SaleorCheckoutError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                cart.status = "pending"
                cart.payment_method = payment_method
                cart.saleor_checkout_id = checkout.get("id", "")
                cart.saleor_order_id = saleor_order.get("id", "")
                cart.saleor_order_number = str(saleor_order.get("number") or "")
                cart.save(update_fields=[
                    "status",
                    "payment_method",
                    "saleor_checkout_id",
                    "saleor_order_id",
                    "saleor_order_number",
                    "subtotal",
                    "total",
                    "updated_at",
                ])
                created_registration_event_ids = _register_order_events(cart)

            # Generate invoice asynchronously from the Saleor order.
            try:
                from invoicing.tasks import create_invoice_from_saleor_order
                create_invoice_from_saleor_order.delay(cart.saleor_order_id)
            except Exception:
                # Checkout should not fail if Celery/invoice queue has a temporary issue.
                pass

            data = OrderSerializer(cart, context={"request": request}).data
            data["checkout_status"] = "payment_pending"
            data["message"] = "Invoice/order created. Please complete manual payment; registration will be confirmed after payment is received."
            data["created_registration_event_ids"] = created_registration_event_ids
            return Response(data, status=status.HTTP_201_CREATED)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)


class OrderMarkPaidView(APIView):
    """
    POST /api/orders/<id>/mark-paid/

    Admin/finance manual payment confirmation. Marks the linked Saleor order
    paid, records invoice payment, and confirms related event registrations.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            order = Order.objects.prefetch_related("items__event").get(pk=pk)
        except Order.DoesNotExist:
            return Response({"detail": "Order not found."}, status=status.HTTP_404_NOT_FOUND)

        if not _user_can_mark_order_paid(request.user, order):
            raise PermissionDenied("You do not have permission to mark this order paid.")

        payment_reference = (request.data.get("payment_reference") or "").strip()
        payment_source = (request.data.get("payment_source") or "manual").strip() or "manual"

        if order.saleor_order_id:
            try:
                mark_saleor_order_paid(order.saleor_order_id, transaction_reference=payment_reference)
            except SaleorCheckoutError as exc:
                return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            order.status = "paid"
            order.payment_reference = payment_reference
            order.paid_at = timezone.now()
            order.save(update_fields=["status", "payment_reference", "paid_at", "updated_at"])

            for item in order.items.select_related("event").all():
                EventRegistration.objects.filter(
                    user=order.user,
                    event=item.event,
                    status="registered",
                ).update(attendee_status="confirmed")

            # Record invoice payment if invoice already exists.
            try:
                from invoicing.models import Invoice, PaymentEvent
                invoice = Invoice.objects.filter(saleor_order_id=order.saleor_order_id).first()
                if invoice and not PaymentEvent.objects.filter(
                    invoice=invoice,
                    event_type="payment",
                    external_reference=payment_reference or order.saleor_order_id,
                ).exists():
                    PaymentEvent.objects.create(
                        invoice=invoice,
                        event_type="payment",
                        amount=invoice.total_gross,
                        currency=invoice.currency,
                        source=payment_source if payment_source in {"manual", "wise"} else "manual",
                        external_reference=payment_reference or order.saleor_order_id,
                        notes=f"Manual payment confirmed from ECP order #{order.id}",
                    )
                    from invoicing.tasks import send_payment_confirmation_email
                    send_payment_confirmation_email.delay(invoice.id)
            except Exception:
                pass

        return Response(OrderSerializer(order, context={"request": request}).data)
