# orders/views.py
from django.conf import settings
from django.db import transaction
from django.db.models import F, Sum
from rest_framework import permissions, status
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Order, OrderItem, OrderAddress
from .serializers import OrderSerializer, OrderItemSerializer, OrderAddressSerializer


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


def _save_address_for_user(serializer, user):
    address_type = serializer.validated_data.get("address_type") or getattr(serializer.instance, "address_type", "billing")
    if serializer.instance is None and not OrderAddress.objects.filter(user=user, address_type=address_type).exists():
        serializer.validated_data["is_default"] = True

    is_default = serializer.validated_data.get("is_default")
    if is_default:
        OrderAddress.objects.filter(user=user, address_type=address_type, is_default=True).update(is_default=False)

    return serializer.save(user=user)


class OrderAddressListCreate(APIView):
    """
    GET/POST /api/orders/addresses/

    Stores user billing/shipping addresses for Saleor checkout. The default
    billing address is used before env fallback values.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        qs = OrderAddress.objects.filter(user=request.user).order_by("-is_default", "-updated_at")
        serializer = OrderAddressSerializer(qs, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = OrderAddressSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            address = _save_address_for_user(serializer, request.user)
        return Response(OrderAddressSerializer(address).data, status=status.HTTP_201_CREATED)


class OrderAddressDetail(APIView):
    """
    PATCH/DELETE /api/orders/addresses/<id>/
    """
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, request, pk):
        try:
            return OrderAddress.objects.get(pk=pk, user=request.user)
        except OrderAddress.DoesNotExist:
            return None

    def patch(self, request, pk):
        address = self.get_object(request, pk)
        if not address:
            return Response({"detail": "Address not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = OrderAddressSerializer(address, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            address = _save_address_for_user(serializer, request.user)
        return Response(OrderAddressSerializer(address).data)

    def delete(self, request, pk):
        address = self.get_object(request, pk)
        if not address:
            return Response(status=status.HTTP_404_NOT_FOUND)

        address_type = address.address_type
        was_default = address.is_default
        with transaction.atomic():
            address.delete()
            if was_default:
                replacement = (
                    OrderAddress.objects
                    .filter(user=request.user, address_type=address_type)
                    .order_by("-updated_at")
                    .first()
                )
                if replacement:
                    replacement.is_default = True
                    replacement.save(update_fields=["is_default", "updated_at"])
        return Response(status=status.HTTP_204_NO_CONTENT)


class OrderList(APIView):
    """
    GET /api/orders/  -> list user's previous orders, including pending manual-payment orders.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        qs = (
            Order.objects
            .filter(user=request.user, status__in=["pending", "paid"])
            .order_by("-created_at")
        )
        serializer = OrderSerializer(qs, many=True, context={"request": request})
        return Response(serializer.data)


class CheckoutView(APIView):
    """
    POST /api/orders/checkout/

    Production behavior:
    - If SALEOR_ENABLED=true and the cart contains paid events, create an unpaid
      Saleor order for manual/offline payment and keep local order as pending.
    - If Saleor is disabled or the cart contains only free events, keep the legacy
      local checkout behavior and mark the order paid immediately.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        cart = get_open_cart(request.user)
        if not cart.items.exists():
            return Response({"detail": "Cart is empty."}, status=status.HTTP_400_BAD_REQUEST)

        cart.recalc()
        paid_count = cart.items.select_related("event").filter(event__is_free=False).count()
        saleor_enabled = bool(getattr(settings, "SALEOR_ENABLED", False))

        if saleor_enabled and paid_count > 0:
            from .saleor_checkout import (
                SaleorCheckoutError,
                create_pending_registrations_for_order,
                create_saleor_unpaid_order_from_cart,
            )

            if cart.saleor_order_id and cart.status == "pending":
                data = OrderSerializer(cart, context={"request": request}).data
                data["checkout_mode"] = "saleor_manual_pending"
                return Response(data, status=status.HTTP_200_OK)

            try:
                saleor_result = create_saleor_unpaid_order_from_cart(cart, request.user)
            except ValidationError:
                raise
            except SaleorCheckoutError as exc:
                return Response(
                    {"detail": str(exc), "saleor_errors": exc.errors},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            payment_reference = f"SALEOR-{saleor_result.order_number or saleor_result.order_id}"
            with transaction.atomic():
                locked = Order.objects.select_for_update().get(pk=cart.pk)
                locked.status = "pending"
                locked.currency = saleor_result.currency.lower()
                locked.saleor_checkout_id = saleor_result.checkout_id
                locked.saleor_order_id = saleor_result.order_id
                locked.saleor_order_number = saleor_result.order_number
                locked.payment_reference = payment_reference
                locked.save(update_fields=[
                    "status", "currency", "saleor_checkout_id", "saleor_order_id",
                    "saleor_order_number", "payment_reference", "subtotal", "total", "updated_at",
                ])
                create_pending_registrations_for_order(locked, payment_reference=payment_reference)

            data = OrderSerializer(locked, context={"request": request}).data
            data.update({
                "checkout_mode": "saleor_manual_pending",
                "payment_status": "pending_manual_payment",
                "payment_reference": payment_reference,
                "message": "Order placed. Please complete offline/manual payment; admin will mark it paid after confirmation.",
            })
            return Response(data, status=status.HTTP_201_CREATED)

        # Legacy/free-event path: finalize current cart locally as paid.
        with transaction.atomic():
            cart.status = "paid"
            cart.save(update_fields=["status", "subtotal", "total", "updated_at"])

            # Confirm/free-register all events in the cart so older frontend flows still work.
            from .saleor_checkout import create_pending_registrations_for_order
            create_pending_registrations_for_order(cart, payment_reference="LOCAL-FREE-CHECKOUT")

        data = OrderSerializer(cart, context={"request": request}).data
        data["checkout_mode"] = "local_legacy_paid"
        return Response(data, status=status.HTTP_201_CREATED)


class OrderMarkPaidView(APIView):
    """
    POST /api/orders/<order_id>/mark-paid/

    Staff-only endpoint for manual/offline payments. It marks the Saleor order paid,
    confirms local event registrations, and queues invoice generation.
    """
    permission_classes = [permissions.IsAdminUser]

    def post(self, request, pk):
        try:
            order = Order.objects.select_related("user").get(pk=pk)
        except Order.DoesNotExist:
            return Response({"detail": "Order not found."}, status=status.HTTP_404_NOT_FOUND)

        if not order.saleor_order_id:
            return Response(
                {"detail": "This order is not linked to a Saleor order."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        payment_reference = str(request.data.get("payment_reference") or order.payment_reference or order.saleor_order_number or order.saleor_order_id)

        from .saleor_checkout import SaleorCheckoutError, confirm_registrations_for_saleor_order, mark_saleor_order_paid
        try:
            saleor_order = mark_saleor_order_paid(order.saleor_order_id, payment_reference)
        except SaleorCheckoutError as exc:
            return Response({"detail": str(exc), "saleor_errors": exc.errors}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            locked = Order.objects.select_for_update().get(pk=order.pk)
            locked.status = "paid"
            locked.payment_reference = payment_reference
            if saleor_order.get("number"):
                locked.saleor_order_number = str(saleor_order.get("number"))
            locked.save(update_fields=["status", "payment_reference", "saleor_order_number", "updated_at"])
            confirmed = confirm_registrations_for_saleor_order(
                saleor_order,
                actor=request.user,
                payment_reference=payment_reference,
            )

        from invoicing.tasks import create_invoice_from_saleor_order
        create_invoice_from_saleor_order.delay(order.saleor_order_id)

        data = OrderSerializer(locked, context={"request": request}).data
        data.update({"confirmed_registrations": confirmed, "invoice_queued": True})
        return Response(data, status=status.HTTP_200_OK)
