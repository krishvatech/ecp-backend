# orders/views.py
from django.db.models import F, Sum
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Order, OrderItem
from .serializers import OrderSerializer, OrderItemSerializer

def get_open_cart(user):
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
            .filter(user=request.user, status="paid")  # only paid orders
            .order_by("-created_at")                  # newest first
        )
        serializer = OrderSerializer(qs, many=True, context={"request": request})
        return Response(serializer.data)


class CheckoutView(APIView):
    """
    POST /api/orders/checkout/ -> turn current cart into a paid order.
    - DOES NOT delete items
    - Just changes status from 'cart' -> 'paid'
    - Next time /cart/ is called, a fresh empty cart order is created.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        cart = get_open_cart(request.user)  # current cart for this user
        if not cart.items.exists():
            return Response(
                {"detail": "Cart is empty."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Make sure totals are up-to-date
        cart.recalc()

        cart.status = "paid"
        cart.save(update_fields=["status", "subtotal", "total", "updated_at"])

        # Return this finalized order (includes items)
        data = OrderSerializer(cart, context={"request": request}).data
        return Response(data, status=status.HTTP_201_CREATED)