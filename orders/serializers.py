# orders/serializers.py
from rest_framework import serializers
from events.models import Event
from .models import Order, OrderItem

class EventMiniSerializer(serializers.ModelSerializer):
    """Used inside OrderItemSerializer and OrderSerializer for cart/order views."""
    thumbnail = serializers.SerializerMethodField()

    class Meta:
        model = Event
        fields = ["id", "title", "price", "thumbnail"]

    def get_thumbnail(self, obj):
        # Always return a URL string (never bytes). Build absolute URL if request is in context.
        img = getattr(obj, "preview_image", None) or getattr(obj, "image_preview", None) or getattr(obj, "image", None)
        if not img:
            return None
        try:
            url = img.url  # DRF wants a string, not bytes/FieldFile
        except Exception:
            return None
        request = self.context.get("request") if hasattr(self, "context") else None
        return request.build_absolute_uri(url) if request else url


class OrderItemSerializer(serializers.ModelSerializer):
    event = EventMiniSerializer(read_only=True)

    class Meta:
        model = OrderItem
        fields = ["id", "event", "quantity", "unit_price", "line_total"]


class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)

    class Meta:
        model = Order
        fields = ["id", "status", "subtotal", "total", "items"]