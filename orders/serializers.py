# orders/serializers.py
from rest_framework import serializers
from events.models import Event
from .models import Order, OrderItem, OrderAddress

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


class OrderAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderAddress
        fields = [
            "id", "address_type", "first_name", "last_name", "company_name",
            "street_address1", "street_address2", "city", "country_area",
            "postal_code", "country", "phone", "is_default",
            "created_at", "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def validate_country(self, value):
        value = str(value or "").strip().upper()
        if len(value) != 2:
            raise serializers.ValidationError("Use a 2-letter ISO country code, for example US, IN, CH.")
        return value

    def validate_address_type(self, value):
        value = str(value or "billing").strip().lower()
        if value not in {"billing", "shipping"}:
            raise serializers.ValidationError("Address type must be billing or shipping.")
        return value

    def validate(self, attrs):
        required = ["first_name", "last_name", "street_address1", "city", "postal_code", "country"]
        for field in required:
            value = attrs.get(field, getattr(self.instance, field, ""))
            if not str(value or "").strip():
                raise serializers.ValidationError({field: "This field is required."})
        return attrs


class OrderItemSerializer(serializers.ModelSerializer):
    event = EventMiniSerializer(read_only=True)

    class Meta:
        model = OrderItem
        fields = ["id", "event", "quantity", "unit_price", "line_total"]


class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)

    class Meta:
        model = Order
        fields = ["id", "status", "subtotal", "total", "items", "created_at"]