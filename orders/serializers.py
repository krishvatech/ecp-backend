# orders/serializers.py
from rest_framework import serializers
from events.models import Event
from .models import BillingAddress, Order, OrderItem



class BillingAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = BillingAddress
        fields = [
            "first_name",
            "last_name",
            "company_name",
            "street_address_1",
            "street_address_2",
            "city",
            "postal_code",
            "country",
            "country_area",
            "phone",
            "updated_at",
        ]
        read_only_fields = ["updated_at"]

    def validate_country(self, value):
        value = (value or "").strip().upper()
        if len(value) != 2:
            raise serializers.ValidationError("Use a 2-letter ISO country code, for example CH, IN, SG, US.")
        return value

    def validate(self, attrs):
        required = ["first_name", "last_name", "street_address_1", "city", "postal_code", "country"]
        missing = [field for field in required if not str(attrs.get(field, "")).strip()]
        if missing:
            raise serializers.ValidationError({field: "This field is required." for field in missing})
        return attrs

    def to_saleor_input(self, data=None):
        source = data or self.validated_data
        saleor_address = {
            "firstName": source.get("first_name"),
            "lastName": source.get("last_name"),
            "companyName": source.get("company_name") or "",
            "streetAddress1": source.get("street_address_1"),
            "streetAddress2": source.get("street_address_2") or "",
            "city": source.get("city"),
            "postalCode": source.get("postal_code"),
            "country": (source.get("country") or "").upper(),
            "countryArea": source.get("country_area") or "",
            "phone": source.get("phone") or "",
        }
        return {key: value for key, value in saleor_address.items() if value not in [None, ""]}

class EventMiniSerializer(serializers.ModelSerializer):
    """Used inside OrderItemSerializer and OrderSerializer for cart/order views."""
    thumbnail = serializers.SerializerMethodField()

    class Meta:
        model = Event
        fields = ["id", "title", "price", "is_free", "thumbnail"]

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
        fields = ["id", "status", "subtotal", "total", "payment_method", "payment_reference", "saleor_checkout_id", "saleor_order_id", "saleor_order_number", "paid_at", "items", "created_at"]