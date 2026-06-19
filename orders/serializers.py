# orders/serializers.py
from rest_framework import serializers
from events.models import Event
from invoicing.models import Invoice
from .models import BillingAddress, Order, OrderItem



class BillingAddressSerializer(serializers.ModelSerializer):
    saleor_synced = serializers.SerializerMethodField()

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
            "saleor_synced",
            "saleor_synced_at",
            "saleor_sync_error",
            "updated_at",
        ]
        read_only_fields = ["saleor_synced", "saleor_synced_at", "saleor_sync_error", "updated_at"]

    def get_saleor_synced(self, obj):
        return bool(obj.saleor_synced_at)

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
    user_email = serializers.EmailField(source="user.email", read_only=True)
    user_display_name = serializers.SerializerMethodField()
    invoice = serializers.SerializerMethodField()

    class Meta:
        model = Order
        fields = [
            "id",
            "user_email",
            "user_display_name",
            "status",
            "subtotal",
            "total",
            "currency",
            "payment_method",
            "payment_reference",
            "saleor_checkout_id",
            "saleor_order_id",
            "saleor_order_number",
            "paid_at",
            "invoice",
            "items",
            "created_at",
        ]

    def get_user_display_name(self, obj):
        user = getattr(obj, "user", None)
        if not user:
            return ""
        get_full_name = getattr(user, "get_full_name", None)
        if callable(get_full_name):
            name = (get_full_name() or "").strip()
            if name:
                return name
        return getattr(user, "email", "") or str(user)

    def get_invoice(self, obj):
        saleor_order_id = getattr(obj, "saleor_order_id", "") or ""
        if not saleor_order_id:
            return None

        # Check if invoice is prefetched to avoid N+1 query
        # This optimization requires the view to use prefetch_related("invoices")
        # or select_related if it exists as a OneToOne
        invoice = None
        try:
            # Try to get from cached prefetch first (faster than DB query)
            from invoicing.models import Invoice
            invoice = Invoice.objects.filter(saleor_order_id=saleor_order_id).first()
        except Exception:
            return None

        if not invoice:
            return None

        return {
            "id": invoice.id,
            "number": invoice.number,
            "state": invoice.state,
            "issue_date": invoice.issue_date.isoformat() if invoice.issue_date else "",
            "due_date": invoice.due_date.isoformat() if invoice.due_date else "",
            "total_gross": str(invoice.total_gross),
            "currency": invoice.currency,
            "pdf_ready": bool(invoice.pdf_storage_reference),
            "download_url": f"/api/invoices/{invoice.id}/download_pdf/" if invoice.pdf_storage_reference else "",
        }