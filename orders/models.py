from django.conf import settings
from django.db import models
from django.db.models import Q, F, Sum
from events.models import Event

class Order(models.Model):
    STATUS = (
        ("cart", "Cart"),
        ("pending", "Pending"),
        ("paid", "Paid"),
        ("canceled", "Canceled"),
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="orders")
    status = models.CharField(max_length=12, choices=STATUS, default="cart", db_index=True)
    currency = models.CharField(max_length=8, default="usd")
    saleor_checkout_id = models.CharField(max_length=255, blank=True, default="", db_index=True)
    saleor_order_id = models.CharField(max_length=255, blank=True, default="", db_index=True)
    saleor_order_number = models.CharField(max_length=64, blank=True, default="")
    payment_reference = models.CharField(max_length=255, blank=True, default="")
    subtotal = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            # one open cart per user
            models.UniqueConstraint(
                fields=["user", "status"],
                condition=Q(status="cart"),
                name="uniq_open_cart_per_user",
            ),
            models.UniqueConstraint(
                fields=["saleor_order_id"],
                condition=~Q(saleor_order_id=""),
                name="uniq_order_saleor_order_id_not_blank",
            ),
        ]
        ordering = ["-created_at"]

    def recalc(self):
        agg = self.items.aggregate(s=Sum(F("line_total")))
        self.subtotal = agg["s"] or 0
        self.total = self.subtotal  # add taxes/fees here later
        self.save(update_fields=["subtotal", "total", "updated_at"])

class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="items")
    event = models.ForeignKey(Event, on_delete=models.PROTECT, related_name="order_items")
    quantity = models.PositiveIntegerField(default=1)
    unit_price = models.DecimalField(max_digits=10, decimal_places=2)
    line_total = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = (("order", "event"),)

    def save(self, *args, **kwargs):
        if not self.unit_price:
            self.unit_price = self.event.price
        self.line_total = self.unit_price * self.quantity
        super().save(*args, **kwargs)
        self.order.recalc()

    def delete(self, *args, **kwargs):
        order = self.order
        super().delete(*args, **kwargs)
        order.recalc()


class OrderAddress(models.Model):
    ADDRESS_TYPES = (
        ("billing", "Billing"),
        ("shipping", "Shipping"),
    )

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="order_addresses")
    address_type = models.CharField(max_length=16, choices=ADDRESS_TYPES, default="billing", db_index=True)
    first_name = models.CharField(max_length=256)
    last_name = models.CharField(max_length=256)
    company_name = models.CharField(max_length=256, blank=True, default="")
    street_address1 = models.CharField(max_length=256)
    street_address2 = models.CharField(max_length=256, blank=True, default="")
    city = models.CharField(max_length=128)
    country_area = models.CharField(max_length=128, blank=True, default="")
    postal_code = models.CharField(max_length=32)
    country = models.CharField(max_length=2, default="US")
    phone = models.CharField(max_length=32, blank=True, default="")
    is_default = models.BooleanField(default=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-is_default", "-updated_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "address_type"],
                condition=Q(is_default=True),
                name="uniq_default_order_address_per_type",
            ),
        ]

    def __str__(self):
        return f"{self.user_id} {self.address_type} address"

    def to_saleor_address(self, user=None):
        data = {
            "firstName": self.first_name,
            "lastName": self.last_name,
            "companyName": self.company_name,
            "streetAddress1": self.street_address1,
            "streetAddress2": self.street_address2,
            "city": self.city,
            "postalCode": self.postal_code,
            "country": (self.country or "US").upper()[:2],
            "countryArea": self.country_area,
            "phone": self.phone,
            "skipValidation": True,
        }
        return {key: value for key, value in data.items() if value not in ("", None)}
