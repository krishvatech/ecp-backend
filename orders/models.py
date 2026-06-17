from django.conf import settings
from django.db import models
from django.db.models import Q, F, Sum
from django.utils import timezone
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
    subtotal = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total = models.DecimalField(max_digits=10, decimal_places=2, default=0)

    # Saleor/manual payment integration
    payment_method = models.CharField(max_length=40, blank=True, default="")
    payment_reference = models.CharField(max_length=255, blank=True, default="")
    saleor_checkout_id = models.CharField(max_length=255, blank=True, default="")
    saleor_order_id = models.CharField(max_length=255, blank=True, default="", db_index=True)
    saleor_order_number = models.CharField(max_length=64, blank=True, default="")
    paid_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            # one open cart per user
            models.UniqueConstraint(
                fields=["user", "status"],
                condition=Q(status="cart"),
                name="uniq_open_cart_per_user",
            )
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


class BillingAddress(models.Model):
    """Default billing address used for Saleor offline checkout and invoices."""
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="billing_address")
    first_name = models.CharField(max_length=256)
    last_name = models.CharField(max_length=256)
    company_name = models.CharField(max_length=256, blank=True, default="")
    street_address_1 = models.CharField(max_length=256)
    street_address_2 = models.CharField(max_length=256, blank=True, default="")
    city = models.CharField(max_length=256)
    postal_code = models.CharField(max_length=32)
    country = models.CharField(max_length=2, default="CH")
    country_area = models.CharField(max_length=128, blank=True, default="")
    phone = models.CharField(max_length=64, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Billing address"
        verbose_name_plural = "Billing addresses"

    def __str__(self):
        return f"{self.user_id}: {self.first_name} {self.last_name} ({self.country})"

    def to_saleor_input(self):
        data = {
            "firstName": self.first_name,
            "lastName": self.last_name,
            "companyName": self.company_name or "",
            "streetAddress1": self.street_address_1,
            "streetAddress2": self.street_address_2 or "",
            "city": self.city,
            "postalCode": self.postal_code,
            "country": (self.country or "CH").upper(),
            "countryArea": self.country_area or "",
            "phone": self.phone or "",
        }
        return {key: value for key, value in data.items() if value not in [None, ""]}
