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
