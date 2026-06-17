from django.contrib import admin
from .models import BillingAddress, Order, OrderItem

class OrderItemInline(admin.TabularInline):
    model = OrderItem
    extra = 0

@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "status", "subtotal", "total", "created_at")
    list_filter = ("status",)
    inlines = [OrderItemInline]


@admin.register(BillingAddress)
class BillingAddressAdmin(admin.ModelAdmin):
    list_display = ("user", "first_name", "last_name", "city", "postal_code", "country", "updated_at")
    search_fields = ("user__email", "first_name", "last_name", "city", "postal_code", "country")
