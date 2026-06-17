from django.contrib import admin
from .models import Order, OrderItem, OrderAddress

class OrderItemInline(admin.TabularInline):
    model = OrderItem
    extra = 0

@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "status", "subtotal", "total", "created_at")
    list_filter = ("status",)
    inlines = [OrderItemInline]


@admin.register(OrderAddress)
class OrderAddressAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "address_type", "city", "country", "is_default", "updated_at")
    list_filter = ("address_type", "country", "is_default")
    search_fields = ("user__username", "user__email", "first_name", "last_name", "street_address1", "city")
