from django.urls import path
from .views import BillingAddressView, CartView, CartItems, CartItemDetail, CartCount, CartClear, OrderList, CheckoutView, OfflineCheckoutView, OrderMarkPaidView
from .webhooks import saleor_order_paid_webhook

urlpatterns = [
    path("cart/", CartView.as_view(), name="cart"),
    path("cart/count/", CartCount.as_view(), name="cart-count"),
    path("cart/items/", CartItems.as_view(), name="cart-items"),
    path("cart/items/<int:pk>/", CartItemDetail.as_view(), name="cart-item-detail"),
    path("cart/clear/", CartClear.as_view(), name="cart-clear"),
    path("orders/", OrderList.as_view(), name="orders"),
    path("orders/billing-address/", BillingAddressView.as_view(), name="orders-billing-address"),
    path("orders/checkout/", CheckoutView.as_view(), name="orders-checkout"),
    path("orders/offline-checkout/", OfflineCheckoutView.as_view(), name="orders-offline-checkout"),
    path("orders/<int:pk>/mark-paid/", OrderMarkPaidView.as_view(), name="orders-mark-paid"),

    # Saleor Webhooks
    path("webhooks/saleor/order-paid/", saleor_order_paid_webhook, name="saleor-order-paid"),
]