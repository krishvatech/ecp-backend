from django.urls import path
from .views import CartView, CartItems, CartItemDetail, CartCount, CartClear

urlpatterns = [
    path("cart/", CartView.as_view(), name="cart"),
    path("cart/count/", CartCount.as_view(), name="cart-count"),
    path("cart/items/", CartItems.as_view(), name="cart-items"),
    path("cart/items/<int:pk>/", CartItemDetail.as_view(), name="cart-item-detail"),
    path("cart/clear/", CartClear.as_view(), name="cart-clear"),  
]