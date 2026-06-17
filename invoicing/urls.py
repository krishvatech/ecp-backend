from django.urls import path, include
from rest_framework.routers import SimpleRouter
from invoicing import views, webhook_handlers

router = SimpleRouter()
router.register('invoices', views.InvoiceViewSet, basename='invoice')

urlpatterns = [
    path('webhooks/saleor/', webhook_handlers.saleor_order_webhook, name='saleor-webhook'),
    # Stripe is intentionally not used in the offline/manual payment flow.
    path('', include(router.urls)),
]
