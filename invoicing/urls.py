from django.urls import path, include
from rest_framework.routers import SimpleRouter
from invoicing import views, webhook_handlers

router = SimpleRouter()
router.register('invoices', views.InvoiceViewSet, basename='invoice')

urlpatterns = [
    path('webhooks/saleor/', webhook_handlers.saleor_order_webhook, name='saleor-webhook'),
    path('webhooks/stripe/<str:entity_code>/', webhook_handlers.stripe_payment_webhook, name='stripe-webhook'),
    path('', include(router.urls)),
]
