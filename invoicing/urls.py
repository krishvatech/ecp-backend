from django.urls import path, include
from rest_framework.routers import SimpleRouter
from invoicing import views, webhook_handlers

router = SimpleRouter()
router.register('invoices', views.InvoiceViewSet, basename='invoice')

urlpatterns = [
    path('invoicing/admin/legal-entity/', views.AdminLegalEntitySettingsView.as_view(), name='admin-legal-entity-settings'),
    path('webhooks/saleor/', webhook_handlers.saleor_order_webhook, name='saleor-webhook'),
    path('invoices/public/<str:token>/download/', views.public_invoice_pdf_download, name='public-invoice-pdf-download'),
    # Stripe is intentionally not used in the offline/manual payment flow.
    path('', include(router.urls)),
]
