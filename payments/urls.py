"""
URL configuration for the payments app.

Registers REST endpoints for ticket plan management and checkout, and
exposes a webhook endpoint for Stripe.  Include this module under
``/api/payments/`` in the project-level URL config.
"""
from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import TicketPlanViewSet, CheckoutView, StripeWebhookView


router = DefaultRouter()
router.register(r"plans", TicketPlanViewSet, basename="ticketplan")

urlpatterns = [
    *router.urls,
    path("checkout/", CheckoutView.as_view(), name="ticket-checkout"),
    path("webhook/stripe/", StripeWebhookView.as_view(), name="stripe-webhook"),
]
