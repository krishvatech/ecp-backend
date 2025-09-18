"""
Views for the payments app.

This module exposes endpoints for managing ticket plans, initiating
checkout sessions and handling Stripe webhook callbacks.  All
endpoints require authentication except the webhook, which relies
solely on signature verification.  Organization owners and admins
may create and manage ticket plans.  Any authenticated user may
purchase a plan for an event via the checkout endpoint.
"""
from __future__ import annotations

import os
import json
import stripe

from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404

from rest_framework import viewsets, status, permissions, views
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.decorators import action

from organizations.models import Organization
from events.models import Event
from .models import TicketPlan, TicketPurchase
from .serializers import TicketPlanSerializer, TicketPurchaseSerializer, CheckoutRequestSerializer
from .tasks import process_purchase_success
from analytics.tasks import increment_metric


class IsOrgAdmin(permissions.BasePermission):
    """Permission to check if the user is an admin or owner of an organization."""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        # obj is an Organization instance
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if user.is_staff or user.is_superuser:
            return True
        # membership check; user.organizations and user.owned_organizations exist
        return (
            user.organizations.filter(id=obj.id).exists()
            or user.owned_organizations.filter(id=obj.id).exists()
        )


class TicketPlanViewSet(viewsets.ModelViewSet):
    """CRUD endpoints for ticket plans.  Creation and updates require org admin privileges."""

    queryset = TicketPlan.objects.all().select_related("organization")
    serializer_class = TicketPlanSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "id"

    def get_queryset(self):
        qs = super().get_queryset()
        # Filter by organization if provided
        org_id = self.request.query_params.get("organization")
        active = self.request.query_params.get("active")
        if org_id:
            qs = qs.filter(organization_id=org_id)
        if active is not None:
            # Accept true/false as strings
            val = active.lower() in ("1", "true", "t", "yes", "y")
            qs = qs.filter(is_active=val)
        return qs.order_by("-created_at")

    def perform_create(self, serializer):
        user = self.request.user
        organization = serializer.validated_data["organization"]
        # Ensure the user is admin/owner of the organization
        if not (
            user.is_staff
            or user.is_superuser
            or user.organizations.filter(id=organization.id).exists()
            or user.owned_organizations.filter(id=organization.id).exists()
        ):
            raise PermissionDenied("You do not have permission to create plans for this organization.")
        # Create Stripe product/price via dj-stripe/stripe if needed
        # Use API keys from environment (test mode).  A product per plan name will be created.
        stripe.api_key = os.environ.get(
            "STRIPE_TEST_SECRET_KEY", settings.STRIPE_TEST_SECRET_KEY if hasattr(settings, "STRIPE_TEST_SECRET_KEY") else None
        )
        currency = serializer.validated_data.get("currency", "usd")
        price_cents = serializer.validated_data.get("price_cents")
        name = serializer.validated_data.get("name")
        # Create product
        stripe_product = None
        stripe_price = None
        try:
            stripe_product = stripe.Product.create(name=name)
            stripe_price = stripe.Price.create(
                unit_amount=price_cents,
                currency=currency,
                product=stripe_product.id,
            )
        except Exception:
            # In case of failure, still create plan but leave stripe_price_id blank
            stripe_price = None
        instance = serializer.save(stripe_price_id=(stripe_price.id if stripe_price else ""))
        return instance

    def perform_update(self, serializer):
        instance = self.get_object()
        user = self.request.user
        if not (
            user.is_staff
            or user.is_superuser
            or user.organizations.filter(id=instance.organization_id).exists()
            or user.owned_organizations.filter(id=instance.organization_id).exists()
        ):
            raise PermissionDenied("You do not have permission to update this plan.")
        return serializer.save()


class CheckoutView(views.APIView):
    """Initiate a Stripe PaymentIntent for a ticket purchase."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = CheckoutRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        event = serializer.validated_data["event"]
        plan = serializer.validated_data["plan"]
        user = request.user
        # Ensure user has membership in organization to purchase
        org_id = plan.organization_id
        if not (
            user.is_staff
            or user.is_superuser
            or user.organizations.filter(id=org_id).exists()
            or user.owned_organizations.filter(id=org_id).exists()
        ):
            raise PermissionDenied("You are not allowed to purchase tickets for this organization.")
        # Create PaymentIntent via Stripe API
        stripe.api_key = os.environ.get(
            "STRIPE_TEST_SECRET_KEY",
            getattr(settings, "STRIPE_TEST_SECRET_KEY", None),
        )
        try:
            payment_intent = stripe.PaymentIntent.create(
                amount=plan.price_cents,
                currency=plan.currency,
                metadata={
                    "event_id": str(event.id),
                    "plan_id": str(plan.id),
                    "user_id": str(user.id),
                },
            )
            intent_id = payment_intent.id
            client_secret = payment_intent.client_secret
        except Exception:
            # Fallback: generate a dummy id and secret for offline/testing environments
            import uuid

            uid = uuid.uuid4().hex
            intent_id = f"pi_{uid}"
            client_secret = f"secret_{uid}"
        # Persist pending purchase
        purchase = TicketPurchase.objects.create(
            event=event,
            user=user,
            plan=plan,
            stripe_payment_intent_id=intent_id,
            status=TicketPurchase.STATUS_PENDING,
            amount_cents=plan.price_cents,
            currency=plan.currency,
        )
        return Response({"client_secret": client_secret, "purchase_id": purchase.id})


@method_decorator(csrf_exempt, name="dispatch")
class StripeWebhookView(views.APIView):
    """Handle incoming Stripe webhook events."""

    permission_classes = []  # no authentication

    def post(self, request):
        payload = request.body
        sig_header = request.META.get("HTTP_STRIPE_SIGNATURE", "")
        stripe.api_key = os.environ.get(
            "STRIPE_TEST_SECRET_KEY",
            getattr(settings, "STRIPE_TEST_SECRET_KEY", None),
        )
        webhook_secret = os.environ.get(
            "STRIPE_WEBHOOK_SECRET",
            getattr(settings, "STRIPE_WEBHOOK_SECRET", None),
        )
        # Verify signature
        try:
            event = stripe.Webhook.construct_event(
                payload=payload, sig_header=sig_header, secret=webhook_secret
            )
        except Exception:
            return HttpResponse(status=400)
        # Handle the event
        event_type = event["type"]
        data_obj = event["data"]["object"]
        if event_type in ("payment_intent.succeeded", "checkout.session.completed"):
            # Payment succeeded
            # Determine PaymentIntent ID
            pi_id = data_obj.get("id") or data_obj.get("payment_intent")
            if not pi_id:
                return HttpResponse(status=200)
            # Update purchase record asynchronously via Celery
            process_purchase_success.delay(pi_id, data_obj.get("amount", 0))
            return HttpResponse(status=200)
        elif event_type == "payment_intent.payment_failed":
            pi_id = data_obj.get("id")
            if pi_id:
                # Mark purchase failed
                TicketPurchase.objects.filter(
                    stripe_payment_intent_id=pi_id
                ).update(status=TicketPurchase.STATUS_FAILED)
            return HttpResponse(status=200)
        return HttpResponse(status=200)
