"""
Serializers for the payments app.

These serializers expose the ticketing models to the REST API and
perform minimal validation.  Heavy lifting (such as creating
Stripe resources) happens in the corresponding views and tasks.
"""
from __future__ import annotations

from django.contrib.auth import get_user_model
from rest_framework import serializers
from organizations.models import Organization
from events.models import Event
from .models import TicketPlan, TicketPurchase


class TicketPlanSerializer(serializers.ModelSerializer):
    """Serializer for TicketPlan objects."""

    organization_id = serializers.PrimaryKeyRelatedField(
        queryset=Organization.objects.all(), source="organization"
    )

    class Meta:
        model = TicketPlan
        fields = [
            "id",
            "organization_id",
            "name",
            "price_cents",
            "currency",
            "stripe_price_id",
            "is_active",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "stripe_price_id", "created_at", "updated_at"]


class TicketPurchaseSerializer(serializers.ModelSerializer):
    """Serializer for TicketPurchase objects (read-only)."""

    event_id = serializers.IntegerField(source="event.id", read_only=True)
    user_id = serializers.IntegerField(source="user.id", read_only=True)
    plan_id = serializers.IntegerField(source="plan.id", read_only=True)

    class Meta:
        model = TicketPurchase
        fields = [
            "id",
            "event_id",
            "user_id",
            "plan_id",
            "stripe_payment_intent_id",
            "status",
            "amount_cents",
            "currency",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class CheckoutRequestSerializer(serializers.Serializer):
    """Serializer for initiating a ticket purchase (checkout)."""

    event_id = serializers.IntegerField()
    plan_id = serializers.IntegerField()

    def validate(self, attrs):
        event_id = attrs.get("event_id")
        plan_id = attrs.get("plan_id")
        try:
            event = Event.objects.get(pk=event_id)
        except Event.DoesNotExist:
            raise serializers.ValidationError({"event_id": "Event not found."})
        try:
            plan = TicketPlan.objects.get(pk=plan_id)
        except TicketPlan.DoesNotExist:
            raise serializers.ValidationError({"plan_id": "Ticket plan not found."})
        # Ensure the plan belongs to the event's organization
        if plan.organization_id != event.organization_id:
            raise serializers.ValidationError(
                {"plan_id": "This plan does not belong to the event's organization."}
            )
        attrs["event"] = event
        attrs["plan"] = plan
        return attrs
