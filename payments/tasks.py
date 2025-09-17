"""
Celery tasks for the payments app.

These tasks decouple processing of successful payments from the
request/response cycle.  When a Stripe webhook indicates a
successful payment, a task updates the corresponding TicketPurchase
record, updates analytics metrics and optionally emits activity feed
entries.
"""
from __future__ import annotations

from celery import shared_task
from django.db import transaction
from .models import TicketPurchase
from ecp_backend.analytics.tasks import increment_metric
from ecp_backend.activity_feed.tasks import create_feed_item_task
from django.contrib.contenttypes.models import ContentType


@shared_task
def process_purchase_success(payment_intent_id: str, amount: int | None = None) -> None:
    """Mark a pending purchase as succeeded and update analytics.

    Args:
        payment_intent_id: The Stripe PaymentIntent identifier.
        amount: Optional amount (in cents) reported by the webhook.  If
            not provided, the existing purchase amount is used.
    """
    with transaction.atomic():
        try:
            purchase = TicketPurchase.objects.select_related("plan", "event", "user").get(
                stripe_payment_intent_id=payment_intent_id
            )
        except TicketPurchase.DoesNotExist:
            return
        if purchase.status != TicketPurchase.STATUS_PENDING:
            return
        purchase.status = TicketPurchase.STATUS_SUCCEEDED
        if amount:
            purchase.amount_cents = amount
        purchase.save(update_fields=["status", "amount_cents", "updated_at"])
        org_id = purchase.plan.organization_id
        event_id = purchase.event_id
        # Increment purchases and revenue metrics
        increment_metric.delay(
            metric_name="purchases_count",
            org_id=org_id,
            event_id=event_id,
            value=1,
        )
        increment_metric.delay(
            metric_name="revenue_cents",
            org_id=org_id,
            event_id=event_id,
            amount_cents=purchase.amount_cents,
        )
        # Emit activity feed item
        metadata = {
            "plan_name": purchase.plan.name,
            "amount": purchase.amount_cents,
            "currency": purchase.currency,
        }
        ct = ContentType.objects.get_for_model(TicketPurchase)
        create_feed_item_task.delay(
            verb="ticket_purchase_succeeded",
            target_content_type_id=ct.id,
            target_object_id=purchase.id,
            organization_id=org_id,
            event_id=event_id,
            actor_id=purchase.user_id,
            metadata=metadata,
        )
        # Trigger CRM sync for new registrant/purchaser
        try:
            from ecp_backend.integrations.tasks import sync_registrant_to_hubspot

            sync_registrant_to_hubspot.delay(org_id, purchase.user_id, event_id)
        except Exception:
            # avoid breaking on errors
            pass
