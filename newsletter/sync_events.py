"""Durable Newsletter -> Mautic synchronization event creation helpers."""

from __future__ import annotations

import uuid

from django.db import transaction

from .models import NewsletterSubscription, NewsletterSyncEvent


IN_FLIGHT_STATUSES = (
    NewsletterSyncEvent.Status.PENDING,
    NewsletterSyncEvent.Status.PROCESSING,
    NewsletterSyncEvent.Status.RETRYING,
)


def build_newsletter_sync_idempotency_key(
    *,
    user_id: int | str,
    category_id: int | str,
    desired_subscribed: bool,
) -> str:
    """Build the stable key for one desired newsletter state."""
    state = "subscribed" if desired_subscribed else "unsubscribed"
    return f"mautic:newsletter:user:{user_id}:category:{category_id}:{state}"


def create_newsletter_sync_event(
    subscription: NewsletterSubscription,
) -> NewsletterSyncEvent:
    """Create or reuse one durable in-flight desired-state event.

    The subscription row is locked so concurrent requests for the same
    user/category cannot create duplicate in-flight events. Equal in-flight
    state is deduplicated. Once an equal state has completed, a later
    transition back to that same state creates a new event, preserving A -> B
    -> A transitions.
    """
    if not getattr(subscription, "pk", None):
        raise ValueError("Saved newsletter subscription is required")

    with transaction.atomic():
        locked = (
            NewsletterSubscription.objects.select_for_update()
            .select_related("category")
            .get(pk=subscription.pk)
        )
        user_id = str(locked.user_id)
        desired_subscribed = bool(locked.is_subscribed)

        existing = (
            NewsletterSyncEvent.objects.filter(
                user_id=user_id,
                category=locked.category,
                desired_subscribed=desired_subscribed,
                status__in=IN_FLIGHT_STATUSES,
            )
            .order_by("created_at")
            .first()
        )
        if existing is not None:
            return existing

        base_key = build_newsletter_sync_idempotency_key(
            user_id=user_id,
            category_id=locked.category_id,
            desired_subscribed=desired_subscribed,
        )
        idempotency_key = base_key
        if NewsletterSyncEvent.objects.filter(
            idempotency_key=base_key
        ).exists():
            idempotency_key = f"{base_key}:{uuid.uuid4().hex[:12]}"

        return NewsletterSyncEvent.objects.create(
            idempotency_key=idempotency_key,
            user_id=user_id,
            category=locked.category,
            desired_subscribed=desired_subscribed,
        )
