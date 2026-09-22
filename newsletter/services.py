"""Newsletter preference service layer."""

import logging
from collections.abc import Iterable

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .dnc_services import (
    SuppressionReconciliation,
    is_suppressed,
    reconcile_email_suppression_for_resubscribe,
    suppression_state,
)
from .models import NewsletterCategory, NewsletterSubscription
from .sync_events import create_newsletter_sync_event


logger = logging.getLogger(__name__)


class InvalidNewsletterCategories(ValueError):
    def __init__(self, slugs):
        self.slugs = tuple(slugs)
        super().__init__(", ".join(self.slugs))


def list_user_preferences(user) -> list[dict]:
    """Return every active category plus the current user's effective state.

    A missing NewsletterSubscription row means the user has never explicitly
    chosen that newsletter and is represented as subscribed=False.

    ``subscribed`` is the *effective* state: the member's own choice AND the
    absence of a Mautic email suppression. Mautic blocks email globally per
    contact, so while a block stands nothing is delivered regardless of the
    per-category choice, and reporting the raw choice would tell the member
    they are receiving mail that Mautic is discarding. ``locally_subscribed``
    keeps the underlying choice visible so it can be restored untouched once
    the block clears.
    """
    categories = list(
        NewsletterCategory.objects.filter(is_active=True).order_by("name")
    )
    subscriptions = {
        subscription.category_id: subscription
        for subscription in NewsletterSubscription.objects.filter(
            user=user,
            category_id__in=[category.pk for category in categories],
        )
    }
    suppressed = is_suppressed(user)

    result = []
    for category in categories:
        subscription = subscriptions.get(category.pk)
        locally_subscribed = bool(subscription and subscription.is_subscribed)
        result.append(
            {
                "slug": category.slug,
                "name": category.name,
                "description": category.description,
                "subscribed": locally_subscribed and not suppressed,
                "locally_subscribed": locally_subscribed,
                "suppressed": suppressed and locally_subscribed,
            }
        )
    return result


def get_email_suppression_state(user) -> dict:
    """Return the member-facing Mautic email suppression summary."""
    return suppression_state(user)


def _dispatch_newsletter_sync_event_safely(event_id: int) -> None:
    """Best-effort Celery dispatch after the preference transaction commits.

    A broker failure must not turn a successful preference update into an API
    failure. The durable NewsletterSyncEvent remains PENDING for the recovery
    dispatcher to pick up later.
    """
    try:
        from .tasks import process_newsletter_sync_event

        process_newsletter_sync_event.delay(event_id)
    except Exception:
        logger.exception(
            "Could not dispatch newsletter preference sync event_id=%s; "
            "durable event remains pending",
            event_id,
        )


def _reconcile_suppression_for_opt_in(
    user,
    items,
) -> SuppressionReconciliation | None:
    """Reconcile Mautic suppression when a request contains an explicit opt-in.

    Runs on the *request*, not on the resulting state change: a member whose
    stored choice is already subscribed but whose delivery is suppressed sees
    the toggle as off, and turning it on must still attempt the reversal even
    though no local row changes.

    Never raises. A Mautic failure leaves the suppression in place, which is
    reported honestly by the response rather than being hidden behind a
    successful save.
    """
    if not any(bool(item.get("subscribed")) for item in items):
        return None
    if not is_suppressed(user):
        return None

    try:
        return reconcile_email_suppression_for_resubscribe(user)
    except Exception:
        logger.exception(
            "Unexpected failure reconciling Mautic email suppression "
            "for user_id=%s; suppression retained",
            getattr(user, "pk", None),
        )
        return SuppressionReconciliation(
            SuppressionReconciliation.UNKNOWN,
            detail="Mautic suppression could not be checked.",
        )


def update_user_preferences(
    user,
    preferences: Iterable[dict],
    *,
    source: str = NewsletterSubscription.Source.USER,
) -> list[dict]:
    """Persist explicit newsletter choices for one user.

    Timestamp semantics:
    - first subscribe: subscribed_at=now, unsubscribed_at=None
    - unsubscribe: subscribed_at is preserved, unsubscribed_at=now
    - resubscribe: subscribed_at=now, unsubscribed_at=None
    - same-state PATCH: timestamps are unchanged

    Sending subscribed=False for a category with no existing row creates an
    explicit opt-out row. This preserves the distinction between "never chose"
    and "explicitly unsubscribed".

    When Mautic sync is enabled, every real state change also persists a
    durable NewsletterSyncEvent in the same database transaction. Celery
    dispatch is registered with transaction.on_commit(), so provider/broker
    activity never occurs before the preference and outbox event are committed.

    When Mautic sync is disabled, preferences are still saved but no sync event
    is created. A future controlled backfill can enqueue existing preferences
    when rollout is intentionally enabled.
    """
    items = list(preferences)
    slugs = [item["slug"] for item in items]
    categories = {
        category.slug: category
        for category in NewsletterCategory.objects.filter(
            slug__in=slugs,
            is_active=True,
        )
    }
    missing = sorted(set(slugs) - set(categories))
    if missing:
        raise InvalidNewsletterCategories(missing)

    # Only after the request is known to be valid: an explicit opt-in is the
    # member's consent to lift their own earlier Mautic opt-out.
    _reconcile_suppression_for_opt_in(user, items)

    now = timezone.now()
    with transaction.atomic():
        existing = {
            subscription.category_id: subscription
            for subscription in NewsletterSubscription.objects.select_for_update().filter(
                user=user,
                category_id__in=[category.pk for category in categories.values()],
            )
        }

        for item in items:
            category = categories[item["slug"]]
            desired = bool(item["subscribed"])
            subscription = existing.get(category.pk)
            state_changed = False

            if subscription is None:
                subscription = NewsletterSubscription.objects.create(
                    user=user,
                    category=category,
                    is_subscribed=desired,
                    subscribed_at=now if desired else None,
                    unsubscribed_at=None if desired else now,
                    source=source,
                )
                existing[category.pk] = subscription
                state_changed = True
            elif subscription.is_subscribed != desired:
                subscription.is_subscribed = desired
                subscription.source = source
                if desired:
                    subscription.subscribed_at = now
                    subscription.unsubscribed_at = None
                else:
                    subscription.unsubscribed_at = now
                subscription.save(
                    update_fields=[
                        "is_subscribed",
                        "source",
                        "subscribed_at",
                        "unsubscribed_at",
                        "updated_at",
                    ]
                )
                state_changed = True

            if not state_changed:
                continue

            if not getattr(settings, "MAUTIC_SYNC_ENABLED", False):
                continue

            event = create_newsletter_sync_event(subscription)
            transaction.on_commit(
                lambda event_id=event.pk: _dispatch_newsletter_sync_event_safely(
                    event_id
                )
            )

    return list_user_preferences(user)
