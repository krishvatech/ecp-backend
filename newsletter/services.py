"""Newsletter preference service layer."""

from collections.abc import Iterable

from django.db import transaction
from django.utils import timezone

from .models import NewsletterCategory, NewsletterSubscription


class InvalidNewsletterCategories(ValueError):
    def __init__(self, slugs):
        self.slugs = tuple(slugs)
        super().__init__(", ".join(self.slugs))


def list_user_preferences(user) -> list[dict]:
    """Return every active category plus the current user's state.

    A missing NewsletterSubscription row means the user has never explicitly
    chosen that newsletter and is represented as subscribed=False.
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

    result = []
    for category in categories:
        subscription = subscriptions.get(category.pk)
        result.append(
            {
                "slug": category.slug,
                "name": category.name,
                "description": category.description,
                "subscribed": bool(
                    subscription and subscription.is_subscribed
                ),
            }
        )
    return result


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

            if subscription is None:
                NewsletterSubscription.objects.create(
                    user=user,
                    category=category,
                    is_subscribed=desired,
                    subscribed_at=now if desired else None,
                    unsubscribed_at=None if desired else now,
                    source=source,
                )
                continue

            if subscription.is_subscribed == desired:
                continue

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

    return list_user_preferences(user)
