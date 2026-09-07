"""Subscription-list contact timeline analytics owned by ECP."""

from collections import defaultdict
from datetime import date, datetime, time, timedelta

from django.utils import timezone

from .models import NewsletterSubscription, NewsletterSyncEvent


DEFAULT_RANGE_DAYS = 30
MAX_RANGE_DAYS = 366


def _parse_iso_date(value, *, field_name):
    if value in (None, ""):
        return None
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must use YYYY-MM-DD format.") from exc


def resolve_contact_timeline_range(*, from_value=None, to_value=None, today=None):
    """Validate/resolve the inclusive date range for list contact analytics."""
    today = today or timezone.localdate()
    end_date = _parse_iso_date(to_value, field_name="to") or today
    start_date = (
        _parse_iso_date(from_value, field_name="from")
        or (end_date - timedelta(days=DEFAULT_RANGE_DAYS - 1))
    )

    if start_date > end_date:
        raise ValueError("from must be on or before to.")

    inclusive_days = (end_date - start_date).days + 1
    if inclusive_days > MAX_RANGE_DAYS:
        raise ValueError(
            f"Date range cannot exceed {MAX_RANGE_DAYS} days."
        )

    return start_date, end_date


def _aware_day_start(value):
    tz = timezone.get_current_timezone()
    return timezone.make_aware(datetime.combine(value, time.min), tz)


def build_category_contact_timeline(category, *, start_date, end_date):
    """Build Added / Removed / Total daily series from ECP-owned state.

    NewsletterSyncEvent is append-only and preserves A -> B -> A transitions,
    but admin reconciliation may create repeated same-state events. We merge
    those events with the latest NewsletterSubscription timestamps, sort them
    per user, and count only real state transitions. That prevents Sync/Repair
    from inflating Added/Removed metrics.

    Subscription timestamps also provide a fallback for users whose preference
    changed while Mautic synchronization was disabled.
    """
    end_exclusive = _aware_day_start(end_date + timedelta(days=1))
    transitions = defaultdict(list)

    subscriptions = list(
        NewsletterSubscription.objects.filter(category=category).values(
            "user_id",
            "is_subscribed",
            "subscribed_at",
            "unsubscribed_at",
        )
    )
    for subscription in subscriptions:
        user_id = str(subscription["user_id"])
        subscribed_at = subscription["subscribed_at"]
        unsubscribed_at = subscription["unsubscribed_at"]
        if subscribed_at is not None and subscribed_at < end_exclusive:
            transitions[user_id].append((subscribed_at, 0, True))
        if unsubscribed_at is not None and unsubscribed_at < end_exclusive:
            transitions[user_id].append((unsubscribed_at, 2, False))

    events = NewsletterSyncEvent.objects.filter(
        category=category,
        created_at__lt=end_exclusive,
    ).values("user_id", "desired_subscribed", "created_at", "id")
    for event in events.iterator():
        transitions[str(event["user_id"])].append(
            (
                event["created_at"],
                1,
                bool(event["desired_subscribed"]),
            )
        )

    daily = defaultdict(lambda: {"added": 0, "removed": 0})
    baseline_total = 0
    tz = timezone.get_current_timezone()

    for user_transitions in transitions.values():
        state = False
        for occurred_at, priority, desired in sorted(
            user_transitions,
            key=lambda item: (item[0], item[1]),
        ):
            if desired == state:
                continue

            state = desired
            local_day = timezone.localtime(occurred_at, tz).date()
            delta = 1 if desired else -1

            if local_day < start_date:
                baseline_total += delta
                continue
            if local_day > end_date:
                continue

            if desired:
                daily[local_day]["added"] += 1
            else:
                daily[local_day]["removed"] += 1

    series = []
    running_total = baseline_total
    current_day = start_date
    while current_day <= end_date:
        bucket = daily[current_day]
        running_total += bucket["added"] - bucket["removed"]
        series.append(
            {
                "date": current_day.isoformat(),
                "added": bucket["added"],
                "removed": bucket["removed"],
                "total": max(0, running_total),
            }
        )
        current_day += timedelta(days=1)

    current_total = NewsletterSubscription.objects.filter(
        category=category,
        is_subscribed=True,
    ).count()

    return {
        "from": start_date.isoformat(),
        "to": end_date.isoformat(),
        "current_total": current_total,
        "range_start_total": max(0, baseline_total),
        "range_end_total": series[-1]["total"] if series else max(0, baseline_total),
        "series": series,
    }
