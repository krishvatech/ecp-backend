"""
Celery tasks for the analytics app.

These tasks provide a simple API for incrementing daily metrics.  By
invoking these tasks asynchronously, other apps can record
analytics without blocking.  A helper function performs an atomic
upsert on the ``MetricDaily`` table and increments the appropriate
fields.
"""
from __future__ import annotations

import datetime
from celery import shared_task
from django.db import transaction

from .models import MetricDaily


@shared_task
def increment_metric(
    metric_name: str,
    org_id: int | None = None,
    event_id: int | None = None,
    value: int = 1,
    amount_cents: int | None = None,
    ts: datetime.datetime | None = None,
) -> None:
    """Increment a given metric for a date, organization and event.

    Args:
        metric_name: One of ``message_count``, ``resource_count``,
            ``registrations_count``, ``purchases_count``, ``revenue_cents``.
        org_id: Optional organization primary key.  Use None for global metrics.
        event_id: Optional event primary key.  Use None if not tied to an event.
        value: Amount to increment the counter by (ignored for revenue).
        amount_cents: Amount of revenue in cents; used when ``metric_name`` is
            ``revenue_cents``.  If provided, supersedes ``value``.
        ts: Timestamp to derive the date.  Defaults to now().
    """
    if ts is None:
        ts = datetime.datetime.utcnow()
    date = ts.date()
    with transaction.atomic():
        obj, _ = MetricDaily.objects.select_for_update().get_or_create(
            organization_id=org_id,
            event_id=event_id,
            date=date,
            defaults={
                "message_count": 0,
                "resource_count": 0,
                "registrations_count": 0,
                "purchases_count": 0,
                "revenue_cents": 0,
            },
        )
        if metric_name == "revenue_cents":
            increment = amount_cents if amount_cents is not None else value
            obj.revenue_cents = (obj.revenue_cents or 0) + increment
        else:
            # generic counter
            current = getattr(obj, metric_name, 0) or 0
            setattr(obj, metric_name, current + value)
        obj.save()


@shared_task
def daily_reconcile(start: datetime.date | None = None, end: datetime.date | None = None) -> None:
    """Optional task to backfill metrics for missing days.

    Currently not implemented.  This placeholder exists to satisfy
    future requirements where daily totals may need to be recomputed
    from raw event logs.
    """
    return
