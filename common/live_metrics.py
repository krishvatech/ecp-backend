"""Lightweight live-meeting metrics helpers.

Counters are stored in cache so they are cheap and safe during load tests.
They are intentionally best-effort: metrics failures must never break user flows.
"""

from __future__ import annotations

from datetime import datetime, timezone
from django.core.cache import cache


def live_metric_incr(name: str, *, event_id=None, amount: int = 1, ttl: int = 60 * 60 * 24) -> None:
    bucket = datetime.now(timezone.utc).strftime("%Y%m%d%H")
    event_part = event_id if event_id is not None else "global"
    key = f"metrics:live:{bucket}:{event_part}:{name}"
    try:
        cache.add(key, 0, ttl)
        cache.incr(key, amount)
    except Exception:
        # Metrics must be non-blocking and must not affect live meeting flows.
        return
