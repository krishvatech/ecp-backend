"""Execution evidence for the periodic newsletter Celery tasks.

Each periodic task records when it last started, succeeded and failed, in the
shared Django cache (Redis), so diagnostics can tell whether scheduled
processing is actually happening.

What this proves, and what it does not: a heartbeat is written by a worker
while it runs a task that Celery Beat scheduled, so a fresh heartbeat proves
the whole Beat -> broker -> worker path worked recently. It does not prove that
the Beat process itself is alive right now, and a missing heartbeat does not
say which link broke. Beat keeps no state ECP can read, so it is never reported
as independently healthy.

Writes never raise: losing a heartbeat must not fail the task it describes.
"""

from __future__ import annotations

import contextlib
import logging
from datetime import datetime, timedelta

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

logger = logging.getLogger(__name__)

#: The recurring newsletter tasks, by Celery task name.
PERIODIC_TASKS = (
    "newsletter.dispatch_due_sync_events",
    "newsletter.dispatch_due_campaign_send_events",
    "newsletter.dispatch_due_scheduled_campaigns",
    "newsletter.reconcile_native_scheduled_campaigns",
)

_KEY = "newsletter:task-heartbeat:{task}:{field}"
#: Long enough to cover a weekend outage; bounded so keys never accumulate.
HEARTBEAT_TTL_SECONDS = int(timedelta(days=7).total_seconds())
#: A run may be skipped this many times (queue backlog, worker restart) before
#: the processing is called stale.
MISSED_RUNS_TOLERANCE = 3

HEALTHY = "Healthy"
DEGRADED = "Degraded"
STALE = "Stale"
NOT_VERIFIED = "Not Verified"
DISABLED = "Disabled"

# Worst first, so the overall status is the first one any task has.
_SEVERITY = (STALE, DEGRADED, NOT_VERIFIED, HEALTHY)


def background_health_enabled() -> bool:
    """Kill switch for heartbeat writes and live broker/worker probes."""
    return bool(getattr(settings, "NEWSLETTER_BACKGROUND_HEALTH_ENABLED", True))


def _key(task: str, field: str) -> str:
    return _KEY.format(task=task, field=field)


def _write(task: str, field: str, value) -> None:
    if not background_health_enabled():
        return
    try:
        cache.set(_key(task, field), value, timeout=HEARTBEAT_TTL_SECONDS)
    except Exception:
        logger.warning("Could not record %s heartbeat for %s", field, task, exc_info=True)


@contextlib.contextmanager
def task_heartbeat(task: str):
    """Record start, then success or failure, around one periodic task run."""
    _write(task, "started", timezone.now().isoformat())
    try:
        yield
    except Exception as exc:
        # The exception type only: messages may carry provider text.
        _write(task, "failed", {"at": timezone.now().isoformat(), "error_type": type(exc).__name__})
        raise
    _write(task, "succeeded", timezone.now().isoformat())


def _parse(value):
    if isinstance(value, dict):
        value = value.get("at")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if timezone.is_aware(parsed) else None


def _age_seconds(moment, now):
    # A worker clock slightly ahead of this one must not produce negative ages.
    return max(0.0, (now - moment).total_seconds()) if moment else None


def _interval_seconds(schedule):
    """Seconds between runs for a timedelta-based Beat entry, else None."""
    if isinstance(schedule, timedelta):
        return schedule.total_seconds()
    run_every = getattr(schedule, "run_every", None)
    if isinstance(run_every, timedelta):
        return run_every.total_seconds()
    return None


def stale_after_seconds(interval_seconds: float) -> float:
    """How old the last run may be before processing counts as stopped.

    MISSED_RUNS_TOLERANCE intervals of backlog, plus one run that took the full
    Celery hard time limit.
    """
    time_limit = float(getattr(settings, "CELERY_TASK_TIME_LIMIT", 300) or 300)
    return interval_seconds * MISSED_RUNS_TOLERANCE + time_limit


def task_stale_after_seconds(task: str):
    """Stale threshold for one periodic task, from its Beat entry; None if it
    is not scheduled."""
    intervals = _scheduled_intervals()
    if task not in intervals:
        return None
    return stale_after_seconds(intervals[task] or 60)


def _scheduled_intervals() -> dict:
    beat = getattr(settings, "CELERY_BEAT_SCHEDULE", {}) or {}
    intervals = {}
    for entry in beat.values():
        if isinstance(entry, dict) and entry.get("task") in PERIODIC_TASKS:
            intervals[entry["task"]] = _interval_seconds(entry.get("schedule"))
    return intervals


def _task_status(task, interval, values, now) -> dict:
    stale_after = stale_after_seconds(interval or 60)
    started = _parse(values.get(_key(task, "started")))
    succeeded = _parse(values.get(_key(task, "succeeded")))
    failed_raw = values.get(_key(task, "failed"))
    failed = _parse(failed_raw)
    report = {
        "interval_seconds": interval,
        "stale_after_seconds": stale_after,
        "last_started_at": started,
        "last_succeeded_at": succeeded,
        "last_failed_at": failed,
        "last_error_type": failed_raw.get("error_type", "") if isinstance(failed_raw, dict) else "",
    }
    if started is None:
        return {**report, "status": NOT_VERIFIED, "reason": "no_run_recorded"}
    if _age_seconds(started, now) > stale_after:
        return {**report, "status": STALE, "reason": "no_recent_run"}
    if failed and (succeeded is None or failed > succeeded):
        return {**report, "status": DEGRADED, "reason": "latest_run_failed"}
    return {**report, "status": HEALTHY, "reason": ""}


def periodic_task_health(now=None) -> dict:
    """Freshness of each periodic newsletter task, from recorded heartbeats."""
    now = now or timezone.now()
    intervals = _scheduled_intervals()
    if not intervals:
        return {"status": DISABLED, "reason": "not_scheduled", "tasks": {}}
    if not background_health_enabled():
        return {"status": NOT_VERIFIED, "reason": "heartbeats_disabled", "tasks": {}}

    keys = [_key(task, field) for task in intervals for field in ("started", "succeeded", "failed")]
    try:
        values = cache.get_many(keys)
    except Exception:
        logger.warning("Could not read newsletter task heartbeats", exc_info=True)
        return {"status": NOT_VERIFIED, "reason": "cache_unavailable", "tasks": {}}

    tasks = {
        task: _task_status(task, interval, values, now)
        for task, interval in intervals.items()
    }
    statuses = {report["status"] for report in tasks.values()}
    overall = next(level for level in _SEVERITY if level in statuses)
    reason = ""
    if overall != HEALTHY:
        reason = next(r["reason"] for r in tasks.values() if r["status"] == overall)
    return {"status": overall, "reason": reason, "tasks": tasks}


__all__ = [
    "DEGRADED",
    "DISABLED",
    "HEALTHY",
    "NOT_VERIFIED",
    "PERIODIC_TASKS",
    "STALE",
    "background_health_enabled",
    "periodic_task_health",
    "stale_after_seconds",
    "task_heartbeat",
    "task_stale_after_seconds",
]
