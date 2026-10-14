"""Independent health of the schedulers behind the Marketing Hub (B10).

Five components, each judged only on evidence that is its own:

* Celery Beat: the Beat process itself records when it started and when it
  last published a scheduled task (``after_task_publish`` fires only after the
  message reached the broker). Recorded from inside Beat, so it says nothing
  about workers.
* Scheduled task execution: the worker-side heartbeats from
  ``task_heartbeats``, read against Beat's publish record, so "Beat published
  but no worker ran it" is told apart from "Beat published nothing".
* Celery worker: a live broadcast ping (``mautic_diagnostics_services``).
* Redis broker: a live ping of CELERY_BROKER_URL.
* Mautic cron and messenger worker: the run records and queue backlog the ECP
  Marketing Bridge reports (``GET ecp/background-health``).

Evaluation happens in the reader (a diagnostics request or the
``check_background_health`` command), never in Beat, so a stopped Beat is
still detected. Evaluation is read-only: it schedules, retries and sends
nothing.

Statuses: Healthy (recent evidence of normal operation), Warning (delayed or
approaching its threshold), Unhealthy (threshold exceeded or a confirmed
failure), Unknown (no evidence, or the evidence source is unavailable), and
Disabled (not in use in this deployment, e.g. a sync messenger transport;
left out of the overall status).
"""

from __future__ import annotations

import contextvars
import functools
import logging
import time
from datetime import datetime, timedelta

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from .task_heartbeats import (
    DEGRADED as LEGACY_DEGRADED,
    DISABLED as LEGACY_DISABLED,
    HEALTHY as LEGACY_HEALTHY,
    NOT_VERIFIED as LEGACY_NOT_VERIFIED,
    PERIODIC_TASKS,
    STALE as LEGACY_STALE,
    background_health_enabled,
    stale_after_seconds,
)

logger = logging.getLogger(__name__)

HEALTHY = "Healthy"
WARNING = "Warning"
UNHEALTHY = "Unhealthy"
UNKNOWN = "Unknown"
DISABLED = "Disabled"

# Worst first; Disabled never contributes.
_ROLLUP = (UNHEALTHY, WARNING, UNKNOWN, HEALTHY)

#: Nagios-style exit codes for check_background_health.
EXIT_CODES = {HEALTHY: 0, DISABLED: 0, WARNING: 1, UNHEALTHY: 2, UNKNOWN: 3}

# ---------------------------------------------------------------------------
# Celery Beat evidence, written from inside the Beat process
# ---------------------------------------------------------------------------

_BEAT_STARTED_KEY = "newsletter:scheduler:beat:started"
_BEAT_PUBLISHED_KEY = "newsletter:scheduler:beat:published"
_BEAT_TASK_PUBLISHED_KEY = "newsletter:scheduler:beat:published:{task}"

#: Beat publishes several tasks a minute; one global write per this many
#: seconds is plenty and keeps Redis traffic negligible.
BEAT_WRITE_INTERVAL_SECONDS = 15
#: After a failed write, stop trying for this long so a Redis outage cannot
#: slow down every scheduling tick (each attempt may wait a socket timeout).
BEAT_WRITE_BACKOFF_SECONDS = 60

_beat_writer = {"last_global_write": None, "suspended_until": 0.0}

#: True only while Beat's own scheduler is publishing an entry. Beat messages
#: carry nothing that marks them as Beat's, so this is what keeps any other
#: publish in the same process (a signal handler, or a worker hosting a
#: threaded embedded Beat) from counting as scheduler activity. Context
#: variables are per thread, so other threads never see it set.
_scheduler_publishing = contextvars.ContextVar("newsletter_beat_scheduler_publishing", default=False)


def _iso_now() -> str:
    return timezone.now().isoformat()


def _beat_write(values: dict) -> None:
    if not background_health_enabled():
        return
    if time.monotonic() < _beat_writer["suspended_until"]:
        return
    try:
        # No expiry: a Beat that has been down for weeks must read as down,
        # not as "no evidence". The key set is small and fixed.
        cache.set_many(values, timeout=None)
    except Exception:
        _beat_writer["suspended_until"] = time.monotonic() + BEAT_WRITE_BACKOFF_SECONDS
        logger.warning("Could not record Celery Beat activity", exc_info=True)


def record_beat_publish(sender=None, headers=None, **kwargs) -> None:
    """``after_task_publish`` receiver, connected only inside Beat.

    The message has reached the broker by the time this runs, so it is
    evidence that Beat is scheduling, not that anything executed. Publishes
    made outside Beat's scheduler are ignored.
    """
    if not _scheduler_publishing.get():
        return
    task = (headers or {}).get("task") or sender
    now = time.monotonic()
    last = _beat_writer["last_global_write"]
    values = {}
    if task in PERIODIC_TASKS:
        values[_BEAT_TASK_PUBLISHED_KEY.format(task=task)] = _iso_now()
    if values or last is None or now - last >= BEAT_WRITE_INTERVAL_SECONDS:
        values[_BEAT_PUBLISHED_KEY] = _iso_now()
        _beat_writer["last_global_write"] = now
    if values:
        _beat_write(values)


def _mark_scheduler_publishes(scheduler) -> None:
    """Flag publishes made by this scheduler instance's ``apply_async``,
    the one path ``tick()`` uses to send due entries."""
    original = scheduler.apply_async
    if getattr(original, "_newsletter_marks_beat_publish", False):
        return

    @functools.wraps(original)
    def apply_async(*args, **kwargs):
        token = _scheduler_publishing.set(True)
        try:
            return original(*args, **kwargs)
        finally:
            _scheduler_publishing.reset(token)

    apply_async._newsletter_marks_beat_publish = True
    scheduler.apply_async = apply_async


def on_beat_init(sender=None, **kwargs) -> None:
    """``beat_init`` receiver: runs once, in the Beat process only.

    ``sender`` is Beat's ``Service``, whose scheduler already exists when
    the signal is sent. Connecting the publish receiver here, rather than at
    import time, keeps workers and web processes from ever writing Beat
    evidence, and only that scheduler's publishes are recorded.
    """
    from celery.signals import after_task_publish

    scheduler = getattr(sender, "scheduler", None)
    if not callable(getattr(scheduler, "apply_async", None)):
        # Without the scheduler no publish can be attributed to Beat; record
        # nothing rather than a start that would never be followed up.
        logger.warning("Celery Beat scheduler not found; Beat activity will not be recorded")
        return
    _mark_scheduler_publishes(scheduler)
    after_task_publish.connect(
        record_beat_publish, weak=False, dispatch_uid="newsletter-scheduler-beat-publish"
    )
    _beat_writer["last_global_write"] = None
    _beat_writer["suspended_until"] = 0.0
    _beat_write({_BEAT_STARTED_KEY: _iso_now()})


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _parse(value):
    if isinstance(value, dict):
        value = value.get("at")
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if timezone.is_aware(parsed) else None


def _age(moment, now):
    # A writer clock slightly ahead of the reader must not give negative ages.
    return max(0.0, (now - moment).total_seconds()) if moment else None


def _iso(moment):
    return moment.isoformat() if moment else None


def _setting_seconds(name, default):
    value = getattr(settings, name, None)
    try:
        value = float(value)
    except (TypeError, ValueError):
        return float(default)
    return value if value > 0 else float(default)


def _component(
    name,
    status,
    reason="",
    detail="",
    *,
    source,
    now,
    last_success=None,
    last_attempt=None,
    cadence=None,
    warning_after=None,
    unhealthy_after=None,
    **extra,
):
    last_activity = max((m for m in (last_success, last_attempt) if m), default=None)
    return {
        "component": name,
        "status": status,
        "reason": reason,
        "detail": detail,
        "last_success_at": _iso(last_success),
        "last_attempt_at": _iso(last_attempt),
        "expected_cadence_seconds": cadence,
        "warning_after_seconds": warning_after,
        "unhealthy_after_seconds": unhealthy_after,
        "seconds_since_last_activity": _age(last_activity, now),
        "evidence_source": source,
        "observed_at": now.isoformat(),
        **extra,
    }


def rollup(statuses) -> str:
    statuses = [s for s in statuses if s != DISABLED]
    if not statuses:
        return DISABLED
    return next(level for level in _ROLLUP if level in statuses)


def _by_age(age, warning_after, unhealthy_after):
    if age > unhealthy_after:
        return UNHEALTHY
    if age > warning_after:
        return WARNING
    return HEALTHY


# ---------------------------------------------------------------------------
# Celery Beat
# ---------------------------------------------------------------------------


def _schedule_interval_seconds(schedule):
    """Seconds between runs of one Beat entry, or None if it is not regular
    or runs less often than hourly (those never set the cadence)."""
    if isinstance(schedule, (int, float)) and schedule > 0:
        return float(schedule)
    if isinstance(schedule, timedelta):
        return schedule.total_seconds()
    run_every = getattr(schedule, "run_every", None)
    if isinstance(run_every, timedelta):
        return run_every.total_seconds()
    minutes = getattr(schedule, "minute", None)
    hours = getattr(schedule, "hour", None)
    if isinstance(minutes, (set, frozenset)) and isinstance(hours, (set, frozenset)) and len(hours) == 24:
        ordered = sorted(minutes)
        if not ordered:
            return None
        gaps = [b - a for a, b in zip(ordered, ordered[1:])] + [60 - ordered[-1] + ordered[0]]
        return float(min(gaps) * 60)
    return None


def beat_cadence_seconds():
    """Shortest interval in CELERY_BEAT_SCHEDULE: how often a healthy Beat
    publishes something. None when nothing is scheduled at sub-daily cadence."""
    beat = getattr(settings, "CELERY_BEAT_SCHEDULE", {}) or {}
    intervals = [
        _schedule_interval_seconds(entry.get("schedule"))
        for entry in beat.values()
        if isinstance(entry, dict)
    ]
    intervals = [value for value in intervals if value]
    return min(intervals) if intervals else None


def beat_thresholds(cadence):
    warning = _setting_seconds("SCHEDULER_MONITOR_BEAT_WARNING_SECONDS", cadence * 2 + 60)
    unhealthy = _setting_seconds("SCHEDULER_MONITOR_BEAT_UNHEALTHY_SECONDS", cadence * 5 + 300)
    grace = _setting_seconds("SCHEDULER_MONITOR_STARTUP_GRACE_SECONDS", cadence + 60)
    return warning, max(unhealthy, warning), grace


def _read_beat_evidence():
    keys = [_BEAT_STARTED_KEY, _BEAT_PUBLISHED_KEY] + [
        _BEAT_TASK_PUBLISHED_KEY.format(task=task) for task in PERIODIC_TASKS
    ]
    values = cache.get_many(keys)
    return {
        "started": _parse(values.get(_BEAT_STARTED_KEY)),
        "published": _parse(values.get(_BEAT_PUBLISHED_KEY)),
        "tasks": {
            task: _parse(values.get(_BEAT_TASK_PUBLISHED_KEY.format(task=task)))
            for task in PERIODIC_TASKS
        },
    }


def beat_health(now, evidence=None, evidence_error=None):
    name = "Celery Beat"
    source = "Beat process publish records (Django cache)"
    cadence = beat_cadence_seconds()
    if cadence is None:
        return _component(name, DISABLED, "not_scheduled", "No periodic tasks are scheduled.", source=source, now=now)
    warning_after, unhealthy_after, grace = beat_thresholds(cadence)
    common = dict(source=source, now=now, cadence=cadence, warning_after=warning_after, unhealthy_after=unhealthy_after)
    if not background_health_enabled():
        return _component(name, UNKNOWN, "monitoring_disabled", "Background health monitoring is switched off.", **common)
    if evidence is None:
        return _component(
            name, UNKNOWN, evidence_error or "cache_unavailable",
            "Beat activity could not be read; the monitoring store is unavailable.", **common,
        )

    started, published = evidence["started"], evidence["published"]
    common.update(last_success=published, last_attempt=started, started_at=_iso(started))

    if started and (published is None or started > published):
        # Beat (re)started and has not published since.
        since_start = _age(started, now)
        if since_start <= grace:
            return _component(
                name, UNKNOWN, "starting",
                "Celery Beat started recently and has not published a task yet.", **common,
            )
        status = UNHEALTHY if since_start > unhealthy_after else WARNING
        return _component(
            name, status, "no_publish_since_start",
            "Celery Beat started but has not published any scheduled task since.", **common,
        )
    if published is None:
        return _component(
            name, UNKNOWN, "no_evidence",
            "No Beat start or publish has been recorded. Beat may not be running, or it has not "
            "been restarted since monitoring was enabled.", **common,
        )

    status = _by_age(_age(published, now), warning_after, unhealthy_after)
    detail = {
        HEALTHY: "Celery Beat is publishing scheduled tasks.",
        WARNING: "Celery Beat has not published a scheduled task for longer than expected.",
        UNHEALTHY: "Celery Beat has stopped publishing scheduled tasks.",
    }[status]
    reason = {HEALTHY: "", WARNING: "publish_delayed", UNHEALTHY: "publish_overdue"}[status]
    return _component(name, status, reason, detail, **common)


# ---------------------------------------------------------------------------
# Scheduled task execution (Beat published it -> did a worker run it?)
# ---------------------------------------------------------------------------


def scheduled_execution_health(scheduled_processing, beat_evidence, now):
    """Per newsletter periodic task: published by Beat, then started and
    finished by a worker. Built on ``task_heartbeats.periodic_task_health``."""
    name = "Scheduled task execution"
    source = "Worker task heartbeats + Beat publish records (Django cache)"
    legacy = scheduled_processing.get("status")
    if legacy == LEGACY_DISABLED:
        return _component(name, DISABLED, "not_scheduled", "No newsletter periodic tasks are scheduled.", source=source, now=now)
    if not scheduled_processing.get("tasks"):
        return _component(
            name, UNKNOWN, scheduled_processing.get("reason") or "no_evidence",
            "Task execution evidence is unavailable.", source=source, now=now,
        )

    published_by_task = (beat_evidence or {}).get("tasks") or {}
    beat_started = (beat_evidence or {}).get("started")
    tasks = {}
    for task, report in scheduled_processing["tasks"].items():
        interval = report.get("interval_seconds") or 60
        stale_after = report.get("stale_after_seconds") or stale_after_seconds(interval)
        warning_after = min(interval * 2 + 60, stale_after)
        started = report.get("last_started_at")
        succeeded = report.get("last_succeeded_at")
        failed = report.get("last_failed_at")
        published = published_by_task.get(task)
        published_recently = published is not None and _age(published, now) <= stale_after

        if started is None:
            if published_recently and beat_started and _age(beat_started, now) > warning_after:
                status, reason = UNHEALTHY, "published_not_executed"
            elif published_recently:
                # Beat only just began publishing; a worker may not have
                # picked the first message up yet.
                status, reason = UNKNOWN, "awaiting_first_run"
            else:
                status, reason = UNKNOWN, "no_run_recorded"
        elif _age(started, now) > stale_after:
            reason = "published_not_executed" if published_recently and published > started else "no_recent_run"
            status = UNHEALTHY
        elif failed and (succeeded is None or failed > succeeded):
            status, reason = UNHEALTHY, "latest_run_failed"
        elif _age(started, now) > warning_after:
            status, reason = WARNING, "run_delayed"
        else:
            status, reason = HEALTHY, ""
        tasks[task] = {
            "status": status,
            "reason": reason,
            "expected_cadence_seconds": interval,
            "warning_after_seconds": warning_after,
            "unhealthy_after_seconds": stale_after,
            "last_published_at": _iso(published),
            "last_started_at": _iso(started),
            "last_succeeded_at": _iso(succeeded),
            "last_failed_at": _iso(failed),
            "last_error_type": report.get("last_error_type", ""),
        }

    status = rollup(t["status"] for t in tasks.values())
    reason = next((t["reason"] for t in tasks.values() if t["status"] == status), "")
    detail = {
        HEALTHY: "Scheduled newsletter tasks are being executed by a worker.",
        WARNING: "A scheduled newsletter task has not run for longer than expected.",
        UNKNOWN: "No scheduled newsletter task run has been recorded yet.",
        UNHEALTHY: {
            "published_not_executed": "Celery Beat is publishing newsletter tasks but no worker is executing them.",
            "latest_run_failed": "The latest run of a scheduled newsletter task failed.",
        }.get(reason, "Scheduled newsletter tasks have stopped running; check Celery Beat and the workers."),
    }[status]
    starts = [_parse(t["last_started_at"]) for t in tasks.values()]
    successes = [_parse(t["last_succeeded_at"]) for t in tasks.values()]
    return _component(
        name, status, reason, detail, source=source, now=now,
        last_success=max((s for s in successes if s), default=None),
        last_attempt=max((s for s in starts if s), default=None),
        cadence=min(t["expected_cadence_seconds"] for t in tasks.values()),
        tasks=tasks,
    )


# ---------------------------------------------------------------------------
# Live probes, translated
# ---------------------------------------------------------------------------


def redis_health(probe, now):
    name, source = "Redis broker", "Live ping of CELERY_BROKER_URL"
    status = {
        LEGACY_HEALTHY: HEALTHY,
        LEGACY_DEGRADED: UNHEALTHY,
        LEGACY_DISABLED: DISABLED,
    }.get(probe.get("status"), UNKNOWN)
    detail = {
        HEALTHY: "The broker answered a ping.",
        UNHEALTHY: "The broker is unreachable from this process.",
        DISABLED: "No Celery broker is configured.",
        UNKNOWN: "The broker was not checked.",
    }[status]
    return _component(
        name, status, probe.get("reason", ""), detail, source=source, now=now,
        last_success=now if status == HEALTHY else None,
    )


def worker_health(probe, now):
    """A ping proves a worker is connected and consuming control messages.
    A worker whose pool is saturated still answers, which is why scheduled
    task execution is judged separately."""
    name, source = "Celery worker", "Live Celery control ping"
    status = {
        LEGACY_HEALTHY: HEALTHY,
        LEGACY_DEGRADED: UNHEALTHY,
        LEGACY_DISABLED: DISABLED,
    }.get(probe.get("status"), UNKNOWN)
    detail = {
        HEALTHY: f"{probe.get('responding') or 0} worker(s) answered a ping.",
        UNHEALTHY: "No Celery worker answered a ping.",
        DISABLED: "No Celery broker is configured.",
        UNKNOWN: "Worker liveness could not be verified.",
    }[status]
    return _component(
        name, status, probe.get("reason", ""), detail, source=source, now=now,
        last_success=now if status == HEALTHY else None,
        responding=probe.get("responding"),
    )


# ---------------------------------------------------------------------------
# Mautic cron and messenger worker
# ---------------------------------------------------------------------------

#: job name (as recorded by ecp-cron-run) -> (label, seconds between runs).
#: Mirrors KT-ecp-mautic's cron template; override with MAUTIC_CRON_MONITORED_JOBS.
DEFAULT_MAUTIC_CRON_JOBS = {
    "segments_update": ("mautic:segments:update", 900),
    "campaigns_update": ("mautic:campaigns:update", 900),
    "campaigns_trigger": ("mautic:campaigns:trigger", 900),
    "broadcasts_send": ("mautic:broadcasts:send", 60),
    "contact_import": ("mautic:import", 60),
}


def mautic_cron_jobs() -> dict:
    configured = getattr(settings, "MAUTIC_CRON_MONITORED_JOBS", None)
    if not isinstance(configured, dict) or not configured:
        return dict(DEFAULT_MAUTIC_CRON_JOBS)
    jobs = {}
    for job, value in configured.items():
        label, interval = DEFAULT_MAUTIC_CRON_JOBS.get(job, (job, None))
        try:
            interval = float(value)
        except (TypeError, ValueError):
            pass
        if interval and interval > 0:
            jobs[job] = (label, interval)
    return jobs or dict(DEFAULT_MAUTIC_CRON_JOBS)


def mautic_cron_thresholds(interval):
    """One missed tick plus margin warns; two missed ticks is unhealthy."""
    return interval + 120, interval * 2 + 300


def _cron_job_status(label, interval, record, now):
    warning_after, unhealthy_after = mautic_cron_thresholds(interval)
    started = _parse(record.get("last_started_at"))
    finished = _parse(record.get("last_finished_at"))
    run_started = _parse(record.get("last_run_started_at"))
    succeeded = _parse(record.get("last_success_at"))
    failed = _parse(record.get("last_failure_at"))
    outcome = record.get("last_outcome")
    report = {
        "command": label,
        "expected_cadence_seconds": interval,
        "warning_after_seconds": warning_after,
        "unhealthy_after_seconds": unhealthy_after,
        "last_started_at": _iso(started),
        "last_finished_at": _iso(finished),
        "last_outcome": outcome,
        "last_exit_code": record.get("last_exit_code"),
        "last_duration_seconds": record.get("last_duration_seconds"),
        "last_success_at": _iso(succeeded),
        "last_failure_at": _iso(failed),
        "last_failure_exit_code": record.get("last_failure_exit_code"),
    }
    if started is None:
        return {**report, "status": UNKNOWN, "reason": "no_run_recorded"}
    since_start = _age(started, now)
    latest_finished = run_started is not None and run_started >= started
    if since_start > unhealthy_after:
        # A run still in progress (e.g. a long import holding its flock, so
        # later ticks never start) is not the same as cron not starting jobs.
        reason = "overdue" if latest_finished else "run_not_finished"
        return {**report, "status": UNHEALTHY, "reason": reason}
    if latest_finished and outcome == "failure":
        return {**report, "status": UNHEALTHY, "reason": "last_run_failed"}
    if succeeded is None:
        if not latest_finished:
            return {**report, "status": UNKNOWN, "reason": "first_run_in_progress"}
        # Only skipped runs so far: another run holds the lock.
        reason = "no_success_recorded"
        return {**report, "status": WARNING if since_start <= warning_after else UNHEALTHY, "reason": reason}
    if _age(succeeded, now) > unhealthy_after:
        # Runs keep starting, but none has completed real work recently:
        # stuck behind a lock, still running, or failing.
        return {**report, "status": UNHEALTHY, "reason": "no_recent_success"}
    if not latest_finished and since_start > warning_after:
        return {**report, "status": WARNING, "reason": "running_long"}
    if since_start > warning_after:
        return {**report, "status": WARNING, "reason": "delayed"}
    if _age(succeeded, now) > warning_after:
        return {**report, "status": WARNING, "reason": "success_delayed"}
    return {**report, "status": HEALTHY, "reason": ""}


_CRON_DETAILS = {
    "overdue": "A Mautic cron job has not started on schedule; Mautic cron may be stopped.",
    "run_not_finished": (
        "A Mautic cron job run started long ago and has not finished: it is stuck or very slow, "
        "or cron stopped while it was running."
    ),
    "last_run_failed": "The latest run of a Mautic cron job exited with an error.",
    "no_recent_success": "A Mautic cron job keeps starting but has not completed successfully recently.",
    "no_success_recorded": "A Mautic cron job has run but has not completed successfully yet.",
    "running_long": "A Mautic cron job run is taking longer than expected.",
    "delayed": "A Mautic cron job is running later than scheduled.",
    "success_delayed": "A Mautic cron job has not completed successfully for longer than expected.",
    "no_run_recorded": "No run of a Mautic cron job has been recorded yet.",
    "first_run_in_progress": "A Mautic cron job's first recorded run is in progress.",
}


_MAUTIC_UNAVAILABLE_DETAILS = {
    "plugin_outdated": "The deployed ECP Marketing Bridge plugin does not report background health yet.",
    "mautic_unavailable": "Mautic could not be reached, so its background evidence is unavailable.",
    "mautic_rejected": "Mautic refused the background health request.",
    "not_checked": "Mautic was not checked.",
}


def _mautic_now(report, fallback):
    """Ages are measured on Mautic's clock, the one that wrote the records."""
    return _parse(report.get("generated_at")) or fallback


def mautic_cron_health(report, now, *, error_reason=""):
    name = "Mautic cron"
    source = "ecp-cron-run records via ECP Marketing Bridge"
    if error_reason == "not_configured":
        return _component(name, DISABLED, "not_configured", "Mautic is not configured.", source=source, now=now)
    if report is None:
        reason = error_reason or "mautic_unavailable"
        return _component(name, UNKNOWN, reason, _MAUTIC_UNAVAILABLE_DETAILS.get(reason, ""), source=source, now=now)
    cron = report.get("cron") if isinstance(report.get("cron"), dict) else {}
    if not cron.get("instrumented"):
        return _component(
            name, UNKNOWN, "not_instrumented",
            "Mautic has no cron run records; the cron wrapper is not deployed or has never run.",
            source=source, now=now,
        )
    mautic_now = _mautic_now(report, now)
    recorded = cron.get("jobs") if isinstance(cron.get("jobs"), dict) else {}
    jobs = {
        job: _cron_job_status(label, interval, recorded.get(job) or {}, mautic_now)
        for job, (label, interval) in mautic_cron_jobs().items()
    }
    status = rollup(j["status"] for j in jobs.values())
    reason = next((j["reason"] for j in jobs.values() if j["status"] == status), "")
    detail = "Mautic cron jobs are running on schedule." if status == HEALTHY else _CRON_DETAILS.get(reason, "")
    starts = [_parse(j["last_started_at"]) for j in jobs.values()]
    successes = [_parse(j["last_success_at"]) for j in jobs.values()]
    return _component(
        name, status, reason, detail, source=source, now=now,
        last_success=max((s for s in successes if s), default=None),
        last_attempt=max((s for s in starts if s), default=None),
        cadence=min(j["expected_cadence_seconds"] for j in jobs.values()),
        mautic_time=_iso(mautic_now),
        jobs=jobs,
    )


def mautic_worker_thresholds():
    warning = _setting_seconds("MAUTIC_WORKER_BACKLOG_WARNING_SECONDS", 300)
    unhealthy = _setting_seconds("MAUTIC_WORKER_BACKLOG_UNHEALTHY_SECONDS", 900)
    return warning, max(warning, unhealthy)


def _transport_status(entry, mautic_now, warning_after, unhealthy_after):
    scheme = entry.get("scheme") if isinstance(entry, dict) else None
    result = {
        "scheme": scheme,
        "queued": entry.get("queued") if isinstance(entry, dict) else None,
        "oldest_queued_at": entry.get("oldest_queued_at") if isinstance(entry, dict) else None,
    }
    if scheme in (None, "sync", "null", "in-memory"):
        return {**result, "status": DISABLED, "reason": "no_queue"}
    if scheme != "doctrine" or not entry.get("inspected"):
        return {**result, "status": UNKNOWN, "reason": "backlog_not_inspectable"}
    oldest = _parse(entry.get("oldest_queued_at"))
    if not entry.get("queued") or oldest is None:
        # An empty queue has nothing waiting on the worker: not a failure.
        return {**result, "status": HEALTHY, "reason": "no_backlog"}
    status = _by_age(_age(oldest, mautic_now), warning_after, unhealthy_after)
    return {**result, "status": status, "reason": "" if status == HEALTHY else "backlog_waiting"}


def mautic_worker_health(report, now, *, error_reason=""):
    """Judged by queue backlog, never by container state: messages waiting
    past the threshold mean no worker is consuming them."""
    name = "Mautic worker"
    source = "Messenger queue backlog via ECP Marketing Bridge"
    if error_reason == "not_configured":
        return _component(name, DISABLED, "not_configured", "Mautic is not configured.", source=source, now=now)
    if report is None:
        reason = error_reason or "mautic_unavailable"
        return _component(name, UNKNOWN, reason, _MAUTIC_UNAVAILABLE_DETAILS.get(reason, ""), source=source, now=now)
    messenger = report.get("messenger") if isinstance(report.get("messenger"), dict) else {}
    configured = messenger.get("transports") if isinstance(messenger.get("transports"), dict) else {}
    warning_after, unhealthy_after = mautic_worker_thresholds()
    mautic_now = _mautic_now(report, now)
    transports = {
        transport: _transport_status(configured.get(transport) or {}, mautic_now, warning_after, unhealthy_after)
        for transport in ("email", "hit")
    }
    failed = messenger.get("failed") if isinstance(messenger.get("failed"), dict) else {}
    failed_count = failed.get("queued") if failed.get("inspected") else None

    status = rollup(t["status"] for t in transports.values())
    reason = next((t["reason"] for t in transports.values() if t["status"] == status), "")
    if status == DISABLED:
        reason = "sync_transports"
        detail = (
            "Email and hit messages are processed synchronously by Mautic, so no worker "
            "queue exists to monitor."
        )
    elif failed_count and status == HEALTHY:
        status, reason = WARNING, "failed_messages"
        detail = "Mautic has messages in its failed transport."
    else:
        detail = {
            HEALTHY: "No Mautic messenger queue has messages waiting past the threshold.",
            WARNING: "Mautic messenger messages are waiting longer than expected.",
            UNHEALTHY: "Mautic messenger messages are not being consumed; the Mautic worker may be stopped.",
            UNKNOWN: "The Mautic messenger queue cannot be inspected.",
        }[status]
    return _component(
        name, status, reason, detail, source=source, now=now,
        warning_after=warning_after, unhealthy_after=unhealthy_after,
        transports=transports, failed_messages=failed_count,
    )


def fetch_mautic_background_report(capabilities=None, client_factory=None):
    """Read Mautic's evidence. Returns (report, error_reason); never raises.

    ``capabilities`` is the bridge capabilities payload when the caller
    already has it: an older plugin without the endpoint is then recognised
    without another request.
    """
    from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError

    if isinstance(capabilities, dict) and capabilities.get("available"):
        if "background_health" not in (capabilities.get("capabilities") or []):
            return None, "plugin_outdated"
    try:
        client = (client_factory or MauticClient)()
    except PermanentMauticError:
        return None, "not_configured"
    try:
        timeout = _setting_seconds("MAUTIC_BACKGROUND_HEALTH_TIMEOUT_SECONDS", 5)
        return client.get_background_health(timeout=timeout), ""
    except PermanentMauticError as exc:
        return None, "plugin_outdated" if "HTTP 404" in str(exc) else "mautic_rejected"
    except TemporaryMauticError:
        return None, "mautic_unavailable"
    except Exception:
        logger.warning("Unexpected error reading Mautic background health", exc_info=True)
        return None, "mautic_unavailable"


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def build_scheduler_monitoring(
    *, redis_probe, worker_probe, scheduled_processing, mautic_report, mautic_error="", now=None
) -> dict:
    now = now or timezone.now()
    beat_evidence, beat_error = None, ""
    if scheduled_processing.get("reason") == "cache_unavailable":
        # The heartbeat read just failed on the same cache; another attempt
        # would only add one more socket timeout to this request.
        beat_error = "cache_unavailable"
    elif background_health_enabled():
        try:
            beat_evidence = _read_beat_evidence()
        except Exception:
            logger.warning("Could not read Celery Beat activity", exc_info=True)
            beat_error = "cache_unavailable"
    components = {
        "celery_beat": beat_health(now, beat_evidence, beat_error),
        "scheduled_tasks": scheduled_execution_health(scheduled_processing, beat_evidence, now),
        "celery_worker": worker_health(worker_probe, now),
        "redis_broker": redis_health(redis_probe, now),
        "mautic_cron": mautic_cron_health(mautic_report, now, error_reason=mautic_error),
        "mautic_worker": mautic_worker_health(mautic_report, now, error_reason=mautic_error),
    }
    return {
        "status": rollup(c["status"] for c in components.values()),
        "observed_at": now.isoformat(),
        "components": components,
    }


def legacy_beat_status(component) -> dict:
    """The B10 Beat result in the vocabulary of the existing ``health`` block."""
    status = {
        HEALTHY: LEGACY_HEALTHY,
        WARNING: LEGACY_DEGRADED,
        UNHEALTHY: LEGACY_STALE,
        DISABLED: LEGACY_DISABLED,
    }.get(component["status"], LEGACY_NOT_VERIFIED)
    return {
        "status": status,
        "reason": component["reason"] or "",
        "detail": component["detail"],
        "last_published_at": component["last_success_at"],
        "last_started_at": component.get("started_at"),
    }


def scheduler_warnings(monitoring, only=None) -> list[str]:
    """Operator warnings for problems, not for missing evidence alone.
    ``only`` limits them to the named components."""
    warnings = []
    for key, component in monitoring["components"].items():
        if only is not None and key not in only:
            continue
        if component["status"] in (WARNING, UNHEALTHY) and component["detail"]:
            warnings.append(f"{component['component']}: {component['detail']}")
    return warnings


__all__ = [
    "DISABLED",
    "EXIT_CODES",
    "HEALTHY",
    "UNHEALTHY",
    "UNKNOWN",
    "WARNING",
    "beat_health",
    "build_scheduler_monitoring",
    "fetch_mautic_background_report",
    "legacy_beat_status",
    "mautic_cron_health",
    "mautic_worker_health",
    "on_beat_init",
    "record_beat_publish",
    "rollup",
    "scheduled_execution_health",
    "scheduler_warnings",
]
