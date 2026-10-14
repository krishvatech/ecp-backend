"""B10 scheduler monitoring: Celery Beat, scheduled task execution, workers,
Redis, Mautic cron and the Mautic worker, each judged on its own evidence.

Evidence goes to an isolated local-memory cache, Mautic is mocked, and the
Redis/worker probes are patched, so nothing here touches the shared Redis, the
Celery broker or a real Mautic. Clocks are fixed instants, never sleeps.
"""

import io
import json
import threading
from contextlib import contextmanager, redirect_stdout
from datetime import datetime, timedelta, timezone as dt_timezone
from unittest.mock import MagicMock, patch

from celery.app.task import Task
from celery.beat import ScheduleEntry, Scheduler, SchedulingError, Service
from celery.schedules import crontab
from celery.signals import after_task_publish, beat_init
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.management import call_command
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter import mautic_diagnostics_services as diagnostics
from newsletter import tasks as newsletter_tasks  # noqa: F401 - registers the periodic tasks with Celery
from newsletter import scheduler_monitoring as monitoring
from newsletter.mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from newsletter.scheduler_monitoring import (
    DISABLED,
    HEALTHY,
    UNHEALTHY,
    UNKNOWN,
    WARNING,
)
from newsletter.task_heartbeats import PERIODIC_TASKS, periodic_task_health
from newsletter.tests.marketing_actors import grant_marketing_access

User = get_user_model()

NOW = datetime(2026, 10, 14, 5, 0, 0, tzinfo=dt_timezone.utc)
SYNC_TASK = "newsletter.dispatch_due_sync_events"

BEAT = {
    f"entry-{task}": {"task": task, "schedule": timedelta(minutes=1)}
    for task in PERIODIC_TASKS
}
BEAT["daily"] = {"task": "friends.tasks.expire_stale_friend_requests", "schedule": crontab(minute="0", hour="3")}
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                      "LOCATION": "scheduler-monitoring-tests"}}
MONITORING = {
    "CACHES": LOCMEM,
    "NEWSLETTER_BACKGROUND_HEALTH_ENABLED": True,
    "CELERY_BEAT_SCHEDULE": BEAT,
    "CELERY_BROKER_URL": "redis://:broker-secret@redis.internal.example:6379/0",
    "CELERY_TASK_TIME_LIMIT": 300,
    "MAUTIC_SYNC_ENABLED": True,
    "SCHEDULER_MONITOR_BEAT_WARNING_SECONDS": None,
    "SCHEDULER_MONITOR_BEAT_UNHEALTHY_SECONDS": None,
    "SCHEDULER_MONITOR_STARTUP_GRACE_SECONDS": None,
}
# Derived for a 60 s schedule: warn > 180 s, unhealthy > 600 s, grace 120 s.
BEAT_WARNING, BEAT_UNHEALTHY, GRACE = 180, 600, 120


def ago(seconds, now=NOW):
    return (now - timedelta(seconds=seconds)).isoformat()


def beat_evidence(*, started=None, published=None, tasks=None):
    keys = {}
    if started is not None:
        keys["newsletter:scheduler:beat:started"] = ago(started)
    if published is not None:
        keys["newsletter:scheduler:beat:published"] = ago(published)
    for task, seconds in (tasks or {}).items():
        keys[f"newsletter:scheduler:beat:published:{task}"] = ago(seconds)
    cache.set_many(keys, None)


def heartbeats(seconds_ago, *, failed_after=False):
    for task in PERIODIC_TASKS:
        cache.set(f"newsletter:task-heartbeat:{task}:started", ago(seconds_ago), 3600)
        cache.set(f"newsletter:task-heartbeat:{task}:succeeded", ago(seconds_ago), 3600)
        if failed_after:
            cache.set(f"newsletter:task-heartbeat:{task}:failed",
                      {"at": ago(max(seconds_ago - 1, 0)), "error_type": "RuntimeError"}, 3600)


def evaluate(**overrides):
    kwargs = dict(
        redis_probe={"status": "Healthy", "reason": ""},
        worker_probe={"status": "Healthy", "reason": "", "responding": 1},
        mautic_report=None,
        mautic_error="not_configured",
        now=NOW,
    )
    kwargs.update(overrides)
    if "scheduled_processing" not in kwargs:
        kwargs["scheduled_processing"] = periodic_task_health(now=NOW)
    return monitoring.build_scheduler_monitoring(**kwargs)


def published_in_broker(task, *args, **kwargs):
    """Stand-in for Task.apply_async: what Celery does once the broker has
    accepted the message."""
    after_task_publish.send(sender=task.name, headers={"task": task.name})


@contextmanager
def as_beat_scheduler():
    token = monitoring._scheduler_publishing.set(True)
    try:
        yield
    finally:
        monitoring._scheduler_publishing.reset(token)


@override_settings(**MONITORING)
class BeatEvidenceRecordingTests(SimpleTestCase):
    def setUp(self):
        cache.clear()
        monitoring._beat_writer.update(last_global_write=None, suspended_until=0.0)
        self.addCleanup(after_task_publish.disconnect, dispatch_uid="newsletter-scheduler-beat-publish")
        publish = patch.object(Task, "apply_async", autospec=True, side_effect=published_in_broker)
        self.task_publish = publish.start()
        self.addCleanup(publish.stop)

    def started_beat(self):
        """A real Beat service, announced the way Service.start() does."""
        from ecp_backend.celery import app  # also registers the beat_init receiver

        service = Service(app=app, scheduler_cls=Scheduler)
        beat_init.send(sender=service)
        return service

    def scheduler_publish(self, service, task=SYNC_TASK):
        from ecp_backend.celery import app

        entry = ScheduleEntry(name=f"b10-{task}", task=task, schedule=timedelta(minutes=1), app=app)
        service.scheduler.apply_async(entry, producer=MagicMock(), advance=False)

    def test_celery_app_records_beat_start_through_beat_init(self):
        with patch("newsletter.scheduler_monitoring.on_beat_init") as on_init:
            import ecp_backend.celery  # noqa: F401 - registers the receiver

            beat_init.send(sender=MagicMock())
        on_init.assert_called_once()

    def test_publishes_by_beats_scheduler_are_recorded(self):
        service = self.started_beat()
        self.assertIsNotNone(cache.get("newsletter:scheduler:beat:started"))
        self.assertIsNone(cache.get("newsletter:scheduler:beat:published"))

        self.scheduler_publish(service)
        self.assertIsNotNone(cache.get("newsletter:scheduler:beat:published"))
        self.assertIsNotNone(cache.get(f"newsletter:scheduler:beat:published:{SYNC_TASK}"))
        # Persisted without expiry: a long outage must still read as an outage.
        key = cache.make_key("newsletter:scheduler:beat:published")
        self.assertIn(key, cache._expire_info)
        self.assertIsNone(cache._expire_info[key])

    def test_other_publishes_in_the_beat_process_never_count(self):
        from ecp_backend.celery import app

        self.started_beat()
        # A task queued by a signal handler, or by a worker hosting a
        # threaded embedded Beat: same process, receiver connected.
        app.tasks[SYNC_TASK].apply_async()
        after_task_publish.send(sender=SYNC_TASK, headers={"task": SYNC_TASK})

        self.assertIsNone(cache.get("newsletter:scheduler:beat:published"))
        self.assertIsNone(cache.get(f"newsletter:scheduler:beat:published:{SYNC_TASK}"))

    def test_another_thread_publishing_while_beat_publishes_does_not_count(self):
        service = self.started_beat()
        other = threading.Thread(
            target=after_task_publish.send, kwargs={"sender": SYNC_TASK, "headers": {"task": SYNC_TASK}},
        )

        def beat_publish_with_concurrent_thread(task, *args, **kwargs):
            other.start()
            other.join()
            published_in_broker(task)

        self.task_publish.side_effect = beat_publish_with_concurrent_thread
        self.scheduler_publish(service, task="newsletter.reconcile_native_scheduled_campaigns")

        self.assertIsNotNone(cache.get(
            "newsletter:scheduler:beat:published:newsletter.reconcile_native_scheduled_campaigns"
        ))
        self.assertIsNone(cache.get(f"newsletter:scheduler:beat:published:{SYNC_TASK}"))

    def test_failed_beat_publish_is_not_recorded(self):
        service = self.started_beat()
        self.task_publish.side_effect = ConnectionError("broker down")
        with self.assertRaises(SchedulingError):
            self.scheduler_publish(service)
        self.assertIsNone(cache.get("newsletter:scheduler:beat:published"))

    def test_without_a_scheduler_nothing_is_recorded(self):
        with self.assertLogs("newsletter.scheduler_monitoring", "WARNING"):
            monitoring.on_beat_init(sender=None)
        self.assertIsNone(cache.get("newsletter:scheduler:beat:started"))
        after_task_publish.send(sender=SYNC_TASK, headers={"task": SYNC_TASK})
        self.assertIsNone(cache.get("newsletter:scheduler:beat:published"))

    def test_repeated_beat_init_wraps_the_scheduler_once(self):
        service = self.started_beat()
        wrapped = service.scheduler.apply_async
        beat_init.send(sender=service)
        self.assertIs(service.scheduler.apply_async, wrapped)

    def test_global_publish_record_is_throttled(self):
        with patch.object(monitoring.cache, "set_many") as set_many, as_beat_scheduler():
            monitoring.record_beat_publish(sender="events.tasks.other")
            monitoring.record_beat_publish(sender="events.tasks.other")
            monitoring.record_beat_publish(sender="events.tasks.other")
        self.assertEqual(set_many.call_count, 1)

    def test_cache_failure_never_raises_and_backs_off(self):
        with patch.object(monitoring.cache, "set_many", side_effect=ConnectionError("down")) as set_many, \
                self.assertLogs("newsletter.scheduler_monitoring", "WARNING"), as_beat_scheduler():
            monitoring.record_beat_publish(sender=SYNC_TASK)
            monitoring.record_beat_publish(sender=SYNC_TASK)
        self.assertEqual(set_many.call_count, 1)

    @override_settings(NEWSLETTER_BACKGROUND_HEALTH_ENABLED=False)
    def test_kill_switch_writes_nothing(self):
        with patch.object(monitoring.cache, "set_many") as set_many:
            service = self.started_beat()
            self.scheduler_publish(service)
        set_many.assert_not_called()


@override_settings(**MONITORING)
class BeatHealthTests(SimpleTestCase):
    def setUp(self):
        cache.clear()

    def beat(self, **evidence):
        beat_evidence(**evidence)
        return evaluate()["components"]["celery_beat"]

    def test_cadence_comes_from_the_shortest_schedule_entry(self):
        self.assertEqual(monitoring.beat_cadence_seconds(), 60)
        with override_settings(CELERY_BEAT_SCHEDULE={
            "a": {"task": "x", "schedule": crontab(minute="*/5")},
            "b": {"task": "y", "schedule": crontab(minute="0", hour="3")},
        }):
            self.assertEqual(monitoring.beat_cadence_seconds(), 300)

    def test_fresh_publish_is_healthy(self):
        component = self.beat(started=3600, published=30)
        self.assertEqual(component["status"], HEALTHY)
        self.assertEqual(component["expected_cadence_seconds"], 60)
        self.assertEqual(component["seconds_since_last_activity"], 30)

    def test_delayed_then_overdue_publish(self):
        self.assertEqual(self.beat(started=3600, published=BEAT_WARNING + 1)["status"], WARNING)
        cache.clear()
        component = self.beat(started=3600, published=BEAT_UNHEALTHY + 1)
        self.assertEqual((component["status"], component["reason"]), (UNHEALTHY, "publish_overdue"))

    def test_no_evidence_is_unknown_not_healthy(self):
        component = self.beat()
        self.assertEqual((component["status"], component["reason"]), (UNKNOWN, "no_evidence"))

    def test_startup_grace_then_no_publish_since_start(self):
        self.assertEqual(self.beat(started=GRACE - 10)["reason"], "starting")
        self.assertEqual(self.beat(started=GRACE - 10)["status"], UNKNOWN)
        cache.clear()
        self.assertEqual(self.beat(started=GRACE + 10)["status"], WARNING)
        cache.clear()
        component = self.beat(started=BEAT_UNHEALTHY + 10, published=BEAT_UNHEALTHY + 20)
        self.assertEqual((component["status"], component["reason"]), (UNHEALTHY, "no_publish_since_start"))

    def test_restart_with_an_old_publish_gets_the_grace_period(self):
        self.assertEqual(self.beat(started=20, published=7200)["status"], UNKNOWN)

    def test_malformed_values_are_no_evidence(self):
        cache.set_many({
            "newsletter:scheduler:beat:started": "yesterday",
            "newsletter:scheduler:beat:published": {"at": 12},
        }, None)
        self.assertEqual(evaluate()["components"]["celery_beat"]["reason"], "no_evidence")

    @override_settings(SCHEDULER_MONITOR_BEAT_WARNING_SECONDS="30",
                       SCHEDULER_MONITOR_BEAT_UNHEALTHY_SECONDS="45")
    def test_thresholds_are_configurable(self):
        self.assertEqual(self.beat(started=3600, published=40)["status"], WARNING)
        cache.clear()
        self.assertEqual(self.beat(started=3600, published=50)["status"], UNHEALTHY)

    def test_unreadable_store_is_unknown(self):
        with patch.object(monitoring.cache, "get_many", side_effect=ConnectionError("down")) as get_many, \
                self.assertLogs("newsletter.task_heartbeats", "WARNING"):
            component = evaluate()["components"]["celery_beat"]
        # One failed read per request: the Beat read is skipped after it.
        self.assertEqual(get_many.call_count, 1)
        self.assertEqual((component["status"], component["reason"]), (UNKNOWN, "cache_unavailable"))

    def test_cache_already_down_is_not_read_twice(self):
        with patch.object(monitoring.cache, "get_many") as get_many:
            component = evaluate(scheduled_processing={
                "status": "Not Verified", "reason": "cache_unavailable", "tasks": {},
            })["components"]["celery_beat"]
        get_many.assert_not_called()
        self.assertEqual((component["status"], component["reason"]), (UNKNOWN, "cache_unavailable"))

    @override_settings(CELERY_BEAT_SCHEDULE={})
    def test_nothing_scheduled_is_disabled(self):
        self.assertEqual(evaluate()["components"]["celery_beat"]["status"], DISABLED)


@override_settings(**MONITORING)
class SchedulerVersusWorkerTests(SimpleTestCase):
    """Beat, task execution, worker and broker never vouch for each other."""

    def setUp(self):
        cache.clear()

    def test_fresh_worker_runs_and_ping_do_not_make_beat_healthy(self):
        heartbeats(10)
        components = evaluate()["components"]
        self.assertEqual(components["scheduled_tasks"]["status"], HEALTHY)
        self.assertEqual(components["celery_worker"]["status"], HEALTHY)
        self.assertEqual(components["celery_beat"]["status"], UNKNOWN)

    def test_beat_publishing_but_worker_blocked_is_not_reported_as_executed(self):
        # Worker still answers pings (a saturated pool does), Beat keeps
        # publishing, but nothing has started for 10 minutes.
        heartbeats(600)
        beat_evidence(started=3600, published=20, tasks={task: 20 for task in PERIODIC_TASKS})
        components = evaluate()["components"]

        self.assertEqual(components["celery_beat"]["status"], HEALTHY)
        self.assertEqual(components["celery_worker"]["status"], HEALTHY)
        tasks = components["scheduled_tasks"]
        self.assertEqual((tasks["status"], tasks["reason"]), (UNHEALTHY, "published_not_executed"))
        self.assertIn("no worker is executing them", tasks["detail"])

    def test_published_but_never_started_is_unhealthy(self):
        beat_evidence(started=3600, published=20, tasks={SYNC_TASK: 20})
        tasks = evaluate()["components"]["scheduled_tasks"]["tasks"]
        self.assertEqual(tasks[SYNC_TASK]["reason"], "published_not_executed")

    def test_first_publish_after_a_fresh_beat_start_is_not_yet_a_failure(self):
        beat_evidence(started=70, published=5, tasks={SYNC_TASK: 5})
        task = evaluate()["components"]["scheduled_tasks"]["tasks"][SYNC_TASK]
        self.assertEqual((task["status"], task["reason"]), (UNKNOWN, "awaiting_first_run"))

    def test_beat_stopped_shows_as_no_recent_run_not_worker_blocked(self):
        heartbeats(900)
        beat_evidence(started=7200, published=900, tasks={task: 900 for task in PERIODIC_TASKS})
        components = evaluate()["components"]
        self.assertEqual(components["celery_beat"]["status"], UNHEALTHY)
        self.assertEqual(components["scheduled_tasks"]["reason"], "no_recent_run")

    def test_latest_failed_run_and_delayed_run(self):
        heartbeats(10, failed_after=True)
        self.assertEqual(evaluate()["components"]["scheduled_tasks"]["reason"], "latest_run_failed")
        cache.clear()
        heartbeats(200)
        self.assertEqual(evaluate()["components"]["scheduled_tasks"]["status"], WARNING)

    def test_worker_down_is_independent_of_beat(self):
        beat_evidence(started=3600, published=10)
        components = evaluate(worker_probe={"status": "Degraded", "reason": "no_worker_replied", "responding": 0})["components"]
        self.assertEqual(components["celery_worker"]["status"], UNHEALTHY)
        self.assertIsNone(components["celery_worker"]["seconds_since_last_activity"])
        self.assertEqual(components["celery_beat"]["status"], HEALTHY)

    def test_unreachable_broker_and_unverified_worker(self):
        components = evaluate(
            redis_probe={"status": "Degraded", "reason": "unreachable"},
            worker_probe={"status": "Not Verified", "reason": "broker_unreachable", "responding": None},
        )["components"]
        self.assertEqual(components["redis_broker"]["status"], UNHEALTHY)
        self.assertEqual((components["celery_worker"]["status"], components["celery_worker"]["reason"]),
                         (UNKNOWN, "broker_unreachable"))

    @override_settings(NEWSLETTER_BACKGROUND_HEALTH_ENABLED=False)
    def test_kill_switch_reads_nothing_and_claims_nothing(self):
        with patch.object(monitoring.cache, "get_many") as get_many:
            components = evaluate(scheduled_processing=periodic_task_health(now=NOW))["components"]
        get_many.assert_not_called()
        self.assertEqual(components["celery_beat"]["reason"], "monitoring_disabled")
        self.assertEqual(components["scheduled_tasks"]["status"], UNKNOWN)


def cron_report(jobs, *, generated_at=NOW, instrumented=True, messenger=None):
    return {
        "generated_at": generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cron": {"instrumented": instrumented, "jobs": jobs},
        "messenger": messenger or {
            "transports": {
                "email": {"scheme": "sync", "queued": None, "oldest_queued_at": None, "inspected": False},
                "hit": {"scheme": "sync", "queued": None, "oldest_queued_at": None, "inspected": False},
            },
            "failed": {"scheme": None, "queued": None, "oldest_queued_at": None, "inspected": False},
        },
    }


def z(seconds, now=NOW):
    return (now - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def job(started, *, outcome="success", duration=2, success=None, failure=None, finished=True,
        exit_code=None, now=NOW):
    def z(seconds):
        return (now - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

    record = {"last_started_at": z(started)}
    if finished:
        record.update(
            last_finished_at=z(started - duration),
            last_run_started_at=z(started),
            last_outcome=outcome,
            last_exit_code=exit_code if exit_code is not None else (0 if outcome != "failure" else 1),
            last_duration_seconds=duration,
        )
    if outcome == "success" and finished:
        record["last_success_at"] = z(started - duration)
    if success is not None:
        record["last_success_at"] = z(success)
    if failure is not None:
        record["last_failure_at"] = z(failure)
        record["last_failure_exit_code"] = 1
    return record


def healthy_jobs(now=NOW, **overrides):
    jobs = {
        "segments_update": job(300, now=now),
        "campaigns_update": job(600, now=now),
        "campaigns_trigger": job(120, now=now),
        "broadcasts_send": job(30, now=now),
        "contact_import": job(30, now=now),
    }
    jobs.update(overrides)
    return jobs


class MauticCronHealthTests(SimpleTestCase):
    def cron(self, report, now=NOW, **kwargs):
        return monitoring.mautic_cron_health(report, now, **kwargs)

    def test_all_jobs_on_schedule_is_healthy(self):
        component = self.cron(cron_report(healthy_jobs()))
        self.assertEqual(component["status"], HEALTHY)
        self.assertEqual(set(component["jobs"]), set(monitoring.DEFAULT_MAUTIC_CRON_JOBS))
        self.assertEqual(component["jobs"]["broadcasts_send"]["command"], "mautic:broadcasts:send")

    def test_cron_stopped_is_overdue(self):
        # Nothing has started for 40 minutes: past 2 x 900 s + 300 s for the
        # 15-minute jobs and far past the 1-minute ones.
        stopped = {name: job(2400) for name in monitoring.DEFAULT_MAUTIC_CRON_JOBS}
        component = self.cron(cron_report(stopped))
        self.assertEqual((component["status"], component["reason"]), (UNHEALTHY, "overdue"))
        self.assertIn("Mautic cron may be stopped", component["detail"])

    def test_one_minute_job_late_warns_before_it_is_unhealthy(self):
        self.assertEqual(self.cron(cron_report(healthy_jobs(broadcasts_send=job(200))))["status"], WARNING)
        self.assertEqual(self.cron(cron_report(healthy_jobs(broadcasts_send=job(500))))["status"], UNHEALTHY)

    def test_failed_command_is_recorded_as_failure(self):
        component = self.cron(cron_report(healthy_jobs(
            campaigns_trigger=job(60, outcome="failure", success=960, failure=58, exit_code=255),
        )))
        trigger = component["jobs"]["campaigns_trigger"]
        self.assertEqual((component["status"], component["reason"]), (UNHEALTHY, "last_run_failed"))
        self.assertEqual(trigger["last_exit_code"], 255)
        self.assertEqual(trigger["last_failure_at"], (NOW - timedelta(seconds=58)).isoformat())

    def test_success_after_a_failure_recovers(self):
        component = self.cron(cron_report(healthy_jobs(campaigns_trigger=job(60, failure=960))))
        self.assertEqual(component["status"], HEALTHY)

    def test_lock_skip_with_recent_success_is_healthy(self):
        component = self.cron(cron_report(healthy_jobs(broadcasts_send=job(20, outcome="skipped", success=80))))
        self.assertEqual(component["status"], HEALTHY)

    def test_runs_that_only_skip_for_too_long_are_unhealthy(self):
        component = self.cron(cron_report(healthy_jobs(contact_import=job(20, outcome="skipped", success=900))))
        self.assertEqual((component["status"], component["reason"]), (UNHEALTHY, "no_recent_success"))

    def test_run_in_progress_and_long_running(self):
        running = job(30, finished=False, success=900 + 60)
        running["last_run_started_at"] = z(930)
        component = self.cron(cron_report(healthy_jobs(segments_update=running)))
        self.assertEqual(component["status"], HEALTHY)

        long_run = job(1100, finished=False, success=1200)
        long_run["last_run_started_at"] = z(2000)
        component = self.cron(cron_report(healthy_jobs(segments_update=long_run)))
        self.assertEqual((component["status"], component["reason"]), (WARNING, "running_long"))

    def test_run_that_never_finishes_is_not_called_a_stopped_cron(self):
        # A long import holds its flock, so later ticks start nothing new.
        stuck = job(900, finished=False, success=960)
        stuck["last_run_started_at"] = z(960)
        component = self.cron(cron_report(healthy_jobs(contact_import=stuck)))
        self.assertEqual((component["status"], component["reason"]), (UNHEALTHY, "run_not_finished"))
        self.assertIn("has not finished", component["detail"])

    def test_first_run_in_progress_is_unknown_not_healthy(self):
        component = self.cron(cron_report(healthy_jobs(segments_update=job(10, finished=False))))
        self.assertEqual((component["status"], component["reason"]), (UNKNOWN, "first_run_in_progress"))

    def test_missing_job_record_is_unknown(self):
        jobs = healthy_jobs()
        del jobs["contact_import"]
        component = self.cron(cron_report(jobs))
        self.assertEqual(component["status"], UNKNOWN)
        self.assertEqual(component["jobs"]["contact_import"]["reason"], "no_run_recorded")

    def test_ages_use_the_mautic_clock(self):
        # ECP's clock is an hour ahead of Mautic's; the records are fresh on Mautic's.
        report = cron_report(healthy_jobs(), generated_at=NOW)
        component = self.cron(report, now=NOW + timedelta(hours=1))
        self.assertEqual(component["status"], HEALTHY)

    def test_not_instrumented_and_unavailable_states(self):
        self.assertEqual(self.cron(cron_report({}, instrumented=False))["reason"], "not_instrumented")
        self.assertEqual(self.cron(None, error_reason="plugin_outdated")["status"], UNKNOWN)
        self.assertEqual(self.cron(None, error_reason="mautic_unavailable")["reason"], "mautic_unavailable")
        self.assertEqual(self.cron(None, error_reason="not_configured")["status"], DISABLED)

    def test_malformed_report_is_unknown_not_an_error(self):
        component = self.cron({"generated_at": "nonsense", "cron": {"instrumented": True, "jobs": {
            "broadcasts_send": {"last_started_at": 42, "last_outcome": ["x"]},
        }}, "messenger": {}})
        self.assertEqual(component["status"], UNKNOWN)

    @override_settings(MAUTIC_CRON_MONITORED_JOBS={"broadcasts_send": 120})
    def test_monitored_jobs_are_configurable(self):
        component = self.cron(cron_report({"broadcasts_send": job(200)}))
        self.assertEqual(list(component["jobs"]), ["broadcasts_send"])
        self.assertEqual(component["status"], HEALTHY)


def messenger(email=None, hit=None, failed=None):
    sync = {"scheme": "sync", "queued": None, "oldest_queued_at": None, "inspected": False}
    return {
        "transports": {"email": email or sync, "hit": hit or sync},
        "failed": failed or {"scheme": None, "queued": None, "oldest_queued_at": None, "inspected": False},
    }


def doctrine(queued, oldest_seconds=None):
    return {"scheme": "doctrine", "queued": queued, "inspected": True,
            "oldest_queued_at": z(oldest_seconds) if oldest_seconds is not None else None}


class MauticWorkerHealthTests(SimpleTestCase):
    def worker(self, report):
        return monitoring.mautic_worker_health(report, NOW)

    def test_sync_transports_need_no_worker(self):
        component = self.worker(cron_report({}))
        self.assertEqual((component["status"], component["reason"]), (DISABLED, "sync_transports"))

    def test_empty_queue_is_not_a_failure(self):
        component = self.worker(cron_report({}, messenger=messenger(email=doctrine(0))))
        self.assertEqual((component["status"], component["reason"]), (HEALTHY, "no_backlog"))

    def test_old_backlog_means_nothing_consumes_it(self):
        self.assertEqual(self.worker(cron_report({}, messenger=messenger(email=doctrine(5, 60))))["status"], HEALTHY)
        self.assertEqual(self.worker(cron_report({}, messenger=messenger(email=doctrine(5, 400))))["status"], WARNING)
        component = self.worker(cron_report({}, messenger=messenger(email=doctrine(5, 1000))))
        self.assertEqual((component["status"], component["reason"]), (UNHEALTHY, "backlog_waiting"))

    def test_uninspectable_transport_is_unknown(self):
        redis_transport = {"scheme": "redis", "queued": None, "oldest_queued_at": None, "inspected": False}
        self.assertEqual(self.worker(cron_report({}, messenger=messenger(hit=redis_transport)))["status"], UNKNOWN)

    def test_failed_messages_warn(self):
        component = self.worker(cron_report({}, messenger=messenger(
            email=doctrine(0), failed={"scheme": "doctrine", "queued": 2, "oldest_queued_at": z(10), "inspected": True},
        )))
        self.assertEqual((component["status"], component["failed_messages"]), (WARNING, 2))

    def test_worker_problem_is_not_confused_with_cron(self):
        report = cron_report(healthy_jobs(), messenger=messenger(email=doctrine(9, 3600)))
        self.assertEqual(monitoring.mautic_cron_health(report, NOW)["status"], HEALTHY)
        self.assertEqual(self.worker(report)["status"], UNHEALTHY)


class RollupTests(SimpleTestCase):
    def test_worst_status_wins_and_disabled_is_ignored(self):
        self.assertEqual(monitoring.rollup([HEALTHY, DISABLED]), HEALTHY)
        self.assertEqual(monitoring.rollup([HEALTHY, UNKNOWN]), UNKNOWN)
        self.assertEqual(monitoring.rollup([UNKNOWN, WARNING]), WARNING)
        self.assertEqual(monitoring.rollup([WARNING, UNHEALTHY, HEALTHY]), UNHEALTHY)
        self.assertEqual(monitoring.rollup([DISABLED]), DISABLED)

    def test_exit_codes(self):
        self.assertEqual(monitoring.EXIT_CODES, {HEALTHY: 0, DISABLED: 0, WARNING: 1, UNHEALTHY: 2, UNKNOWN: 3})


class MauticBackgroundFetchTests(SimpleTestCase):
    def test_outdated_plugin_is_recognised_without_a_request(self):
        factory = MagicMock()
        report, error = monitoring.fetch_mautic_background_report(
            {"available": True, "capabilities": ["segment_counts"]}, client_factory=factory,
        )
        self.assertEqual((report, error), (None, "plugin_outdated"))
        factory.assert_not_called()

    def test_errors_map_to_reasons_and_never_raise(self):
        for exc, reason in (
            (TemporaryMauticError("timeout"), "mautic_unavailable"),
            (PermanentMauticError("Mautic API request failed (HTTP 404)"), "plugin_outdated"),
            (PermanentMauticError("Mautic API request failed (HTTP 403)"), "mautic_rejected"),
        ):
            factory = MagicMock()
            factory.return_value.get_background_health.side_effect = exc
            self.assertEqual(monitoring.fetch_mautic_background_report(client_factory=factory), (None, reason))

    @override_settings(MAUTIC_BACKGROUND_HEALTH_TIMEOUT_SECONDS=2.5)
    def test_uses_the_short_timeout(self):
        factory = MagicMock()
        factory.return_value.get_background_health.return_value = {"cron": {}, "messenger": {}}
        monitoring.fetch_mautic_background_report(client_factory=factory)
        factory.return_value.get_background_health.assert_called_once_with(timeout=2.5)


@override_settings(
    MAUTIC_BASE_URL="https://mautic.example.test",
    MAUTIC_USERNAME="api-user",
    MAUTIC_PASSWORD="super-secret",
    MAUTIC_REQUEST_TIMEOUT=15,
)
class MauticClientBackgroundHealthTests(SimpleTestCase):
    def client_with(self, payload, status=200):
        session = MagicMock()
        response = MagicMock(status_code=status)
        response.json.return_value = payload
        session.request.return_value = response
        return MauticClient(session=session), session

    def test_get_uses_the_override_timeout_and_validates_the_shape(self):
        client, session = self.client_with({"generated_at": "x", "cron": {}, "messenger": {}})
        self.assertIn("cron", client.get_background_health(timeout=3))
        args, kwargs = session.request.call_args
        self.assertEqual(args, ("GET", "https://mautic.example.test/api/ecp/background-health"))
        self.assertEqual(kwargs["timeout"], 3)

    def test_default_timeout_is_unchanged_for_other_calls(self):
        client, session = self.client_with({"total": 0, "contacts": {}})
        client.health_check()
        self.assertEqual(session.request.call_args.kwargs["timeout"], 15.0)

    def test_invalid_shape_is_temporary(self):
        client, _ = self.client_with({"cron": []})
        with self.assertRaises(TemporaryMauticError):
            client.get_background_health()


CAPABILITIES = {"capabilities": ["segment_counts", "background_health"], "plugin": "EcpMarketingBridgeBundle"}


@override_settings(
    **MONITORING,
    MAUTIC_BASE_URL="https://mautic.example.test",
    MAUTIC_USERNAME="api-user",
    MAUTIC_PASSWORD="super-secret",
    MAUTIC_WEBHOOK_SECRET="webhook-secret",
)
class DiagnosticsApiSchedulerMonitoringTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.admin = User.objects.create_user(
            username="b10-admin", email="b10-admin@example.test", password="pw",
            is_staff=True, is_superuser=True,
        )
        grant_marketing_access(self.admin)
        self.url = reverse("newsletter-admin-mautic-diagnostics")

    def get(self, *, report=None, background_error=None, capabilities=CAPABILITIES, bridge_error=None, user=None):
        self.client.force_authenticate(user or self.admin)
        with patch.object(diagnostics, "MauticClient") as client_cls, \
                patch.object(diagnostics, "_ping_workers", return_value=[{"w1": {"ok": "pong"}}]), \
                patch("redis.Redis.from_url"), \
                patch("celery.app.task.Task.apply_async") as apply_async, \
                patch("celery.app.base.Celery.send_task") as send_task:
            mautic = client_cls.return_value
            mautic.health_check.return_value = True
            if bridge_error:
                mautic.get_marketing_bridge_capabilities.side_effect = bridge_error
            else:
                mautic.get_marketing_bridge_capabilities.return_value = capabilities
            mautic.get_campaign_builder_capabilities.return_value = {
                "actions": [], "conditions": [], "decisions": [], "connectionRestrictions": {},
            }
            if background_error:
                mautic.get_background_health.side_effect = background_error
            else:
                now = datetime.now(dt_timezone.utc).replace(microsecond=0)
                mautic.get_background_health.return_value = report or cron_report(healthy_jobs(now), generated_at=now)
            response = self.client.get(self.url)
            self.background_calls = mautic.get_background_health.call_count
            self.published = apply_async.call_count + send_task.call_count
        return response

    def test_scheduler_monitoring_is_added_and_existing_contract_kept(self):
        response = self.get()
        self.assertEqual(response.status_code, 200)
        for key in ("connection", "api", "bridges", "webhook", "sync", "background_processing",
                    "native_broadcasts", "broadcast_sends", "health", "identity", "diagnostics"):
            self.assertIn(key, response.data)
        self.assertEqual(set(response.data["health"]), {
            "redis", "celery_worker", "celery_beat", "scheduled_processing",
            "ecp_scheduled_broadcasts", "send_now_outcomes", "native_reconciliation",
        })
        components = response.data["scheduler_monitoring"]["components"]
        self.assertEqual(set(components), {
            "celery_beat", "scheduled_tasks", "celery_worker", "redis_broker", "mautic_cron", "mautic_worker",
        })
        for component in components.values():
            for field in ("component", "status", "reason", "detail", "last_success_at", "last_attempt_at",
                          "expected_cadence_seconds", "seconds_since_last_activity", "evidence_source",
                          "observed_at"):
                self.assertIn(field, component)
        self.assertEqual(components["mautic_cron"]["status"], HEALTHY)
        self.assertEqual(components["mautic_worker"]["status"], DISABLED)
        self.assertEqual(self.background_calls, 1)

    def test_beat_evidence_flows_into_the_legacy_health_block(self):
        cache.set("newsletter:scheduler:beat:started", datetime.now(dt_timezone.utc).isoformat(), None)
        cache.set("newsletter:scheduler:beat:published", datetime.now(dt_timezone.utc).isoformat(), None)
        data = self.get().data
        self.assertEqual(data["scheduler_monitoring"]["components"]["celery_beat"]["status"], HEALTHY)
        self.assertEqual(data["health"]["celery_beat"]["status"], "Healthy")

        cache.set("newsletter:scheduler:beat:published",
                  (datetime.now(dt_timezone.utc) - timedelta(hours=1)).isoformat(), None)
        cache.set("newsletter:scheduler:beat:started",
                  (datetime.now(dt_timezone.utc) - timedelta(hours=2)).isoformat(), None)
        data = self.get().data
        self.assertEqual(data["health"]["celery_beat"]["status"], "Stale")
        self.assertIn("Celery Beat: Celery Beat has stopped publishing scheduled tasks.",
                      data["diagnostics"]["warnings"])

    def test_cron_failure_reaches_operator_warnings(self):
        now = datetime.now(dt_timezone.utc).replace(microsecond=0)
        report = cron_report(
            healthy_jobs(now, campaigns_trigger=job(60, outcome="failure", success=960, failure=58, now=now)),
            generated_at=now,
        )
        data = self.get(report=report).data
        self.assertEqual(data["scheduler_monitoring"]["components"]["mautic_cron"]["reason"], "last_run_failed")
        self.assertTrue(any(w.startswith("Mautic cron:") for w in data["diagnostics"]["warnings"]))

    def test_mautic_down_costs_no_extra_request(self):
        data = self.get(bridge_error=TemporaryMauticError("timeout")).data
        self.assertEqual(self.background_calls, 0)
        cron = data["scheduler_monitoring"]["components"]["mautic_cron"]
        self.assertEqual((cron["status"], cron["reason"]), (UNKNOWN, "mautic_unavailable"))

    def test_background_endpoint_failure_is_unknown(self):
        data = self.get(background_error=TemporaryMauticError("timeout")).data
        self.assertEqual(data["scheduler_monitoring"]["components"]["mautic_cron"]["status"], UNKNOWN)
        self.assertEqual(data["scheduler_monitoring"]["components"]["mautic_worker"]["status"], UNKNOWN)

    def test_repeated_requests_publish_and_write_nothing(self):
        for _ in range(3):
            self.assertEqual(self.get().status_code, 200)
            self.assertEqual(self.published, 0)
        for key in ("started", "published"):
            self.assertIsNone(cache.get(f"newsletter:scheduler:beat:{key}"))

    def test_no_secrets_in_the_response(self):
        body = json.dumps(self.get().data, default=str)
        for leaked in ("broker-secret", "redis.internal.example", "super-secret", "webhook-secret"):
            self.assertNotIn(leaked, body)

    def test_non_superuser_and_anonymous_are_refused(self):
        member = User.objects.create_user(username="b10-member", email="m@example.test", password="pw")
        self.client.force_authenticate(member)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.client.force_authenticate(None)
        self.assertIn(self.client.get(self.url).status_code, (401, 403))


@override_settings(
    **MONITORING,
    MAUTIC_BASE_URL="https://mautic.example.test",
    MAUTIC_USERNAME="api-user",
    MAUTIC_PASSWORD="super-secret",
)
class CheckBackgroundHealthCommandTests(SimpleTestCase):
    def setUp(self):
        cache.clear()

    def run_command(self, *args, worker=(), report=None, background_error=None):
        out = io.StringIO()
        with patch.object(diagnostics, "_ping_workers", return_value=list(worker)), \
                patch("redis.Redis.from_url"), \
                patch.object(diagnostics, "MauticClient") as client_cls, \
                redirect_stdout(out):
            if background_error:
                client_cls.return_value.get_background_health.side_effect = background_error
            else:
                client_cls.return_value.get_background_health.return_value = report
            with self.assertRaises(SystemExit) as exit_info:
                call_command("check_background_health", *args, stdout=out)
            self.background_calls = client_cls.return_value.get_background_health.call_count
        return exit_info.exception.code, out.getvalue()

    def fresh_report(self):
        now = datetime.now(dt_timezone.utc).replace(microsecond=0)
        return cron_report({name: job(5, now=now) for name in monitoring.DEFAULT_MAUTIC_CRON_JOBS}, generated_at=now)

    def test_dead_worker_exits_unhealthy(self):
        code, out = self.run_command(worker=[], report=self.fresh_report())
        self.assertEqual(code, 2)
        self.assertIn("celery_worker: Unhealthy", out)

    def test_missing_evidence_exits_unknown(self):
        code, _ = self.run_command("--skip-mautic", worker=[{"w": {}}])
        self.assertEqual(code, 3)
        self.assertEqual(self.background_calls, 0)

    def test_everything_fresh_exits_healthy_with_json(self):
        now = datetime.now(dt_timezone.utc)
        cache.set_many({
            "newsletter:scheduler:beat:started": (now - timedelta(hours=1)).isoformat(),
            "newsletter:scheduler:beat:published": now.isoformat(),
        }, None)
        for task in PERIODIC_TASKS:
            cache.set(f"newsletter:task-heartbeat:{task}:started", now.isoformat(), 3600)
            cache.set(f"newsletter:task-heartbeat:{task}:succeeded", now.isoformat(), 3600)
        code, out = self.run_command("--json", worker=[{"w": {}}], report=self.fresh_report())
        self.assertEqual(code, 0, out)
        data = json.loads(out)
        self.assertEqual(data["status"], HEALTHY)
        self.assertNotIn("broker-secret", out)
        self.assertNotIn("super-secret", out)
