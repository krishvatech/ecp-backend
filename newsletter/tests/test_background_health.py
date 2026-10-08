"""Background-processing health for Marketing Hub diagnostics.

Heartbeats go to an isolated local-memory cache and the Redis/worker probes are
patched, so these tests never touch the shared Redis or the Celery broker.
Each signal must report what its evidence proves and nothing more: in
particular a fresh task heartbeat or a worker ping never makes Beat "Healthy".
"""

import json
import threading
import time
from datetime import timedelta
from unittest.mock import MagicMock, patch

from kombu.exceptions import OperationalError

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter import tasks
from newsletter import mautic_diagnostics_services as diagnostics
from newsletter.mautic_diagnostics_services import _broadcast_send_status, _health_summary
from newsletter.models import NewsletterCampaign
from newsletter.task_heartbeats import (
    PERIODIC_TASKS,
    periodic_task_health,
    task_heartbeat,
)
from newsletter.tests.marketing_actors import grant_marketing_access

User = get_user_model()

BEAT = {
    f"entry-{task}": {"task": task, "schedule": timedelta(minutes=1)}
    for task in PERIODIC_TASKS
}
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                      "LOCATION": "background-health-tests"}}
BROKER = "redis://:broker-secret@redis.internal.example:6379/0"
HEALTH = {
    "CACHES": LOCMEM,
    "NEWSLETTER_BACKGROUND_HEALTH_ENABLED": True,
    "CELERY_BEAT_SCHEDULE": BEAT,
    "CELERY_BROKER_URL": BROKER,
    "CELERY_TASK_TIME_LIMIT": 300,
    "MAUTIC_SYNC_ENABLED": True,
}
# 3 missed one-minute runs plus one run at the 300 s hard time limit.
STALE_AFTER = 3 * 60 + 300


def _set(task, field, value):
    cache.set(f"newsletter:task-heartbeat:{task}:{field}", value, 3600)


def _beat_all(at):
    for task in PERIODIC_TASKS:
        _set(task, "started", at.isoformat())
        _set(task, "succeeded", at.isoformat())


@override_settings(**HEALTH)
class PeriodicTaskHeartbeatTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_running_the_real_periodic_tasks_records_healthy_evidence(self):
        tasks.dispatch_due_newsletter_sync_events()
        tasks.dispatch_due_newsletter_campaign_send_events()
        tasks.dispatch_due_newsletter_scheduled_campaigns()
        tasks.reconcile_native_newsletter_scheduled_campaigns()

        health = periodic_task_health()
        self.assertEqual(health["status"], "Healthy")
        self.assertEqual(set(health["tasks"]), set(PERIODIC_TASKS))
        for report in health["tasks"].values():
            self.assertEqual(report["status"], "Healthy")
            self.assertEqual(report["interval_seconds"], 60)
            self.assertEqual(report["stale_after_seconds"], STALE_AFTER)
            self.assertTrue(timezone.is_aware(report["last_succeeded_at"]))

    def test_first_startup_without_evidence_is_not_verified_rather_than_broken(self):
        health = periodic_task_health()
        self.assertEqual(health["status"], "Not Verified")
        self.assertEqual(health["reason"], "no_run_recorded")

    def test_stale_heartbeat_is_reported_stale(self):
        _beat_all(timezone.now() - timedelta(seconds=STALE_AFTER + 1))
        health = periodic_task_health()
        self.assertEqual(health["status"], "Stale")
        self.assertEqual(health["reason"], "no_recent_run")

    def test_one_stale_task_makes_the_whole_path_stale(self):
        _beat_all(timezone.now())
        _set(PERIODIC_TASKS[0], "started", (timezone.now() - timedelta(hours=1)).isoformat())
        self.assertEqual(periodic_task_health()["status"], "Stale")

    def test_failed_run_is_degraded_and_the_exception_still_propagates(self):
        with self.assertRaises(RuntimeError):
            with task_heartbeat(PERIODIC_TASKS[0]):
                raise RuntimeError("provider said no")
        for task in PERIODIC_TASKS[1:]:
            with task_heartbeat(task):
                pass

        health = periodic_task_health()
        self.assertEqual(health["status"], "Degraded")
        self.assertEqual(health["tasks"][PERIODIC_TASKS[0]]["last_error_type"], "RuntimeError")
        # Only the exception type is kept, never its message.
        self.assertNotIn("provider said no", json.dumps(health, default=str))

    def test_success_after_a_failure_recovers(self):
        with self.assertRaises(RuntimeError):
            with task_heartbeat(PERIODIC_TASKS[0]):
                raise RuntimeError()
        _beat_all(timezone.now() + timedelta(seconds=1))
        self.assertEqual(periodic_task_health()["status"], "Healthy")

    def test_long_running_task_within_time_limit_is_not_stale(self):
        _beat_all(timezone.now() - timedelta(minutes=10))
        for task in PERIODIC_TASKS:
            _set(task, "started", (timezone.now() - timedelta(seconds=290)).isoformat())
        health = periodic_task_health()
        self.assertEqual(health["status"], "Healthy")

    def test_worker_clock_ahead_is_tolerated(self):
        _beat_all(timezone.now() + timedelta(seconds=30))
        self.assertEqual(periodic_task_health()["status"], "Healthy")

    def test_heartbeats_from_several_workers_share_one_view(self):
        _beat_all(timezone.now() - timedelta(minutes=2))
        _set(PERIODIC_TASKS[0], "started", timezone.now().isoformat())  # another worker, later
        self.assertEqual(periodic_task_health()["status"], "Healthy")

    def test_cache_failure_never_breaks_the_task(self):
        with patch("newsletter.task_heartbeats.cache.set", side_effect=ConnectionError("redis down")):
            result = tasks.dispatch_due_newsletter_sync_events()
        self.assertIn("disabled", result)

    def test_unreadable_cache_is_not_verified(self):
        with patch("newsletter.task_heartbeats.cache.get_many", side_effect=ConnectionError()):
            health = periodic_task_health()
        self.assertEqual((health["status"], health["reason"]), ("Not Verified", "cache_unavailable"))

    @override_settings(NEWSLETTER_BACKGROUND_HEALTH_ENABLED=False)
    def test_kill_switch_writes_nothing(self):
        tasks.dispatch_due_newsletter_sync_events()
        self.assertIsNone(cache.get(f"newsletter:task-heartbeat:{PERIODIC_TASKS[0]}:started"))
        self.assertEqual(periodic_task_health()["reason"], "heartbeats_disabled")

    @override_settings(CELERY_BEAT_SCHEDULE={})
    def test_unscheduled_processing_is_disabled_not_broken(self):
        self.assertEqual(periodic_task_health()["status"], "Disabled")


@override_settings(**HEALTH)
class HealthSummaryTests(TestCase):
    def setUp(self):
        cache.clear()

    def summary(self, *, redis="Healthy", worker=("Healthy", 2), processing=None, now=None):
        now = now or timezone.now()
        return _health_summary(
            {"status": redis, "reason": ""},
            {"status": worker[0], "reason": "", "responding": worker[1]},
            processing or periodic_task_health(now=now),
            _broadcast_send_status(),
            {"due": 0, "needs_attention": 0, "scheduled": 0},
            now=now,
        )

    def test_worker_reply_and_fresh_tasks_never_claim_beat_is_healthy(self):
        _beat_all(timezone.now())
        components = self.summary()["components"]
        self.assertEqual(components["celery_worker"]["status"], "Healthy")
        self.assertEqual(components["scheduled_processing"]["status"], "Healthy")
        self.assertEqual(components["celery_beat"]["status"], "Not Verified")
        self.assertEqual(components["celery_beat"]["reason"], "no_independent_signal")

    def test_worker_alive_but_no_scheduled_runs_warns_about_beat(self):
        result = self.summary(worker=("Healthy", 1))
        self.assertEqual(result["components"]["scheduled_processing"]["status"], "Not Verified")
        self.assertIn("Celery Beat or a worker may not be running", " ".join(result["warnings"]))

    def test_stale_processing_and_dead_worker_and_redis_each_warn(self):
        _beat_all(timezone.now() - timedelta(hours=1))
        warnings = " ".join(self.summary(redis="Degraded", worker=("Degraded", 0))["warnings"])
        self.assertIn("Redis broker is unreachable", warnings)
        self.assertIn("No Celery worker answered", warnings)
        self.assertIn("have not run recently", warnings)

    def test_overdue_ecp_schedule_is_reported_but_native_is_not(self):
        past = timezone.now() - timedelta(hours=1)
        NewsletterCampaign.objects.create(name="ECP late", subject="x", status="scheduled", scheduled_at=past)
        NewsletterCampaign.objects.create(name="Native", subject="x", status="scheduled", scheduled_at=past,
                                          schedule_owner=NewsletterCampaign.ScheduleOwner.MAUTIC)
        NewsletterCampaign.objects.create(name="ECP soon", subject="x", status="scheduled",
                                          scheduled_at=timezone.now() - timedelta(seconds=30))
        result = self.summary()
        self.assertEqual(result["components"]["ecp_scheduled_broadcasts"]["overdue"], 1)
        self.assertIn("ECP-scheduled broadcasts are overdue", " ".join(result["warnings"]))

    @override_settings(MAUTIC_SYNC_ENABLED=False)
    def test_disabled_sync_is_disabled_not_broken(self):
        components = self.summary()["components"]
        self.assertEqual(components["ecp_scheduled_broadcasts"]["status"], "Disabled")
        self.assertEqual(components["native_reconciliation"]["status"], "Disabled")


@override_settings(
    **HEALTH,
    MAUTIC_BASE_URL="https://mautic.example.test",
    MAUTIC_USERNAME="api-user",
    MAUTIC_PASSWORD="super-secret",
    MAUTIC_WEBHOOK_SECRET="webhook-secret",
)
class DiagnosticsApiHealthTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.admin = User.objects.create_user(
            username="health-admin", email="health-admin@example.test", password="pw",
            is_staff=True, is_superuser=True,
        )
        grant_marketing_access(self.admin)
        self.url = reverse("newsletter-admin-mautic-diagnostics")

    def get(self, *, ping=(), redis_ok=True, user=None):
        self.client.force_authenticate(user or self.admin)
        with patch("newsletter.mautic_diagnostics_services.MauticClient") as client_cls, patch(
            "newsletter.mautic_diagnostics_services._ping_workers", return_value=list(ping)
        ) as ping_workers, patch("redis.Redis.from_url") as from_url:
            client_cls.return_value.health_check.return_value = True
            client_cls.return_value.get_marketing_bridge_capabilities.return_value = {"capabilities": []}
            client_cls.return_value.get_campaign_builder_capabilities.return_value = {
                "actions": [], "conditions": [], "decisions": [], "connectionRestrictions": {},
            }
            if not redis_ok:
                from_url.return_value.ping.side_effect = ConnectionError("refused")
            response = self.client.get(self.url)
            self.ping_calls = ping_workers.call_count
            return response

    def test_existing_fields_stay_and_health_is_added(self):
        _beat_all(timezone.now())
        response = self.get(ping=[{"w1@host": {"ok": "pong"}}, {"w2@host": {"ok": "pong"}}])

        self.assertEqual(response.status_code, 200)
        for key in ("connection", "api", "bridges", "webhook", "sync", "background_processing",
                    "native_broadcasts", "broadcast_sends", "identity", "diagnostics"):
            self.assertIn(key, response.data)
        background = response.data["background_processing"]
        self.assertEqual(background["live_worker_status"], "Healthy (2 responding)")
        self.assertTrue(background["newsletter_sync_scheduled"])
        health = response.data["health"]
        self.assertEqual(health["celery_worker"]["responding"], 2)
        self.assertEqual(health["scheduled_processing"]["status"], "Healthy")
        self.assertEqual(health["celery_beat"]["status"], "Not Verified")
        self.assertEqual(health["redis"]["status"], "Healthy")

    def test_no_worker_replied_degrades_diagnostics(self):
        response = self.get(ping=[])

        self.assertEqual(response.data["health"]["celery_worker"]["status"], "Degraded")
        self.assertEqual(response.data["health"]["celery_worker"]["reason"], "no_worker_replied")
        self.assertEqual(response.data["health"]["redis"]["status"], "Healthy")
        self.assertEqual(response.data["background_processing"]["live_worker_status"], "No worker responded")
        self.assertEqual(response.data["diagnostics"]["status"], "Degraded")

    def test_unreachable_broker_skips_the_worker_ping_even_with_a_healthy_cache(self):
        # The heartbeat cache is up and fresh; that says nothing about the broker.
        _beat_all(timezone.now())
        response = self.get(ping=[{"w1": {"ok": "pong"}}], redis_ok=False)

        self.assertEqual(self.ping_calls, 0)
        health = response.data["health"]
        self.assertEqual(health["redis"]["status"], "Degraded")
        self.assertEqual(health["scheduled_processing"]["status"], "Healthy")
        self.assertEqual(
            (health["celery_worker"]["status"], health["celery_worker"]["reason"]),
            ("Not Verified", "broker_unreachable"),
        )
        self.assertEqual(health["celery_beat"]["status"], "Not Verified")
        self.assertEqual(response.data["background_processing"]["live_worker_status"], "Not Verifiable")
        self.assertEqual(response.data["diagnostics"]["status"], "Degraded")
        self.assertIn("Redis broker is unreachable from the web process.",
                      response.data["diagnostics"]["warnings"])

    @override_settings(NEWSLETTER_BACKGROUND_HEALTH_ENABLED=False)
    def test_kill_switch_runs_no_broker_or_worker_probe(self):
        with patch("redis.Redis.from_url") as from_url, patch(
            "newsletter.mautic_diagnostics_services._ping_workers"
        ) as ping_workers, patch("newsletter.mautic_diagnostics_services.MauticClient") as client_cls:
            client_cls.return_value.get_marketing_bridge_capabilities.return_value = {"capabilities": []}
            client_cls.return_value.get_campaign_builder_capabilities.return_value = {
                "actions": [], "conditions": [], "decisions": [], "connectionRestrictions": {},
            }
            self.client.force_authenticate(self.admin)
            health = self.client.get(self.url).data["health"]
        from_url.assert_not_called()
        ping_workers.assert_not_called()
        self.assertEqual(health["redis"]["reason"], "probes_disabled")
        self.assertEqual(health["celery_worker"]["reason"], "probes_disabled")

    def test_no_secret_or_worker_host_names_are_exposed(self):
        _beat_all(timezone.now())
        body = json.dumps(self.get(ping=[{"w1@secret-host": {"ok": "pong"}}]).data, default=str)
        for leaked in ("broker-secret", "redis.internal.example", BROKER, "secret-host", "super-secret"):
            self.assertNotIn(leaked, body)

    def test_uncertain_send_warning_still_reported(self):
        NewsletterCampaign.objects.create(
            name="Lost response", subject="x", status="sending",
            send_started_at=timezone.now() - timedelta(hours=1),
        )
        response = self.get(ping=[{"w1": {"ok": "pong"}}])
        self.assertEqual(response.data["broadcast_sends"], {"sending": 1, "needs_review": 1})
        self.assertEqual(response.data["health"]["send_now_outcomes"]["status"], "Degraded")
        self.assertIn("Broadcast sends have no confirmed outcome; check them in Mautic.",
                      response.data["diagnostics"]["warnings"])

    def test_non_superuser_cannot_read_health(self):
        member = User.objects.create_user(username="member", email="m@example.test", password="pw")
        self.assertEqual(self.get(user=member).status_code, 403)


class _ProbeHang:
    """A worker probe that blocks until released, like a broker connect that
    is waiting out the kernel's SYN retries."""

    def __init__(self):
        self.release = threading.Event()
        self.entered = threading.Event()

    def __call__(self):
        self.entered.set()
        self.release.wait(10)
        return [{"w1": {"ok": "pong"}}]


@override_settings(**HEALTH)
class WorkerProbeTests(TestCase):
    """The worker probe is gated on the broker probe and bounded end to end.

    Connections are mocked except for one refused connect to 127.0.0.1:9, which
    fails locally and immediately; nothing here reaches a shared broker.
    """

    BROKER_UP = {"status": "Healthy", "reason": ""}
    BROKER_DOWN = {"status": "Degraded", "reason": "unreachable"}

    def tearDown(self):
        # A failed assertion must not leave the single-flight lock held.
        if diagnostics._worker_probe_lock.locked():
            time.sleep(0.5)
        self.assertFalse(diagnostics._worker_probe_lock.locked())

    def status(self, broker=BROKER_UP, replies=()):
        with patch.object(diagnostics, "_ping_workers", return_value=list(replies)) as ping:
            result = diagnostics._worker_status(broker=broker)
        return result, ping

    def test_responding_worker_is_healthy(self):
        result, _ = self.status(replies=[{"w1@h": {"ok": "pong"}}])
        self.assertEqual(result, {"status": "Healthy", "reason": "", "responding": 1})

    def test_multiple_workers_are_counted_without_names(self):
        result, _ = self.status(replies=[{f"w{i}@secret-host": {"ok": "pong"}} for i in range(3)])
        self.assertEqual(result["responding"], 3)
        self.assertNotIn("secret-host", json.dumps(result))

    def test_no_worker_reply_within_the_reply_timeout_is_degraded(self):
        result, _ = self.status(replies=[])
        self.assertEqual((result["status"], result["reason"]), ("Degraded", "no_worker_replied"))

    def test_unavailable_broker_skips_the_ping_and_is_never_healthy(self):
        result, ping = self.status(broker=self.BROKER_DOWN, replies=[{"w1": {"ok": "pong"}}])
        ping.assert_not_called()
        self.assertEqual(result, {"status": "Not Verified", "reason": "broker_unreachable", "responding": None})

    @override_settings(NEWSLETTER_BACKGROUND_HEALTH_ENABLED=False)
    def test_kill_switch_skips_the_ping(self):
        result, ping = self.status()
        ping.assert_not_called()
        self.assertEqual(result["reason"], "probes_disabled")

    @override_settings(CELERY_BROKER_URL="")
    def test_unconfigured_broker_is_disabled(self):
        result, ping = self.status()
        ping.assert_not_called()
        self.assertEqual(result["status"], "Disabled")

    @override_settings(CELERY_BROKER_URL="amqp://guest:pw@rabbit.internal.example//")
    def test_non_redis_broker_is_not_verified_rather_than_misprobed(self):
        with patch("redis.Redis.from_url") as from_url:
            probe = diagnostics._redis_status()
        from_url.assert_not_called()
        self.assertEqual(probe, {"status": "Not Verified", "reason": "non_redis_broker"})

    def test_connection_failure_is_not_verified_and_logs_only_the_type(self):
        with patch.object(diagnostics, "_ping_workers",
                          side_effect=OperationalError("redis://:broker-secret@redis.internal.example")), \
                self.assertLogs("newsletter.mautic_diagnostics_services", "WARNING") as logs:
            result = diagnostics._worker_status(broker=self.BROKER_UP)
        self.assertEqual((result["status"], result["reason"]), ("Not Verified", "ping_failed"))
        self.assertNotIn("broker-secret", " ".join(logs.output))
        self.assertIn("The Celery worker check did not complete", " ".join(self._warnings(result)))

    def test_hung_probe_returns_at_the_deadline_as_not_verified(self):
        hang = _ProbeHang()
        try:
            with patch.object(diagnostics, "_ping_workers", hang), \
                    patch.object(diagnostics, "WORKER_PROBE_DEADLINE_SECONDS", 0.2):
                started = time.monotonic()
                result = diagnostics._worker_status(broker=self.BROKER_UP)
                elapsed = time.monotonic() - started
                self.assertEqual((result["status"], result["reason"]), ("Not Verified", "probe_timeout"))
                self.assertLess(elapsed, 1.0)
                # While the stuck probe is still running, no second one starts.
                again = diagnostics._worker_status(broker=self.BROKER_UP)
                self.assertEqual(again["reason"], "probe_in_progress")
        finally:
            hang.release.set()
        for _ in range(50):
            if not diagnostics._worker_probe_lock.locked():
                break
            time.sleep(0.02)
        self.assertFalse(diagnostics._worker_probe_lock.locked())
        self.assertEqual(self.status(replies=[{"w": {}}])[0]["status"], "Healthy")

    def test_full_diagnostics_return_promptly_when_the_worker_probe_hangs(self):
        hang = _ProbeHang()
        try:
            with patch.object(diagnostics, "_ping_workers", hang), \
                    patch.object(diagnostics, "WORKER_PROBE_DEADLINE_SECONDS", 0.2), \
                    patch("redis.Redis.from_url"), \
                    patch.object(diagnostics, "MauticClient") as client_cls:
                client_cls.return_value.get_marketing_bridge_capabilities.return_value = {"capabilities": []}
                client_cls.return_value.get_campaign_builder_capabilities.return_value = {
                    "actions": [], "conditions": [], "decisions": [], "connectionRestrictions": {},
                }
                started = time.monotonic()
                data = diagnostics.get_mautic_diagnostics()
                elapsed = time.monotonic() - started
        finally:
            hang.release.set()
        self.assertLess(elapsed, 2.0)
        self.assertEqual(data["health"]["celery_worker"]["reason"], "probe_timeout")
        self.assertEqual(data["health"]["celery_beat"]["status"], "Not Verified")
        body = json.dumps(data, default=str)
        for leaked in ("broker-secret", "redis.internal.example"):
            self.assertNotIn(leaked, body)
        for _ in range(50):
            if not diagnostics._worker_probe_lock.locked():
                break
            time.sleep(0.02)

    def test_probe_uses_a_dedicated_bounded_non_retrying_connection(self):
        from ecp_backend.celery import app

        connection = MagicMock()
        with patch.object(app, "connection_for_write", return_value=connection) as connect, \
                patch.object(app.control, "ping", return_value=[{"w1": {"ok": "pong"}}]) as ping:
            replies = diagnostics._ping_workers()

        self.assertEqual(len(replies), 1)
        kwargs = connect.call_args.kwargs
        self.assertEqual(kwargs["url"], BROKER)
        self.assertEqual(kwargs["connect_timeout"], 1.0)
        options = kwargs["transport_options"]
        self.assertEqual(options["max_retries"], 0)
        self.assertEqual(options["socket_connect_timeout"], 1.0)
        self.assertEqual(options["socket_timeout"], 2.0)
        self.assertIs(options["retry_on_timeout"], False)
        connection.ensure_connection.assert_called_once_with(max_retries=0)
        ping.assert_called_once_with(timeout=1.0, connection=connection)
        connection.release.assert_called_once_with()
        # The app's own broker settings are left as they were.
        self.assertNotIn("socket_connect_timeout", app.conf.broker_transport_options or {})

    def test_connection_is_released_when_connect_or_auth_fails(self):
        from ecp_backend.celery import app

        for error in (OperationalError("refused"), TimeoutError("timed out"),
                      OperationalError("invalid password")):
            connection = MagicMock()
            connection.ensure_connection.side_effect = error
            with patch.object(app, "connection_for_write", return_value=connection), \
                    patch.object(app.control, "ping") as ping:
                with self.assertRaises(type(error)):
                    diagnostics._ping_workers()
            ping.assert_not_called()
            connection.release.assert_called_once_with()

    @override_settings(CELERY_BROKER_URL="redis://127.0.0.1:9/0")
    def test_refused_broker_fails_fast_with_retries_disabled(self):
        # Real kombu connection to a closed local port: with the default retry
        # policy this takes ~6 s (2 s + 4 s back-off); with retries off it fails
        # on the first attempt.
        started = time.monotonic()
        with self.assertRaises(Exception):
            diagnostics._ping_workers()
        self.assertLess(time.monotonic() - started, 2.0)

    def test_delivery_inspection_still_imports_the_heartbeat_threshold(self):
        from newsletter import broadcast_delivery_inspection
        from newsletter.task_heartbeats import task_stale_after_seconds

        self.assertIs(broadcast_delivery_inspection.task_stale_after_seconds, task_stale_after_seconds)
        self.assertEqual(task_stale_after_seconds("newsletter.dispatch_due_scheduled_campaigns"), STALE_AFTER)

    def _warnings(self, worker):
        return _health_summary(
            self.BROKER_UP, worker, periodic_task_health(), _broadcast_send_status(),
            {"due": 0, "needs_attention": 0, "scheduled": 0}, now=timezone.now(),
        )["warnings"]
