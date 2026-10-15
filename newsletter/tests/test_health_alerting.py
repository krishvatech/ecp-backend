"""B14: independent background health alerting.

publish_background_health turns one B10 report into CloudWatch metrics. AWS
is never contacted here: the CloudWatch client is a mock or --dry-run is used,
and the Redis, worker and Mautic probes are patched as in the B10 tests.
"""

import io
import json
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone as dt_timezone
from unittest.mock import MagicMock, patch

from celery.app.task import Task
from django.core.cache import cache
from django.core.management import call_command
from django.test import SimpleTestCase, override_settings

from newsletter import health_alerting as alerting
from newsletter import mautic_diagnostics_services as diagnostics
from newsletter.scheduler_monitoring import DEFAULT_MAUTIC_CRON_JOBS
from newsletter.task_heartbeats import PERIODIC_TASKS
from newsletter.tests.test_scheduler_monitoring import MONITORING, cron_report, job


def report(status="Healthy", **components):
    statuses = {name: "Healthy" for name in alerting.COMPONENTS}
    statuses.update(components)
    return {
        "status": status,
        "observed_at": "2026-10-15T10:00:00+00:00",
        "components": {
            name: {"status": value, "reason": "" if value == "Healthy" else f"{name}-reason",
                   "detail": "redis://:broker-secret@redis.internal.example:6379/0"}
            for name, value in statuses.items()
        },
    }


def values(data, metric):
    return {
        next((d["Value"] for d in item["Dimensions"] if d["Name"] == "Component"), None): item["Value"]
        for item in data if item["MetricName"] == metric
    }


class MetricDataTests(SimpleTestCase):
    def test_healthy_report_is_a_heartbeat_with_all_zero_components(self):
        data = alerting.metric_data(report(), environment="production")

        self.assertEqual(len(data), 2 + 3 * len(alerting.COMPONENTS))
        self.assertEqual(values(data, "MonitorSample"), {None: 1.0})
        self.assertEqual(values(data, "OverallStatusCode"), {None: 0.0})
        for metric in ("ComponentUnhealthy", "ComponentDegraded", "ComponentUnknown"):
            self.assertEqual(set(values(data, metric)), set(alerting.COMPONENTS))
            self.assertEqual(set(values(data, metric).values()), {0.0})

    def test_each_status_sets_its_flags(self):
        data = alerting.metric_data(report(
            "Unhealthy", celery_beat="Unhealthy", celery_worker="Warning", mautic_cron="Unknown",
        ), environment="production")

        self.assertEqual(values(data, "OverallStatusCode"), {None: 2.0})
        self.assertEqual(values(data, "ComponentUnhealthy")["celery_beat"], 1.0)
        # Degraded is Warning or worse: an escalation never reads as recovery.
        self.assertEqual(values(data, "ComponentDegraded")["celery_beat"], 1.0)
        self.assertEqual(values(data, "ComponentDegraded")["celery_worker"], 1.0)
        self.assertEqual(values(data, "ComponentDegraded")["mautic_cron"], 0.0)
        self.assertEqual(values(data, "ComponentUnhealthy")["celery_worker"], 0.0)
        self.assertEqual(values(data, "ComponentUnknown")["mautic_cron"], 1.0)
        self.assertEqual(sum(values(data, "ComponentUnhealthy").values()), 1.0)

    def test_overall_status_codes_follow_check_background_health(self):
        for status, code in (("Healthy", 0), ("Warning", 1), ("Unhealthy", 2), ("Unknown", 3), ("Bogus", 3)):
            with self.subTest(status=status):
                data = alerting.metric_data(report(status), environment="e")
                self.assertEqual(values(data, "OverallStatusCode"), {None: float(code)})

    def test_disabled_component_is_not_a_fault(self):
        data = alerting.metric_data(report(mautic_worker="Disabled"), environment="e")

        for metric in ("ComponentUnhealthy", "ComponentDegraded", "ComponentUnknown"):
            self.assertEqual(values(data, metric)["mautic_worker"], 0.0)

    def test_absent_component_is_unknown_never_healthy(self):
        partial = report()
        del partial["components"]["redis_broker"]

        data = alerting.metric_data(partial, environment="e")

        self.assertEqual(values(data, "ComponentUnknown")["redis_broker"], 1.0)

    def test_dimensions_carry_environment_and_no_instance_identity(self):
        data = alerting.metric_data(report(), environment="staging")

        for item in data:
            names = {d["Name"] for d in item["Dimensions"]}
            self.assertLessEqual(names, {"Environment", "Component"})
            self.assertIn({"Name": "Environment", "Value": "staging"}, item["Dimensions"])
            self.assertEqual(item["Timestamp"], "2026-10-15T10:00:00+00:00")
            self.assertEqual(item["Unit"], "Count")

    def test_summary_and_metrics_carry_no_connection_details(self):
        r = report("Unhealthy", redis_broker="Unhealthy")
        text = json.dumps([alerting.summary(r), alerting.metric_data(r, environment="e")])

        self.assertNotIn("broker-secret", text)
        self.assertNotIn("redis.internal.example", text)
        self.assertEqual(alerting.summary(r)["components"]["redis_broker"],
                         {"status": "Unhealthy", "reason": "redis_broker-reason"})

    @override_settings(HEALTH_ALERTING_ENVIRONMENT="prod east/1 ☃", HEALTH_ALERTING_NAMESPACE="")
    def test_environment_is_sanitized_and_namespace_defaults(self):
        self.assertEqual(alerting.alerting_environment(), "prodeast1")
        self.assertEqual(alerting.alerting_environment("x" * 100), "x" * 64)
        self.assertEqual(alerting.alerting_environment("!!!"), "development")
        self.assertEqual(alerting.alerting_namespace(), "ECP/MarketingHub")


class PublishCloudWatchTests(SimpleTestCase):
    def test_sends_one_bounded_call(self):
        client = MagicMock()
        data = alerting.metric_data(report(), environment="e")

        alerting.publish_cloudwatch(data, namespace="ECP/Test", client=client)

        client.put_metric_data.assert_called_once_with(Namespace="ECP/Test", MetricData=data)

    def test_aws_errors_become_publish_error_with_the_type_only(self):
        client = MagicMock()
        client.put_metric_data.side_effect = PermissionError("arn:aws:iam::123456789012:role/x denied")

        with self.assertRaises(alerting.PublishError) as raised:
            alerting.publish_cloudwatch([], namespace="n", client=client)

        self.assertEqual(str(raised.exception), "PermissionError")

    @override_settings(HEALTH_ALERTING_AWS_REGION="eu-west-2")
    def test_default_client_has_short_timeouts_and_few_retries(self):
        with patch("boto3.client") as factory:
            alerting.publish_cloudwatch([], namespace="n")

        _, kwargs = factory.call_args
        self.assertEqual(factory.call_args.args, ("cloudwatch",))
        self.assertEqual(kwargs["region_name"], "eu-west-2")
        config = kwargs["config"]
        self.assertEqual((config.connect_timeout, config.read_timeout), (3, 5))
        self.assertEqual(config.retries["max_attempts"], 2)


@override_settings(
    **MONITORING,
    MAUTIC_BASE_URL="https://mautic.example.test",
    MAUTIC_USERNAME="api-user",
    MAUTIC_PASSWORD="super-secret",
    HEALTH_ALERTING_ENVIRONMENT="test-env",
    HEALTH_ALERTING_NAMESPACE="ECP/Test",
)
class PublishBackgroundHealthCommandTests(SimpleTestCase):
    def setUp(self):
        cache.clear()

    def healthy_evidence(self):
        now = datetime.now(dt_timezone.utc)
        cache.set_many({
            "newsletter:scheduler:beat:started": (now - timedelta(hours=1)).isoformat(),
            "newsletter:scheduler:beat:published": now.isoformat(),
        }, None)
        for task in PERIODIC_TASKS:
            cache.set(f"newsletter:task-heartbeat:{task}:started", now.isoformat(), 3600)
            cache.set(f"newsletter:task-heartbeat:{task}:succeeded", now.isoformat(), 3600)

    def fresh_cron(self):
        now = datetime.now(dt_timezone.utc).replace(microsecond=0)
        return cron_report({name: job(5, now=now) for name in DEFAULT_MAUTIC_CRON_JOBS}, generated_at=now)

    def run_command(self, *args, worker=({"w": {}},), cron=None, cloudwatch=None, publish_error=None):
        out, err = io.StringIO(), io.StringIO()
        cloudwatch = cloudwatch or MagicMock()
        if publish_error:
            cloudwatch.put_metric_data.side_effect = publish_error
        with patch.object(diagnostics, "_ping_workers", return_value=list(worker)), \
                patch("redis.Redis.from_url"), \
                patch.object(diagnostics, "MauticClient") as client_cls, \
                patch("boto3.client", return_value=cloudwatch) as boto_client, \
                patch.object(Task, "apply_async") as apply_async, \
                redirect_stdout(out):
            client_cls.return_value.get_background_health.return_value = cron or self.fresh_cron()
            with self.assertRaises(SystemExit) as exit_info:
                call_command("publish_background_health", *args, stdout=out, stderr=err)
        self.boto_client = boto_client
        self.cloudwatch = cloudwatch
        self.apply_async = apply_async
        lines = [line for line in out.getvalue().splitlines() if line.startswith("{")]
        return exit_info.exception.code, json.loads(lines[-1]), err.getvalue()

    def test_healthy_publishes_and_exits_zero(self):
        self.healthy_evidence()

        code, output, _ = self.run_command()

        self.assertEqual(code, 0, output)
        self.assertTrue(output["published"])
        self.assertEqual((output["namespace"], output["environment"]), ("ECP/Test", "test-env"))
        kwargs = self.cloudwatch.put_metric_data.call_args.kwargs
        self.assertEqual(kwargs["Namespace"], "ECP/Test")
        self.assertEqual(len(kwargs["MetricData"]), 20)

    def test_dead_worker_publishes_unhealthy_and_exits_two(self):
        self.healthy_evidence()

        code, output, _ = self.run_command(worker=())

        self.assertEqual(code, 2)
        self.assertEqual(output["components"]["celery_worker"]["status"], "Unhealthy")
        sent = self.cloudwatch.put_metric_data.call_args.kwargs["MetricData"]
        self.assertEqual(values(sent, "ComponentUnhealthy")["celery_worker"], 1.0)

    def test_stopped_beat_is_unhealthy_even_with_a_live_worker(self):
        self.healthy_evidence()
        stale = (datetime.now(dt_timezone.utc) - timedelta(hours=2)).isoformat()
        cache.set("newsletter:scheduler:beat:published", stale, None)
        for task in PERIODIC_TASKS:
            cache.set(f"newsletter:task-heartbeat:{task}:started", stale, 3600)
            cache.set(f"newsletter:task-heartbeat:{task}:succeeded", stale, 3600)

        code, output, _ = self.run_command()

        self.assertEqual(code, 2)
        self.assertEqual(output["components"]["celery_beat"]["status"], "Unhealthy")
        self.assertEqual(output["components"]["celery_worker"]["status"], "Healthy")

    def test_no_evidence_is_unknown_and_still_published(self):
        code, output, _ = self.run_command("--skip-mautic")

        self.assertEqual(code, 3)
        self.assertTrue(output["published"])
        sent = self.cloudwatch.put_metric_data.call_args.kwargs["MetricData"]
        self.assertEqual(values(sent, "MonitorSample"), {None: 1.0})
        self.assertEqual(values(sent, "ComponentUnknown")["mautic_cron"], 1.0)

    def test_dry_run_never_creates_an_aws_client(self):
        self.healthy_evidence()

        code, output, _ = self.run_command("--dry-run", "--environment", "local dev")

        self.assertEqual(code, 0)
        self.boto_client.assert_not_called()
        self.assertFalse(output["published"])
        self.assertEqual(output["environment"], "localdev")
        self.assertEqual(len(output["metric_data"]), 20)

    def test_publish_failure_exits_four_not_a_health_code(self):
        self.healthy_evidence()

        code, output, err = self.run_command(publish_error=TimeoutError("connect timeout"))

        self.assertEqual(code, alerting.MONITOR_FAILED_EXIT_CODE)
        self.assertFalse(output["published"])
        self.assertEqual(output["publish_error"], "TimeoutError")
        self.assertIn("Could not publish", err)

    def test_collection_crash_exits_four_not_warning(self):
        with patch("newsletter.management.commands.publish_background_health.collect_scheduler_monitoring",
                   side_effect=RuntimeError("database is down at db.internal")):
            code, output, err = self.run_command()

        self.assertEqual(code, alerting.MONITOR_FAILED_EXIT_CODE)
        self.assertEqual(output["monitor_error"], "RuntimeError")
        self.assertNotIn("db.internal", json.dumps(output) + err)
        self.cloudwatch.put_metric_data.assert_not_called()

    def test_output_has_no_secrets_and_dispatches_no_task(self):
        self.healthy_evidence()

        _, output, err = self.run_command(worker=())

        text = json.dumps(output) + err
        for leaked in ("broker-secret", "redis.internal.example", "super-secret", "api-user"):
            self.assertNotIn(leaked, text)
        self.apply_async.assert_not_called()

    def test_repeated_runs_are_read_only(self):
        self.healthy_evidence()
        before = {key: cache.get(key) for key in ("newsletter:scheduler:beat:published",)}

        for _ in range(3):
            self.run_command()

        self.assertEqual(before, {key: cache.get(key) for key in before})
        self.apply_async.assert_not_called()
