import json
import sys

from django.core.management.base import BaseCommand

from newsletter.health_alerting import (
    MONITOR_FAILED_EXIT_CODE,
    PublishError,
    alerting_environment,
    alerting_namespace,
    metric_data,
    publish_cloudwatch,
    summary,
)
from newsletter.mautic_diagnostics_services import collect_scheduler_monitoring
from newsletter.scheduler_monitoring import EXIT_CODES, UNKNOWN


class Command(BaseCommand):
    help = (
        "Observe Marketing Hub background health once (the same read-only checks as "
        "check_background_health) and publish it as CloudWatch metrics for alarms. "
        "Run it from a scheduler independent of Celery Beat. Prints one JSON line with "
        "the statuses. Exit code: the health exit code (0 Healthy, 1 Warning, "
        "2 Unhealthy, 3 Unknown), or 4 if no sample could be produced or published."
    )

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true",
                            help="Do not contact AWS; print the metric data that would be sent.")
        parser.add_argument("--skip-mautic", action="store_true",
                            help="Do not contact Mautic; its components report Unknown.")
        parser.add_argument("--namespace", default=None, help="CloudWatch namespace (default: settings).")
        parser.add_argument("--environment", default=None, help="Environment dimension (default: settings).")

    def _fail(self, output, message):
        self.stdout.write(json.dumps(output, default=str))
        self.stderr.write(message)
        raise SystemExit(MONITOR_FAILED_EXIT_CODE)

    def handle(self, *args, **options):
        environment = alerting_environment(options["environment"])
        namespace = options["namespace"] or alerting_namespace()
        output = {"namespace": namespace, "environment": environment, "published": False}

        try:
            report = collect_scheduler_monitoring(include_mautic=not options["skip_mautic"])
            data = metric_data(report, environment=environment)
        except Exception as exc:
            # Without a sample the health is unknown, not Warning: Django's
            # default exit status 1 would read as a health result.
            output["monitor_error"] = type(exc).__name__
            self._fail(output, f"Could not observe background health: {type(exc).__name__}")

        health_code = EXIT_CODES.get(report["status"], EXIT_CODES[UNKNOWN])
        output.update(health_exit_code=health_code, **summary(report))
        if options["dry_run"]:
            output["metric_data"] = data
        else:
            try:
                publish_cloudwatch(data, namespace=namespace)
                output["published"] = True
            except PublishError as exc:
                output["publish_error"] = str(exc)
                self._fail(output, f"Could not publish background health metrics: {exc}")

        self.stdout.write(json.dumps(output, default=str))
        sys.stdout.flush()
        raise SystemExit(health_code)
