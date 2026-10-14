import json

from django.core.management.base import BaseCommand

from newsletter.mautic_diagnostics_services import collect_scheduler_monitoring
from newsletter.scheduler_monitoring import EXIT_CODES, UNKNOWN


class Command(BaseCommand):
    help = (
        "Report Celery Beat, Celery worker, Redis broker, scheduled task execution, "
        "Mautic cron and Mautic worker health, for an external monitor. Read-only: "
        "it schedules, retries and sends nothing. Exit code: 0 Healthy, 1 Warning, "
        "2 Unhealthy, 3 Unknown. Run it from a scheduler that does not depend on "
        "Celery Beat (host cron, a systemd timer, SSM, a container healthcheck)."
    )

    def add_arguments(self, parser):
        parser.add_argument("--json", action="store_true", help="Print the full report as JSON.")
        parser.add_argument(
            "--skip-mautic",
            action="store_true",
            help="Do not contact Mautic; its components report Unknown.",
        )

    def handle(self, *args, **options):
        report = collect_scheduler_monitoring(include_mautic=not options["skip_mautic"])
        if options["json"]:
            self.stdout.write(json.dumps(report, indent=2, default=str))
        else:
            self.stdout.write(f"overall: {report['status']}")
            for key, component in report["components"].items():
                age = component["seconds_since_last_activity"]
                age_text = f", last activity {int(age)}s ago" if age is not None else ""
                reason = f" [{component['reason']}]" if component["reason"] else ""
                self.stdout.write(f"{key}: {component['status']}{reason}{age_text} - {component['detail']}")
        # Exit through SystemExit so the code reaches the external monitor.
        raise SystemExit(EXIT_CODES.get(report["status"], EXIT_CODES[UNKNOWN]))
