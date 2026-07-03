from django.core.management.base import BaseCommand

from events.platform_sync import process_pending_platform_sync_jobs


class Command(BaseCommand):
    help = "Process pending IMAA Connect event platform sync outbox jobs."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=20, help="Maximum jobs to process once.")

    def handle(self, *args, **options):
        summary = process_pending_platform_sync_jobs(limit=options["limit"])
        self.stdout.write(
            self.style.SUCCESS(
                f"Processed {summary['processed']}; succeeded {summary['succeeded']}; failed {summary['failed']}"
            )
        )
        for item in summary["errors"]:
            self.stderr.write(f"Job {item['job_id']}: {item['error']}")
