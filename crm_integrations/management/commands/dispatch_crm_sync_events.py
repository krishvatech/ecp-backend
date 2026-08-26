from django.core.management.base import BaseCommand, CommandError

from crm_integrations.operations import dispatch_due_sync_events


class Command(BaseCommand):
    help = "Dispatch pending, due-retry, and stale-processing CRM sync events."

    def add_arguments(self, parser):
        parser.add_argument("--batch-size", type=int, default=100)

    def handle(self, *args, **options):
        batch_size = options["batch_size"]
        if batch_size < 1 or batch_size > 5000:
            raise CommandError("--batch-size must be between 1 and 5000")
        result = dispatch_due_sync_events(batch_size=batch_size)
        if result["disabled"]:
            self.stdout.write(self.style.WARNING("CRM synchronization is disabled."))
            return
        self.stdout.write(
            self.style.SUCCESS(
                "Selected {selected}; dispatched {dispatched}; failures {failed}.".format(
                    **result
                )
            )
        )
