from django.core.management.base import BaseCommand
from django.db import transaction

from events.models import ExternalEventMapping


class Command(BaseCommand):
    help = (
        "Align IMAA Connect Event.canonical_event_id with active MANDA "
        "ExternalEventMapping rows. Run after deploying the MANDA event upsert "
        "canonical ID fix to repair older local test/staging data."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--commit",
            action="store_true",
            help="Actually update events. Without this flag the command is a dry run.",
        )

    def handle(self, *args, **options):
        commit = bool(options["commit"])
        mappings = (
            ExternalEventMapping.objects.select_related("local_event")
            .filter(source_platform=ExternalEventMapping.SOURCE_MANDA, is_active=True)
            .order_by("id")
        )

        checked = 0
        fixed = 0
        for mapping in mappings:
            checked += 1
            event = mapping.local_event
            if event.canonical_event_id == mapping.canonical_event_id:
                continue

            fixed += 1
            self.stdout.write(
                f"Event {event.id} ({event.slug}): "
                f"{event.canonical_event_id} -> {mapping.canonical_event_id} "
                f"from MANDA source_event_id={mapping.source_event_id}"
            )
            if commit:
                with transaction.atomic():
                    event.canonical_event_id = mapping.canonical_event_id
                    event.save(update_fields=["canonical_event_id", "updated_at"])

        mode = "UPDATED" if commit else "DRY-RUN"
        self.stdout.write(self.style.SUCCESS(f"{mode}: checked={checked}, mismatched={fixed}"))
