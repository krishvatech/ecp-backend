from django.core.management.base import BaseCommand
from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone

from events.models import Event


class Command(BaseCommand):
    help = (
        "Repair events whose archive marker is still active but whose status was "
        "overwritten by a stale live-room client."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--event-id",
            type=int,
            help="Repair only one event ID. Omit to inspect all affected events.",
        )
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Apply the repair. Without this flag the command is a dry run.",
        )

    def handle(self, *args, **options):
        event_id = options.get("event_id")
        apply_changes = bool(options.get("apply"))

        active_archive_marker = Q(archived_at__isnull=False) & (
            Q(restored_at__isnull=True) | Q(archived_at__gt=F("restored_at"))
        )
        queryset = Event.objects.filter(active_archive_marker).exclude(status="archived")
        if event_id:
            queryset = queryset.filter(pk=event_id)

        rows = list(
            queryset.order_by("id").values(
                "id",
                "slug",
                "title",
                "status",
                "is_live",
                "is_hidden",
                "archived_at",
                "restored_at",
            )
        )

        if not rows:
            self.stdout.write(self.style.SUCCESS("No corrupted archived event lifecycle rows found."))
            return

        mode = "APPLY" if apply_changes else "DRY RUN"
        self.stdout.write(f"{mode}: found {len(rows)} event(s) with an active archive marker:")
        for row in rows:
            self.stdout.write(
                "  id={id} slug={slug!r} status={status!r} "
                "is_live={is_live} is_hidden={is_hidden}".format(**row)
            )

        if not apply_changes:
            self.stdout.write(
                self.style.WARNING(
                    "No changes made. Re-run with --apply after reviewing the rows above."
                )
            )
            return

        ids = [row["id"] for row in rows]
        with transaction.atomic():
            updated = Event.objects.filter(pk__in=ids).update(
                status="archived",
                is_live=False,
                is_on_break=False,
                is_hidden=True,
                is_featured=False,
                is_pinned=False,
                updated_at=timezone.now(),
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"Repaired {updated} event(s). No registrations, participants, orders, "
                "recordings, WordPress IDs, MANDA mappings, Saleor IDs, or sync jobs were deleted."
            )
        )
