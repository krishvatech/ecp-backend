"""
Create 1200x630 social-preview images for events (WhatsApp/LinkedIn previews).

Usage:
    python manage.py generate_event_og_images --dry-run
    python manage.py generate_event_og_images
    python manage.py generate_event_og_images --slug=m-a-in-asia-2026
    python manage.py generate_event_og_images --event-id=123 --force
"""

from django.core.files.storage import default_storage
from django.core.management.base import BaseCommand

from events.models import Event
from events.social_image import (
    ensure_event_og_image,
    event_source_image,
    og_image_key,
)

STATUSES = ("published", "live", "ended")


class Command(BaseCommand):
    help = "Generate social-preview (og:image) derivatives for event cover/preview images"

    def add_arguments(self, parser):
        parser.add_argument("--event-id", type=int)
        parser.add_argument("--slug")
        parser.add_argument("--limit", type=int, default=0)
        parser.add_argument("--force", action="store_true", help="Rebuild even if it exists")
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **opts):
        events = Event.objects.filter(status__in=STATUSES, is_hidden=False)
        if opts["event_id"]:
            events = events.filter(pk=opts["event_id"])
        if opts["slug"]:
            events = events.filter(slug=opts["slug"])
        events = events.order_by("pk")

        created = existing = skipped = failed = 0
        processed = 0
        for event in events.iterator():
            source = event_source_image(event)
            key = og_image_key(getattr(source, "name", ""))
            if not key:
                skipped += 1
                continue
            if opts["limit"] and processed >= opts["limit"]:
                break
            processed += 1

            already = default_storage.exists(key)
            if already and not opts["force"]:
                existing += 1
                continue
            if opts["dry_run"]:
                self.stdout.write(f"[dry-run] would build {key} (event {event.pk})")
                created += 1
                continue
            if ensure_event_og_image(event, force=opts["force"]):
                created += 1
                self.stdout.write(f"built {key} (event {event.pk})")
            else:
                failed += 1
                self.stderr.write(f"FAILED event {event.pk} ({event.slug})")

        self.stdout.write(
            f"created={created} existing={existing} no_image={skipped} failed={failed}"
        )
