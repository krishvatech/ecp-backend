"""Idempotently initialize IPDT-778 sponsor/partner category defaults."""
from django.core.management.base import BaseCommand
from events.models import EventSupporterCategory

DEFAULTS = [
    ("sponsor", "Diamond", 10),
    ("sponsor", "Platinum", 20),
    ("sponsor", "Gold", 30),
    ("partner", "Knowledge Partner", 10),
    ("partner", "Supporting End-User Partner", 20),
    ("partner", "Supporting Partner", 30),
    ("partner", "Media Partner", 40),
]


class Command(BaseCommand):
    help = "Create missing default IPDT-778 sponsor/partner types (does not overwrite edits)."

    def handle(self, *args, **kwargs):
        created = 0
        for kind, name, order in DEFAULTS:
            _, was_created = EventSupporterCategory.objects.get_or_create(
                kind=kind, name=name, defaults={"display_order": order},
            )
            created += int(was_created)
        self.stdout.write(self.style.SUCCESS(f"Sponsor/partner types ready; created {created}."))
