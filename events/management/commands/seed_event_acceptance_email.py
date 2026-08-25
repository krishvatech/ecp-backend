"""
Install a custom acceptance email template on a single event.

Loads the HTML/text bodies from templates/emails/custom/<template-name>.{html,txt}
and upserts them as EventEmailTemplate rows so only that event uses them.

Usage:
    python manage.py seed_event_acceptance_email
    python manage.py seed_event_acceptance_email --slug m-a-in-asia-2026 --dry-run
"""
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from events.models import Event, EventEmailTemplate

DEFAULT_SLUG = "m-a-in-asia-2026"
DEFAULT_TEMPLATE = "maa_asia_2026_accepted"

# Both acceptance keys get the same body - the template branches on `amount_due`.
TEMPLATE_KEYS = {
    "application_accepted_applicant": "Your place at {{ event_name }} is confirmed",
    "application_accepted_payment_pending": "Your place at {{ event_name }} - payment pending",
}


class Command(BaseCommand):
    help = "Install the custom application-acceptance email template on a specific event."

    def add_arguments(self, parser):
        parser.add_argument("--slug", default=DEFAULT_SLUG, help="Event slug to install the template on.")
        parser.add_argument("--template", default=DEFAULT_TEMPLATE, help="Base filename under templates/emails/custom/.")
        parser.add_argument("--dry-run", action="store_true", help="Show what would change without writing.")

    def handle(self, *args, **options):
        slug = options["slug"]
        template_name = options["template"]
        dry_run = options["dry_run"]

        try:
            event = Event.objects.get(slug=slug)
        except Event.DoesNotExist:
            raise CommandError(f"No event found with slug '{slug}'")

        base = Path(settings.BASE_DIR) / "templates" / "emails" / "custom"
        html_path = base / f"{template_name}.html"
        text_path = base / f"{template_name}.txt"

        if not html_path.exists():
            raise CommandError(f"Missing HTML template: {html_path}")

        html_body = html_path.read_text(encoding="utf-8")
        text_body = text_path.read_text(encoding="utf-8") if text_path.exists() else ""

        for template_key, subject in TEMPLATE_KEYS.items():
            if dry_run:
                exists = EventEmailTemplate.objects.filter(event=event, template_key=template_key).exists()
                self.stdout.write(f"[dry-run] would {'update' if exists else 'create'} {template_key} for {event.title}")
                continue

            obj, created = EventEmailTemplate.objects.update_or_create(
                event=event,
                template_key=template_key,
                defaults={
                    "subject": subject,
                    "html_body": html_body,
                    "text_body": text_body,
                    "is_active": True,
                    "notes": f"Custom acceptance email seeded from templates/emails/custom/{template_name}.*",
                },
            )
            self.stdout.write(self.style.SUCCESS(
                f"{'Created' if created else 'Updated'} {template_key} for '{event.title}' (id={obj.id})"
            ))
