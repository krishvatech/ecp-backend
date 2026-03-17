"""
Management command to seed EmailTemplate DB records from file-based templates.
Reads templates/emails/<key>.html and templates/emails/<key>.txt files and creates
EmailTemplate records in the database. Idempotent — safe to re-run multiple times.
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from pathlib import Path
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

# Default subjects per template key — mirrors the hardcoded subjects in email_utils.py / views.py
DEFAULT_SUBJECTS = {
    "welcome": "Welcome to {{ app_name }}",
    "password_changed": "Your {{ app_name }} password was changed",
    "speaker_credentials": "Your {{ app_name }} Speaker Account - Login Credentials",
    "admin_credentials": "Welcome to {{ app_name }} - Your Admin Credentials",
    "event_confirmation": "You're Confirmed as {{ role }} - {{ event_title }}",
    "event_cancelled": "Update: '{{ event_title }}' has been cancelled",
    "event_invite": "You're invited to '{{ event_title }}' on {{ app_name }}",
    "group_invite": "You're invited to join '{{ group_name }}' on {{ app_name }}",
    "replay_no_show": "You missed '{{ event_title }}' – the recording is now available",
    "replay_partial": "You left '{{ event_title }}' early – catch what you missed",
    "kyc_approved": "Your identity verification is complete ✅",
    "kyc_failed": "Action needed: identity verification failed ❌",
    "name_change_approved": "Your name change request is approved ✅",
    "name_change_manual_review": "Your name change request is under review",
    "name_change_verification_failed": "Your name change verification was unsuccessful",
    "name_change_rejected": "Your name change request was rejected ❌",
    "admin_name_change_review": "New Identity Review Required: Name Change Request #{{ request_id }}",
}


class Command(BaseCommand):
    help = "Seed EmailTemplate DB records from existing .html/.txt template files. Idempotent."

    def add_arguments(self, parser):
        parser.add_argument(
            "--overwrite",
            action="store_true",
            help="Overwrite existing DB records with file contents (destructive).",
        )

    def handle(self, *args, **options):
        from cms.models import EmailTemplate, TEMPLATE_KEY_CHOICES

        overwrite = options["overwrite"]
        template_dir = Path(settings.BASE_DIR) / "templates" / "emails"

        if not template_dir.exists():
            self.stdout.write(self.style.ERROR(f"Template directory not found: {template_dir}"))
            return

        created = 0
        skipped = 0
        updated = 0

        for key, display in TEMPLATE_KEY_CHOICES:
            html_path = template_dir / f"{key}.html"
            txt_path = template_dir / f"{key}.txt"

            # Read files (both optional — some templates are text-only like name_change_rejected)
            html_body = html_path.read_text(encoding="utf-8") if html_path.exists() else ""
            text_body = txt_path.read_text(encoding="utf-8") if txt_path.exists() else ""

            if not html_body and not text_body:
                self.stdout.write(self.style.WARNING(f"  SKIP {key}: no files found"))
                continue

            subject = DEFAULT_SUBJECTS.get(key, f"[{key}]")

            obj, was_created = EmailTemplate.objects.get_or_create(
                template_key=key,
                defaults={
                    "subject": subject,
                    "html_body": html_body,
                    "text_body": text_body,
                    "is_active": True,
                    "notes": f"Seeded from file on {timezone.now().date()}",
                },
            )

            if was_created:
                created += 1
                self.stdout.write(self.style.SUCCESS(f"  CREATED {key}"))
            elif overwrite:
                obj.html_body = html_body
                obj.text_body = text_body
                obj.subject = subject
                obj.save()
                updated += 1
                self.stdout.write(self.style.WARNING(f"  UPDATED {key} (overwrite)"))
            else:
                skipped += 1
                self.stdout.write(f"  EXISTS  {key} (use --overwrite to update)")

        self.stdout.write(
            self.style.SUCCESS(
                f"\nDone. Created: {created}, Updated: {updated}, Skipped: {skipped}"
            )
        )
