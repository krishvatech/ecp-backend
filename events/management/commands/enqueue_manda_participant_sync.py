"""Enqueue MANDA participant sync jobs for existing IMAA registrations.

This command is intentionally an outbox backfill: it creates PlatformSyncJob
rows and lets the normal process_platform_sync_jobs worker send them to MANDA.
"""

from django.core.management.base import BaseCommand

from events.models import EventRegistration
from events.participant_sync import enqueue_participant_upsert


class Command(BaseCommand):
    help = "Enqueue MANDA participant_upsert jobs for existing Cognito-linked IMAA registrations."

    def add_arguments(self, parser):
        parser.add_argument(
            "--event-slug",
            dest="event_slug",
            default="",
            help="Limit to one event slug.",
        )
        parser.add_argument(
            "--event-id",
            dest="event_id",
            type=int,
            default=None,
            help="Limit to one event id.",
        )
        parser.add_argument(
            "--email",
            dest="email",
            default="",
            help="Limit to one user email.",
        )
        parser.add_argument(
            "--limit",
            dest="limit",
            type=int,
            default=100,
            help="Maximum registrations to inspect.",
        )
        parser.add_argument(
            "--commit",
            action="store_true",
            help="Actually create jobs. Without this flag, only prints what would happen.",
        )

    def handle(self, *args, **options):
        qs = (
            EventRegistration.objects.select_related("event", "user")
            .filter(status="registered")
            .exclude(attendee_status="cancelled")
            .order_by("id")
        )

        if options["event_slug"]:
            qs = qs.filter(event__slug=options["event_slug"])
        if options["event_id"]:
            qs = qs.filter(event_id=options["event_id"])
        if options["email"]:
            qs = qs.filter(user__email__iexact=options["email"])

        limit = max(options["limit"], 0)
        qs = qs[:limit]

        checked = 0
        created = 0
        skipped = 0

        for reg in qs:
            checked += 1
            if not options["commit"]:
                self.stdout.write(
                    "DRY RUN registration_id={reg_id} event={event_id}:{slug} "
                    "user={email} canonical_event_id={canonical}".format(
                        reg_id=reg.id,
                        event_id=reg.event_id,
                        slug=reg.event.slug,
                        email=reg.user.email,
                        canonical=reg.event.canonical_event_id,
                    )
                )
                continue

            jobs = enqueue_participant_upsert(reg)
            if jobs:
                created += len(jobs)
                self.stdout.write(
                    self.style.SUCCESS(
                        "created job(s) {job_ids} for registration_id={reg_id}".format(
                            job_ids=",".join(str(job.id) for job in jobs),
                            reg_id=reg.id,
                        )
                    )
                )
            else:
                skipped += 1
                self.stdout.write(
                    "skipped registration_id={reg_id} event={event_id}:{slug} user={email}".format(
                        reg_id=reg.id,
                        event_id=reg.event_id,
                        slug=reg.event.slug,
                        email=reg.user.email,
                    )
                )

        self.stdout.write(
            self.style.SUCCESS(
                "checked={checked} created_jobs={created} skipped={skipped} commit={commit}".format(
                    checked=checked,
                    created=created,
                    skipped=skipped,
                    commit=options["commit"],
                )
            )
        )
