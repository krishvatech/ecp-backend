from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models import Q

from events.models import (
    Event,
    EventApplication,
    EventApplicationTrackApplication,
    EventPreApprovalCode,
)


# A code is marked used in the same request that creates its track application,
# so a genuine pair is created within seconds of each other.
MAX_USED_AT_DRIFT = timedelta(minutes=10)


class Command(BaseCommand):
    help = (
        "Link historical track applications to the pre-approval code they used. "
        "Read-only unless --apply is passed. Only fills empty per-track fields; "
        "never modifies codes, applications, or statuses."
    )

    def add_arguments(self, parser):
        parser.add_argument("--event", help="Limit to one event (id or slug).")
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Write the unambiguous links. Without this flag nothing is changed.",
        )

    def handle(self, *args, **options):
        codes = (
            EventPreApprovalCode.objects
            .filter(status=EventPreApprovalCode.STATUS_USED, used_by_application__isnull=False)
            .select_related("track", "used_by_application")
            .order_by("used_at", "id")
        )
        if options["event"]:
            event_ref = options["event"]
            lookup = Q(slug=event_ref) | (Q(id=int(event_ref)) if event_ref.isdigit() else Q())
            event = Event.objects.filter(lookup).first()
            if not event:
                raise CommandError(f"Event not found: {event_ref}")
            codes = codes.filter(event=event)
            self.stdout.write(f"Event: {event.id} {event.title}")

        apply = options["apply"]
        self.stdout.write("Mode: APPLY" if apply else "Mode: DRY RUN (no changes)")

        # row_id -> list of (code, row); a row matched by more than one code is ambiguous
        matches = {}
        skipped = []
        for code in codes:
            candidates = EventApplicationTrackApplication.all_objects.filter(
                application_id=code.used_by_application_id
            ).select_related("track")
            if code.track_id:
                candidates = candidates.filter(track_id=code.track_id)
            if code.submission_mode:
                candidates = candidates.filter(submission_mode=code.submission_mode)
            if code.used_at:
                candidates = candidates.filter(
                    created_at__gte=code.used_at - MAX_USED_AT_DRIFT,
                    created_at__lte=code.used_at + MAX_USED_AT_DRIFT,
                )
            candidates = list(candidates)

            if len(candidates) != 1:
                skipped.append((code, f"{len(candidates)} matching track applications"))
                continue
            row = candidates[0]
            if row.preapproval_code_id == code.id:
                skipped.append((code, f"already linked to track application {row.id}"))
                continue
            if row.preapproval_code_id or row.preapproval_source != EventApplication.PREAPPROVAL_SOURCE_NONE:
                skipped.append((code, f"track application {row.id} already has pre-approval data"))
                continue
            matches.setdefault(row.id, []).append((code, row))

        linked = 0
        with transaction.atomic():
            for row_id, pairs in matches.items():
                if len(pairs) > 1:
                    for code, _ in pairs:
                        skipped.append((code, f"track application {row_id} matched by several codes"))
                    continue
                code, row = pairs[0]
                self.stdout.write(
                    f"  LINK track_app={row.id} app={row.application_id} "
                    f"track={row.track.label!r} mode={row.submission_mode} "
                    f"email={code.used_by_email} code={code.code!r}"
                )
                if apply:
                    # Guarded update: only fills rows that are still empty. .update()
                    # leaves updated_at untouched so review history is unchanged.
                    linked += EventApplicationTrackApplication.all_objects.filter(
                        id=row.id,
                        preapproval_code__isnull=True,
                        preapproval_source=EventApplication.PREAPPROVAL_SOURCE_NONE,
                    ).update(
                        preapproval_code=code,
                        preapproval_source=EventApplication.PREAPPROVAL_SOURCE_CODE,
                    )
                else:
                    linked += 1

        for code, reason in skipped:
            self.stdout.write(
                f"  SKIP code={code.code!r} app={code.used_by_application_id} "
                f"email={code.used_by_email}: {reason}"
            )

        verb = "Linked" if apply else "Would link"
        self.stdout.write(self.style.SUCCESS(f"{verb}: {linked} | Skipped: {len(skipped)}"))
