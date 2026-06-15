from django.core.management.base import BaseCommand

from courses.models import MoodleEnrollment


class Command(BaseCommand):
    help = "Remove local course enrollments for users without a linked WordPress/Edwiser account."

    def add_arguments(self, parser):
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Actually delete matching enrollments. Without this flag, the command only reports a dry run.",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=20,
            help="Number of sample rows to print in dry-run mode.",
        )

    def handle(self, *args, **options):
        apply_changes = options["apply"]
        limit = options["limit"]

        qs = MoodleEnrollment.objects.filter(user__profile__wordpress_id__isnull=True)
        total = qs.count()

        if not apply_changes:
            self.stdout.write(f"DRY RUN: found {total} enrollment(s) for users without wordpress_id.")
            for enrollment in qs.select_related("user", "course")[:limit]:
                self.stdout.write(
                    f"[WILL DELETE] user={enrollment.user.email} "
                    f"course={enrollment.course.full_name} "
                    f"enrollment_id={enrollment.id}"
                )
            self.stdout.write("Run again with --apply to delete these stale enrollments.")
            return

        deleted, _ = qs.delete()
        self.stdout.write(self.style.SUCCESS(f"Deleted {deleted} stale enrollment row(s)."))