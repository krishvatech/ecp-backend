"""
Repair names garbled by a UTF-8 -> Latin-1/cp1252 mis-decode
(e.g. "çŽ‹ä½©æ´" -> "王佩洁") on User and UserProfile.

- Default behavior is dry-run (no database changes).
- Requires explicit --commit flag to update records.
- Only rewrites values that decode as strict UTF-8, so genuine accented
  names ("José Müller") are never touched.

Usage:
    python manage.py repair_mojibake_names              # dry-run
    python manage.py repair_mojibake_names --commit     # apply changes
    python manage.py repair_mojibake_names -v 2         # also print old/new values
"""

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.db import transaction
from django.db.models import Q

from users.kyc_name_match import looks_like_mojibake, repair_mojibake
from users.models import UserProfile

USER_FIELDS = ("first_name", "last_name")
PROFILE_FIELDS = ("full_name", "middle_name")


class Command(BaseCommand):
    help = "Repair mojibake (garbled UTF-8) in user and profile name fields."

    def add_arguments(self, parser):
        parser.add_argument("--commit", action="store_true", help="Write changes to the database.")

    def _candidates(self, model, fields):
        # Every mojibake sequence starts with one of these lead characters.
        q = Q()
        for field in fields:
            for lead in ("Ã", "Â", "Ä", "Å", "Æ", "Ç", "Ð", "Ñ", "â", "ã", "ä", "å", "æ", "ç", "è", "é", "ê", "ë", "ì", "í", "î", "ï", "ð"):
                q |= Q(**{f"{field}__contains": lead})
        return model.objects.filter(q)

    def _repair(self, obj, fields, label):
        changed = []
        for field in fields:
            old = getattr(obj, field) or ""
            if not looks_like_mojibake(old):
                continue
            new = repair_mojibake(old)
            if new == old:
                self.stdout.write(self.style.WARNING(f"  {label} #{obj.pk} {field}: garbled but not repairable, skipped"))
                continue
            setattr(obj, field, new)
            changed.append(field)
            msg = f"  {label} #{obj.pk} {field}: repaired"
            if self.verbosity >= 2:
                msg += f" {old!r} -> {new!r}"
            self.stdout.write(msg)
        return changed

    def handle(self, *args, **options):
        self.verbosity = options.get("verbosity", 1)
        commit = options["commit"]
        total = 0

        with transaction.atomic():
            for user in self._candidates(User, USER_FIELDS):
                changed = self._repair(user, USER_FIELDS, "User")
                if changed:
                    total += 1
                    if commit:
                        user.save(update_fields=changed)

            for profile in self._candidates(UserProfile, PROFILE_FIELDS):
                changed = self._repair(profile, PROFILE_FIELDS, "UserProfile")
                if changed:
                    total += 1
                    if commit:
                        profile.save(update_fields=changed)

        if commit:
            self.stdout.write(self.style.SUCCESS(f"Repaired {total} record(s)."))
        else:
            self.stdout.write(self.style.WARNING(f"Dry run: {total} record(s) would be repaired. Re-run with --commit to apply."))
