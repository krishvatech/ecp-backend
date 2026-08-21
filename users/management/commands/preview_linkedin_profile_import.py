from pathlib import Path
import json

from django.core.management.base import BaseCommand, CommandError

from users.linkedin_profile_import import (
    extract_profile_pdf_text,
    structure_profile_text,
)


class Command(BaseCommand):
    help = (
        "Preview LinkedIn PDF import extraction. "
        "Does not modify database."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "pdf_path",
            type=str,
            help="Path to LinkedIn profile PDF",
        )

    def handle(self, *args, **options):
        pdf_path = Path(options["pdf_path"])

        if not pdf_path.exists():
            raise CommandError(
                f"PDF not found: {pdf_path}"
            )

        try:
            with pdf_path.open("rb") as pdf_file:
                extracted_text = extract_profile_pdf_text(
                    pdf_file
                )

            profile_data = structure_profile_text(
                extracted_text
            )

        except Exception as exc:
            raise CommandError(
                str(exc)
            ) from exc

        self.stdout.write(
            json.dumps(
                profile_data,
                indent=2,
                ensure_ascii=False,
            )
        )