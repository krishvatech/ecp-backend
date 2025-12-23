from django.core.management.base import BaseCommand
from django.conf import settings
from pathlib import Path

from users.models import GeoCountry

class Command(BaseCommand):
    help = "Import GeoNames CountryInfo.txt into GeoCountry"

    def add_arguments(self, parser):
        parser.add_argument("--file", required=True, help="Path to CountryInfo.txt")

    def handle(self, *args, **opts):
        path = Path(opts["file"])
        if not path.exists():
            self.stderr.write(self.style.ERROR(f"File not found: {path}"))
            return

        to_create = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split("\t")
                # CountryInfo columns: ISO, ISO3, ISO-Numeric, fips, Country, ...
                # We only need ISO (0), ISO3 (1), Country (4)
                if len(parts) < 5:
                    continue

                iso2 = parts[0].strip()
                iso3 = parts[1].strip()
                name = parts[4].strip()

                if len(iso2) != 2 or not name:
                    continue

                to_create.append(GeoCountry(iso2=iso2, iso3=iso3, name=name))

        # upsert style (simple + safe)
        # If table is small, easiest is clear + insert, OR update_or_create in loop.
        # Here: bulk create ignore conflicts, then update missing names if needed.
        GeoCountry.objects.bulk_create(to_create, ignore_conflicts=True)

        # ensure names are updated (optional)
        for c in to_create:
            GeoCountry.objects.filter(iso2=c.iso2).update(name=c.name, iso3=c.iso3)

        self.stdout.write(self.style.SUCCESS(f"Imported/updated {len(to_create)} countries"))
