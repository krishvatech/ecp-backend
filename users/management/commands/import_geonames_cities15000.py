from django.core.management.base import BaseCommand
from django.conf import settings
from django.utils.dateparse import parse_date
from pathlib import Path

from users.models import GeoCity


class Command(BaseCommand):
    help = "Import GeoNames cities15000.txt into GeoCity table (offline)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--file",
            type=str,
            default="data/geonames/cities15000.txt",
            help="Path to cities15000.txt",
        )
        parser.add_argument(
            "--truncate",
            action="store_true",
            help="Delete existing GeoCity rows before import",
        )

    def handle(self, *args, **options):
        file_path = Path(options["file"])
        if not file_path.is_absolute():
            file_path = Path(settings.BASE_DIR) / file_path

        if not file_path.exists():
            self.stderr.write(self.style.ERROR(f"File not found: {file_path}"))
            return

        if options["truncate"]:
            GeoCity.objects.all().delete()
            self.stdout.write(self.style.WARNING("GeoCity truncated."))

        batch = []
        created = 0
        skipped = 0
        batch_size = 2000

        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                parts = line.split("\t")
                if len(parts) < 19:
                    skipped += 1
                    continue

                try:
                    geoname_id = int(parts[0])
                    name = parts[1]
                    ascii_name = parts[2]
                    lat = float(parts[4]) if parts[4] else None
                    lng = float(parts[5]) if parts[5] else None
                    feature_class = parts[6] or ""
                    feature_code = parts[7] or ""
                    country_code = (parts[8] or "").upper()
                    admin1 = parts[10] or ""
                    admin2 = parts[11] or ""
                    population = int(parts[14]) if parts[14] else 0
                    tz = parts[17] or ""
                    modified_at = parse_date(parts[18]) if parts[18] else None
                except Exception:
                    skipped += 1
                    continue

                batch.append(
                    GeoCity(
                        geoname_id=geoname_id,
                        name=name,
                        ascii_name=ascii_name,
                        country_code=country_code,
                        admin1_code=admin1,
                        admin2_code=admin2,
                        latitude=lat,
                        longitude=lng,
                        feature_class=feature_class,
                        feature_code=feature_code,
                        population=population,
                        timezone=tz,
                        modified_at=modified_at,
                    )
                )

                if len(batch) >= batch_size:
                    GeoCity.objects.bulk_create(batch, ignore_conflicts=True, batch_size=batch_size)
                    created += len(batch)
                    batch = []

        if batch:
            GeoCity.objects.bulk_create(batch, ignore_conflicts=True, batch_size=batch_size)
            created += len(batch)

        self.stdout.write(self.style.SUCCESS(f"Imported (attempted): {created}, skipped lines: {skipped}"))
