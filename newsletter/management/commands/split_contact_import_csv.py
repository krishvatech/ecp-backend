"""Split a contact CSV that exceeds the import limits into batch files.

    python manage.py split_contact_import_csv contacts.csv --out-dir ./batches

Writes <name>.part-01-of-02.csv, ... and <name>.manifest.json (row counts,
source row ranges and checksums). Nothing is imported: validate and import
each batch through Marketing Hub > Contacts > Import CSV, one at a time.
Existing files are never overwritten.
"""

from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from newsletter.contact_import_batches import manifest, split_csv
from newsletter.contact_import_services import ContactImportError, max_bytes, max_rows


class Command(BaseCommand):
    help = "Split a contact CSV into batches that fit the CSV import limits (no import)."

    def add_arguments(self, parser):
        parser.add_argument("source", help="CSV file to split")
        parser.add_argument("--out-dir", required=True, help="Directory for the batch files")
        parser.add_argument(
            "--rows", type=int, default=None, help=f"Contacts per batch (default and maximum: {max_rows():,})"
        )
        parser.add_argument(
            "--max-bytes", type=int, default=None, help=f"Bytes per batch (default and maximum: {max_bytes():,})"
        )

    def handle(self, *args, **options):
        for option in ("rows", "max_bytes"):
            if options[option] is not None and options[option] <= 0:
                raise CommandError(f"--{option.replace('_', '-')} must be greater than zero.")
        source = Path(options["source"])
        out_dir = Path(options["out_dir"])
        if not source.is_file():
            raise CommandError(f"{source} is not a file.")
        try:
            result = split_csv(
                source.read_bytes(), batch_rows=options["rows"], batch_bytes=options["max_bytes"]
            )
        except ContactImportError as exc:
            raise CommandError(str(exc)) from None

        count = len(result.batches)
        names = [f"{source.stem}.part-{n:02d}-of-{count:02d}.csv" for n in range(1, count + 1)]
        manifest_name = f"{source.stem}.manifest.json"
        out_dir.mkdir(parents=True, exist_ok=True)
        existing = [name for name in [*names, manifest_name] if (out_dir / name).exists()]
        if existing:
            raise CommandError("Refusing to overwrite: " + ", ".join(existing))

        for name, batch in zip(names, result.batches):
            with open(out_dir / name, "xb") as handle:
                handle.write(batch.content)
        data = manifest(result, names, source.name)
        with open(out_dir / manifest_name, "x", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)

        self.stdout.write(f"{result.total_rows:,} contact rows -> {count} batch file(s) in {out_dir}")
        for entry in data["batches"]:
            first, last = entry["source_rows"]
            self.stdout.write(f"  {entry['file']}: {entry['rows']:,} rows (source rows {first}-{last})")
        if result.blank_records_dropped:
            self.stdout.write(
                f"  {result.blank_records_dropped} blank record(s) after the last contact did not fit and were left out."
            )
        self.stdout.write(f"Manifest: {out_dir / manifest_name}. Import each batch separately; nothing was imported.")
