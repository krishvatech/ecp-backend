"""
Production-safe management command to backfill UserProfile location fields.

⚠️ PRODUCTION SAFETY RULES ⚠️
- This command NEVER modifies existing user-entered data.
- It only fills empty/null fields with values safely derived from profile.location.
- It will never overwrite existing non-empty structured location fields.
- Default behavior is dry-run (no database changes).
- Requires explicit --commit flag to update records.

Usage:
    python manage.py backfill_profile_locations              # dry-run
    python manage.py backfill_profile_locations --commit     # apply changes
    python manage.py backfill_profile_locations --limit 100  # test with 100 records
    python manage.py backfill_profile_locations --export-unmatched  # export CSV of unmatched
"""

import csv
from io import StringIO
from django.core.management.base import BaseCommand
from django.db import transaction
from django.db.models import Q
from users.models import UserProfile, GeoCity, GeoCountry


class Command(BaseCommand):
    help = "Backfill structured location fields from existing profile.location values."

    def add_arguments(self, parser):
        parser.add_argument(
            "--commit",
            action="store_true",
            help="Actually update the database. Without this flag, only dry-run.",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=None,
            help="Limit number of profiles to process (for testing).",
        )
        parser.add_argument(
            "--user-id",
            type=int,
            default=None,
            help="Test on specific user ID only (e.g., --user-id 5)",
        )
        parser.add_argument(
            "--username",
            type=str,
            default=None,
            help="Test on specific username only (e.g., --username john_doe)",
        )
        parser.add_argument(
            "--export-unmatched",
            action="store_true",
            help="Export unmatched records to CSV file.",
        )

    def handle(self, *args, **options):
        commit = options.get("commit", False)
        limit = options.get("limit", None)
        user_id = options.get("user_id", None)
        username = options.get("username", None)
        export_unmatched = options.get("export_unmatched", False)

        if not commit:
            self.stdout.write(self.style.WARNING("DRY RUN ONLY - no database changes made\n"))
        else:
            self.stdout.write(self.style.SUCCESS("COMMIT MODE - database will be updated\n"))

        stats = self.backfill(
            commit=commit,
            limit=limit,
            user_id=user_id,
            username=username,
            export_unmatched=export_unmatched,
        )
        self.print_summary(stats, commit=commit)

    def backfill(self, commit=False, limit=None, user_id=None, username=None, export_unmatched=False):
        """
        Main backfill logic.
        Returns dict with statistics.
        """
        stats = {
            "checked": 0,
            "already_has_coords": 0,
            "matched_city": 0,
            "country_only": 0,
            "skipped_empty_location": 0,
            "skipped_ambiguous": 0,
            "skipped_no_match": 0,
            "errors": 0,
            "unmatched_records": [],
        }

        # Query profiles with non-empty location, ordered by ID
        qs = UserProfile.objects.filter(location__isnull=False).exclude(location="").order_by("id")

        # Filter by specific user if provided
        if user_id:
            qs = qs.filter(user_id=user_id)
            self.stdout.write(self.style.SUCCESS(f"Filtering to user_id={user_id}\n"))
        elif username:
            qs = qs.filter(user__username=username)
            self.stdout.write(self.style.SUCCESS(f"Filtering to username={username}\n"))

        if limit:
            qs = qs[:limit]

        total = qs.count()
        self.stdout.write(f"Processing {total} profiles with non-empty location...\n")

        profiles_to_update = []

        for profile in qs:
            stats["checked"] += 1

            # Show progress every 100 records
            if stats["checked"] % 100 == 0:
                self.stdout.write(f"  Processed {stats['checked']}/{total}...", ending="\r")

            try:
                # Skip if already has both lat and lng
                if profile.location_lat is not None and profile.location_lng is not None:
                    stats["already_has_coords"] += 1
                    continue

                # Parse location string
                parsed = self._parse_location(profile.location)
                city_name = parsed.get("city")
                country_name = parsed.get("country")

                if not city_name and not country_name:
                    stats["skipped_empty_location"] += 1
                    stats["unmatched_records"].append({
                        "profile_id": profile.id,
                        "user_id": profile.user_id,
                        "location": profile.location,
                        "parsed_city": None,
                        "parsed_country": None,
                        "reason": "Could not parse city or country from location",
                    })
                    continue

                # Try to find matching GeoCity
                match = self._find_matching_city(city_name, country_name)

                if not match:
                    # No city match found. Try country-only approach
                    if not city_name and country_name:
                        # Country-only location: try to fill country fields without coordinates
                        country_code = self._find_country_code(country_name)
                        if country_code:
                            update_data = {}
                            if not profile.location_country:
                                update_data["location_country"] = country_name
                            if not profile.location_country_code:
                                update_data["location_country_code"] = country_code

                            if update_data:
                                profiles_to_update.append((profile, update_data))
                                stats["country_only"] += 1
                            else:
                                stats["already_has_coords"] += 1
                        else:
                            stats["unmatched_records"].append({
                                "profile_id": profile.id,
                                "user_id": profile.user_id,
                                "location": profile.location,
                                "parsed_city": city_name,
                                "parsed_country": country_name,
                                "reason": "Country-only location (country not found in database)",
                            })
                            stats["skipped_no_match"] += 1
                        continue
                    else:
                        reason = "No city match found for city+country"
                        stats["skipped_no_match"] += 1

                    stats["unmatched_records"].append({
                        "profile_id": profile.id,
                        "user_id": profile.user_id,
                        "location": profile.location,
                        "parsed_city": city_name,
                        "parsed_country": country_name,
                        "reason": reason,
                    })
                    continue

                # Build update dict with only empty fields (city match found)
                update_data = {}

                if not profile.location_city:
                    update_data["location_city"] = match["city_name"]

                if not profile.location_country:
                    update_data["location_country"] = match["country_name"]

                if not profile.location_country_code:
                    update_data["location_country_code"] = match["country_code"]

                if profile.location_lat is None:
                    update_data["location_lat"] = match["lat"]

                if profile.location_lng is None:
                    update_data["location_lng"] = match["lng"]

                if not update_data:
                    # All fields already filled
                    stats["already_has_coords"] += 1
                    continue

                profiles_to_update.append((profile, update_data))
                stats["matched_city"] += 1

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"Error processing profile {profile.id}: {str(e)}")
                )
                stats["errors"] += 1
                continue

        # Perform batch update if --commit
        if commit and profiles_to_update:
            self._perform_batch_update(profiles_to_update)

        # Export unmatched if requested
        if export_unmatched and stats["unmatched_records"]:
            self._export_unmatched_csv(stats["unmatched_records"])

        return stats

    def _parse_location(self, location_str):
        """
        Parse location string into city and country.

        Examples:
        - "Mumbai, Maharashtra, India" -> {"city": "Mumbai", "country": "India"}
        - "London, United Kingdom" -> {"city": "London", "country": "United Kingdom"}
        - "India" -> {"city": None, "country": "India"}
        """
        if not location_str or not isinstance(location_str, str):
            return {"city": None, "country": None}

        parts = [p.strip() for p in location_str.split(",")]
        parts = [p for p in parts if p]

        if not parts:
            return {"city": None, "country": None}

        if len(parts) == 1:
            # Only one part: treat as country-only
            return {"city": None, "country": parts[0]}

        # Multiple parts: first = city, last = country
        city = parts[0]
        country = parts[-1]

        return {"city": city, "country": country}

    def _find_matching_city(self, city_name, country_name):
        """
        Find a matching GeoCity record.

        Returns dict with match data or None if no match found.

        Matching rules:
        - First try exact city + country match (case-insensitive)
        - If ambiguous (multiple matches), skip
        - If only country match, optionally fill country fields only (not lat/lng)
        """
        if not city_name or not country_name:
            return None

        # Try to find country code from country name
        country_code = self._find_country_code(country_name)
        if not country_code:
            return None

        # Try exact city + country match
        qs = GeoCity.objects.filter(
            country_code=country_code,
            name__iexact=city_name,
        ).order_by("-population")

        matches = list(qs[:2])  # Get top 2 to detect ambiguity

        if not matches:
            return None

        if len(matches) > 1:
            # Multiple matches: ambiguous
            return None

        city = matches[0]

        # Fetch country name
        try:
            country = GeoCountry.objects.get(iso2=city.country_code)
            country_name_resolved = country.name
        except GeoCountry.DoesNotExist:
            country_name_resolved = country_name

        return {
            "city_name": city.name,
            "country_name": country_name_resolved,
            "country_code": city.country_code,
            "lat": city.latitude,
            "lng": city.longitude,
        }

    def _find_country_code(self, country_name):
        """
        Find ISO2 country code from country name (case-insensitive).

        Returns country code or None if not found.
        """
        try:
            country = GeoCountry.objects.get(name__iexact=country_name)
            return country.iso2
        except GeoCountry.DoesNotExist:
            return None

    def _perform_batch_update(self, profiles_to_update):
        """
        Perform batch update with transaction safety.
        """
        updated_count = 0
        error_count = 0

        with transaction.atomic():
            for profile, update_data in profiles_to_update:
                try:
                    for key, value in update_data.items():
                        setattr(profile, key, value)

                    # Use update_fields to only update specific fields
                    profile.save(update_fields=list(update_data.keys()))
                    updated_count += 1

                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(f"Error updating profile {profile.id}: {str(e)}")
                    )
                    error_count += 1

        self.stdout.write(
            self.style.SUCCESS(f"\nUpdated {updated_count} profiles")
        )
        if error_count > 0:
            self.stdout.write(
                self.style.ERROR(f"Errors updating {error_count} profiles")
            )

    def _export_unmatched_csv(self, unmatched_records):
        """
        Export unmatched records to CSV file.
        """
        filename = "backfill_profile_locations_unmatched.csv"

        try:
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "profile_id",
                        "user_id",
                        "location",
                        "parsed_city",
                        "parsed_country",
                        "reason",
                    ],
                )
                writer.writeheader()
                writer.writerows(unmatched_records)

            self.stdout.write(
                self.style.SUCCESS(f"Exported {len(unmatched_records)} unmatched records to {filename}")
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Error exporting unmatched records: {str(e)}")
            )

    def print_summary(self, stats, commit=False):
        """
        Print final summary statistics.
        """
        self.stdout.write("\n" + "=" * 70)

        if not commit:
            self.stdout.write(self.style.WARNING("DRY RUN - NO DATABASE CHANGES MADE"))
        else:
            self.stdout.write(self.style.SUCCESS("COMMIT - DATABASE UPDATED"))

        self.stdout.write("=" * 70)
        self.stdout.write(f"Profiles checked:             {stats['checked']}")
        self.stdout.write(f"Already had coordinates:      {stats['already_has_coords']}")
        self.stdout.write(f"Matched city+coordinates:     {stats['matched_city']}")
        self.stdout.write(f"Country-only (no coords):     {stats['country_only']}")
        self.stdout.write(f"Skipped - ambiguous match:    {stats['skipped_ambiguous']}")
        self.stdout.write(f"Skipped - no match found:     {stats['skipped_no_match']}")
        self.stdout.write(f"Errors:                       {stats['errors']}")

        if not commit and stats['matched_city'] > 0:
            self.stdout.write(
                self.style.WARNING(
                    f"\nWould update: {stats['matched_city']} profiles (use --commit to apply)"
                )
            )

        unmatched_count = len(stats["unmatched_records"])
        if unmatched_count > 0:
            self.stdout.write(
                self.style.WARNING(f"\nUnmatched records: {unmatched_count}")
            )
            if unmatched_count <= 10:
                self.stdout.write("\nUnmatched records:")
                for record in stats["unmatched_records"]:
                    self.stdout.write(
                        f"  Profile {record['profile_id']}: {record['location']} "
                        f"({record['reason']})"
                    )
            else:
                self.stdout.write(
                    f"(use --export-unmatched to export to CSV)"
                )

        self.stdout.write("=" * 70)
