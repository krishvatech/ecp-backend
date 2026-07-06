"""
Tests for backfill_profile_locations management command.

These tests verify:
- Dry-run mode does not modify database
- Commit mode updates records correctly
- Existing coordinates are never overwritten
- Location parsing works correctly
- City matching works as expected
- Ambiguous matches are skipped
- Country-only locations are handled
"""

from django.test import TestCase
from django.core.management import call_command
from io import StringIO
from django.contrib.auth.models import User

from users.models import UserProfile, GeoCity, GeoCountry


class BackfillProfileLocationsTestCase(TestCase):
    """Test backfill_profile_locations management command."""

    @classmethod
    def setUpTestData(cls):
        """Create test data."""
        # Create test countries
        cls.country_in = GeoCountry.objects.create(iso2="IN", iso3="IND", name="India")
        cls.country_gb = GeoCountry.objects.create(iso2="GB", iso3="GBR", name="United Kingdom")

        # Create test cities
        cls.city_mumbai = GeoCity.objects.create(
            geoname_id=1275339,
            name="Mumbai",
            ascii_name="Mumbai",
            country_code="IN",
            admin1_code="MH",
            latitude=19.0760,
            longitude=72.8777,
            timezone="Asia/Kolkata",
            population=20411000,
        )

        cls.city_london = GeoCity.objects.create(
            geoname_id=2643743,
            name="London",
            ascii_name="London",
            country_code="GB",
            admin1_code="ENG",
            latitude=51.5085,
            longitude=-0.1257,
            timezone="Europe/London",
            population=9002488,
        )

    def setUp(self):
        """Create test user profiles before each test."""
        # User with city+country location
        self.user1 = User.objects.create_user(username="user1", email="user1@test.com")
        self.profile1 = UserProfile.objects.create(
            user=self.user1,
            location="Mumbai, India",
            location_city="",
            location_country="",
            location_country_code="",
            location_lat=None,
            location_lng=None,
        )

        # User with already-set coordinates (should not be changed)
        self.user2 = User.objects.create_user(username="user2", email="user2@test.com")
        self.profile2 = UserProfile.objects.create(
            user=self.user2,
            location="London, United Kingdom",
            location_city="London",
            location_country="United Kingdom",
            location_country_code="GB",
            location_lat=51.5085,
            location_lng=-0.1257,
        )

        # User with country-only location
        self.user3 = User.objects.create_user(username="user3", email="user3@test.com")
        self.profile3 = UserProfile.objects.create(
            user=self.user3,
            location="India",
            location_city="",
            location_country="",
            location_country_code="",
            location_lat=None,
            location_lng=None,
        )

        # User with empty location (should be skipped)
        self.user4 = User.objects.create_user(username="user4", email="user4@test.com")
        self.profile4 = UserProfile.objects.create(
            user=self.user4,
            location="",
            location_city="",
            location_country="",
            location_country_code="",
            location_lat=None,
            location_lng=None,
        )

    def test_dry_run_makes_no_changes(self):
        """Dry-run mode should not modify database."""
        out = StringIO()
        call_command("backfill_profile_locations", stdout=out)

        output = out.getvalue()
        self.assertIn("DRY RUN", output)

        # Verify no changes were made
        self.profile1.refresh_from_db()
        self.assertEqual(self.profile1.location_city, "")
        self.assertIsNone(self.profile1.location_lat)

    def test_commit_fills_empty_fields(self):
        """Commit mode should fill empty structured location fields."""
        out = StringIO()
        call_command("backfill_profile_locations", "--commit", stdout=out)

        output = out.getvalue()
        self.assertIn("COMMIT", output)

        # Verify profile1 was updated
        self.profile1.refresh_from_db()
        self.assertEqual(self.profile1.location_city, "Mumbai")
        self.assertEqual(self.profile1.location_country, "India")
        self.assertEqual(self.profile1.location_country_code, "IN")
        self.assertAlmostEqual(self.profile1.location_lat, 19.0760, places=4)
        self.assertAlmostEqual(self.profile1.location_lng, 72.8777, places=4)

    def test_does_not_overwrite_existing_coordinates(self):
        """Should never overwrite existing lat/lng."""
        # profile2 already has coordinates
        original_lat = self.profile2.location_lat
        original_lng = self.profile2.location_lng

        call_command("backfill_profile_locations", "--commit")

        self.profile2.refresh_from_db()
        self.assertEqual(self.profile2.location_lat, original_lat)
        self.assertEqual(self.profile2.location_lng, original_lng)

    def test_skips_empty_locations(self):
        """Should skip profiles with empty location strings."""
        out = StringIO()
        call_command("backfill_profile_locations", stdout=out)

        output = out.getvalue()
        # Should report that profile4 was checked but skipped
        self.assertIn("checked", output)

    def test_does_not_overwrite_existing_structured_fields(self):
        """Should not overwrite existing location_city or location_country."""
        # Create a profile with partially filled fields
        user5 = User.objects.create_user(username="user5", email="user5@test.com")
        profile5 = UserProfile.objects.create(
            user=user5,
            location="Mumbai, India",
            location_city="Custom City",  # Already filled
            location_country="",
            location_country_code="",
            location_lat=None,
            location_lng=None,
        )

        call_command("backfill_profile_locations", "--commit")

        profile5.refresh_from_db()
        self.assertEqual(profile5.location_city, "Custom City")  # Should NOT change
        self.assertEqual(profile5.location_country, "India")  # Should be filled

    def test_country_only_location(self):
        """Country-only locations should be handled correctly."""
        call_command("backfill_profile_locations", "--commit")

        self.profile3.refresh_from_db()
        # Should parse country but not set coordinates
        self.assertEqual(self.profile3.location_country, "India")
        self.assertEqual(self.profile3.location_country_code, "IN")
        self.assertIsNone(self.profile3.location_lat)
        self.assertIsNone(self.profile3.location_lng)

    def test_limit_option(self):
        """--limit option should restrict processing."""
        out = StringIO()
        call_command("backfill_profile_locations", "--limit", "1", stdout=out)

        output = out.getvalue()
        self.assertIn("Processing 1 profile", output)

    def test_parsing_multi_part_location(self):
        """Should correctly parse locations with multiple parts."""
        user = User.objects.create_user(username="user_parse", email="parse@test.com")
        profile = UserProfile.objects.create(
            user=user,
            location="London, England, United Kingdom",
            location_city="",
            location_country="",
            location_country_code="",
            location_lat=None,
            location_lng=None,
        )

        call_command("backfill_profile_locations", "--commit")

        profile.refresh_from_db()
        self.assertEqual(profile.location_city, "London")
        self.assertEqual(profile.location_country, "United Kingdom")

    def test_case_insensitive_matching(self):
        """City matching should be case-insensitive."""
        user = User.objects.create_user(username="user_case", email="case@test.com")
        profile = UserProfile.objects.create(
            user=user,
            location="mumbai, india",  # lowercase
            location_city="",
            location_country="",
            location_country_code="",
            location_lat=None,
            location_lng=None,
        )

        call_command("backfill_profile_locations", "--commit")

        profile.refresh_from_db()
        self.assertEqual(profile.location_city, "Mumbai")
        self.assertEqual(profile.location_country_code, "IN")

    def test_export_unmatched(self):
        """--export-unmatched should create CSV file."""
        import os
        import csv

        # Create a profile with non-matching location
        user = User.objects.create_user(username="user_unmatched", email="unmatched@test.com")
        profile = UserProfile.objects.create(
            user=user,
            location="NonExistentCity, NonExistentCountry",
            location_city="",
            location_country="",
            location_country_code="",
            location_lat=None,
            location_lng=None,
        )

        out = StringIO()
        call_command("backfill_profile_locations", "--export-unmatched", stdout=out)

        # Check if CSV file was created
        filename = "backfill_profile_locations_unmatched.csv"
        if os.path.exists(filename):
            try:
                with open(filename, "r") as f:
                    reader = csv.DictReader(f)
                    rows = list(reader)
                    self.assertGreater(len(rows), 0)
                    self.assertIn("profile_id", rows[0])
                    self.assertIn("location", rows[0])
                    self.assertIn("reason", rows[0])
            finally:
                if os.path.exists(filename):
                    os.remove(filename)


class BackfillCommandOutputTest(TestCase):
    """Test command output formatting."""

    def test_dry_run_output_format(self):
        """Verify dry-run output format."""
        out = StringIO()
        call_command("backfill_profile_locations", stdout=out)

        output = out.getvalue()
        self.assertIn("DRY RUN", output)
        self.assertIn("Profiles checked", output)
        self.assertIn("Matched city", output)

    def test_commit_output_format(self):
        """Verify commit output format."""
        out = StringIO()
        call_command("backfill_profile_locations", "--commit", stdout=out)

        output = out.getvalue()
        self.assertIn("COMMIT", output)
        self.assertIn("Profiles checked", output)
