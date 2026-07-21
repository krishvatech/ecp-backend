from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from rest_framework.test import APIClient

from friends.models import Friendship
from users.models import Experience, GeoCity, UserProfile


User = get_user_model()


class MemberDirectoryMapPointsTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.viewer = self._create_user("viewer", "Viewer", "Member")
        self.client.force_authenticate(self.viewer)

        GeoCity.objects.create(
            geoname_id=2643743,
            name="London",
            ascii_name="London",
            country_code="GB",
            latitude=51.5085,
            longitude=-0.1257,
            population=9002488,
        )

    def _create_user(
        self,
        username,
        first_name,
        last_name,
        *,
        location="London, United Kingdom",
        city="London",
        country="United Kingdom",
        country_code="GB",
        latitude=None,
        longitude=None,
        directory_hidden=False,
        profile_status="active",
    ):
        user = User.objects.create_user(
            username=username,
            email=f"{username}@example.com",
            first_name=first_name,
            last_name=last_name,
            password="test-password",
        )
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.full_name = f"{first_name} {last_name}"
        profile.location = location
        profile.location_city = city
        profile.location_country = country
        profile.location_country_code = country_code
        profile.location_lat = latitude
        profile.location_lng = longitude
        profile.directory_hidden = directory_hidden
        profile.profile_status = profile_status
        profile.save()
        return user

    def _add_experience(self, user, company="Acme Advisory", position="Director"):
        return Experience.objects.create(
            user=user,
            community_name=company,
            position=position,
            industry="Financial Services",
            number_of_employees="51-200",
            currently_work_here=True,
        )

    def test_compact_map_endpoint_returns_only_map_shape_and_resolves_city_once(self):
        member = self._create_user("member", "Map", "Member")
        self._add_experience(member)

        response = self.client.get(reverse("user-roster-map-points"))

        self.assertEqual(response.status_code, 200)
        result = next(item for item in response.data if item["id"] == member.id)
        self.assertEqual(result["first_name"], "Map")
        self.assertEqual(result["profile"]["location_lat"], 51.5085)
        self.assertEqual(result["profile"]["location_lng"], -0.1257)
        self.assertFalse(result["is_contact"])
        self.assertNotIn("email", result)
        self.assertNotIn("company_from_experience", result)

    def test_map_endpoint_respects_hidden_and_blocked_profile_rules(self):
        visible = self._create_user("visible", "Visible", "Member")
        hidden = self._create_user(
            "hidden",
            "Hidden",
            "Member",
            directory_hidden=True,
        )
        blocked = self._create_user(
            "blocked",
            "Blocked",
            "Member",
            profile_status="suspended",
        )

        response = self.client.get(reverse("user-roster-map-points"))
        returned_ids = {item["id"] for item in response.data}

        self.assertIn(visible.id, returned_ids)
        self.assertNotIn(hidden.id, returned_ids)
        self.assertNotIn(blocked.id, returned_ids)

    def test_contacts_only_returns_active_contacts_and_marks_them(self):
        active_contact = self._create_user("active-contact", "Active", "Contact")
        removed_contact = self._create_user("removed-contact", "Removed", "Contact")
        stranger = self._create_user("stranger", "Other", "Member")

        Friendship.objects.create(
            user1=min(self.viewer, active_contact, key=lambda user: user.id),
            user2=max(self.viewer, active_contact, key=lambda user: user.id),
            status=Friendship.STATUS_ACTIVE,
        )
        Friendship.objects.create(
            user1=min(self.viewer, removed_contact, key=lambda user: user.id),
            user2=max(self.viewer, removed_contact, key=lambda user: user.id),
            status=Friendship.STATUS_REMOVED,
        )

        response = self.client.get(
            reverse("user-roster-map-points"),
            {"contacts_only": "1"},
        )
        returned = {item["id"]: item for item in response.data}

        self.assertIn(active_contact.id, returned)
        self.assertTrue(returned[active_contact.id]["is_contact"])
        self.assertNotIn(removed_contact.id, returned)
        self.assertNotIn(stranger.id, returned)

        bulk_response = self.client.get(
            reverse("friends-status-bulk"),
            {"user_ids": f"{active_contact.id},{removed_contact.id}"},
        )
        self.assertEqual(bulk_response.status_code, 200)
        self.assertEqual(
            bulk_response.data["results"][str(active_contact.id)]["status"],
            "friends",
        )
        self.assertEqual(
            bulk_response.data["results"][str(removed_contact.id)]["status"],
            "none",
        )

    def test_map_does_not_use_a_city_from_the_wrong_country(self):
        GeoCity.objects.create(
            geoname_id=4409896,
            name="Springfield",
            ascii_name="Springfield",
            country_code="US",
            latitude=37.2153,
            longitude=-93.2982,
            population=169176,
        )
        member = self._create_user(
            "springfield-unknown-country",
            "Springfield",
            "Member",
            location="Springfield, Unknown",
            city="Springfield",
            country="Unknown",
            country_code="ZZ",
        )

        response = self.client.get(reverse("user-roster-map-points"))

        self.assertEqual(response.status_code, 200)
        result = next(item for item in response.data if item["id"] == member.id)
        self.assertIsNone(result["profile"]["location_lat"])
        self.assertIsNone(result["profile"]["location_lng"])

    def test_map_keeps_city_only_fallback_when_country_code_is_missing(self):
        GeoCity.objects.create(
            geoname_id=4409896,
            name="Springfield",
            ascii_name="Springfield",
            country_code="US",
            latitude=37.2153,
            longitude=-93.2982,
            population=169176,
        )
        member = self._create_user(
            "springfield-no-country",
            "Springfield",
            "Member",
            location="Springfield",
            city="Springfield",
            country="",
            country_code="",
        )

        response = self.client.get(reverse("user-roster-map-points"))

        self.assertEqual(response.status_code, 200)
        result = next(item for item in response.data if item["id"] == member.id)
        self.assertEqual(result["profile"]["location_lat"], 37.2153)
        self.assertEqual(result["profile"]["location_lng"], -93.2982)

    def test_map_query_count_does_not_grow_four_queries_per_member(self):
        for index in range(20):
            member = self._create_user(
                f"member-{index}",
                "Performance",
                str(index),
                latitude=10.0 + index,
                longitude=20.0 + index,
            )
            self._add_experience(member, company=f"Company {index}")

        with CaptureQueriesContext(connection) as queries:
            response = self.client.get(reverse("user-roster-map-points"))

        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(
            len(queries),
            10,
            f"Expected a constant number of map queries, got {len(queries)}",
        )

    def test_roster_reuses_prefetched_best_experience(self):
        for index in range(5):
            member = self._create_user(
                f"roster-member-{index}",
                "Roster",
                str(index),
            )
            self._add_experience(member, company=f"Roster Company {index}")

        with CaptureQueriesContext(connection) as queries:
            response = self.client.get(
                reverse("user-roster"),
                {"page": 1, "page_size": 5},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data["results"]), 5)
        self.assertLessEqual(
            len(queries),
            12,
            f"Expected prefetched roster experiences, got {len(queries)} queries",
        )
