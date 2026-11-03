"""Event Companion participant directory is sorted by last name."""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from community.models import Community
from events.models import Event, EventPlatform, EventPublication, EventRegistration
from events.views import _last_name_sort_key


class LastNameSortKeyTests(SimpleTestCase):
    def test_uses_stored_last_name(self):
        self.assertEqual(
            _last_name_sort_key("Maria de Souza", "Maria", "de Souza"),
            ("de souza", "maria", "maria de souza"),
        )

    def test_falls_back_to_final_word_of_display_name(self):
        self.assertEqual(_last_name_sort_key("Alex  Loh"), ("loh", "alex", "alex  loh"))
        self.assertEqual(_last_name_sort_key("Madonna"), ("madonna", "", "madonna"))
        self.assertEqual(_last_name_sort_key(""), ("", "", ""))
        self.assertEqual(_last_name_sort_key(None), ("", "", ""))

    def test_full_name_in_first_name_only(self):
        self.assertEqual(_last_name_sort_key("Aaron Tay", "Aaron Tay", ""), ("tay", "aaron", "aaron tay"))

    def test_case_and_accent_insensitive(self):
        self.assertEqual(_last_name_sort_key("Zoë Ångström")[0], "angstrom")
        self.assertEqual(_last_name_sort_key("albert ee")[0], "ee")


class CompanionDirectorySortTests(TestCase):
    def setUp(self):
        User = get_user_model()
        now = timezone.now()
        owner = User.objects.create_user(username="sort-owner", password="pass")
        community = Community.objects.create(name="Sort community", owner=owner)
        platform, _ = EventPlatform.objects.update_or_create(
            slug="imaa_connect", defaults={"name": "IMAA Connect", "is_active": True},
        )
        self.event = Event(
            title="Sort summit", community=community, created_by=owner, format="in_person",
            status="published", start_time=now - timedelta(hours=1), end_time=now + timedelta(hours=5),
        )
        self.event.skip_saleor_sync = True
        self.event.save()
        # Non-admin event lookups require an enabled IMAA Connect publication.
        EventPublication.objects.get_or_create(event=self.event, platform=platform, defaults={"is_enabled": True})

        names = [
            ("Aaron", "Tay"),
            ("albert", "ee"),
            ("Alex", "Loh"),
            ("Zoë", "Ångström"),
            ("Maria", "de Souza"),
            ("Bob", "Loh"),
        ]
        self.users = []
        for i, (first, last) in enumerate(names):
            user = User.objects.create_user(
                username=f"sort-user-{i}", email=f"sort{i}@example.com",
                first_name=first, last_name=last,
            )
            EventRegistration.objects.create(event=self.event, user=user, status="registered")
            self.users.append(user)

        self.client = APIClient()
        self.client.force_authenticate(self.users[0])

    def test_participants_sorted_by_last_name_then_first_name(self):
        response = self.client.get(f"/api/events/{self.event.id}/companion-directory/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [row["display_name"] for row in response.data["participants"]],
            ["Zoë Ångström", "Maria de Souza", "albert ee", "Alex Loh", "Bob Loh", "Aaron Tay"],
        )
