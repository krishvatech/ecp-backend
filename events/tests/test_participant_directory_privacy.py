"""
Regression tests for the public participant directory.

``/api/events/<id>/participants/directory/`` and its ``/search/`` sibling are
anonymous endpoints. They listed every confirmed attendee, ignoring the
member's own ``UserProfile.directory_hidden`` opt-out. These tests pin that
hidden members appear in neither response, that opted-in attendees still do,
and that no email address is returned.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from community.models import Community
from events.models import Event, EventPlatform, EventPublication, EventRegistration
from users.models import UserProfile


User = get_user_model()


class ParticipantDirectoryPrivacyTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.owner = User.objects.create_user(
            username="directory-owner",
            email="directory-owner@example.com",
            password="pass1234",
        )
        self.community = Community.objects.create(
            name="Directory Community",
            owner=self.owner,
        )
        self.platform, _ = EventPlatform.objects.update_or_create(
            slug="imaa_connect",
            defaults={"name": "IMAA Connect", "is_active": True},
        )

        event = Event(
            community=self.community,
            created_by=self.owner,
            title="Directory Event",
            slug="directory-event",
            status="published",
            # The directory is only served for in-person events.
            format="in_person",
            location="Berlin",
            start_time=timezone.now() + timezone.timedelta(days=1),
            end_time=timezone.now() + timezone.timedelta(days=1, hours=2),
            is_free=True,
        )
        event.skip_saleor_sync = True
        event.save()
        EventPublication.objects.get_or_create(
            event=event,
            platform=self.platform,
            defaults={"is_enabled": True},
        )
        self.event = event

        self.visible_user = self._attendee("Vera", "Visible", directory_hidden=False)
        self.hidden_user = self._attendee("Hilda", "Hidden", directory_hidden=True)

    def _attendee(self, first_name, last_name, directory_hidden):
        user = User.objects.create_user(
            username=f"directory-{first_name.lower()}",
            email=f"directory-{first_name.lower()}@example.com",
            password="pass1234",
            first_name=first_name,
            last_name=last_name,
        )
        UserProfile.objects.update_or_create(
            user=user,
            defaults={
                "company": f"{last_name} Corp",
                "job_title": "Attendee",
                "directory_hidden": directory_hidden,
            },
        )
        EventRegistration.objects.create(
            event=self.event,
            user=user,
            status="registered",
            attendee_status="confirmed",
        )
        return user

    def _directory(self, **params):
        query = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"/api/events/{self.event.id}/participants/directory/"
        if query:
            url = f"{url}?{query}"
        return self.client.get(url)

    def test_directory_lists_opted_in_attendee(self):
        resp = self._directory(limit=100)
        self.assertEqual(resp.status_code, 200)

        body = resp.json()
        names = {row["display_name"] for row in body["results"]}
        self.assertIn("Vera Visible", names)
        self.assertEqual(body["count"], 1)

    def test_directory_excludes_hidden_attendee(self):
        resp = self._directory(limit=100)

        names = {row["display_name"] for row in resp.json()["results"]}
        self.assertNotIn("Hilda Hidden", names)
        self.assertNotIn("Hidden", resp.content.decode())

    def test_directory_search_excludes_hidden_attendee(self):
        resp = self._directory(limit=100, search="Hidden")

        self.assertEqual(resp.json()["results"], [])
        self.assertEqual(resp.json()["count"], 0)

    def test_search_endpoint_excludes_hidden_attendee(self):
        hidden = self.client.get(
            f"/api/events/{self.event.id}/participants/search/?q=Hidden"
        )
        visible = self.client.get(
            f"/api/events/{self.event.id}/participants/search/?q=Visible"
        )

        self.assertEqual(hidden.json()["results"], [])
        self.assertEqual(len(visible.json()["results"]), 1)

    def test_directory_exposes_no_email_address(self):
        resp = self._directory(limit=100)
        text = resp.content.decode()

        for row in resp.json()["results"]:
            self.assertNotIn("email", row)
        self.assertNotIn(self.visible_user.email, text)
        self.assertNotIn(self.hidden_user.email, text)
