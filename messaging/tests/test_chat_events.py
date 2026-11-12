"""GET /api/messaging/conversations/chat-events/ (Sentry ECP-BACKEND-P).

The view used to put the Event.cover_image FieldFile itself into the
response. DRF's JSON encoder then iterated the file: it downloaded the
image from storage and tried to UTF-8 decode the JPEG bytes, which raised
UnicodeDecodeError ("can't decode byte 0xff in position 0") and returned
500 for anyone linked to an event that has a cover image.

Storage is swapped for Django's in-memory backend so no test touches S3.
"""
from datetime import timedelta
from io import BytesIO
from types import SimpleNamespace

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.test import TestCase, override_settings
from django.utils import timezone
from PIL import Image
from rest_framework.test import APIClient

from community.models import Community
from events.guest_auth import GuestPrincipal
from events.models import Event, EventRegistration

URL = "/api/messaging/conversations/chat-events/"

IN_MEMORY_STORAGES = {
    **settings.STORAGES,
    "default": {"BACKEND": "django.core.files.storage.InMemoryStorage"},
}


def jpeg_bytes():
    out = BytesIO()
    Image.new("RGB", (8, 8), "navy").save(out, format="JPEG")
    data = out.getvalue()
    assert data[:1] == b"\xff"  # the byte from the Sentry error
    return data


@override_settings(STORAGES=IN_MEMORY_STORAGES)
class ChatEventsCoverImageTests(TestCase):
    def setUp(self):
        User = get_user_model()
        now = timezone.now()
        self.owner = User.objects.create_user(username="chat-events-owner")
        self.member = User.objects.create_user(username="chat-events-member")
        community = Community.objects.create(name="Chat events community", owner=self.owner)

        def event(title):
            ev = Event(
                title=title, community=community, created_by=self.owner,
                format="virtual", status="ended",
                start_time=now - timedelta(days=3), end_time=now - timedelta(days=2),
            )
            ev.skip_saleor_sync = True
            ev.save()
            return ev

        self.with_cover = event("Event with cover")
        self.without_cover = event("Event without cover")

        # Store the image directly so Event.save() image hooks never run.
        self.cover_name = default_storage.save(
            "previews/event/ma-asia-2026-kv-optimized.jpg", ContentFile(jpeg_bytes())
        )
        Event.objects.filter(pk=self.with_cover.pk).update(cover_image=self.cover_name)

    def get_rows(self, user):
        client = APIClient()
        client.force_authenticate(user)
        response = client.get(URL)
        self.assertEqual(response.status_code, 200)
        return {row["id"]: row for row in response.json()}

    def assert_cover_url(self, row):
        self.assertIsInstance(row["cover_image"], str)
        self.assertTrue(row["cover_image"].endswith(self.cover_name), row["cover_image"])

    def test_registered_member_gets_cover_image_as_url(self):
        for ev in (self.with_cover, self.without_cover):
            EventRegistration.objects.create(event=ev, user=self.member, status="registered")

        rows = self.get_rows(self.member)

        self.assert_cover_url(rows[self.with_cover.id])
        self.assertEqual(rows[self.without_cover.id]["cover_image"], "")
        self.assertEqual(rows[self.with_cover.id]["title"], "Event with cover")

    def test_event_creator_gets_cover_image_as_url(self):
        rows = self.get_rows(self.owner)

        self.assert_cover_url(rows[self.with_cover.id])
        self.assertEqual(rows[self.without_cover.id]["cover_image"], "")

    def test_guest_gets_cover_image_as_url(self):
        guest = SimpleNamespace(
            id=1, email="guest@example.com", event_id=self.with_cover.id,
            get_display_name=lambda: "Guest",
        )

        rows = self.get_rows(GuestPrincipal(guest))

        self.assertEqual(list(rows), [self.with_cover.id])
        self.assert_cover_url(rows[self.with_cover.id])
