"""IPDT-778 regression tests: public logo showcase and admin/category boundaries.

Requires the event supporter tables created in the test database. Migrations are
intentionally not committed on the development branch per deployment workflow.
"""
from io import BytesIO
from tempfile import TemporaryDirectory

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from PIL import Image
from rest_framework.test import APIClient

from community.models import Community
from events.models import (
    Event, EventPlatform, EventPublication, EventSupporter, EventSupporterCategory,
)


class EventSupporterAPITests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._media_dir = TemporaryDirectory()
        cls._storage_override = override_settings(
            MEDIA_ROOT=cls._media_dir.name,
            STORAGES={
                "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
                "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
            },
        )
        cls._storage_override.enable()

    @classmethod
    def tearDownClass(cls):
        cls._storage_override.disable()
        cls._media_dir.cleanup()
        super().tearDownClass()

    @staticmethod
    def logo(name="logo.png"):
        buffer = BytesIO()
        Image.new("RGB", (20, 20), color="white").save(buffer, format="PNG")
        return SimpleUploadedFile(name, buffer.getvalue(), content_type="image/png")

    def setUp(self):
        User = get_user_model()
        self.owner = User.objects.create_user(username="supporter-owner", password="pw")
        self.other = User.objects.create_user(username="supporter-other", password="pw")
        self.admin = User.objects.create_superuser(username="supporter-admin", email="admin@example.com", password="pw")
        community = Community.objects.create(name="Supporter Test Community", owner=self.owner)
        self.event = Event(
            title="Supporter Public Event", slug="supporter-public-event",
            community=community, created_by=self.owner, status="published",
        )
        self.event.skip_saleor_sync = True
        self.event.save()
        self.platform, _ = EventPlatform.objects.get_or_create(
            slug="imaa_connect", defaults={"name": "IMAA Connect"}
        )
        EventPublication.objects.update_or_create(
            event=self.event, platform=self.platform, defaults={"is_enabled": True}
        )
        self.sponsor = EventSupporterCategory.objects.create(kind="sponsor", name="Diamond", display_order=10)
        self.partner = EventSupporterCategory.objects.create(kind="partner", name="Media Partner", display_order=20)
        self.client = APIClient()
        self.list_url = f"/api/events/{self.event.pk}/supporters/"
        self.types_url = "/api/events/supporter-categories/"

    def add_logo(self, category=None):
        self.client.force_authenticate(user=self.owner)
        return self.client.post(self.list_url, {
            "name": "Datasite", "category": category or self.sponsor.pk, "logo": self.logo(),
        }, format="multipart")

    def test_owner_creates_and_anon_reads_event_specific_logo(self):
        created = self.add_logo()
        self.assertEqual(created.status_code, 201, created.data)
        self.assertEqual(created.data["kind"], "sponsor")
        self.assertTrue(created.data["logo_url"])
        self.client.force_authenticate(user=None)
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["category_name"], "Diamond")

    def test_partner_tagging_and_per_event_isolation(self):
        self.assertEqual(self.add_logo(category=self.partner.pk).status_code, 201)
        self.client.force_authenticate(user=None)
        response = self.client.get(self.list_url)
        self.assertEqual(response.data[0]["kind"], "partner")
        # The same category can be reused without sharing entries across events.
        second_event = Event(
            title="Second Event", slug="second-supporter-event",
            community=self.event.community, created_by=self.owner, status="published",
        )
        second_event.skip_saleor_sync = True
        second_event.save()
        EventPublication.objects.create(event=second_event, platform=self.platform, is_enabled=True)
        self.assertEqual(self.client.get(f"/api/events/{second_event.pk}/supporters/").data, [])

    def test_only_creator_or_superuser_can_mutate(self):
        self.client.force_authenticate(user=self.other)
        response = self.client.post(self.list_url, {
            "name": "Unauthorized", "category": self.sponsor.pk, "logo": self.logo(),
        }, format="multipart")
        self.assertEqual(response.status_code, 403)
        self.client.force_authenticate(user=None)
        self.assertEqual(self.client.post(self.list_url, {}, format="multipart").status_code, 403)
        self.client.force_authenticate(user=self.admin)
        self.assertEqual(self.client.post(self.list_url, {
            "name": "Authorized admin", "category": self.sponsor.pk, "logo": self.logo(),
        }, format="multipart").status_code, 201)

    def test_draft_hidden_and_unpublished_event_logos_are_not_public(self):
        self.assertEqual(self.add_logo().status_code, 201)
        self.client.force_authenticate(user=None)
        self.event.status = "draft"
        self.event.save(update_fields=["status"])
        self.assertEqual(self.client.get(self.list_url).status_code, 404)
        self.event.status = "published"
        self.event.is_hidden = True
        self.event.save(update_fields=["status", "is_hidden"])
        self.assertEqual(self.client.get(self.list_url).status_code, 404)
        self.event.is_hidden = False
        self.event.save(update_fields=["is_hidden"])
        EventPublication.objects.filter(event=self.event).update(is_enabled=False)
        self.assertEqual(self.client.get(self.list_url).status_code, 404)

    def test_logo_is_required_and_invalid_images_rejected(self):
        self.client.force_authenticate(user=self.owner)
        no_logo = self.client.post(self.list_url, {"name": "Without logo", "category": self.sponsor.pk})
        self.assertEqual(no_logo.status_code, 400)
        bad_logo = SimpleUploadedFile("fake.png", b"not a picture", content_type="image/png")
        invalid = self.client.post(self.list_url, {"name": "Bad logo", "category": self.sponsor.pk, "logo": bad_logo}, format="multipart")
        self.assertEqual(invalid.status_code, 400)
        disguised = self.client.post(self.list_url, {
            "name": "Disguised", "category": self.sponsor.pk,
            "logo": self.logo("fake.svg"),
        }, format="multipart")
        self.assertEqual(disguised.status_code, 400)
        self.assertEqual(EventSupporter.objects.count(), 0)

    def test_logo_update_and_delete_scoped_to_event(self):
        item_id = self.add_logo().data["id"]
        response = self.client.patch(f"{self.list_url}{item_id}/", {"name": "Updated sponsor"}, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["name"], "Updated sponsor")
        self.client.force_authenticate(user=self.other)
        self.assertEqual(self.client.delete(f"{self.list_url}{item_id}/").status_code, 403)
        self.client.force_authenticate(user=self.owner)
        self.assertEqual(self.client.delete(f"{self.list_url}{item_id}/").status_code, 204)
        self.assertEqual(EventSupporter.objects.count(), 0)

    def test_global_types_superuser_only_and_protected_if_used(self):
        self.client.force_authenticate(user=self.owner)
        self.assertEqual(self.client.post(self.types_url, {"kind": "sponsor", "name": "Silver"}, format="json").status_code, 403)
        self.client.force_authenticate(user=self.admin)
        created = self.client.post(self.types_url, {"kind": "sponsor", "name": "Silver"}, format="json")
        self.assertEqual(created.status_code, 201)
        self.assertEqual(self.client.patch(f"{self.types_url}{created.data['id']}/", {"name": "Bronze"}, format="json").status_code, 200)
        self.assertEqual(self.client.delete(f"{self.types_url}{created.data['id']}/").status_code, 204)
        self.assertEqual(self.add_logo().status_code, 201)
        self.client.force_authenticate(user=self.admin)
        self.assertEqual(self.client.delete(f"{self.types_url}{self.sponsor.pk}/").status_code, 409)
        self.assertEqual(self.client.patch(f"{self.types_url}{self.sponsor.pk}/", {"kind": "partner"}, format="json").status_code, 400)
        self.assertEqual(self.client.post(self.types_url, {"kind": "sponsor", "name": "DIAMOND"}, format="json").status_code, 400)
