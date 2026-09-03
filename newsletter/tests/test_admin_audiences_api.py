from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.models import NewsletterAudience


User = get_user_model()


class NewsletterAdminAudienceAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.normal_user = User.objects.create_user(
            username="audience-normal",
            email="audience-normal@example.test",
            password="test-password",
        )
        self.staff = User.objects.create_user(
            username="audience-staff",
            email="audience-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.superuser = User.objects.create_superuser(
            username="audience-superuser",
            email="audience-superuser@example.test",
            password="test-password",
        )
        self.list_url = reverse("newsletter-admin-audience-list")

    def _authenticate(self, user):
        self.client.force_authenticate(user=user)

    def _detail_url(self, audience):
        return reverse("newsletter-admin-audience-detail", args=[audience.uuid])

    def _payload(self, **overrides):
        payload = {
            "name": "IMA Members",
            "description": "Static audience for IMA members.",
            "audience_type": NewsletterAudience.AudienceType.STATIC,
            "status": NewsletterAudience.Status.DRAFT,
            "is_active": True,
        }
        payload.update(overrides)
        return payload

    def test_anonymous_and_normal_user_are_denied(self):
        audience = NewsletterAudience.objects.create(name="Denied Audience")
        detail_url = self._detail_url(audience)
        endpoints = [
            ("get", self.list_url, None),
            ("post", self.list_url, self._payload()),
            ("get", detail_url, None),
            ("patch", detail_url, {"name": "Updated"}),
            ("delete", detail_url, None),
        ]

        for method, url, payload in endpoints:
            response = getattr(self.client, method)(url, payload, format="json")
            self.assertIn(response.status_code, (401, 403))

        self._authenticate(self.normal_user)
        for method, url, payload in endpoints:
            response = getattr(self.client, method)(url, payload, format="json")
            self.assertEqual(response.status_code, 403)

    def test_staff_and_superuser_can_list_audiences(self):
        NewsletterAudience.objects.create(name="Listed Audience")

        for user in (self.staff, self.superuser):
            self._authenticate(user)
            response = self.client.get(self.list_url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data[0]["name"], "Listed Audience")

    def test_staff_can_create_audience_with_defaults(self):
        self._authenticate(self.staff)

        response = self.client.post(
            self.list_url,
            {"name": "Created Audience"},
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        audience = NewsletterAudience.objects.get(uuid=response.data["uuid"])
        self.assertEqual(audience.name, "Created Audience")
        self.assertEqual(audience.audience_type, NewsletterAudience.AudienceType.STATIC)
        self.assertEqual(audience.status, NewsletterAudience.Status.DRAFT)
        self.assertTrue(audience.is_active)
        self.assertIsNone(audience.estimated_count)
        self.assertEqual(audience.rule_definition, {})
        self.assertIsNone(audience.mautic_segment_id)
        self.assertEqual(audience.created_by, self.staff)
        self.assertNotIn("rule_definition", response.data)
        self.assertNotIn("mautic_segment_id", response.data)
        self.assertNotIn("created_by", response.data)

    def test_staff_can_retrieve_audience(self):
        audience = NewsletterAudience.objects.create(
            name="Retrieve Audience",
            audience_type=NewsletterAudience.AudienceType.DYNAMIC,
        )
        self._authenticate(self.staff)

        response = self.client.get(self._detail_url(audience))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["uuid"], str(audience.uuid))
        self.assertEqual(response.data["name"], "Retrieve Audience")
        self.assertEqual(response.data["audience_type"], "dynamic")

    def test_staff_can_update_audience(self):
        audience = NewsletterAudience.objects.create(name="Original Audience")
        self._authenticate(self.staff)

        response = self.client.patch(
            self._detail_url(audience),
            {
                "name": "Updated Audience",
                "description": "Updated description.",
                "audience_type": NewsletterAudience.AudienceType.DYNAMIC,
                "status": NewsletterAudience.Status.ACTIVE,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        audience.refresh_from_db()
        self.assertEqual(audience.name, "Updated Audience")
        self.assertEqual(audience.description, "Updated description.")
        self.assertEqual(audience.audience_type, NewsletterAudience.AudienceType.DYNAMIC)
        self.assertEqual(audience.status, NewsletterAudience.Status.ACTIVE)

    def test_staff_can_archive_audience_without_hard_delete(self):
        audience = NewsletterAudience.objects.create(
            name="Archive Audience",
            status=NewsletterAudience.Status.ACTIVE,
        )
        self._authenticate(self.staff)

        response = self.client.delete(self._detail_url(audience))

        self.assertEqual(response.status_code, 200)
        audience.refresh_from_db()
        self.assertEqual(audience.status, NewsletterAudience.Status.ARCHIVED)
        self.assertFalse(audience.is_active)
        self.assertTrue(NewsletterAudience.objects.filter(pk=audience.pk).exists())
        self.assertEqual(response.data["status"], "archived")
        self.assertFalse(response.data["is_active"])

    def test_list_excludes_archived_inactive_audiences(self):
        NewsletterAudience.objects.create(name="Active Audience")
        NewsletterAudience.objects.create(
            name="Archived Audience",
            status=NewsletterAudience.Status.ARCHIVED,
            is_active=False,
        )
        self._authenticate(self.staff)

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 200)
        names = {item["name"] for item in response.data}
        self.assertEqual(names, {"Active Audience"})

    def test_missing_name_is_rejected(self):
        self._authenticate(self.staff)

        response = self.client.post(
            self.list_url,
            {"description": "No name."},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(NewsletterAudience.objects.exists())

    def test_blank_name_is_rejected(self):
        self._authenticate(self.staff)

        response = self.client.post(
            self.list_url,
            self._payload(name="   "),
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(NewsletterAudience.objects.exists())

    def test_invalid_audience_type_is_rejected(self):
        self._authenticate(self.staff)

        response = self.client.post(
            self.list_url,
            self._payload(audience_type="invalid"),
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(NewsletterAudience.objects.exists())
