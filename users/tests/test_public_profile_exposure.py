"""
Regression tests for ``GET /api/users/<id>/profile/``.

Production verification found this endpoint answering anonymous requests with
the account's email address, KYC status and moderation state. The endpoint
stays public (it backs the public profile page), but the response is now
reduced for anyone who is neither the profile owner nor platform staff.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from users.models import Education, EducationDocument, UserProfile


User = get_user_model()

PRIVATE_PROFILE_KEYS = (
    "links",
    "location_lat",
    "location_lng",
    "kyc_status",
    "can_edit_profiles",
    "profile_status",
    "profile_status_reason",
    "profile_status_updated_at",
    "last_activity_at",
)


class PublicProfileExposureTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.target = User.objects.create_user(
            username="profile-target",
            email="profile-target@example.com",
            password="pass1234",
            first_name="Pat",
            last_name="Target",
        )
        self.staff = User.objects.create_user(
            username="profile-staff",
            email="profile-staff@example.com",
            password="pass1234",
            is_staff=True,
        )
        self.outsider = User.objects.create_user(
            username="profile-outsider",
            email="profile-outsider@example.com",
            password="pass1234",
        )

        # The post_save signal creates the profile in an on_commit hook, which
        # does not run inside TestCase's transaction, so create it here and
        # fill the fields that production was leaking.
        UserProfile.objects.update_or_create(
            user=self.target,
            defaults=dict(
                job_title="Analyst",
                company="Acme",
                location="Berlin, Germany",
                location_lat=52.52,
                location_lng=13.405,
                links={"email": "side-channel@example.com", "phone": "+10000000000"},
                kyc_status="verified",
                profile_status="active",
                profile_status_reason="internal moderation note",
            ),
        )

        education = Education.objects.create(
            user=self.target,
            school="Test University",
            degree="MSc",
            field_of_study="Finance",
        )
        EducationDocument.objects.create(
            education=education,
            filename="diploma.pdf",
        )

        self.url = f"/api/users/{self.target.pk}/profile/"

    # ---------------- anonymous ----------------

    def test_anonymous_profile_is_still_reachable(self):
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["user"]["id"], self.target.pk)

    def test_anonymous_profile_hides_the_email_address(self):
        body = self.client.get(self.url).json()

        self.assertNotIn("email", body["user"])
        self.assertNotIn(self.target.email, self.client.get(self.url).content.decode())

    def test_anonymous_profile_hides_internal_and_location_fields(self):
        body = self.client.get(self.url).json()
        profile = body["profile"]

        for key in PRIVATE_PROFILE_KEYS:
            self.assertNotIn(key, profile, f"{key} must not be public")
        self.assertNotIn("kyc_status", body["user"])

    def test_anonymous_profile_hides_uploaded_documents(self):
        body = self.client.get(self.url).json()

        for entry in body["educations"]:
            self.assertNotIn("documents", entry)

    def test_anonymous_profile_keeps_public_display_fields(self):
        """The public profile card must still render."""
        body = self.client.get(self.url).json()

        self.assertEqual(body["user"]["first_name"], "Pat")
        self.assertEqual(body["profile"]["job_title"], "Analyst")
        self.assertEqual(body["profile"]["company"], "Acme")
        self.assertEqual(body["profile"]["location"], "Berlin, Germany")
        self.assertEqual(body["educations"][0]["school"], "Test University")

    def test_authenticated_outsider_is_treated_as_public(self):
        self.client.force_authenticate(self.outsider)
        body = self.client.get(self.url).json()

        self.assertNotIn("email", body["user"])
        self.assertNotIn("kyc_status", body["profile"])

    # ---------------- privileged viewers keep their data ----------------

    def test_profile_owner_still_receives_private_fields(self):
        self.client.force_authenticate(self.target)
        body = self.client.get(self.url).json()

        self.assertEqual(body["user"]["email"], self.target.email)
        self.assertEqual(body["profile"]["kyc_status"], "verified")
        self.assertEqual(body["profile"]["location_lat"], 52.52)
        self.assertIn("links", body["profile"])
        self.assertIn("documents", body["educations"][0])

    def test_staff_still_receives_private_fields(self):
        self.client.force_authenticate(self.staff)
        body = self.client.get(self.url).json()

        self.assertEqual(body["user"]["email"], self.target.email)
        self.assertEqual(body["profile"]["profile_status_reason"], "internal moderation note")
        self.assertIn("documents", body["educations"][0])
