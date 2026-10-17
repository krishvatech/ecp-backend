"""IPDT-772: CognitoBootstrapView must be able to seed profile.location
(Country/Region) for the authenticated user so a newly registered guest
applicant passes event lead-generation validation. It must only touch the
caller's own profile and must not clobber an existing location.
"""
from django.contrib.auth.models import User
from rest_framework.test import APITestCase

from users.models import UserProfile


class CognitoBootstrapLocationTests(APITestCase):
    URL = "/api/auth/cognito/bootstrap/"

    def setUp(self):
        self.user = User.objects.create_user(
            username="guest-applicant",
            email="guest-applicant@example.com",
            password="ValidPassword123!",
            first_name="Guest",
            last_name="Applicant",
        )

    def test_bootstrap_sets_location_company_job_title(self):
        self.client.force_authenticate(user=self.user)
        resp = self.client.post(
            self.URL,
            {
                "username": "guest-applicant",
                "email": "guest-applicant@example.com",
                "firstName": "Guest",
                "lastName": "Applicant",
                "company": "Acme Ltd",
                "job_title": "Analyst",
                "location": "Germany",
            },
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        profile = UserProfile.objects.get(user=self.user)
        self.assertEqual(profile.location, "Germany")
        self.assertEqual(profile.company, "Acme Ltd")
        self.assertEqual(profile.job_title, "Analyst")

    def test_bootstrap_does_not_overwrite_existing_location(self):
        UserProfile.objects.update_or_create(
            user=self.user, defaults={"location": "France"}
        )
        self.client.force_authenticate(user=self.user)
        resp = self.client.post(
            self.URL,
            {"email": "guest-applicant@example.com", "location": "Germany"},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(UserProfile.objects.get(user=self.user).location, "France")

    def test_bootstrap_without_location_is_unchanged(self):
        self.client.force_authenticate(user=self.user)
        resp = self.client.post(
            self.URL,
            {"email": "guest-applicant@example.com", "company": "Acme Ltd"},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        profile = UserProfile.objects.get(user=self.user)
        self.assertEqual(profile.company, "Acme Ltd")
        self.assertFalse((profile.location or "").strip())

    def test_bootstrap_rejects_email_mismatch_other_user(self):
        other = User.objects.create_user(
            username="other-user", email="other@example.com", password="ValidPassword123!"
        )
        UserProfile.objects.get_or_create(user=other)
        self.client.force_authenticate(user=self.user)
        resp = self.client.post(
            self.URL,
            {"email": "other@example.com", "location": "Germany"},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)
        # The other user's profile is untouched.
        self.assertFalse((UserProfile.objects.get(user=other).location or "").strip())
