from django.contrib.auth.models import User
from django.test import TestCase

from rest_framework.test import APITestCase

from users.models import (
    Education,
    Experience,
    ProfileCertification,
    UserEmailAlias,
    UserProfile,
)
from users.linkedin_profile_import_service import import_linkedin_profile_data


class LinkedInProfileImportConfirmTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="linkedin-import-test",
            password="Password123!",
        )

    def payload(self):
        return {
            "full_name": "Shruti Makwana",
            "headline": "Software Engineer",
            "bio": "Developer",
            "location": "Surat",
            "experiences": [
                {
                    "community_name": "ExampleCorp",
                    "position": "Software Engineer",
                    "start_date": "2026-01-01",
                    "end_date": None,
                    "currently_work_here": True,
                    "location": "Surat",
                    "description": "Development",
                }
            ],
            "educations": [
                {
                    "school": "Saurashtra University",
                    "degree": "BCA",
                    "field_of_study": "IT",
                    "start_date": None,
                    "end_date": "2025-04-01",
                    "grade": None,
                    "description": None,
                }
            ],
            "certifications": [
                {
                    "certification_name": "Python Certificate",
                    "issuing_organization": "Python",
                    "issue_date": None,
                    "expiration_date": None,
                    "no_expiration": False,
                    "credential_id": None,
                    "credential_url": None,
                }
            ],
            "skills": [],
        }

    def test_import_creates_profile_records(self):
        result = import_linkedin_profile_data(
            user=self.user,
            profile_data=self.payload(),
        )

        self.assertTrue(result["profile_updated"])
        self.assertEqual(Experience.objects.filter(user=self.user).count(), 1)
        self.assertEqual(Education.objects.filter(user=self.user).count(), 1)
        self.assertEqual(ProfileCertification.objects.filter(user=self.user).count(), 1)

    def test_import_stores_skills_on_profile(self):
        payload = self.payload()
        payload["skills"] = ["Python", "Django"]

        result = import_linkedin_profile_data(
            user=self.user,
            profile_data=payload,
        )

        self.user.profile.refresh_from_db()
        self.assertTrue(result["skills_updated"])
        self.assertEqual(self.user.profile.skills, ["Python", "Django"])

    def test_import_deduplicates_and_strips_skills(self):
        payload = self.payload()
        payload["skills"] = ["  Python  ", "python", "", None, "Django"]

        import_linkedin_profile_data(
            user=self.user,
            profile_data=payload,
        )

        self.user.profile.refresh_from_db()
        self.assertEqual(self.user.profile.skills, ["Python", "Django"])

    def test_import_is_duplicate_safe(self):
        import_linkedin_profile_data(user=self.user, profile_data=self.payload())
        import_linkedin_profile_data(user=self.user, profile_data=self.payload())

        self.assertEqual(Experience.objects.filter(user=self.user).count(), 1)


class LinkedInProfileImportEmailValidationTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="linkedin-email-test",
            password="Password123!",
            email="owner@example.com",
        )
        profile, _ = UserProfile.objects.get_or_create(user=self.user)
        profile.full_name = "Test User"
        profile.save(update_fields=["full_name"])
        self.client.force_authenticate(self.user)
        self.url = "/api/auth/linkedin-profile/import-confirm/"

    def profile_data(self, email, full_name="Test User"):
        return {
            "email": email,
            "full_name": full_name,
            "headline": "Software Engineer",
            "bio": "Test",
            "location": "Surat",
            "location_city": "Surat",
            "location_country": "India",
            "current_job_title": "Engineer",
            "current_company": "Company",
            "experiences": [],
            "educations": [],
            "skills": [],
            "certifications": [],
        }

    def test_requires_confirmation_when_email_differs_but_name_matches(self):
        response = self.client.post(
            self.url,
            {"profile_data": self.profile_data("another-user@example.com")},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("confirm that this is your LinkedIn profile", response.data["message"])

    def test_allows_confirmed_override_when_email_differs_and_name_matches(self):
        response = self.client.post(
            self.url,
            {
                "profile_data": self.profile_data("another-user@example.com"),
                "ownership_confirmed": True,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200, response.content)

    def test_allows_common_first_name_prefix_for_fuzzy_match(self):
        self.user.profile.full_name = "Christopher Kummer"
        self.user.profile.save(update_fields=["full_name"])

        response = self.client.post(
            self.url,
            {
                "profile_data": self.profile_data(
                    "another-user@example.com",
                    full_name="Chris Kummer",
                ),
                "ownership_confirmed": True,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200, response.content)

    def test_name_match_ignores_linkedin_credentials(self):
        response = self.client.post(
            self.url,
            {
                "profile_data": self.profile_data(
                    "another-user@example.com",
                    full_name="Test User, PhD",
                ),
                "ownership_confirmed": True,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200, response.content)

    def test_blocks_override_when_email_and_name_both_differ(self):
        response = self.client.post(
            self.url,
            {
                "profile_data": self.profile_data(
                    "another-user@example.com",
                    full_name="Different Person",
                ),
                "ownership_confirmed": True,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("appears to belong to another person", response.data["message"])

    def test_confirmed_override_can_add_linkedin_email_to_profile(self):
        response = self.client.post(
            self.url,
            {
                "profile_data": self.profile_data("linkedin-contact@example.com"),
                "ownership_confirmed": True,
                "add_linkedin_email": True,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(response.data["data"]["email_added"])

        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "owner@example.com")
        self.user.profile.refresh_from_db()
        emails = self.user.profile.links["contact"]["emails"]
        self.assertEqual(
            emails,
            [
                {
                    "email": "linkedin-contact@example.com",
                    "type": "professional",
                    "visibility": "contacts",
                }
            ],
        )

    def test_add_linkedin_email_does_not_duplicate_existing_profile_email(self):
        self.user.profile.links = {
            "contact": {
                "emails": [
                    {
                        "email": "linkedin-contact@example.com",
                        "type": "personal",
                        "visibility": "private",
                    }
                ]
            }
        }
        self.user.profile.save(update_fields=["links"])

        response = self.client.post(
            self.url,
            {
                "profile_data": self.profile_data("linkedin-contact@example.com"),
                "ownership_confirmed": True,
                "add_linkedin_email": True,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertFalse(response.data["data"]["email_added"])

        self.user.profile.refresh_from_db()
        emails = self.user.profile.links["contact"]["emails"]
        self.assertEqual(len(emails), 1)
        self.assertEqual(emails[0]["type"], "personal")
        self.assertEqual(emails[0]["visibility"], "private")

    def test_allows_matching_linkedin_email(self):
        response = self.client.post(
            self.url,
            {"profile_data": self.profile_data(self.user.email)},
            format="json",
        )

        self.assertEqual(response.status_code, 200, response.content)

    def test_allows_import_when_account_has_no_email(self):
        self.user.email = ""
        self.user.save(update_fields=["email"])

        response = self.client.post(
            self.url,
            {"profile_data": self.profile_data("anything@example.com")},
            format="json",
        )

        self.assertEqual(response.status_code, 200, response.content)

    def test_allows_import_matching_a_verified_email_alias(self):
        UserEmailAlias.objects.create(
            user=self.user,
            email="alias@example.com",
            verified=True,
            is_active=True,
        )

        response = self.client.post(
            self.url,
            {"profile_data": self.profile_data("alias@example.com")},
            format="json",
        )

        self.assertEqual(response.status_code, 200, response.content)

    def test_unverified_email_alias_still_requires_confirmation(self):
        UserEmailAlias.objects.create(
            user=self.user,
            email="unverified@example.com",
            verified=False,
            is_active=True,
        )

        response = self.client.post(
            self.url,
            {"profile_data": self.profile_data("unverified@example.com")},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("confirm that this is your LinkedIn profile", response.data["message"])
