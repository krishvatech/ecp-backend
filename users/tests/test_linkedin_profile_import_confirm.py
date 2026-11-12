from django.contrib.auth.models import User
from django.test import TestCase, override_settings

from rest_framework.test import APITestCase

from users.models import (
    Education,
    Experience,
    ProfileCertification,
    UserEmailAlias,
    UserProfile,
)
from users.linkedin_profile_import_service import import_linkedin_profile_data
from users.linkedin_profile_import import extract_linkedin_profile_url


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

    def test_import_overwrites_existing_linkedin_profile_url(self):
        profile, _ = UserProfile.objects.get_or_create(user=self.user)
        profile.links = {
            "linkedin": "https://www.linkedin.com/in/old-profile",
            "x": "https://x.com/example",
        }
        profile.save(update_fields=["links"])

        payload = self.payload()
        payload["linkedin_url"] = "https://www.linkedin.com/in/cbkummer"

        result = import_linkedin_profile_data(
            user=self.user,
            profile_data=payload,
        )

        profile.refresh_from_db()
        self.assertTrue(result["profile_updated"])
        self.assertEqual(
            profile.links["linkedin"],
            "https://www.linkedin.com/in/cbkummer",
        )
        self.assertEqual(profile.links["x"], "https://x.com/example")

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


@override_settings(COGNITO_REGION="", COGNITO_USER_POOL_ID="")
class LinkedInProfileImportNameTests(TestCase):
    """An import must never change the name a member set up their account with."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="linkedin-name-test",
            password="Password123!",
        )
        self.profile, _ = UserProfile.objects.get_or_create(user=self.user)

    def payload(self, full_name="Jordan Sample"):
        return {
            "full_name": full_name,
            "headline": "Imported Headline",
            "experiences": [],
            "educations": [],
            "certifications": [],
            "skills": [],
        }

    def import_pdf(self, full_name="Jordan Sample"):
        result = import_linkedin_profile_data(
            user=self.user,
            profile_data=self.payload(full_name),
        )
        self.profile.refresh_from_db()
        self.user.refresh_from_db()
        return result

    def test_import_keeps_existing_profile_name(self):
        self.profile.full_name = "Alex Example"
        self.profile.save(update_fields=["full_name"])

        self.import_pdf("Alexander Example-Other")

        self.assertEqual(self.profile.full_name, "Alex Example")
        self.assertEqual(self.profile.headline, "Imported Headline")

    def test_import_keeps_account_first_and_last_name(self):
        self.user.first_name = "Alex"
        self.user.last_name = "Example"
        self.user.save(update_fields=["first_name", "last_name"])

        self.import_pdf("Jordan Sample")

        # Filling full_name here would change the name other members see,
        # which falls back to first + last name while full_name is empty.
        self.assertEqual(self.profile.full_name, "")
        self.assertEqual(self.user.first_name, "Alex")
        self.assertEqual(self.user.last_name, "Example")
        self.assertEqual(self.profile.headline, "Imported Headline")

    def test_import_never_changes_verified_name(self):
        self.profile.full_name = "Alex Example"
        self.profile.legal_name_locked = True
        self.profile.save(update_fields=["full_name", "legal_name_locked"])

        self.import_pdf("Jordan Sample")

        self.assertEqual(self.profile.full_name, "Alex Example")
        self.assertTrue(self.profile.legal_name_locked)

    def test_import_does_not_fill_name_when_name_is_locked(self):
        self.profile.legal_name_locked = True
        self.profile.save(update_fields=["legal_name_locked"])

        self.import_pdf("Jordan Sample")

        self.assertEqual(self.profile.full_name, "")

    def test_import_fills_name_only_when_account_has_no_name(self):
        result = self.import_pdf("  Jordan Sample  ")

        self.assertTrue(result["profile_updated"])
        self.assertEqual(self.profile.full_name, "Jordan Sample")

    def test_import_with_same_name_reports_no_name_change(self):
        self.profile.full_name = "Jordan Sample"
        self.profile.headline = "Imported Headline"
        self.profile.save(update_fields=["full_name", "headline"])

        result = self.import_pdf("Jordan Sample")

        self.assertFalse(result["profile_updated"])
        self.assertEqual(self.profile.full_name, "Jordan Sample")


class LinkedInProfileImportUrlExtractionTests(TestCase):
    def test_extracts_linkedin_profile_url_from_pdf_text(self):
        text = "Contact\nwww.linkedin.com/in/cbkummer\nwww.imaa.org"

        self.assertEqual(
            extract_linkedin_profile_url(text),
            "https://www.linkedin.com/in/cbkummer",
        )

    def test_strips_trailing_punctuation_from_linkedin_profile_url(self):
        text = "LinkedIn: https://www.linkedin.com/in/cbkummer,"

        self.assertEqual(
            extract_linkedin_profile_url(text),
            "https://www.linkedin.com/in/cbkummer",
        )


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
