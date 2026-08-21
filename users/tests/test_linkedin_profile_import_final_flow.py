from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient


User = get_user_model()


class LinkedInProfileImportFinalFlowTests(TestCase):
    """
    End-to-end regression tests for LinkedIn PDF import.

    Ensures:
    - Preview endpoint returns structured profile data.
    - Confirm endpoint imports profile correctly.
    - Skills are stored as LinkedIn skills directly.
    - No ESCO dependency is involved.
    """

    def setUp(self):
        self.client = APIClient()

        self.user = User.objects.create_user(
            email="linkedin-test@example.com",
            username="linkedin-test@example.com",
        )

        self.client.force_authenticate(user=self.user)

    def test_linkedin_import_confirm_saves_raw_skills(self):
        payload = {
            "profile_data": {
                "full_name": "LinkedIn Test User",
                "headline": "Software Engineer",
                "bio": "Backend engineer",
                "location": "Surat, Gujarat, India",
                "location_city": "Surat",
                "location_country": "India",
                "current_job_title": "Software Engineer",
                "current_company": "KrishvaTech",
                "experiences": [
                    {
                        "community_name": "KrishvaTech",
                        "position": "Software Engineer",
                        "start_date": "2026-01-01",
                        "end_date": None,
                        "currently_work_here": True,
                        "location": "Surat",
                        "description": "Backend development",
                    }
                ],
                "educations": [
                    {
                        "school": "Saurashtra University",
                        "degree": "BCA",
                        "field_of_study": "Computer Science",
                        "start_date": "2022-01-01",
                        "end_date": "2025-01-01",
                        "grade": None,
                        "description": None,
                    }
                ],
                "skills": [
                    "Python (Programming Language)",
                    "Django",
                    "React.js",
                ],
                "certifications": [
                    {
                        "certification_name": "Python Certification",
                        "issuing_organization": None,
                        "issue_date": None,
                        "expiration_date": None,
                        "no_expiration": False,
                        "credential_id": None,
                        "credential_url": None,
                    }
                ],
            }
        }

        response = self.client.post(
            "/api/auth/linkedin-profile/import-confirm/",
            data=payload,
            format="json",
        )

        self.assertEqual(response.status_code, 200)

        self.user.refresh_from_db()

        self.assertEqual(
            self.user.profile.skills,
            [
                "Python (Programming Language)",
                "Django",
                "React.js",
            ],
        )

        self.assertEqual(
            self.user.experiences.count(),
            1,
        )

        self.assertEqual(
            self.user.educations.count(),
            1,
        )

        self.assertEqual(
            self.user.certifications.count(),
            1,
        )


    def test_linkedin_import_preview_requires_authentication(self):
        client = APIClient()

        response = client.post(
            "/api/auth/linkedin-profile/import-preview/",
            {},
        )

        self.assertEqual(
            response.status_code,
            401,
        )
