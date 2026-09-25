from io import BytesIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from reportlab.pdfgen import canvas
from rest_framework.test import APITestCase

from users.models import UserProfile

User = get_user_model()


def build_pdf():
    """Build a small in-memory PDF fixture without touching project storage."""

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer)
    pdf.drawString(50, 800, "Shruti Makwana")
    pdf.drawString(50, 780, "Software Engineer")
    pdf.save()
    buffer.seek(0)
    return buffer


def build_upload(content_type="application/pdf"):
    return SimpleUploadedFile(
        "profile.pdf",
        build_pdf().read(),
        content_type=content_type,
    )


class LinkedInProfileImportPreviewApiTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username="linkedin-test",
            email="linkedin-test@example.com",
            password="password123",
        )
        self.client.force_authenticate(self.user)
        self.url = reverse("linkedin-profile-import-preview")

    @patch("users.views.extract_profile_pdf_text")
    @patch("users.views.structure_profile_text")
    def test_preview_import_success(self, mock_structure, mock_extract):
        mock_extract.return_value = "profile text"
        mock_structure.return_value = {
            "full_name": "Shruti Makwana",
            "experiences": [],
            "educations": [],
            "skills": [],
            "certifications": [],
        }

        response = self.client.post(
            self.url,
            {"file": build_upload()},
            format="multipart",
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(response.data["success"])
        self.assertEqual(response.data["data"], mock_structure.return_value)
        self.assertEqual(response.data["identity_check"]["status"], "matched")

    @patch("users.views.extract_profile_pdf_text")
    @patch("users.views.structure_profile_text")
    def test_preview_marks_email_mismatch_as_review_when_name_matches(
        self, mock_structure, mock_extract
    ):
        profile, _ = UserProfile.objects.get_or_create(user=self.user)
        profile.full_name = "Christopher Kummer"
        profile.save(update_fields=["full_name"])

        mock_extract.return_value = "profile text"
        mock_structure.return_value = {
            "full_name": "Christopher Kummer, PhD",
            "email": "linkedin-email@example.com",
            "experiences": [],
            "educations": [],
            "skills": [],
            "certifications": [],
        }

        response = self.client.post(
            self.url,
            {"file": build_upload()},
            format="multipart",
        )

        self.assertEqual(response.status_code, 200, response.content)
        identity = response.data["identity_check"]
        self.assertEqual(identity["status"], "review")
        self.assertFalse(identity["email_match"])
        self.assertTrue(identity["name_match"])
        self.assertTrue(identity["requires_confirmation"])
        self.assertEqual(identity["account_email"], self.user.email)
        self.assertEqual(identity["linkedin_email"], "linkedin-email@example.com")

    @patch("users.views.extract_profile_pdf_text")
    @patch("users.views.structure_profile_text")
    def test_preview_blocks_when_email_and_name_both_differ(
        self, mock_structure, mock_extract
    ):
        profile, _ = UserProfile.objects.get_or_create(user=self.user)
        profile.full_name = "Christopher Kummer"
        profile.save(update_fields=["full_name"])

        mock_extract.return_value = "profile text"
        mock_structure.return_value = {
            "full_name": "Different Person",
            "email": "someone-else@example.com",
            "experiences": [],
            "educations": [],
            "skills": [],
            "certifications": [],
        }

        response = self.client.post(
            self.url,
            {"file": build_upload()},
            format="multipart",
        )

        self.assertEqual(response.status_code, 200, response.content)
        identity = response.data["identity_check"]
        self.assertEqual(identity["status"], "blocked")
        self.assertFalse(identity["email_match"])
        self.assertFalse(identity["name_match"])
        self.assertFalse(identity["requires_confirmation"])

    def test_requires_file(self):
        response = self.client.post(self.url)

        self.assertEqual(response.status_code, 400, response.content)
        self.assertFalse(response.data["success"])

    def test_rejects_non_pdf_upload(self):
        response = self.client.post(
            self.url,
            {"file": build_upload(content_type="image/png")},
            format="multipart",
        )

        self.assertEqual(response.status_code, 400, response.content)
        self.assertFalse(response.data["success"])

    def test_requires_authentication(self):
        self.client.force_authenticate(None)

        response = self.client.post(
            self.url,
            {"file": build_upload()},
            format="multipart",
        )

        self.assertIn(response.status_code, (401, 403))
