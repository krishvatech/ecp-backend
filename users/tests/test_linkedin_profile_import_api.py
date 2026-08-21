from io import BytesIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from reportlab.pdfgen import canvas
from rest_framework.test import APITestCase

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
