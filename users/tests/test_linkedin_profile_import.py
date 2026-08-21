import json
from io import BytesIO
from unittest import TestCase
from unittest.mock import Mock, patch

import requests
from django.test import override_settings
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas

from users.linkedin_profile_import_service import (
    normalize_import_phone_number,
)
from users.linkedin_profile_import import (
    EmptyProfilePdfError,
    InvalidProfilePdfError,
    InvalidStructuredProfileError,
    MAX_PROFILE_TEXT_CHARS,
    OPENAI_CHAT_COMPLETIONS_URL,
    ProfileAiServiceError,
    extract_profile_pdf_text,
    structure_profile_text,
    validate_structured_profile_data,
)


def build_text_pdf(*pages: str) -> BytesIO:
    """Build a small in-memory PDF fixture without touching project storage."""

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer)

    for page_index, page_text in enumerate(pages):
        if page_index:
            pdf.showPage()

        y = 800
        for line in page_text.splitlines():
            pdf.drawString(50, y, line)
            y -= 20

    pdf.save()
    buffer.seek(0)
    return buffer


def encrypt_pdf(source: BytesIO) -> BytesIO:
    source.seek(0)
    reader = PdfReader(source)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    writer.encrypt("test-password")
    encrypted = BytesIO()
    writer.write(encrypted)
    encrypted.seek(0)
    return encrypted


def valid_structured_profile() -> dict:
    return {
        "full_name": "Shruti Makwana",
        "email": "shruti@example.com",
        "phone": "9974401442",
        "linkedin_url": "https://www.linkedin.com/in/shrutimakwana",
        "headline": "Software Engineer | AI/ML",
        "bio": "Software Engineer with experience building web applications.",
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
                "description": "Developing scalable web applications.",
            }
        ],
        "educations": [
            {
                "school": "Saurashtra University, Rajkot",
                "degree": "Bachelor of Computer Applications (BCA)",
                "field_of_study": "Computer Programming",
                "start_date": "2022-04-01",
                "end_date": "2025-04-01",
                "grade": None,
                "description": None,
            }
        ],
        "skills": ["Python", "Django", "React.js"],
        "certifications": [
            {
                "certification_name": "Python 101 for Data Science",
                "issuing_organization": None,
                "issue_date": None,
                "expiration_date": None,
                "no_expiration": False,
                "credential_id": None,
                "credential_url": None,
            }
        ],
    }


def mock_openai_response(profile: dict | None = None, **message_overrides) -> Mock:
    message = {
        "content": json.dumps(profile if profile is not None else valid_structured_profile()),
        "refusal": None,
    }
    message.update(message_overrides)

    response = Mock()
    response.status_code = 200
    response.json.return_value = {
        "choices": [
            {
                "finish_reason": "stop",
                "message": message,
            }
        ]
    }
    return response


class LinkedInProfilePdfExtractionTests(TestCase):
    def test_extracts_text_from_single_page_pdf(self):
        pdf = build_text_pdf(
            "Shruti Makwana\n"
            "Software Engineer\n"
            "KrishvaTech"
        )

        text = extract_profile_pdf_text(pdf)

        self.assertIn("Shruti Makwana", text)
        self.assertIn("Software Engineer", text)
        self.assertIn("KrishvaTech", text)

    def test_extracts_text_from_multiple_pages(self):
        pdf = build_text_pdf(
            "Experience\nKrishvaTech\nSoftware Engineer",
            "Education\nSaurashtra University\nBCA",
        )

        text = extract_profile_pdf_text(pdf)

        self.assertIn("Experience", text)
        self.assertIn("KrishvaTech", text)
        self.assertIn("Education", text)
        self.assertIn("Saurashtra University", text)

    def test_rejects_missing_file(self):
        with self.assertRaises(InvalidProfilePdfError):
            extract_profile_pdf_text(None)

    def test_rejects_non_pdf_content(self):
        invalid_file = BytesIO(b"This is not a PDF")

        with self.assertRaises(InvalidProfilePdfError):
            extract_profile_pdf_text(invalid_file)

    def test_rejects_pdf_without_extractable_text(self):
        buffer = BytesIO()
        pdf = canvas.Canvas(buffer)
        pdf.showPage()
        pdf.save()
        buffer.seek(0)

        with self.assertRaises(EmptyProfilePdfError):
            extract_profile_pdf_text(buffer)

    def test_rejects_encrypted_pdf(self):
        pdf = encrypt_pdf(build_text_pdf("Private profile"))

        with self.assertRaises(InvalidProfilePdfError):
            extract_profile_pdf_text(pdf)

    def test_restores_original_file_position_after_success(self):
        pdf = build_text_pdf("Shruti Makwana")
        pdf.seek(5)
        original_position = pdf.tell()

        extract_profile_pdf_text(pdf)

        self.assertEqual(pdf.tell(), original_position)

    def test_restores_original_file_position_after_failure(self):
        invalid_file = BytesIO(b"not a pdf")
        invalid_file.seek(3)
        original_position = invalid_file.tell()

        with self.assertRaises(InvalidProfilePdfError):
            extract_profile_pdf_text(invalid_file)

        self.assertEqual(invalid_file.tell(), original_position)


class LinkedInPhoneNormalizationTests(TestCase):
    def test_national_number_uses_the_supplied_region(self):
        self.assertEqual(
            normalize_import_phone_number("9974401442", region="IN"),
            "+919974401442",
        )
        self.assertEqual(
            normalize_import_phone_number("(415) 555-2671", region="US"),
            "+14155552671",
        )
        self.assertEqual(
            normalize_import_phone_number("07911 123456", region="GB"),
            "+447911123456",
        )

    def test_explicit_country_code_wins_over_the_region(self):
        self.assertEqual(
            normalize_import_phone_number("+1 415 555 2671", region="IN"),
            "+14155552671",
        )
        self.assertEqual(
            normalize_import_phone_number("+91 99744 01442", region="US"),
            "+919974401442",
        )

    def test_treats_double_zero_prefix_as_international(self):
        self.assertEqual(
            normalize_import_phone_number("0091 99744 01442", region="US"),
            "+919974401442",
        )

    def test_returns_none_for_empty_or_unusable_input(self):
        self.assertIsNone(normalize_import_phone_number(None))
        self.assertIsNone(normalize_import_phone_number(""))
        self.assertIsNone(normalize_import_phone_number("   "))
        self.assertIsNone(normalize_import_phone_number("Mobile"))

    def test_rejects_a_number_that_is_not_valid_for_the_region(self):
        # Ten digits, but not a valid US number: never stored.
        self.assertIsNone(
            normalize_import_phone_number("9974401442", region="US")
        )


class LinkedInStructuredProfileValidationTests(TestCase):
    def test_validates_and_normalizes_profile_data(self):
        data = valid_structured_profile()
        data["full_name"] = "  Shruti Makwana  "
        data["skills"] = ["Python", " python ", "Django", ""]

        normalized = validate_structured_profile_data(data)

        self.assertEqual(normalized["full_name"], "Shruti Makwana")
        self.assertEqual(normalized["phone"], "9974401442")
        self.assertEqual(normalized["skills"], ["Python", "Django"])
        self.assertTrue(normalized["experiences"][0]["currently_work_here"])

    def test_rejects_missing_required_top_level_key(self):
        data = valid_structured_profile()
        data.pop("educations")

        with self.assertRaises(InvalidStructuredProfileError):
            validate_structured_profile_data(data)

    def test_rejects_unexpected_top_level_key(self):
        data = valid_structured_profile()
        data["made_up_field"] = "do not accept this"

        with self.assertRaises(InvalidStructuredProfileError):
            validate_structured_profile_data(data)

    def test_rejects_non_iso_date(self):
        data = valid_structured_profile()
        data["experiences"][0]["start_date"] = "January 2026"

        with self.assertRaises(InvalidStructuredProfileError):
            validate_structured_profile_data(data)

    def test_rejects_current_experience_with_end_date(self):
        data = valid_structured_profile()
        data["experiences"][0]["end_date"] = "2026-07-01"

        with self.assertRaises(InvalidStructuredProfileError):
            validate_structured_profile_data(data)

    def test_rejects_end_date_before_start_date(self):
        data = valid_structured_profile()
        data["educations"][0]["start_date"] = "2025-04-01"
        data["educations"][0]["end_date"] = "2022-04-01"

        with self.assertRaises(InvalidStructuredProfileError):
            validate_structured_profile_data(data)

    def test_rejects_expiration_when_certification_has_no_expiration(self):
        data = valid_structured_profile()
        certification = data["certifications"][0]
        certification["no_expiration"] = True
        certification["expiration_date"] = "2030-01-01"

        with self.assertRaises(InvalidStructuredProfileError):
            validate_structured_profile_data(data)


class LinkedInProfileAiStructuringTests(TestCase):
    @override_settings(OPENAI_API_KEY="test-openai-key")
    @patch("users.linkedin_profile_import.requests.post")
    def test_structures_profile_text_using_strict_json_schema(self, mock_post):
        mock_post.return_value = mock_openai_response()

        result = structure_profile_text(
            "Shruti Makwana\nExperience\nKrishvaTech\nSoftware Engineer\nJanuary 2026 - Present"
        )

        self.assertEqual(result["full_name"], "Shruti Makwana")
        self.assertEqual(result["current_company"], "KrishvaTech")

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], OPENAI_CHAT_COMPLETIONS_URL)
        self.assertEqual(kwargs["timeout"], 20)
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer test-openai-key")

        payload = kwargs["json"]
        self.assertEqual(payload["response_format"]["type"], "json_schema")
        self.assertTrue(payload["response_format"]["json_schema"]["strict"])
        self.assertFalse(
            payload["response_format"]["json_schema"]["schema"]["additionalProperties"]
        )
        self.assertIn("all explicit historical experience", payload["messages"][0]["content"])
        self.assertIn("<profile_text>", payload["messages"][1]["content"])

    @override_settings(
        OPENAI_API_KEY="test-openai-key",
        LINKEDIN_PROFILE_IMPORT_AI_MODEL="gpt-4o-mini-test",
    )
    @patch("users.linkedin_profile_import.requests.post")
    def test_uses_dedicated_model_setting_when_configured(self, mock_post):
        mock_post.return_value = mock_openai_response()

        structure_profile_text("Profile text")

        self.assertEqual(mock_post.call_args.kwargs["json"]["model"], "gpt-4o-mini-test")

    @override_settings(OPENAI_API_KEY="")
    @patch.dict("os.environ", {"OPENAI_API_KEY": ""})
    @patch("users.linkedin_profile_import.requests.post")
    def test_rejects_missing_api_key_without_calling_provider(self, mock_post):
        with self.assertRaises(ProfileAiServiceError):
            structure_profile_text("Profile text")

        mock_post.assert_not_called()

    @override_settings(OPENAI_API_KEY="test-openai-key")
    @patch("users.linkedin_profile_import.requests.post")
    def test_rejects_empty_profile_text_without_calling_provider(self, mock_post):
        with self.assertRaises(InvalidStructuredProfileError):
            structure_profile_text("   ")

        mock_post.assert_not_called()

    @override_settings(OPENAI_API_KEY="test-openai-key")
    @patch("users.linkedin_profile_import.requests.post")
    def test_rejects_oversized_profile_text_without_truncating(self, mock_post):
        with self.assertRaises(InvalidStructuredProfileError):
            structure_profile_text("x" * (MAX_PROFILE_TEXT_CHARS + 1))

        mock_post.assert_not_called()

    @override_settings(OPENAI_API_KEY="test-openai-key")
    @patch("users.linkedin_profile_import.requests.post")
    def test_translates_provider_timeout(self, mock_post):
        mock_post.side_effect = requests.Timeout("timeout")

        with self.assertRaises(ProfileAiServiceError):
            structure_profile_text("Profile text")

    @override_settings(OPENAI_API_KEY="test-openai-key")
    @patch("users.linkedin_profile_import.requests.post")
    def test_rejects_non_200_provider_response(self, mock_post):
        response = Mock()
        response.status_code = 429
        mock_post.return_value = response

        with self.assertRaises(ProfileAiServiceError):
            structure_profile_text("Profile text")

    @override_settings(OPENAI_API_KEY="test-openai-key")
    @patch("users.linkedin_profile_import.requests.post")
    def test_rejects_provider_refusal(self, mock_post):
        mock_post.return_value = mock_openai_response()
        mock_post.return_value.json.return_value["choices"][0]["message"]["refusal"] = (
            "Unable to process"
        )

        with self.assertRaises(ProfileAiServiceError):
            structure_profile_text("Profile text")

    @override_settings(OPENAI_API_KEY="test-openai-key")
    @patch("users.linkedin_profile_import.requests.post")
    def test_rejects_truncated_provider_response(self, mock_post):
        mock_post.return_value = mock_openai_response()
        mock_post.return_value.json.return_value["choices"][0]["finish_reason"] = "length"

        with self.assertRaises(ProfileAiServiceError):
            structure_profile_text("Profile text")

    @override_settings(OPENAI_API_KEY="test-openai-key")
    @patch("users.linkedin_profile_import.requests.post")
    def test_rejects_non_json_content(self, mock_post):
        mock_post.return_value = mock_openai_response(content="not json")

        with self.assertRaises(InvalidStructuredProfileError):
            structure_profile_text("Profile text")

    @override_settings(OPENAI_API_KEY="test-openai-key")
    @patch("users.linkedin_profile_import.requests.post")
    def test_revalidates_ai_output_locally(self, mock_post):
        invalid_profile = valid_structured_profile()
        invalid_profile["unexpected"] = "must be rejected"
        mock_post.return_value = mock_openai_response(invalid_profile)

        with self.assertRaises(InvalidStructuredProfileError):
            structure_profile_text("Profile text")
