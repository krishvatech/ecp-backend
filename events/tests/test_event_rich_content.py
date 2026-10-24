from django.test import SimpleTestCase
from django.core.files.uploadedfile import SimpleUploadedFile
from types import SimpleNamespace
from unittest.mock import patch
from io import BytesIO
from PIL import Image

from events.rich_content import plain_event_description, sanitize_event_description
from events.views import EventViewSet


class EventRichContentTests(SimpleTestCase):
    def test_legacy_text_is_preserved(self):
        self.assertEqual(sanitize_event_description("First line\nSecond line"), "First line\nSecond line")
        self.assertEqual(plain_event_description("First line\nSecond line"), "First line\nSecond line")
        self.assertEqual(plain_event_description("<h2>Agenda</h2><p>Day &amp; time</p>"), "Agenda Day & time")

    def test_rich_content_and_allowed_embed_survive(self):
        result = sanitize_event_description('<h2>Agenda</h2><table><tr><td>Day 1</td></tr></table><a class="event-cta" href="https://example.com">Join</a><iframe src="https://www.youtube-nocookie.com/embed/abcdefghijk"></iframe>')
        self.assertIn("<h2>Agenda</h2>", result)
        self.assertIn("<table>", result)
        self.assertIn("event-cta", result)
        self.assertIn("youtube-nocookie.com", result)

    def test_unsafe_links_and_embeds_are_removed(self):
        result = sanitize_event_description('<a href="javascript:alert(1)">bad</a><img src="data:image/svg+xml,a"><iframe src="https://evil.example/embed/x"></iframe><script>alert(1)</script>')
        self.assertNotIn("javascript:", result)
        self.assertNotIn("<img", result)
        self.assertNotIn("<iframe", result)
        self.assertNotIn("<script", result)

    def test_image_settings_and_local_media_are_preserved_safely(self):
        result = sanitize_event_description('<figure class="event-content-image--right evil" data-width="75" style="position:fixed"><img src="/media/event-content/photo.png" alt="Photo"><figcaption>Caption</figcaption></figure><a href="#registration">Register</a>')
        self.assertIn('data-width="75"', result)
        self.assertIn('event-content-image--right', result)
        self.assertIn('src="/media/event-content/photo.png"', result)
        self.assertIn('<figcaption>Caption</figcaption>', result)
        self.assertIn('href="#registration"', result)
        self.assertNotIn("position:fixed", result)
        self.assertNotIn("evil", result)

    def test_upload_rejects_invalid_file_and_stores_verified_image(self):
        user = SimpleNamespace(is_superuser=True)
        view = EventViewSet()
        invalid = SimpleNamespace(user=user, FILES={"image": SimpleUploadedFile("bad.png", b"not an image", content_type="image/png")})
        self.assertEqual(view.upload_description_image(invalid).status_code, 400)
        buffer = BytesIO()
        Image.new("RGB", (2, 2)).save(buffer, format="PNG")
        request = SimpleNamespace(user=user, FILES={"image": SimpleUploadedFile("photo.png", buffer.getvalue(), content_type="image/png")}, build_absolute_uri=lambda path: f"http://localhost:8000{path}")
        with patch("django.core.files.storage.default_storage.save", return_value="event-content/photo.png") as save, patch("django.core.files.storage.default_storage.url", return_value="/media/event-content/photo.png"):
            response = view.upload_description_image(request)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["url"], "http://localhost:8000/media/event-content/photo.png")
        save.assert_called_once()
