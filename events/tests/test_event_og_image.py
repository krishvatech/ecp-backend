import tempfile
from io import BytesIO
from types import SimpleNamespace
from unittest import mock

from django.core.cache import cache
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage
from django.test import RequestFactory, SimpleTestCase, override_settings
from PIL import Image

from events import social_image
from events.social_image import (
    OG_HEIGHT,
    OG_WIDTH,
    build_og_image,
    ensure_event_og_image,
    get_event_og_image,
    og_image_key,
)


def jpeg_bytes(size, noisy=False, mode="RGB"):
    image = Image.effect_noise(size, 100).convert("RGB") if noisy else Image.new(mode, size, "navy")
    out = BytesIO()
    image.save(out, format="PNG" if mode == "RGBA" else "JPEG")
    return out.getvalue()



class FakeField:
    def __init__(self, name):
        self.name = name
        self.url = f"https://cdn.example/{name}"

    def __bool__(self):
        return bool(self.name)


def make_event(cover="", preview="", pk=1):
    return SimpleNamespace(pk=pk, slug="e", cover_image=FakeField(cover), preview_image=FakeField(preview))


class BuildOgImageTests(SimpleTestCase):
    def decode(self, payload):
        image = Image.open(BytesIO(payload))
        image.load()
        return image

    def test_4_3_noisy_image_becomes_1200x630_within_budget(self):
        payload = build_og_image(BytesIO(jpeg_bytes((2048, 1536), noisy=True)))
        image = self.decode(payload)
        self.assertEqual(image.size, (OG_WIDTH, OG_HEIGHT))
        self.assertEqual(image.format, "JPEG")
        self.assertLessEqual(len(payload), 150_000)

    def test_16_9_image_is_resized_not_cropped(self):
        payload = build_og_image(BytesIO(jpeg_bytes((1278, 720))))
        self.assertEqual(self.decode(payload).size, (OG_WIDTH, OG_HEIGHT))

    def test_already_correct_ratio_is_just_resized(self):
        payload = build_og_image(BytesIO(jpeg_bytes((2400, 1260))))
        self.assertEqual(self.decode(payload).size, (OG_WIDTH, OG_HEIGHT))

    def test_transparent_png_is_flattened_to_jpeg(self):
        payload = build_og_image(BytesIO(jpeg_bytes((800, 800), mode="RGBA")))
        image = self.decode(payload)
        self.assertEqual((image.format, image.mode), ("JPEG", "RGB"))

    def test_garbage_raises_value_error(self):
        with self.assertRaises(ValueError):
            build_og_image(BytesIO(b"not an image"))

    def test_key_is_derived_from_source_name(self):
        self.assertEqual(
            og_image_key("previews/event/ma-asia-b388f48f.jpg"),
            "previews/event/og/ma-asia-b388f48f-og-v1.jpg",
        )
        self.assertEqual(og_image_key(""), "")


LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "og-tests"}}


@override_settings(CACHES=LOCMEM)
class EnsureAndLookupTests(SimpleTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.storage = FileSystemStorage(location=self.tmp.name)
        patcher = mock.patch.object(social_image, "default_storage", self.storage)
        patcher.start()
        self.addCleanup(patcher.stop)
        cache.clear()

    def put_source(self, name="previews/event/src-aaaa1111.jpg", size=(2048, 1536)):
        self.storage.save(name, ContentFile(jpeg_bytes(size)))
        return name

    def test_builds_once_and_is_idempotent(self):
        event = make_event(preview=self.put_source())
        key = ensure_event_og_image(event)
        self.assertEqual(key, "previews/event/og/src-aaaa1111-og-v1.jpg")
        self.assertTrue(self.storage.exists(key))
        mtime = self.storage.get_modified_time(key)
        self.assertEqual(ensure_event_og_image(event), key)
        self.assertEqual(self.storage.get_modified_time(key), mtime)

    def test_cover_image_has_priority_over_preview_image(self):
        cover = self.put_source("previews/event/cover-bbbb2222.jpg")
        preview = self.put_source("previews/event/prev-cccc3333.jpg")
        key = ensure_event_og_image(make_event(cover=cover, preview=preview))
        self.assertIn("cover-bbbb2222", key)

    def test_no_image_returns_empty(self):
        self.assertEqual(ensure_event_og_image(make_event()), "")
        self.assertEqual(get_event_og_image(make_event()), {})

    def test_unreadable_source_returns_empty_without_raising(self):
        self.storage.save("previews/event/bad-dddd4444.jpg", ContentFile(b"junk"))
        self.assertEqual(ensure_event_og_image(make_event(preview="previews/event/bad-dddd4444.jpg")), "")

    def test_lookup_returns_derivative_info_when_present(self):
        event = make_event(preview=self.put_source())
        ensure_event_og_image(event)
        info = get_event_og_image(event)
        self.assertEqual(
            (info["type"], info["width"], info["height"]),
            ("image/jpeg", OG_WIDTH, OG_HEIGHT),
        )

    def test_missing_derivative_returns_empty_and_enqueues_once(self):
        event = make_event(preview=self.put_source())
        with mock.patch("events.tasks.generate_event_og_image") as task:
            self.assertEqual(get_event_og_image(event), {})
            self.assertEqual(get_event_og_image(event), {})
        task.delay.assert_called_once_with(event.pk)

    def test_enqueue_failure_never_breaks_the_lookup(self):
        event = make_event(preview=self.put_source())
        with mock.patch("events.tasks.generate_event_og_image") as task:
            task.delay.side_effect = RuntimeError("broker down")
            self.assertEqual(get_event_og_image(event), {})


@override_settings(CACHES=LOCMEM)
class EventMetaViewTests(SimpleTestCase):
    def render(self, event, og):
        from ecp_backend import views

        qs = mock.MagicMock()
        qs.filter.return_value.select_related.return_value.first.return_value = event
        with mock.patch.object(views.Event, "objects", qs), \
                mock.patch.object(views, "get_event_og_image", return_value=og), \
                mock.patch.object(views, "default_storage") as storage, \
                override_settings(FRONTEND_URL="https://connect.example"):
            storage.url.side_effect = lambda key: f"https://cdn.example/{key}"
            request = RequestFactory().get("/events/e/")
            event.title, event.description, event.status = "T", "<p>D</p>", "published"
            response = views.public_event_meta(request, "e")
            response.render()
        return response.content.decode()

    def test_uses_derivative_with_dimensions_and_alt(self):
        event = make_event(preview="previews/event/src-aaaa1111.jpg")
        html = self.render(event, {
            "key": "previews/event/og/src-aaaa1111-og-v1.jpg",
            "type": "image/jpeg", "width": 1200, "height": 630,
        })
        self.assertIn('og:image" content="https://cdn.example/previews/event/og/src-aaaa1111-og-v1.jpg"', html)
        self.assertIn('og:image:type" content="image/jpeg"', html)
        self.assertIn('og:image:width" content="1200"', html)
        self.assertIn('og:image:height" content="630"', html)
        self.assertIn('og:image:alt" content="T"', html)

    def test_falls_back_to_original_without_fake_dimensions(self):
        event = make_event(preview="previews/event/src-aaaa1111.jpg")
        html = self.render(event, {})
        self.assertIn('og:image" content="https://cdn.example/previews/event/src-aaaa1111.jpg"', html)
        self.assertIn('og:image:type" content="image/jpeg"', html)
        self.assertNotIn("og:image:width", html)

    def test_no_image_has_no_image_tags(self):
        html = self.render(make_event(), {})
        self.assertNotIn("og:image", html)
        self.assertIn('og:title" content="T"', html)
