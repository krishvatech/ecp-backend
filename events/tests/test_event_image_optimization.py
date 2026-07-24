from io import BytesIO

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, override_settings
from PIL import Image

from events.image_utils import optimize_event_image
from events.serializers import EventSerializer


def make_image_upload(*, size, image_format, name, noisy=False, alpha=False):
    if noisy:
        image = Image.effect_noise(size, 100).convert("RGB")
    elif alpha:
        image = Image.new("RGBA", size, (25, 80, 160, 120))
    else:
        image = Image.new("RGB", size, "navy")

    output = BytesIO()
    image.save(output, format=image_format)
    content_type = "image/png" if image_format == "PNG" else "image/jpeg"
    return SimpleUploadedFile(name, output.getvalue(), content_type=content_type)


@override_settings(EVENT_SOCIAL_IMAGE_MAX_BYTES=600_000)
class EventImageOptimizationTests(SimpleTestCase):
    def test_small_image_is_not_reencoded(self):
        upload = make_image_upload(
            size=(600, 400),
            image_format="PNG",
            name="small.png",
        )

        result = optimize_event_image(upload, max_dimensions=(1280, 720))

        self.assertIs(result, upload)
        self.assertEqual(result.name, "small.png")

    def test_large_opaque_image_is_resized_and_compressed(self):
        upload = make_image_upload(
            size=(2048, 1536),
            image_format="PNG",
            name="large-cover.png",
            noisy=True,
        )
        self.assertGreater(upload.size, 600_000)

        result = optimize_event_image(upload, max_dimensions=(1280, 720))

        self.assertLessEqual(result.size, 600_000)
        self.assertTrue(result.name.endswith("-optimized.jpg"))
        with Image.open(result) as image:
            self.assertLessEqual(image.width, 1280)
            self.assertLessEqual(image.height, 720)
            self.assertEqual(image.format, "JPEG")

    def test_large_transparent_image_keeps_png(self):
        upload = make_image_upload(
            size=(2200, 2200),
            image_format="PNG",
            name="transparent-logo.png",
            alpha=True,
        )

        result = optimize_event_image(upload, max_dimensions=(1200, 1200))

        self.assertLessEqual(result.size, 600_000)
        self.assertTrue(result.name.endswith("-optimized.png"))
        with Image.open(result) as image:
            self.assertLessEqual(image.width, 1200)
            self.assertLessEqual(image.height, 1200)
            self.assertIn(image.mode, {"RGBA", "LA"})

    def test_event_serializer_uses_cover_limits(self):
        upload = make_image_upload(
            size=(1640, 924),
            image_format="JPEG",
            name="session-9.jpg",
            noisy=True,
        )

        result = EventSerializer().validate_cover_image(upload)

        self.assertLessEqual(result.size, 600_000)
        with Image.open(result) as image:
            self.assertLessEqual(image.width, 1280)
            self.assertLessEqual(image.height, 720)
