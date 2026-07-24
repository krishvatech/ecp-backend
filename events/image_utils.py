"""Reusable image optimisation helpers for event uploads."""

from io import BytesIO
from pathlib import Path

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.utils.text import slugify
from PIL import Image, ImageOps, UnidentifiedImageError


JPEG_QUALITY_STEPS = (86, 82, 78, 74, 70, 66, 62, 58, 54, 50, 46)
RESIZE_FACTOR = 0.85
MIN_LONG_EDGE = 480


def _has_alpha(image):
    return image.mode in {"RGBA", "LA"} or "transparency" in image.info


def _output_name(original_name, extension):
    stem = slugify(Path(original_name or "event-image").stem) or "event-image"
    return f"{stem}-optimized{extension}"


def _resize_to_fit(image, max_dimensions):
    resized = image.copy()
    resized.thumbnail(max_dimensions, Image.Resampling.LANCZOS)
    return resized


def _shrink(image):
    width, height = image.size
    new_width = max(1, int(width * RESIZE_FACTOR))
    new_height = max(1, int(height * RESIZE_FACTOR))
    return image.resize((new_width, new_height), Image.Resampling.LANCZOS)


def _encode_jpeg(image, max_bytes):
    working = image.convert("RGB")

    while True:
        for quality in JPEG_QUALITY_STEPS:
            output = BytesIO()
            working.save(
                output,
                format="JPEG",
                quality=quality,
                optimize=True,
                progressive=True,
            )
            payload = output.getvalue()
            if len(payload) <= max_bytes:
                return payload, ".jpg"

        if max(working.size) <= MIN_LONG_EDGE:
            break
        working = _shrink(working)

    raise ValidationError(
        "The image could not be compressed below the configured social-preview size. "
        "Please upload a smaller image."
    )


def _encode_png(image, max_bytes):
    working = image.convert("RGBA")

    while True:
        output = BytesIO()
        working.save(output, format="PNG", optimize=True, compress_level=9)
        payload = output.getvalue()
        if len(payload) <= max_bytes:
            return payload, ".png"

        if max(working.size) <= MIN_LONG_EDGE:
            break
        working = _shrink(working)

    raise ValidationError(
        "The transparent image could not be compressed below the configured "
        "social-preview size. Please upload a smaller image."
    )


def optimize_event_image(uploaded_file, *, max_dimensions):
    """Return an upload suitable for event display and social previews.

    Small files that already meet both the byte and dimension limits are returned
    unchanged. Larger images are resized without cropping, stripped of metadata,
    and recompressed. Transparent images stay PNG; opaque images become JPEG.
    """
    if uploaded_file is None:
        return None

    max_bytes = int(getattr(settings, "EVENT_SOCIAL_IMAGE_MAX_BYTES", 600_000))

    try:
        uploaded_file.seek(0)
        with Image.open(uploaded_file) as source:
            source.load()
            source = ImageOps.exif_transpose(source)

            within_dimensions = (
                source.width <= max_dimensions[0]
                and source.height <= max_dimensions[1]
            )
            if uploaded_file.size <= max_bytes and within_dimensions:
                uploaded_file.seek(0)
                return uploaded_file

            if getattr(source, "is_animated", False):
                raise ValidationError(
                    "Animated event images cannot be automatically compressed. "
                    "Please upload a JPG, PNG, or WebP image."
                )

            resized = _resize_to_fit(source, max_dimensions)
            if _has_alpha(resized):
                payload, extension = _encode_png(resized, max_bytes)
            else:
                payload, extension = _encode_jpeg(resized, max_bytes)

    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise ValidationError("Upload a valid event image.") from exc
    finally:
        try:
            uploaded_file.seek(0)
        except (AttributeError, OSError):
            pass

    return ContentFile(
        payload,
        name=_output_name(getattr(uploaded_file, "name", "event-image"), extension),
    )
