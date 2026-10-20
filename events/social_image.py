"""Social-preview (Open Graph) image derivatives for events.

WhatsApp/LinkedIn crawlers download ``og:image`` with a short timeout, so the
shared image should be small and in the 1.91:1 large-card ratio. For each event
we derive a 1200x630 JPEG (<= ~150 KB) from ``cover_image``/``preview_image``.

There is no DB field: the derivative lives at a deterministic storage key built
from the source file name. Source names already carry a random suffix, so a new
upload yields a new key (and a new URL that crawler caches have never seen).
"""

import logging
from io import BytesIO
from pathlib import Path

from django.conf import settings
from django.core.cache import cache
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from PIL import Image, ImageFilter, ImageOps

logger = logging.getLogger(__name__)

OG_WIDTH = 1200
OG_HEIGHT = 630
OG_MIME_TYPE = "image/jpeg"
OG_KEY_TEMPLATE = "previews/event/og/{stem}-og-v1.jpg"
OG_JPEG_QUALITY_STEPS = (85, 80, 75, 70, 65, 60, 55, 50, 45)
# Sources already this close to 1.91:1 are resized without a backdrop.
OG_RATIO_TOLERANCE = 0.03
OG_EXISTS_CACHE_TTL = 600
OG_MISSING_CACHE_TTL = 120
OG_GENERATE_LOCK_TTL = 300


def _max_bytes():
    return int(getattr(settings, "EVENT_OG_IMAGE_MAX_BYTES", 150_000))


def event_source_image(event):
    """The image field the preview is derived from (same priority as the page)."""
    return getattr(event, "cover_image", None) or getattr(event, "preview_image", None)


def og_image_key(source_name):
    stem = Path(source_name or "").stem
    return OG_KEY_TEMPLATE.format(stem=stem) if stem else ""


def _flatten_to_rgb(image):
    if image.mode in {"RGBA", "LA"} or "transparency" in image.info:
        rgba = image.convert("RGBA")
        background = Image.new("RGB", rgba.size, (255, 255, 255))
        background.paste(rgba, mask=rgba.getchannel("A"))
        return background
    return image.convert("RGB")


def _compose_canvas(source):
    """Fit ``source`` into 1200x630 without cropping any of it.

    Event key visuals carry text near their edges, so we never centre-crop. When
    the ratio differs, the picture is centred over a blurred, darkened copy of
    itself instead of flat bars.
    """
    size = (OG_WIDTH, OG_HEIGHT)
    target_ratio = OG_WIDTH / OG_HEIGHT
    source_ratio = source.width / source.height

    if abs(source_ratio - target_ratio) / target_ratio <= OG_RATIO_TOLERANCE:
        return source.resize(size, Image.Resampling.LANCZOS)

    backdrop = ImageOps.fit(source, size, Image.Resampling.LANCZOS)
    backdrop = backdrop.filter(ImageFilter.GaussianBlur(radius=28))
    backdrop = Image.blend(backdrop, Image.new("RGB", size, (0, 0, 0)), 0.35)

    foreground = ImageOps.contain(source, size, Image.Resampling.LANCZOS)
    offset = ((OG_WIDTH - foreground.width) // 2, (OG_HEIGHT - foreground.height) // 2)
    backdrop.paste(foreground, offset)
    return backdrop


def build_og_image(fileobj):
    """Return JPEG bytes (1200x630, within the byte budget) for ``fileobj``.

    Raises ValueError when the file is not a usable still image.
    """
    try:
        with Image.open(fileobj) as opened:
            if getattr(opened, "is_animated", False):
                opened.seek(0)
            opened.load()
            source = _flatten_to_rgb(ImageOps.exif_transpose(opened))
    except Exception as exc:  # PIL raises several unrelated types
        raise ValueError(f"unreadable image: {exc}") from exc

    if not source.width or not source.height:
        raise ValueError("empty image")

    canvas = _compose_canvas(source)
    max_bytes = _max_bytes()
    payload = b""
    for quality in OG_JPEG_QUALITY_STEPS:
        output = BytesIO()
        canvas.save(output, format="JPEG", quality=quality, optimize=True)
        payload = output.getvalue()
        if len(payload) <= max_bytes:
            return payload
    # Fixed 1200x630 canvas; if even the lowest quality is over budget, still
    # return it (far smaller than a typical source) rather than fail the share.
    logger.warning("OG image over budget at lowest quality: %s bytes", len(payload))
    return payload


def ensure_event_og_image(event, *, force=False):
    """Create the OG derivative for ``event`` if missing; return its key or "".

    Returns "" when the event has no image or the image cannot be processed.
    """
    source = event_source_image(event)
    key = og_image_key(getattr(source, "name", ""))
    if not key:
        return ""

    if not force and default_storage.exists(key):
        return key

    try:
        with default_storage.open(source.name, "rb") as fh:
            payload = build_og_image(fh)
    except Exception:
        logger.warning(
            "Could not build OG image for event %s from %s",
            getattr(event, "pk", None),
            source.name,
            exc_info=True,
        )
        return ""

    if force and default_storage.exists(key):
        default_storage.delete(key)
    default_storage.save(key, ContentFile(payload))
    _cache_set(_exists_cache_key(key), True, OG_EXISTS_CACHE_TTL)
    return key


def _exists_cache_key(key):
    return f"event-og-image:{key}"


def _cache_get(name):
    try:
        return cache.get(name)
    except Exception:
        return None


def _cache_set(name, value, ttl):
    try:
        cache.set(name, value, ttl)
    except Exception:
        pass


def _og_key_exists(key):
    """Storage existence check, cached so crawler hits cost at most one lookup
    per key per TTL."""
    cache_key = _exists_cache_key(key)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    try:
        exists = bool(default_storage.exists(key))
    except Exception:
        return False
    _cache_set(cache_key, exists, OG_EXISTS_CACHE_TTL if exists else OG_MISSING_CACHE_TTL)
    return exists


def _enqueue_generation(event_pk):
    """Ask Celery to build the derivative; never raises (this runs in a view)."""
    lock_key = f"event-og-image-gen:{event_pk}"
    try:
        if not cache.add(lock_key, 1, OG_GENERATE_LOCK_TTL):
            return
        from events.tasks import generate_event_og_image

        generate_event_og_image.delay(event_pk)
    except Exception:
        logger.warning("Could not enqueue OG image generation for event %s", event_pk, exc_info=True)


def get_event_og_image(event):
    """Return ``{"key", "type", "width", "height"}`` when the derivative exists,
    else ``{}``. A missing derivative schedules generation so the next crawl gets
    it; callers fall back to the original image in the meantime."""
    source = event_source_image(event)
    key = og_image_key(getattr(source, "name", ""))
    if not key:
        return {}
    if _og_key_exists(key):
        return {"key": key, "type": OG_MIME_TYPE, "width": OG_WIDTH, "height": OG_HEIGHT}
    _enqueue_generation(event.pk)
    return {}
