"""
WordPress media migration into ECP storage (Django storage: S3 when configured,
FileSystemStorage locally/in tests).

Security (URLs come from article HTML, so SSRF safety is mandatory):
  * only http/https, default ports only;
  * only hosts derived from WP_IMAA_BLOG_BASE_URL (the bare host and its www.
    variant) - arbitrary third-party images are never downloaded;
  * every resolved address must be public (no loopback, RFC1918, link-local,
    metadata, reserved or multicast addresses);
  * redirects are followed manually and each hop is re-validated;
  * streamed download with connect/read timeouts and a hard byte cap;
  * the bytes are verified with Pillow (Content-Type is never trusted):
    JPEG/PNG/WebP/GIF only, bounded pixel count, decompression bombs rejected.

Idempotency: BlogMediaAsset records one migrated object per source URL, so a
re-import reuses it without downloading or uploading again. Storage names are
deterministic (source-URL hash + content hash), never random.
"""
import hashlib
import io
import ipaddress
import logging
import os
import socket
import warnings
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.db import IntegrityError
from django.utils.text import slugify
from PIL import Image, UnidentifiedImageError

from blogs.models import BlogMediaAsset
from blogs.serializers import FEATURED_IMAGE_MAX_BYTES

logger = logging.getLogger(__name__)

MEDIA_PREFIX = "blogs/wordpress/media/"
MAX_MEDIA_BYTES = FEATURED_IMAGE_MAX_BYTES  # same 10 MB limit as Blog featured-image uploads
MAX_PIXELS = 40_000_000
MAX_REDIRECTS = 3
TIMEOUT = (5, 20)  # connect, read
ALLOWED_FORMATS = {"JPEG": "jpg", "PNG": "png", "WEBP": "webp", "GIF": "gif"}
USER_AGENT = "ECP-Blog-Importer/1.0 (+media; read-only)"


class MediaError(Exception):
    """A single media item could not be migrated. `code` is safe to report."""

    def __init__(self, code, message=""):
        super().__init__(message or code)
        self.code = code
        self.message = message or code


def _bare_host(host):
    host = (host or "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def allowed_media_hosts(base_url):
    """Hosts trusted for media: the configured WordPress host and its www. variant."""
    bare = _bare_host(urlsplit(base_url or "").hostname)
    return frozenset({bare, f"www.{bare}"}) if bare else frozenset()


def normalize_media_url(src, base_url):
    """Absolute, fragment-free URL for an <img src> (relative paths resolve against WordPress)."""
    raw = (src or "").strip()
    if not raw:
        return ""
    if raw.startswith("//"):
        raw = f"https:{raw}"
    elif raw.startswith("/"):
        raw = urljoin(f"{base_url.rstrip('/')}/", raw)
    parts = urlsplit(raw)
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, ""))


def is_trusted_media_url(url, hosts):
    try:
        parts = urlsplit(url)
        return parts.scheme in ("http", "https") and (parts.hostname or "").lower() in hosts
    except ValueError:
        return False


def _is_public_ip(address):
    ip = ipaddress.ip_address(address)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not (ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local or ip.is_private)


class SafeMediaFetcher:
    """Downloads one image from a trusted WordPress host with SSRF defences."""

    def __init__(self, hosts, *, session=None, resolver=socket.getaddrinfo, timeout=TIMEOUT, max_bytes=MAX_MEDIA_BYTES):
        self.hosts = frozenset(h.lower() for h in hosts)
        self.session = session or requests.Session()
        self.resolver = resolver
        self.timeout = timeout
        self.max_bytes = int(max_bytes)

    def _check(self, url):
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            raise MediaError("invalid_url", "malformed URL")
        if parts.scheme not in ("http", "https"):
            raise MediaError("blocked_scheme", f"scheme '{parts.scheme}' is not allowed")
        host = (parts.hostname or "").lower()
        if host not in self.hosts:
            raise MediaError("blocked_host", f"host '{host}' is not the configured WordPress site")
        if port not in (None, 80, 443):
            raise MediaError("blocked_port", f"port {port} is not allowed")
        try:
            infos = self.resolver(host, port or (443 if parts.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
        except (socket.gaierror, OSError):
            raise MediaError("dns_failure", f"could not resolve '{host}'")
        addresses = {info[4][0] for info in infos}
        if not addresses or not all(_is_public_ip(a) for a in addresses):
            raise MediaError("blocked_address", f"'{host}' resolves to a non-public address")

    def fetch(self, url):
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            self._check(current)
            try:
                response = self.session.get(
                    current, stream=True, allow_redirects=False, timeout=self.timeout,
                    headers={"User-Agent": USER_AGENT, "Accept": "image/*"},
                )
            except requests.Timeout:
                raise MediaError("timeout", "download timed out")
            except requests.RequestException as exc:
                raise MediaError("connection", f"download failed ({exc.__class__.__name__})")
            try:
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location")
                    if not location:
                        raise MediaError("bad_redirect", "redirect without Location")
                    current = urljoin(current, location)
                    continue
                if response.status_code != 200:
                    raise MediaError(f"http_{response.status_code}", f"HTTP {response.status_code}")
                declared = response.headers.get("Content-Length")
                if declared and declared.isdigit() and int(declared) > self.max_bytes:
                    raise MediaError("too_large", f"{declared} bytes exceeds {self.max_bytes}")
                buffer = io.BytesIO()
                for chunk in response.iter_content(64 * 1024):
                    buffer.write(chunk)
                    if buffer.tell() > self.max_bytes:
                        raise MediaError("too_large", f"exceeds {self.max_bytes} bytes")
                return buffer.getvalue()
            finally:
                response.close()
        raise MediaError("too_many_redirects", f"more than {MAX_REDIRECTS} redirects")


def validate_image(data):
    """Return (format, width, height) for real image bytes, else raise MediaError."""
    if not data:
        raise MediaError("empty", "empty response")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as probe:
                image_format = (probe.format or "").upper()
                width, height = probe.size
                if image_format not in ALLOWED_FORMATS:
                    raise MediaError("unsupported_format", f"format '{image_format or 'unknown'}' is not allowed")
                if width <= 0 or height <= 0 or width * height > MAX_PIXELS:
                    raise MediaError("bad_dimensions", f"{width}x{height} is outside the allowed size")
                probe.verify()
            with Image.open(io.BytesIO(data)) as decoded:
                decoded.load()  # full decode catches truncated/corrupt files
    except MediaError:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise MediaError("decompression_bomb", "image pixel count is unsafe")
    except (UnidentifiedImageError, OSError, SyntaxError, ValueError):
        raise MediaError("invalid_image", "content is not a valid image")
    return image_format, width, height


def url_hash(url):
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def storage_name_for(url, data, image_format):
    source_hash = url_hash(url)
    content = hashlib.sha256(data).hexdigest()
    stem = slugify(os.path.splitext(os.path.basename(urlsplit(url).path))[0])[:40] or "image"
    return f"{MEDIA_PREFIX}{source_hash[:2]}/{source_hash[:16]}-{content[:12]}-{stem}.{ALLOWED_FORMATS[image_format]}", content


class MediaStore:
    """Migrates trusted WordPress media into Django storage, once per source URL."""

    def __init__(self, fetcher, *, storage=None):
        self.fetcher = fetcher
        self.storage = storage or default_storage

    def get_or_migrate(self, url):
        """Return (BlogMediaAsset, downloaded: bool). Raises MediaError."""
        key = url_hash(url)
        asset = BlogMediaAsset.objects.filter(source_url_hash=key).first()
        if asset is not None:
            return asset, False
        data = self.fetcher.fetch(url)
        image_format, width, height = validate_image(data)
        name, content_sha = storage_name_for(url, data, image_format)
        if not self.storage.exists(name):
            name = self.storage.save(name, ContentFile(data))
        try:
            asset = BlogMediaAsset.objects.create(
                source_url=url, source_url_hash=key, storage_name=name, sha256=content_sha,
                image_format=image_format, width=width, height=height, size_bytes=len(data),
            )
        except IntegrityError:  # another worker migrated it first
            asset = BlogMediaAsset.objects.get(source_url_hash=key)
            return asset, False
        return asset, True

    def url(self, asset):
        return self.storage.url(asset.storage_name)
