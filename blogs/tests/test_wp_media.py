import io

import requests
from django.core.files.storage import InMemoryStorage
from django.test import SimpleTestCase, TestCase
from PIL import Image

from blogs.models import BlogMediaAsset
from blogs.wordpress.media import (
    MEDIA_PREFIX,
    MediaError,
    MediaStore,
    SafeMediaFetcher,
    allowed_media_hosts,
    normalize_media_url,
    validate_image,
)

from .media_fixtures import FakeMediaResponse, FakeMediaSession, image_bytes, resolver_for

HOSTS = allowed_media_hosts("https://imaa.test")
IMG_URL = "https://imaa.test/wp-content/uploads/2024/01/chart.png"


def fetcher(routes, resolver=None, **kwargs):
    session = FakeMediaSession(routes)
    return SafeMediaFetcher(HOSTS, session=session, resolver=resolver or resolver_for(), **kwargs), session


class HostAndUrlTests(SimpleTestCase):
    def test_allowed_hosts_are_the_configured_site_and_www_variant_only(self):
        self.assertEqual(HOSTS, frozenset({"imaa.test", "www.imaa.test"}))
        self.assertEqual(allowed_media_hosts("https://www.imaa.test/wp-json"), HOSTS)
        self.assertEqual(allowed_media_hosts(""), frozenset())

    def test_url_normalisation(self):
        self.assertEqual(normalize_media_url("//imaa.test/a.png#x", "https://imaa.test"), "https://imaa.test/a.png")
        self.assertEqual(normalize_media_url("/wp-content/a.png", "https://imaa.test"), "https://imaa.test/wp-content/a.png")
        self.assertEqual(normalize_media_url("", "https://imaa.test"), "")


class SafeFetcherTests(SimpleTestCase):
    def test_downloads_trusted_public_image(self):
        body = image_bytes()
        f, session = fetcher({IMG_URL: FakeMediaResponse(200, body)})
        self.assertEqual(f.fetch(IMG_URL), body)
        self.assertEqual(session.requested, [IMG_URL])

    def test_rejects_non_http_schemes(self):
        f, _ = fetcher({})
        for url in ("file:///etc/passwd", "ftp://imaa.test/a.png", "data:image/png;base64,AA", "javascript:alert(1)"):
            with self.assertRaises(MediaError) as ctx:
                f.fetch(url)
            self.assertIn(ctx.exception.code, ("blocked_scheme", "blocked_host"), url)

    def test_rejects_other_hosts(self):
        f, session = fetcher({})
        with self.assertRaises(MediaError) as ctx:
            f.fetch("https://cdn.example.com/a.png")
        self.assertEqual(ctx.exception.code, "blocked_host")
        self.assertEqual(session.requested, [])

    def test_rejects_private_loopback_link_local_and_metadata_addresses(self):
        for ip in ("127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.9", "169.254.169.254", "::1", "fd00::1", "0.0.0.0"):
            f, session = fetcher({IMG_URL: FakeMediaResponse(200, image_bytes())}, resolver=resolver_for(default=ip))
            with self.assertRaises(MediaError) as ctx:
                f.fetch(IMG_URL)
            self.assertEqual(ctx.exception.code, "blocked_address", ip)
            self.assertEqual(session.requested, [], "no request is sent to a private address")

    def test_rejects_non_default_ports(self):
        f, _ = fetcher({})
        with self.assertRaises(MediaError) as ctx:
            f.fetch("https://imaa.test:8443/a.png")
        self.assertEqual(ctx.exception.code, "blocked_port")

    def test_redirects_are_revalidated(self):
        body = image_bytes()
        ok, _ = fetcher({
            IMG_URL: FakeMediaResponse(301, headers={"Location": "https://www.imaa.test/final.png"}),
            "https://www.imaa.test/final.png": FakeMediaResponse(200, body),
        })
        self.assertEqual(ok.fetch(IMG_URL), body)

        to_other_host, _ = fetcher({IMG_URL: FakeMediaResponse(302, headers={"Location": "https://evil.example/a.png"})})
        with self.assertRaises(MediaError) as ctx:
            to_other_host.fetch(IMG_URL)
        self.assertEqual(ctx.exception.code, "blocked_host")

        private = resolver_for({"imaa.test": "93.184.216.34", "www.imaa.test": "10.1.2.3"})
        to_private, session = fetcher(
            {IMG_URL: FakeMediaResponse(302, headers={"Location": "https://www.imaa.test/internal.png"})}, resolver=private
        )
        with self.assertRaises(MediaError) as ctx:
            to_private.fetch(IMG_URL)
        self.assertEqual(ctx.exception.code, "blocked_address")
        self.assertEqual(session.requested, [IMG_URL])

    def test_redirect_loops_are_bounded(self):
        loop = {IMG_URL: FakeMediaResponse(302, headers={"Location": IMG_URL})}
        f, _ = fetcher(loop)
        with self.assertRaises(MediaError) as ctx:
            f.fetch(IMG_URL)
        self.assertEqual(ctx.exception.code, "too_many_redirects")

    def test_size_limit_by_header_and_by_stream(self):
        declared, _ = fetcher({IMG_URL: FakeMediaResponse(200, b"x", {"Content-Length": "999999999"})}, max_bytes=1000)
        with self.assertRaises(MediaError) as ctx:
            declared.fetch(IMG_URL)
        self.assertEqual(ctx.exception.code, "too_large")
        streamed, _ = fetcher({IMG_URL: FakeMediaResponse(200, b"x" * 5000)}, max_bytes=1000)
        with self.assertRaises(MediaError) as ctx:
            streamed.fetch(IMG_URL)
        self.assertEqual(ctx.exception.code, "too_large")

    def test_http_errors_and_timeouts(self):
        missing, _ = fetcher({})
        with self.assertRaises(MediaError) as ctx:
            missing.fetch(IMG_URL)
        self.assertEqual(ctx.exception.code, "http_404")
        slow, _ = fetcher({IMG_URL: requests.Timeout("slow")})
        with self.assertRaises(MediaError) as ctx:
            slow.fetch(IMG_URL)
        self.assertEqual(ctx.exception.code, "timeout")

    def test_dns_failure(self):
        f, _ = fetcher({}, resolver=resolver_for(default=None))
        with self.assertRaises(MediaError) as ctx:
            f.fetch(IMG_URL)
        self.assertEqual(ctx.exception.code, "dns_failure")


class ImageValidationTests(SimpleTestCase):
    def test_valid_formats_regardless_of_content_type(self):
        for fmt, expected in (("JPEG", "JPEG"), ("PNG", "PNG"), ("WEBP", "WEBP"), ("GIF", "GIF")):
            self.assertEqual(validate_image(image_bytes(fmt, size=(5, 4)))[0], expected)
        self.assertEqual(validate_image(image_bytes("PNG", size=(7, 3)))[1:], (7, 3))

    def test_html_script_and_empty_bodies_rejected(self):
        for body in (b"<html><script>alert(1)</script></html>", b"", b"GIF89a but not really"):
            with self.assertRaises(MediaError) as ctx:
                validate_image(body)
            self.assertIn(ctx.exception.code, ("invalid_image", "empty"))

    def test_corrupt_image_rejected(self):
        truncated = image_bytes("JPEG", size=(64, 64))[:200]
        with self.assertRaises(MediaError) as ctx:
            validate_image(truncated)
        self.assertEqual(ctx.exception.code, "invalid_image")

    def test_unsupported_format_and_svg_rejected(self):
        buffer = io.BytesIO()
        Image.new("RGB", (4, 4)).save(buffer, format="BMP")
        with self.assertRaises(MediaError) as ctx:
            validate_image(buffer.getvalue())
        self.assertEqual(ctx.exception.code, "unsupported_format")
        with self.assertRaises(MediaError):
            validate_image(b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>')

    def test_oversized_dimensions_rejected(self):
        with self.assertRaises(MediaError) as ctx:
            validate_image(image_bytes("PNG", size=(8000, 6000)))
        self.assertIn(ctx.exception.code, ("bad_dimensions", "decompression_bomb"))


class MediaStoreTests(TestCase):
    def setUp(self):
        self.storage = InMemoryStorage()
        self.body = image_bytes("WEBP")
        self.fetcher, self.session = fetcher({IMG_URL: FakeMediaResponse(200, self.body)})
        self.store = MediaStore(self.fetcher, storage=self.storage)

    def test_first_use_downloads_and_stores_deterministically(self):
        asset, downloaded = self.store.get_or_migrate(IMG_URL)
        self.assertTrue(downloaded)
        self.assertTrue(asset.storage_name.startswith(MEDIA_PREFIX))
        self.assertTrue(asset.storage_name.endswith("-chart.webp"))
        self.assertEqual((asset.image_format, asset.width, asset.height), ("WEBP", 4, 3))
        self.assertTrue(self.storage.exists(asset.storage_name))
        self.assertEqual(self.store.url(asset), self.storage.url(asset.storage_name))

    def test_repeat_use_reuses_without_download_or_upload(self):
        first, _ = self.store.get_or_migrate(IMG_URL)
        second, downloaded = self.store.get_or_migrate(IMG_URL)
        self.assertFalse(downloaded)
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(self.session.requested, [IMG_URL], "downloaded exactly once")
        self.assertEqual(BlogMediaAsset.objects.count(), 1)
        self.assertEqual(len(self.storage.listdir(MEDIA_PREFIX + first.storage_name.split("/")[3])[1]), 1)

    def test_same_bytes_under_new_url_get_a_new_ledger_row_but_existing_object_is_reused(self):
        other = "https://imaa.test/wp-content/uploads/copy.png"
        self.session.routes[other] = FakeMediaResponse(200, self.body)
        a, _ = self.store.get_or_migrate(IMG_URL)
        b, _ = self.store.get_or_migrate(other)
        self.assertNotEqual(a.storage_name, b.storage_name, "source URL is part of the deterministic name")

    def test_changed_content_behind_a_migrated_url_is_not_refetched(self):
        # Policy: WordPress upload URLs are treated as immutable; the ledger row
        # is authoritative. A content change only takes effect for a new URL.
        asset, _ = self.store.get_or_migrate(IMG_URL)
        self.session.routes[IMG_URL] = FakeMediaResponse(200, image_bytes("PNG", size=(9, 9)))
        again, downloaded = self.store.get_or_migrate(IMG_URL)
        self.assertFalse(downloaded)
        self.assertEqual(again.sha256, asset.sha256)

    def test_invalid_download_stores_nothing(self):
        self.session.routes[IMG_URL] = FakeMediaResponse(200, b"<html>login</html>", {"Content-Type": "image/png"})
        with self.assertRaises(MediaError):
            self.store.get_or_migrate(IMG_URL)
        self.assertFalse(BlogMediaAsset.objects.exists())
        self.assertEqual(self.storage.listdir("")[0], [])
