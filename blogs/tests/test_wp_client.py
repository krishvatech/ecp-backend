from unittest import mock

import requests
from django.test import SimpleTestCase

from django.test import override_settings

from blogs.wordpress.client import (
    SUPPORTED_STATUSES,
    WordPressBlogAPIError,
    WordPressBlogAuthError,
    WordPressBlogClient,
    WordPressBlogConfigError,
)
from blogs.wordpress.formats import detect_source_format

from .wp_fixtures import (
    CLASSIC_HTML,
    ELEMENTOR_HTML,
    GUTENBERG_HTML,
    INVALID_JSON,
    AUTH,
    MIXED_HTML,
    SITE,
    WP_APP_PASSWORD,
    WP_USER,
    FakeResponse,
    FakeWordPress,
    make_post,
)


def client_for(fake, **kwargs):
    kwargs.setdefault("retries", 0)
    return WordPressBlogClient(SITE, timeout=5, session=fake, **kwargs)


class WordPressBlogClientTests(SimpleTestCase):
    def test_requires_a_base_url(self):
        with self.assertRaises(WordPressBlogConfigError):
            WordPressBlogClient("")
        self.assertEqual(WordPressBlogClient(f"{SITE}/wp-json/", session=FakeWordPress()).base_url, SITE)

    def test_category_fetch(self):
        category = client_for(FakeWordPress()).get_category(58)
        self.assertEqual((category["id"], category["name"], category["slug"]), (58, "Blog", "blog"))

    def test_missing_category_is_a_clear_404(self):
        with self.assertRaises(WordPressBlogAPIError) as ctx:
            client_for(FakeWordPress()).get_category(59)
        self.assertEqual(ctx.exception.status, 404)
        self.assertIn("GET /wp-json/wp/v2/categories/59 HTTP 404", str(ctx.exception))
        self.assertIn("rest_term_invalid", str(ctx.exception))

    def test_post_listing_reads_total_headers(self):
        fake = FakeWordPress(posts=[make_post(1), make_post(2)])
        page = client_for(fake).list_posts(58, per_page=100)
        self.assertEqual([p["id"] for p in page.posts], [1, 2])
        self.assertEqual((page.total, page.total_pages), (2, 1))
        path, params = fake.calls[-1]
        self.assertEqual(path, "/posts")
        self.assertEqual((params["categories"], params["status"], params["_embed"]), (58, "publish", 1))

    def test_iter_posts_follows_every_page_once(self):
        fake = FakeWordPress(posts=[make_post(i) for i in range(1, 8)])
        client = client_for(fake)
        ids = [p["id"] for p in client.iter_posts(58, per_page=3)]
        self.assertEqual(ids, list(range(1, 8)))
        pages = [params["page"] for path, params in fake.calls if path == "/posts"]
        self.assertEqual(pages, [1, 2, 3])
        self.assertEqual((client.stats.api_total, client.stats.api_total_pages, client.stats.pages_fetched), (7, 3, 3))

    def test_pagination_loop_guard(self):
        fake = FakeWordPress()
        # A broken server that always claims more pages and returns new ids.
        counter = iter(range(1, 1000))
        fake.overrides["/posts"] = None

        def endless(url, params=None, timeout=None, headers=None, auth=None):
            return FakeResponse(200, [{"id": next(counter)}], {"X-WP-Total": "999", "X-WP-TotalPages": "999"})

        fake.get = endless
        with self.assertRaises(WordPressBlogAPIError) as ctx:
            list(client_for(fake).iter_posts(58, per_page=1, max_pages=5))
        self.assertEqual(ctx.exception.code, "pagination_limit")

    def test_repeated_page_content_stops_iteration(self):
        def same_page(url, params=None, timeout=None, headers=None, auth=None):
            return FakeResponse(200, [{"id": 1}], {"X-WP-TotalPages": "50"})

        fake = FakeWordPress()
        fake.get = same_page
        self.assertEqual([p["id"] for p in client_for(fake).iter_posts(58, per_page=1)], [1])

    def test_timeout(self):
        fake = FakeWordPress()
        fake.overrides["/posts"] = requests.Timeout("slow")
        with self.assertRaises(WordPressBlogAPIError) as ctx:
            client_for(fake).list_posts(58)
        self.assertEqual(ctx.exception.code, "timeout")
        self.assertIn("timed out after 5s: GET /wp-json/wp/v2/posts", str(ctx.exception))

    def test_transient_failures_are_retried_then_succeed(self):
        fake = FakeWordPress(posts=[make_post(1)])
        failures = [requests.Timeout("slow"), FakeResponse(503, {"code": "busy", "message": "Busy"})]
        original = fake.get

        def flaky(url, params=None, timeout=None, headers=None, auth=None):
            if failures:
                failure = failures.pop(0)
                if isinstance(failure, Exception):
                    raise failure
                return failure
            return original(url, params, timeout, headers, auth)

        fake.get = flaky
        delays = []
        page = client_for(fake, retries=2, backoff=1, sleep=delays.append).list_posts(58)
        self.assertEqual([p["id"] for p in page.posts], [1])
        self.assertEqual(delays, [1, 2])

    def test_retries_are_bounded_and_not_used_for_client_errors(self):
        fake = FakeWordPress()
        fake.overrides["/posts"] = requests.Timeout("slow")
        delays = []
        with self.assertRaises(WordPressBlogAPIError):
            client_for(fake, retries=2, backoff=1, sleep=delays.append).list_posts(58)
        self.assertEqual(len(fake.paths("/posts")), 3)
        fake.calls.clear()
        fake.overrides["/posts"] = FakeResponse(404, {"code": "rest_no_route", "message": "No route"})
        with self.assertRaises(WordPressBlogAPIError):
            client_for(fake, retries=2, sleep=delays.append).list_posts(58)
        self.assertEqual(len(fake.paths("/posts")), 1)

    def test_connection_error(self):
        fake = FakeWordPress()
        fake.overrides["/posts"] = requests.ConnectionError("dns failure")
        with self.assertRaises(WordPressBlogAPIError) as ctx:
            client_for(fake).list_posts(58)
        self.assertEqual(ctx.exception.code, "connection")

    def test_http_404_and_5xx(self):
        fake = FakeWordPress()
        for status in (404, 500, 503):
            fake.overrides["/posts"] = FakeResponse(status, {"code": "boom", "message": "Down"})
            with self.assertRaises(WordPressBlogAPIError) as ctx:
                client_for(fake).list_posts(58)
            self.assertEqual(ctx.exception.status, status)
            self.assertIn(f"HTTP {status}", str(ctx.exception))

    def test_html_error_page_without_json(self):
        fake = FakeWordPress()
        fake.overrides["/posts"] = FakeResponse(502, INVALID_JSON)
        with self.assertRaises(WordPressBlogAPIError) as ctx:
            client_for(fake).list_posts(58)
        self.assertIn("HTTP 502", str(ctx.exception))

    def test_invalid_json(self):
        fake = FakeWordPress()
        fake.overrides["/posts"] = FakeResponse(200, INVALID_JSON)
        with self.assertRaises(WordPressBlogAPIError) as ctx:
            client_for(fake).list_posts(58)
        self.assertEqual(ctx.exception.code, "invalid_json")

    def test_rest_error_payload_is_reported(self):
        fake = FakeWordPress()
        fake.overrides["/posts"] = FakeResponse(400, {"code": "rest_invalid_param", "message": "Invalid parameter(s): status"})
        with self.assertRaises(WordPressBlogAPIError) as ctx:
            client_for(fake).list_posts(58)
        self.assertEqual(ctx.exception.code, "rest_invalid_param")
        self.assertIn("Invalid parameter(s): status", str(ctx.exception))

    def test_malformed_list_payload(self):
        fake = FakeWordPress()
        fake.overrides["/posts"] = FakeResponse(200, {"not": "a list"})
        with self.assertRaises(WordPressBlogAPIError) as ctx:
            client_for(fake).list_posts(58)
        self.assertEqual(ctx.exception.code, "malformed")

    def test_single_post_fetch_with_and_without_embed(self):
        fake = FakeWordPress(posts=[make_post(157)])
        client = client_for(fake)
        self.assertIn("_embedded", client.get_post(157))
        self.assertNotIn("_embedded", client.get_post(157, embed=False))
        with self.assertRaises(WordPressBlogAPIError) as ctx:
            client.get_post(999)
        self.assertEqual(ctx.exception.status, 404)

    def test_term_lookups_are_batched_and_cached(self):
        fake = FakeWordPress(terms={"categories": {}, "tags": {5: {"id": 5, "name": "A", "slug": "a"}, 6: {"id": 6, "name": "B", "slug": "b"}}})
        client = client_for(fake)
        client.get_terms("tags", [5, 6, 5])
        client.get_terms("tags", [6, 5])
        client.get_terms("tags", [7])  # unknown: fetched once, cached as a miss
        client.get_terms("tags", [7])
        self.assertEqual(len(fake.paths("/tags")), 2)
        self.assertEqual(fake.calls[0][1]["include"], "5,6")

    def test_no_credentials_or_auth_headers_are_sent(self):
        seen = {}

        def capture(url, params=None, timeout=None, headers=None, **kwargs):
            seen.update(headers=headers, kwargs=kwargs, timeout=timeout)
            return FakeResponse(200, {"id": 58, "name": "Blog", "slug": "blog"})

        fake = FakeWordPress()
        fake.get = capture
        client_for(fake).get_category(58)
        self.assertNotIn("Authorization", seen["headers"])
        self.assertEqual(seen["kwargs"], {"auth": None}, "an anonymous client never sends credentials")
        self.assertEqual(seen["timeout"], 5.0)


class AuthenticatedClientTests(SimpleTestCase):
    def test_basic_auth_is_sent_and_public_requests_opt_out(self):
        fake = FakeWordPress(posts=[make_post(1)])
        client = client_for(fake, auth=AUTH)
        client.get_category(58)
        client.list_posts(58, include=[1], public=True)
        self.assertEqual(fake.call_auth, [AUTH, None])
        self.assertTrue(client.authenticated)
        self.assertNotIn(WP_APP_PASSWORD, repr(client))

    @override_settings(WP_IMAA_BLOG_BASE_URL=SITE, WP_IMAA_BLOG_API_USER=WP_USER, WP_IMAA_BLOG_APP_PASSWORD=WP_APP_PASSWORD)
    def test_from_settings_authenticated(self):
        self.assertEqual(WordPressBlogClient.from_settings(authenticated=True)._auth, AUTH)
        self.assertFalse(WordPressBlogClient.from_settings().authenticated, "anonymous unless asked")

    def test_missing_username_or_password_is_a_safe_config_error(self):
        for user, password, missing in ((WP_USER, "", "WP_IMAA_BLOG_APP_PASSWORD"), ("", WP_APP_PASSWORD, "WP_IMAA_BLOG_API_USER")):
            with self.subTest(missing=missing), override_settings(
                    WP_IMAA_BLOG_BASE_URL=SITE, WP_IMAA_BLOG_API_USER=user, WP_IMAA_BLOG_APP_PASSWORD=password):
                with self.assertRaises(WordPressBlogConfigError) as ctx:
                    WordPressBlogClient.from_settings(authenticated=True)
                message = str(ctx.exception)
                self.assertIn("Authenticated WordPress Blog import is not configured.", message)
                self.assertIn(missing, message)
                self.assertNotIn(WP_APP_PASSWORD, message)

    def test_credentials_require_https(self):
        with self.assertRaises(WordPressBlogConfigError):
            WordPressBlogClient("http://imaa.test", session=FakeWordPress(), auth=AUTH)

    def test_401_and_403_are_safe_auth_errors_and_not_retried(self):
        for fake, status, code in ((FakeWordPress(credentials=("x", "y")), 401, "auth_failed"),
                                   (FakeWordPress(forbid_auth=True), 403, "auth_forbidden")):
            with self.subTest(status=status):
                client = client_for(fake, auth=AUTH, retries=3, sleep=lambda s: None)
                with self.assertRaises(WordPressBlogAuthError) as ctx:
                    client.editorial_manifest(58)
                self.assertEqual((ctx.exception.status, ctx.exception.code), (status, code))
                self.assertEqual(len(fake.calls), 1, "auth failures are not retried")
                for secret in (WP_APP_PASSWORD, WP_USER, "invalid application password"):
                    self.assertNotIn(secret, str(ctx.exception))

    def test_manifest_uses_edit_context_explicit_statuses_and_paginates_each(self):
        posts = [make_post(i, slug=f"p{i}", status=status) for i, status in enumerate(
            ["publish"] * 3 + ["draft"] * 3 + ["pending"] * 3 + ["future"] * 3 + ["private"] * 3 + ["trash", "auto-draft"], start=1)]
        fake = FakeWordPress(posts=posts)
        client = client_for(fake, auth=AUTH)
        with mock.patch("blogs.wordpress.client.MAX_PER_PAGE", 2):  # force several pages per status
            manifest = client.editorial_manifest(58, per_page=2)
        self.assertEqual([p["id"] for p in manifest], list(range(1, 16)), "trash/auto-draft never listed")
        self.assertEqual(client.stats.status_counts, {status: 3 for status in SUPPORTED_STATUSES})
        self.assertTrue(all(params["context"] == "edit" for _, params in fake.calls))
        self.assertEqual(sorted({params["status"] for _, params in fake.calls}), sorted(SUPPORTED_STATUSES))
        pages = {(params["status"], params["page"]) for _, params in fake.calls}
        for status in SUPPORTED_STATUSES:
            self.assertIn((status, 1), pages)
            self.assertIn((status, 2), pages, f"{status} is paginated")
        self.assertTrue(all("_embed" not in params and params["_fields"] for _, params in fake.calls))

    def test_manifest_dedupes_and_drops_unsupported_statuses(self):
        fake = FakeWordPress()
        fake.overrides["/posts"] = FakeResponse(200, [
            {"id": 1, "status": "publish"}, {"id": 1, "status": "publish"}, {"id": 2, "status": "trash"},
            {"id": 3, "status": "inherit"}, {"id": "bad", "status": "draft"},
        ], {"X-WP-TotalPages": "1"})
        manifest = client_for(fake, auth=AUTH).editorial_manifest(58)
        self.assertEqual([p["id"] for p in manifest], [1])

    def test_manifest_requires_credentials(self):
        with self.assertRaises(WordPressBlogConfigError):
            client_for(FakeWordPress()).editorial_manifest(58)

    def test_manifest_timeout_is_retried_then_raised(self):
        fake = FakeWordPress()
        fake.overrides["/posts"] = requests.Timeout("slow")
        delays = []
        with self.assertRaises(WordPressBlogAPIError) as ctx:
            client_for(fake, auth=AUTH, retries=2, backoff=1, sleep=delays.append).editorial_manifest(58)
        self.assertEqual((ctx.exception.code, len(fake.calls), delays), ("timeout", 3, [1.0, 2.0]))


class FormatDetectionTests(SimpleTestCase):
    def test_gutenberg(self):
        self.assertEqual(detect_source_format(GUTENBERG_HTML), "gutenberg")
        self.assertEqual(detect_source_format('<figure class="wp-block-image"><img src="a.png"></figure>'), "gutenberg")

    def test_elementor(self):
        self.assertEqual(detect_source_format(ELEMENTOR_HTML), "elementor")

    def test_classic(self):
        self.assertEqual(detect_source_format(CLASSIC_HTML), "classic")
        self.assertEqual(detect_source_format("Plain text only"), "classic")

    def test_mixed(self):
        self.assertEqual(detect_source_format(MIXED_HTML), "mixed")

    def test_unknown(self):
        self.assertEqual(detect_source_format(""), "unknown")
        self.assertEqual(detect_source_format("   "), "unknown")

    def test_false_positive_resistance(self):
        text = "<p>We compared Elementor and wp-block- editors in <!-- a note --> our elementor-widget review.</p>"
        self.assertEqual(detect_source_format(text), "classic")
        self.assertEqual(detect_source_format('<p class="elementor-widget">one stray class</p>'), "classic")
