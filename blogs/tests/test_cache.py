from functools import partial
from unittest import mock

from django.core.cache import cache
from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from rest_framework import status

from blogs import cache as blog_cache
from blogs.content_chunks import content_chunks
from blogs.models import BlogCategory, BlogImportRun, BlogPost
from blogs.wordpress import sync

from .factories import BlogAPITestCase, make_post, make_published_post, make_superuser, make_user
from .test_content_chunks import TARGET, article
from .test_wp_sync import SITE, SyncHarness

LIST_URL = reverse("blogs:post-list")


def detail_url(slug):
    return reverse("blogs:post-detail", kwargs={"slug": slug})


def content_url(slug):
    return reverse("blogs:post-content", kwargs={"slug": slug})


def blog_queries(ctx):
    return [q["sql"] for q in ctx.captured_queries if "blogs_" in q["sql"]]


class BrokenCache:
    """Stands in for an unreachable Redis: every operation raises."""

    def __init__(self):
        self.calls = 0

    def _fail(self, *args, **kwargs):
        self.calls += 1
        raise ConnectionError("redis down")

    get = set = add = incr = delete = _fail


class CacheTestCase(BlogAPITestCase):
    def setUp(self):
        super().setUp()
        blog_cache.reset_failure_state()
        self.addCleanup(blog_cache.reset_failure_state)
        self.reader = make_user("reader")
        self.client.force_authenticate(self.reader)
        self.post = make_published_post(title="Cached story", content_html="<p>Original body</p>")

    def get(self, url, params=None, **extra):
        return self.client.get(url, params or {}, **extra)

    def assertCache(self, response, expected):
        self.assertEqual(response.status_code, status.HTTP_200_OK, getattr(response, "data", None))
        self.assertEqual(response["X-Blog-Cache"], expected)


class ReaderCacheHitTests(CacheTestCase):
    def test_second_list_request_is_served_from_cache_without_blog_queries(self):
        first = self.get(LIST_URL)
        self.assertCache(first, "MISS")
        with CaptureQueriesContext(connection) as ctx:
            second = self.get(LIST_URL)
        self.assertCache(second, "HIT")
        self.assertEqual(blog_queries(ctx), [])
        self.assertEqual(second.data, first.data)

    def test_detail_chunked_detail_and_chunks_share_one_cached_post(self):
        long_post = make_published_post(title="Long read", content_html=article())
        self.assertCache(self.get(detail_url(long_post.slug)), "MISS")
        with mock.patch("blogs.views.content_chunks", partial(content_chunks, target=TARGET)):
            with CaptureQueriesContext(connection) as ctx:
                full = self.get(detail_url(long_post.slug))
                chunked = self.get(detail_url(long_post.slug), {"content_mode": "chunked"})
                rest = [self.get(content_url(long_post.slug), {"chunk": n})
                        for n in range(2, chunked.data["content_chunks"] + 1)]
        self.assertEqual(blog_queries(ctx), [])
        for response in (full, chunked, *rest):
            self.assertCache(response, "HIT")
        self.assertGreater(chunked.data["content_chunks"], 1)
        rebuilt = chunked.data["content_html"] + "".join(r.data["content_html"] for r in rest)
        self.assertEqual(rebuilt, full.data["content_html"])
        self.assertEqual(full.data["content_html"], article(), "chunked mode never mutates the cached post")

    def test_each_page_and_filter_is_cached_separately(self):
        category = BlogCategory.objects.create(name="Deals")
        in_category = make_published_post(title="Deal story")
        in_category.categories.add(category)

        everything = self.get(LIST_URL)
        filtered = self.get(LIST_URL, {"category": category.slug})
        small_page = self.get(LIST_URL, {"page_size": 1})
        for response in (everything, filtered, small_page):
            self.assertCache(response, "MISS")
        self.assertEqual(len(everything.data["results"]), 2)
        self.assertEqual([p["slug"] for p in filtered.data["results"]], [in_category.slug])
        self.assertEqual(len(small_page.data["results"]), 1)
        self.assertCache(self.get(LIST_URL, {"category": category.slug}), "HIT")

    @override_settings(ALLOWED_HOSTS=["testserver", "other.example"])
    def test_host_is_part_of_the_key_because_pagination_links_are_absolute(self):
        make_published_post(title="Second")
        first = self.get(LIST_URL, {"page_size": 1})
        other = self.get(LIST_URL, {"page_size": 1}, HTTP_HOST="other.example")
        self.assertCache(other, "MISS")
        self.assertIn("other.example", other.data["next"])
        self.assertIn("testserver", first.data["next"])

    def test_search_is_never_cached(self):
        for _ in range(2):
            response = self.get(LIST_URL, {"search": "Cached"})
            self.assertCache(response, "MISS")
            self.assertEqual(len(response.data["results"]), 1)

    def test_drafts_and_unknown_slugs_are_404_and_never_cached(self):
        draft = make_post(title="Secret draft")
        with mock.patch.object(blog_cache, "safe_set", wraps=blog_cache.safe_set) as writes:
            for slug in (draft.slug, "no-such-post"):
                self.assertEqual(self.get(detail_url(slug)).status_code, status.HTTP_404_NOT_FOUND)
                self.assertEqual(self.get(content_url(slug), {"chunk": 1}).status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(writes.called)

    def test_chunk_validation_still_applies_on_cache_hits(self):
        self.get(detail_url(self.post.slug))
        self.assertEqual(self.get(content_url(self.post.slug), {"chunk": "x"}).status_code, 400)
        self.assertEqual(self.get(content_url(self.post.slug), {"chunk": 9}).status_code, 404)

    def test_unauthenticated_requests_are_rejected_even_when_cached(self):
        self.get(LIST_URL)
        self.get(detail_url(self.post.slug))
        self.client.force_authenticate(None)
        for url in (LIST_URL, detail_url(self.post.slug)):
            self.assertIn(self.get(url).status_code, (401, 403))

    def test_admin_endpoints_are_not_cached(self):
        self.client.force_authenticate(make_superuser())
        response = self.get(reverse("blogs:admin-post-list"))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("X-Blog-Cache", response)

    @override_settings(BLOGS_RESPONSE_CACHE_ENABLED=False)
    def test_kill_switch_disables_response_caching(self):
        for _ in range(2):
            self.assertCache(self.get(LIST_URL), "MISS")
            self.assertCache(self.get(detail_url(self.post.slug)), "MISS")


class InvalidationTests(CacheTestCase):
    def setUp(self):
        super().setUp()
        self.admin = make_superuser()

    def warm(self):
        self.assertCache(self.get(LIST_URL), "MISS")
        self.assertCache(self.get(detail_url(self.post.slug)), "MISS")
        self.assertCache(self.get(LIST_URL), "HIT")

    def as_admin(self, method, url, data=None):
        self.client.force_authenticate(self.admin)
        response = getattr(self.client, method)(url, data or {}, format="json")
        self.client.force_authenticate(self.reader)
        self.assertLess(response.status_code, 300, response.data)
        return response

    def test_publishing_a_new_post_shows_it_immediately(self):
        self.warm()
        draft = make_post(title="Fresh news")
        self.as_admin("post", reverse("blogs:admin-post-publish", kwargs={"pk": draft.pk}))
        listed = self.get(LIST_URL)
        self.assertCache(listed, "MISS")
        self.assertIn(draft.slug, [p["slug"] for p in listed.data["results"]])

    def test_unpublishing_removes_a_cached_post_from_list_and_detail(self):
        self.warm()
        self.as_admin("post", reverse("blogs:admin-post-unpublish", kwargs={"pk": self.post.pk}))
        self.assertEqual(self.get(LIST_URL).data["results"], [])
        self.assertEqual(self.get(detail_url(self.post.slug)).status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(self.get(content_url(self.post.slug), {"chunk": 1}).status_code, 404)

    def test_admin_edit_is_visible_immediately(self):
        self.warm()
        self.as_admin("patch", reverse("blogs:admin-post-detail", kwargs={"pk": self.post.pk}),
                      {"title": "Edited title", "content_html": "<p>Edited body</p>"})
        detail = self.get(detail_url(self.post.slug))
        self.assertCache(detail, "MISS")
        self.assertEqual(detail.data["title"], "Edited title")
        self.assertEqual(detail.data["content_html"], "<p>Edited body</p>")
        self.assertEqual(self.get(LIST_URL).data["results"][0]["title"], "Edited title")

    def test_category_assignment_and_rename_are_visible_immediately(self):
        category = BlogCategory.objects.create(name="Deals")
        self.warm()
        self.post.categories.add(category)
        self.assertEqual([c["name"] for c in self.get(LIST_URL).data["results"][0]["categories"]], ["Deals"])
        self.as_admin("patch", reverse("blogs:admin-category-detail", kwargs={"pk": category.pk}), {"name": "M&A Deals"})
        self.assertEqual(self.get(detail_url(self.post.slug)).data["categories"][0]["name"], "M&A Deals")
        self.post.categories.clear()
        self.assertEqual(self.get(LIST_URL).data["results"][0]["categories"], [])

    def test_invalidate_bumps_now_and_again_after_commit(self):
        before = blog_cache.current_version()
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            blog_cache.invalidate()
            self.assertEqual(blog_cache.current_version(), before + 1)
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(blog_cache.current_version(), before + 2)

    def test_evicted_version_key_never_revives_old_entries(self):
        self.warm()
        old = blog_cache.current_version()
        cache.delete(blog_cache.VERSION_KEY)
        self.assertNotEqual(blog_cache.current_version(), old)
        self.assertCache(self.get(LIST_URL), "MISS")

    def test_wordpress_import_invalidates_even_when_it_fails(self):
        self.warm()

        def failing_import(run, **kwargs):
            # Like the media/link phases: a queryset update fires no signals.
            BlogPost.objects.filter(pk=self.post.pk).update(title="Changed by import")
            raise RuntimeError("source went away")

        with mock.patch.object(sync, "_execute_import_run", side_effect=failing_import):
            with self.assertRaises(RuntimeError):
                sync.execute_import_run(BlogImportRun.objects.create())
        self.assertEqual(self.get(detail_url(self.post.slug)).data["title"], "Changed by import")
        self.assertEqual(self.get(LIST_URL).data["results"][0]["title"], "Changed by import")


@override_settings(WP_IMAA_BLOG_BASE_URL=SITE, WP_IMAA_BLOG_CATEGORY_ID=58)
class ImportInvalidationTests(SyncHarness, CacheTestCase):
    def test_real_import_results_are_visible_to_readers_straight_away(self):
        self.assertCache(self.get(LIST_URL), "MISS")
        self.assertCache(self.get(LIST_URL), "HIT")
        self.run_import()
        listed = {p["slug"] for p in self.get(LIST_URL).data["results"]}
        self.assertTrue({"first-post", "second-post"} <= listed)
        body = self.get(detail_url("first-post")).data["content_html"]
        self.assertNotIn(f"{SITE}/wp-content/uploads/2024/01/chart.png", body,
                         "reader sees the migrated media written by the .update() phase")


class RedisOutageTests(CacheTestCase):
    def test_reader_endpoints_fall_back_to_the_database(self):
        long_post = make_published_post(title="Long read", content_html=article())
        broken = BrokenCache()
        with mock.patch.object(blog_cache, "cache", broken), self.assertLogs("blogs.cache", "WARNING"):
            listed = self.get(LIST_URL)
            detail = self.get(detail_url(long_post.slug))
            chunked = self.get(detail_url(long_post.slug), {"content_mode": "chunked"})
            first_chunk = self.get(content_url(long_post.slug), {"chunk": 1})
        for response in (listed, detail, chunked, first_chunk):
            self.assertCache(response, "MISS")
        self.assertEqual(len(listed.data["results"]), 2)
        self.assertEqual(detail.data["content_html"], article())
        self.assertTrue(first_chunk.data["content_html"])

    def test_outage_skips_the_cache_during_cooldown(self):
        broken = BrokenCache()
        with mock.patch.object(blog_cache, "cache", broken), self.assertLogs("blogs.cache", "WARNING"):
            self.get(LIST_URL)
            calls_after_first_failure = broken.calls
            for _ in range(5):
                self.assertCache(self.get(LIST_URL), "MISS")
        self.assertEqual(calls_after_first_failure, 1)
        self.assertEqual(broken.calls, 1, "no Redis round-trips (or socket timeouts) while cooling down")

    def test_cache_is_used_again_after_the_cooldown(self):
        with mock.patch.object(blog_cache, "cache", BrokenCache()), self.assertLogs("blogs.cache", "WARNING"):
            self.get(LIST_URL)
        with mock.patch("blogs.cache.time.monotonic", return_value=10**9):
            self.assertCache(self.get(LIST_URL), "MISS")
            self.assertCache(self.get(LIST_URL), "HIT")

    def test_blog_writes_succeed_while_redis_is_down(self):
        with mock.patch.object(blog_cache, "cache", BrokenCache()), self.assertLogs("blogs.cache", "WARNING"):
            with self.captureOnCommitCallbacks(execute=True):
                self.post.unpublish()
                BlogCategory.objects.create(name="Created during outage")
        self.post.refresh_from_db()
        self.assertEqual(self.post.status, BlogPost.STATUS_DRAFT)
