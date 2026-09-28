from datetime import timedelta
from unittest import mock

from bs4 import BeautifulSoup
from django.core.files.storage import InMemoryStorage
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status as http

from blogs.models import BlogCategory, BlogImportRun, BlogMediaAsset, BlogPost, BlogTag
from blogs.tasks import run_wordpress_blog_import
from blogs.views import BlogWordPressImportViewSet
from blogs.wordpress.client import WordPressBlogAPIError, WordPressBlogClient
from blogs.wordpress.media import MEDIA_PREFIX, MediaStore, SafeMediaFetcher, allowed_media_hosts
from blogs.wordpress.sync import execute_import_run, expire_stale_runs

from .factories import BlogAPITestCase, make_post as make_blog, make_superuser, make_user
from .media_fixtures import FakeMediaResponse, FakeMediaSession, image_bytes, resolver_for
from .wp_fixtures import SITE, FakeWordPress, make_post

TEASER = ('<p>Opening only.</p><div class="woocommerce"><div class="woocommerce-info wc-memberships-restriction-message">'
          'To access this post, you must purchase <a href="https://imaa.test/product/m/">Membership</a>.</div></div>')
INLINE = f"{SITE}/wp-content/uploads/2024/01/chart.png"
EXTERNAL_IMG = "https://cdn.example.com/photo.jpg"


def article(links=""):
    return (f'<p>Intro paragraph.</p><figure><img src="{INLINE}" srcset="{INLINE} 1024w, {SITE}/wp-content/uploads/2024/01/chart-300x200.png 300w" '
            f'sizes="(max-width: 1024px) 100vw" alt="Chart"></figure><p><img src="{EXTERNAL_IMG}" alt="Ext"></p>{links}')


def source_posts():
    links = (f'<p><a href="{SITE}/blog/second-post/">second</a> <a href="https://www.imaa.test/blog/members-post/">locked</a> '
             f'<a href="{SITE}/courses/pmi/">course</a> <a href="https://example.org/x">external</a> '
             f'<a href="{SITE}/blog/not-imported-anywhere/">missing</a></p>')
    return [
        make_post(301, slug="first-post", content=article(links), author=7, author_name="Jane Writer"),
        make_post(302, slug="second-post", content="<p>Second article body with enough text.</p>", featured=False),
        make_post(303, slug="members-post", content=TEASER),
    ]


class SyncHarness:
    def setUp(self):
        super().setUp()
        self.wp = FakeWordPress(posts=source_posts())
        self.media_session = FakeMediaSession({
            INLINE: FakeMediaResponse(200, image_bytes("PNG")),
            f"{SITE}/wp-content/uploads/cover-301.jpg": FakeMediaResponse(200, image_bytes("JPEG")),
        })
        self.storage = InMemoryStorage()

    def run_import(self, post_ids=None):
        run = BlogImportRun.objects.create()
        client = WordPressBlogClient(SITE, session=self.wp, retries=0)
        fetcher = SafeMediaFetcher(allowed_media_hosts(SITE), session=self.media_session, resolver=resolver_for())
        store = MediaStore(fetcher, storage=self.storage)
        execute_import_run(run, client=client, media_store=store, post_ids=post_ids)
        run.refresh_from_db()
        return run


@override_settings(WP_IMAA_BLOG_BASE_URL=SITE, WP_IMAA_BLOG_CATEGORY_ID=58)
class FullSyncTests(SyncHarness, TestCase):
    def test_first_run_creates_migrates_media_and_rewrites_links(self):
        run = self.run_import()
        self.assertEqual(run.status, "succeeded")
        self.assertEqual(run.current_step, "completed")
        self.assertEqual(
            (run.total_discovered, run.total_importable, run.created_count, run.updated_count,
             run.skipped_count, run.restricted_count, run.failed_count),
            (3, 2, 2, 0, 0, 1, 0),
        )
        self.assertIsNotNone(run.started_at)
        self.assertIsNotNone(run.finished_at)
        self.assertFalse(BlogPost.objects.filter(wp_post_id=303).exists(), "no teaser Blog is created")
        self.assertEqual(run.report_json["restricted_post_ids"], [303])

        first = BlogPost.objects.get(wp_post_id=301)
        self.assertEqual(first.status, "published")
        self.assertTrue(first.featured_image.name.startswith(MEDIA_PREFIX))
        self.assertEqual(first.wp_featured_media_id, 1201)
        self.assertTrue(self.storage.exists(first.featured_image.name))

        doc = BeautifulSoup(first.content_html, "html.parser")
        chart = doc.find("img", alt="Chart")
        self.assertIn(MEDIA_PREFIX, chart["src"])
        self.assertFalse(chart.has_attr("srcset"))
        self.assertFalse(chart.has_attr("sizes"))
        self.assertNotIn("/wp-content/uploads/", first.content_html)
        self.assertEqual(doc.find("img", alt="Ext")["src"], EXTERNAL_IMG, "third-party images are left external")
        self.assertNotIn(EXTERNAL_IMG, self.media_session.requested)

        hrefs = {a.get_text(): a["href"] for a in doc.find_all("a")}
        self.assertEqual(hrefs["second"], "/blogs/second-post")
        self.assertEqual(hrefs["locked"], "https://www.imaa.test/blog/members-post/", "restricted target keeps WP URL")
        self.assertEqual(hrefs["course"], f"{SITE}/courses/pmi/")
        self.assertEqual(hrefs["external"], "https://example.org/x")
        self.assertEqual(hrefs["missing"], f"{SITE}/blog/not-imported-anywhere/")
        self.assertEqual(run.links_rewritten_count, 1)
        links = run.report_json["links"]
        self.assertEqual((links["rewritten"], links["restricted_target"], links["unresolved"]), (1, 1, 1))

        self.assertEqual(run.media_migrated_count, 2)
        self.assertEqual(run.media_skipped_count, 1, "external inline image")
        self.assertEqual(run.media_failed_count, 0)
        for dangerous in ("<script", "onerror", "javascript:", "elementor"):
            self.assertNotIn(dangerous, first.content_html)

    def test_selected_posts_only(self):
        run = self.run_import(post_ids=[302])
        self.assertEqual((run.total_discovered, run.created_count), (1, 1))
        self.assertEqual(list(BlogPost.objects.values_list("wp_post_id", flat=True)), [302])

    def test_second_run_skips_everything_and_reuses_media(self):
        self.run_import()
        snapshot = {
            "posts": list(BlogPost.objects.order_by("pk").values("pk", "content_html", "featured_image", "updated_at")),
            "requests": len(self.media_session.requested),
            "assets": BlogMediaAsset.objects.count(),
            "objects": sorted(self.storage.listdir(MEDIA_PREFIX)[0]),
            "terms": (BlogCategory.objects.count(), BlogTag.objects.count()),
        }
        run = self.run_import()
        self.assertEqual(run.status, "succeeded")
        self.assertEqual((run.created_count, run.updated_count, run.skipped_count, run.restricted_count, run.failed_count),
                         (0, 0, 2, 1, 0))
        self.assertEqual(run.media_migrated_count, 0)
        self.assertEqual(run.links_rewritten_count, 0)
        self.assertEqual(len(self.media_session.requested), snapshot["requests"], "no re-download")
        self.assertEqual(BlogMediaAsset.objects.count(), snapshot["assets"])
        self.assertEqual(sorted(self.storage.listdir(MEDIA_PREFIX)[0]), snapshot["objects"], "no duplicate storage objects")
        self.assertEqual((BlogCategory.objects.count(), BlogTag.objects.count()), snapshot["terms"])
        self.assertEqual(
            list(BlogPost.objects.order_by("pk").values("pk", "content_html", "featured_image", "updated_at")),
            snapshot["posts"],
            "unchanged posts are not rewritten",
        )

    def test_changed_source_updates_only_that_post(self):
        self.run_import()
        second = BlogPost.objects.get(wp_post_id=302)
        self.wp.posts[1]["title"]["rendered"] = "Second, revised"
        run = self.run_import()
        self.assertEqual((run.created_count, run.updated_count, run.skipped_count), (0, 1, 1))
        self.assertEqual(BlogPost.objects.get(wp_post_id=302).pk, second.pk)
        self.assertEqual(BlogPost.objects.get(wp_post_id=302).title, "Second, revised")
        self.assertEqual(BlogPost.objects.filter(imported_from_wordpress=True).count(), 2)

    def test_changed_content_is_rewritten_again(self):
        self.run_import()
        self.wp.posts[0]["content"]["rendered"] = article() + "<p>New closing paragraph.</p>"
        run = self.run_import()
        self.assertEqual(run.updated_count, 1)
        first = BlogPost.objects.get(wp_post_id=301)
        self.assertIn("New closing paragraph.", first.content_html)
        self.assertNotIn("/wp-content/uploads/", first.content_html, "media rewritten again after update")
        self.assertEqual(run.media_migrated_count, 0, "same image reused from the ledger")

    def test_manual_blog_is_never_touched(self):
        manual = make_blog(title="Manual", slug="first-post", content_html="<p>Manual body</p>")
        self.run_import()
        manual.refresh_from_db()
        self.assertEqual((manual.slug, manual.content_html, manual.wp_post_id), ("first-post", "<p>Manual body</p>", None))
        self.assertEqual(BlogPost.objects.get(wp_post_id=301).slug, "first-post-wp301")

    def test_unpublished_import_stays_unpublished(self):
        self.run_import()
        BlogPost.objects.get(wp_post_id=302).unpublish()
        self.wp.posts[1]["title"]["rendered"] = "Changed in WordPress"
        run = self.run_import()
        post = BlogPost.objects.get(wp_post_id=302)
        self.assertEqual(run.updated_count, 1)
        self.assertEqual(post.title, "Changed in WordPress")
        self.assertEqual(post.status, "draft", "ECP owns status after the first import")

    def test_admin_replaced_or_removed_featured_image_is_respected(self):
        self.run_import()
        BlogPost.objects.filter(wp_post_id=301).update(featured_image="blogs/featured/manual-cover.jpg")
        self.wp.posts[0]["title"]["rendered"] = "Trigger update"
        self.run_import()
        self.assertEqual(BlogPost.objects.get(wp_post_id=301).featured_image.name, "blogs/featured/manual-cover.jpg")
        BlogPost.objects.filter(wp_post_id=301).update(featured_image="")
        self.run_import()
        self.assertEqual(BlogPost.objects.get(wp_post_id=301).featured_image.name, "", "not re-added after removal")

    def test_changed_wordpress_featured_image_replaces_imported_one(self):
        self.run_import()
        old = BlogPost.objects.get(wp_post_id=301).featured_image.name
        new_url = f"{SITE}/wp-content/uploads/new-cover.jpg"
        self.media_session.routes[new_url] = FakeMediaResponse(200, image_bytes("JPEG", color=(1, 2, 3)))
        media = self.wp.posts[0]["_embedded"]["wp:featuredmedia"][0]
        media.update(id=4444, source_url=new_url)
        self.wp.posts[0]["featured_media"] = 4444
        self.run_import()
        post = BlogPost.objects.get(wp_post_id=301)
        self.assertNotEqual(post.featured_image.name, old)
        self.assertEqual(post.wp_featured_media_id, 4444)

    def test_posts_missing_from_wordpress_are_not_deleted_or_unpublished(self):
        self.run_import()
        self.wp.posts = [p for p in self.wp.posts if p["id"] != 302]
        self.run_import()
        post = BlogPost.objects.get(wp_post_id=302)
        self.assertEqual(post.status, "published")

    def test_media_failures_make_the_run_partial_and_keep_the_article(self):
        self.media_session.routes[INLINE] = FakeMediaResponse(200, b"<html>not an image</html>", {"Content-Type": "image/png"})
        run = self.run_import()
        self.assertEqual(run.status, "partial")
        self.assertEqual(run.media_failed_count, 1)
        self.assertEqual(run.created_count, 2)
        failure = run.report_json["media_failures"][0]
        self.assertEqual((failure["wp_post_id"], failure["kind"], failure["code"]), (301, "inline", "invalid_image"))
        first = BlogPost.objects.get(wp_post_id=301)
        self.assertIn(INLINE, first.content_html, "failed image keeps its WordPress URL")
        self.assertFalse(BlogMediaAsset.objects.filter(source_url=INLINE).exists())

    def test_private_redirect_is_reported_not_followed(self):
        self.media_session.routes[INLINE] = FakeMediaResponse(302, headers={"Location": "http://169.254.169.254/latest/meta-data"})
        run = self.run_import()
        self.assertEqual(run.status, "partial")
        self.assertEqual(run.report_json["media_failures"][0]["code"], "blocked_host")
        self.assertNotIn("http://169.254.169.254/latest/meta-data", self.media_session.requested)

    def test_post_failure_is_isolated(self):
        from blogs.wordpress import importer

        real_apply = importer.apply_plan
        calls = {"n": 0}

        def flaky(plan, commit):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("disk full at /srv/data")
            return real_apply(plan, commit=commit)

        with mock.patch("blogs.wordpress.importer.apply_plan", side_effect=flaky):
            run = self.run_import()
        self.assertEqual(run.status, "partial")
        self.assertEqual((run.created_count, run.failed_count), (1, 1))
        self.assertIn("import failed and was rolled back: RuntimeError", run.report_json["errors"][0]["message"])
        self.assertNotIn("/srv/data", str(run.report_json), "no server paths in the admin report")


@override_settings(WP_IMAA_BLOG_BASE_URL=SITE, WP_IMAA_BLOG_CATEGORY_ID=58)
class TaskTests(SyncHarness, TestCase):
    def patches(self):
        client = mock.patch("blogs.wordpress.sync.WordPressBlogClient.from_settings",
                            side_effect=lambda: WordPressBlogClient(SITE, session=self.wp, retries=0))
        fetcher = mock.patch("blogs.wordpress.sync.SafeMediaFetcher",
                             side_effect=lambda hosts: SafeMediaFetcher(hosts, session=self.media_session, resolver=resolver_for()))
        storage = override_settings(STORAGES={
            "default": {"BACKEND": "django.core.files.storage.InMemoryStorage"},
            "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
        })
        return client, fetcher, storage

    def test_queued_to_running_to_succeeded(self):
        run = BlogImportRun.objects.create()
        seen = []
        original = execute_import_run

        def observe(r, **kwargs):
            seen.append(BlogImportRun.objects.get(pk=r.pk).status)
            return original(r, **kwargs)

        client, fetcher, storage = self.patches()
        with client, fetcher, storage, mock.patch("blogs.tasks.execute_import_run", side_effect=observe):
            result = run_wordpress_blog_import.apply(args=[str(run.pk)]).get()
        run.refresh_from_db()
        self.assertEqual(seen, ["queued"])
        self.assertEqual((result, run.status, run.created_count), ("succeeded", "succeeded", 2))
        self.assertIsNotNone(run.finished_at)

    def test_fatal_error_marks_failed_and_releases_lock(self):
        run = BlogImportRun.objects.create()
        with mock.patch("blogs.tasks.execute_import_run", side_effect=RuntimeError("secret /srv/path detail")):
            run_wordpress_blog_import.apply(args=[str(run.pk)])
        run.refresh_from_db()
        self.assertEqual(run.status, "failed")
        self.assertEqual(run.error_message, "Unexpected error (RuntimeError). Completed posts were kept.")
        BlogImportRun.objects.create()  # lock released: a new run can start

    def test_wordpress_outage_retries_then_fails(self):
        run = BlogImportRun.objects.create()
        with mock.patch("blogs.tasks.execute_import_run", side_effect=WordPressBlogAPIError("HTTP 503")) as execute:
            run_wordpress_blog_import.apply(args=[str(run.pk)])
        run.refresh_from_db()
        self.assertEqual(execute.call_count, 3, "initial attempt + 2 retries")
        self.assertEqual(run.status, "failed")
        self.assertIn("WordPress was unavailable after retries", run.error_message)

    def test_crash_mid_run_then_rerun_does_not_duplicate(self):
        client, fetcher, storage = self.patches()
        first = BlogImportRun.objects.create()
        with client, fetcher, storage, mock.patch(
            "blogs.wordpress.sync.rewrite_blog_links", side_effect=RuntimeError("worker died")
        ):
            run_wordpress_blog_import.apply(args=[str(first.pk)])
        first.refresh_from_db()
        self.assertEqual(first.status, "failed")
        self.assertEqual(BlogPost.objects.filter(imported_from_wordpress=True).count(), 2, "committed posts kept")
        assets = BlogMediaAsset.objects.count()

        client, fetcher, storage = self.patches()
        second = BlogImportRun.objects.create()
        with client, fetcher, storage:
            run_wordpress_blog_import.apply(args=[str(second.pk)])
        second.refresh_from_db()
        self.assertEqual(second.status, "succeeded")
        self.assertEqual((second.created_count, second.skipped_count), (0, 2))
        self.assertEqual(second.links_rewritten_count, 1, "the interrupted phase completes on the rerun")
        self.assertEqual(BlogPost.objects.filter(imported_from_wordpress=True).count(), 2)
        self.assertEqual(BlogMediaAsset.objects.count(), assets)

    def test_duplicate_delivery_of_a_finished_run_is_a_no_op(self):
        run = BlogImportRun.objects.create(status="succeeded")
        with mock.patch("blogs.tasks.execute_import_run") as execute:
            self.assertEqual(run_wordpress_blog_import.apply(args=[str(run.pk)]).get(), "succeeded")
        execute.assert_not_called()


@override_settings(WP_IMAA_BLOG_BASE_URL=SITE)
class ImportApiTests(BlogAPITestCase):
    def setUp(self):
        super().setUp()
        self.superuser = make_superuser()
        self.start_url = reverse("blogs:admin-wordpress-import-list")
        self.enqueue = mock.patch.object(BlogWordPressImportViewSet, "enqueue", return_value="task-123")
        self.enqueued = self.enqueue.start()
        self.addCleanup(self.enqueue.stop)

    def start(self):
        with self.captureOnCommitCallbacks(execute=True):
            return self.client.post(self.start_url, {}, format="json")

    def test_non_superusers_are_forbidden(self):
        for user in (make_user("reader"), make_user("staff", is_staff=True)):
            self.client.force_authenticate(user)
            self.assertEqual(self.start().status_code, http.HTTP_403_FORBIDDEN)
            self.assertEqual(self.client.get(self.start_url).status_code, http.HTTP_403_FORBIDDEN)
            self.assertEqual(self.client.get(reverse("blogs:admin-wordpress-import-latest")).status_code, http.HTTP_403_FORBIDDEN)
        self.client.force_authenticate(None)
        self.assertIn(self.start().status_code, (401, 403))
        self.assertFalse(BlogImportRun.objects.exists())
        self.enqueued.assert_not_called()

    def test_superuser_start_queues_exactly_once(self):
        self.client.force_authenticate(self.superuser)
        response = self.start()
        self.assertEqual(response.status_code, http.HTTP_202_ACCEPTED)
        self.assertEqual(response.data["status"], "queued")
        self.assertEqual(response.data["message"], "WordPress Blog import queued.")
        self.enqueued.assert_called_once()
        run = BlogImportRun.objects.get()
        self.assertEqual((run.requested_by, run.celery_task_id), (self.superuser, "task-123"))
        self.assertEqual(self.enqueued.call_args.args[0].pk, run.pk, "only the run id reaches the task")

    def test_second_start_while_active_is_409_with_the_active_run(self):
        self.client.force_authenticate(self.superuser)
        first = self.start()
        second = self.start()
        self.assertEqual(second.status_code, http.HTTP_409_CONFLICT)
        self.assertEqual(second.data["detail"], "An import is already running.")
        self.assertEqual(second.data["active_run"]["id"], first.data["id"])
        self.enqueued.assert_called_once()
        self.assertEqual(BlogImportRun.objects.count(), 1)

    def test_finished_run_releases_the_lock(self):
        self.client.force_authenticate(self.superuser)
        first = self.start()
        BlogImportRun.objects.filter(pk=first.data["id"]).update(status="partial")
        self.assertEqual(self.start().status_code, http.HTTP_202_ACCEPTED)

    def test_stale_run_is_expired_so_a_new_import_can_start(self):
        stale = BlogImportRun.objects.create(status="running")
        BlogImportRun.objects.filter(pk=stale.pk).update(updated_at=timezone.now() - timedelta(hours=2))
        self.client.force_authenticate(self.superuser)
        self.assertEqual(self.start().status_code, http.HTTP_202_ACCEPTED)
        stale.refresh_from_db()
        self.assertEqual(stale.status, "failed")
        self.assertEqual(expire_stale_runs(), 0)

    def test_queue_failure_marks_run_failed_and_frees_lock(self):
        self.enqueued.side_effect = ConnectionError("broker down")
        self.client.force_authenticate(self.superuser)
        self.start()
        run = BlogImportRun.objects.get()
        self.assertEqual(run.status, "failed")
        self.assertEqual(run.error_message, "The import could not be queued. Please try again later.")
        self.enqueued.side_effect = None
        self.assertEqual(self.start().status_code, http.HTTP_202_ACCEPTED)

    @override_settings(WP_IMAA_BLOG_BASE_URL="")
    def test_unconfigured_source_is_503_without_a_run(self):
        self.client.force_authenticate(self.superuser)
        self.assertEqual(self.start().status_code, http.HTTP_503_SERVICE_UNAVAILABLE)
        self.assertFalse(BlogImportRun.objects.exists())

    def test_status_latest_history_and_unknown(self):
        self.client.force_authenticate(self.superuser)
        latest_url = reverse("blogs:admin-wordpress-import-latest")
        self.assertEqual(self.client.get(latest_url).status_code, http.HTTP_404_NOT_FOUND)
        run_id = self.start().data["id"]
        BlogImportRun.objects.filter(pk=run_id).update(
            status="partial", processed_count=3, total_importable=4, created_count=2, failed_count=1,
            report_json={"errors": [{"wp_post_id": 9, "message": "import failed and was rolled back: RuntimeError"}],
                         "restricted_post_ids": [5], "media_failures": [{"wp_post_id": 9, "kind": "inline", "code": "timeout",
                                                                          "message": "download timed out", "url": "https://x"}]},
        )
        detail = self.client.get(reverse("blogs:admin-wordpress-import-detail", args=[run_id]))
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.data["progress"], {"processed": 3, "total": 4, "media_processed": 0, "media_total": 0})
        self.assertEqual(detail.data["summary"]["restricted_post_ids"], [5])
        self.assertNotIn("url", detail.data["summary"]["media_failures"][0])
        self.assertEqual(self.client.get(latest_url).data["id"], run_id)
        self.assertEqual(len(self.client.get(self.start_url).data), 1)
        unknown = reverse("blogs:admin-wordpress-import-detail", args=["00000000-0000-0000-0000-000000000000"])
        self.assertEqual(self.client.get(unknown).status_code, http.HTTP_404_NOT_FOUND)
