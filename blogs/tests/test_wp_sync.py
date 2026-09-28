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
from .wp_fixtures import AUTH, SITE, WP_APP_PASSWORD, WP_USER, FakeWordPress, make_post

TEASER = ('<p>Opening only.</p><div class="woocommerce"><div class="woocommerce-info wc-memberships-restriction-message">'
          'To access this post, you must purchase <a href="https://imaa.test/product/m/">Membership</a>.</div></div>')
INLINE = f"{SITE}/wp-content/uploads/2024/01/chart.png"
MEMBERS_INLINE = f"{SITE}/wp-content/uploads/2024/02/members-chart.png"
EXTERNAL_IMG = "https://cdn.example.com/photo.jpg"
MEMBERS_ARTICLE = f'<p>Full members-only analysis with every deal.</p><p><img src="{MEMBERS_INLINE}" alt="Members chart"></p>'
CREDENTIALS = {"WP_IMAA_BLOG_API_USER": WP_USER, "WP_IMAA_BLOG_APP_PASSWORD": WP_APP_PASSWORD}


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
        make_post(303, slug="members-post", content=MEMBERS_ARTICLE, members_only=True),
        make_post(304, slug="", generated_slug="draft-idea", status="draft",
                  content="<p>Work in progress draft body.</p>", featured=False),
    ]


def post_in(wp, post_id):
    return next(p for p in wp.posts if p["id"] == post_id)


class SyncHarness:
    def setUp(self):
        super().setUp()
        self.wp = FakeWordPress(posts=source_posts())
        self.media_session = FakeMediaSession({
            INLINE: FakeMediaResponse(200, image_bytes("PNG")),
            f"{SITE}/wp-content/uploads/cover-301.jpg": FakeMediaResponse(200, image_bytes("JPEG")),
            f"{SITE}/wp-content/uploads/cover-303.jpg": FakeMediaResponse(200, image_bytes("JPEG", color=(9, 9, 9))),
            MEMBERS_INLINE: FakeMediaResponse(200, image_bytes("PNG", color=(4, 5, 6))),
        })
        self.storage = InMemoryStorage()

    def run_import(self, post_ids=None):
        run = BlogImportRun.objects.create()
        client = WordPressBlogClient(SITE, session=self.wp, retries=0, auth=AUTH)
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
            (4, 4, 4, 0, 0, 1, 0),
        )
        self.assertIsNotNone(run.started_at)
        self.assertIsNotNone(run.finished_at)
        self.assertEqual(run.report_json["restricted_post_ids"], [303])
        self.assertEqual(run.report_json["restricted"]["imported_as_draft"], 1)
        self.assertEqual(run.report_json["source_status_counts"],
                         {"publish": 3, "draft": 1, "pending": 0, "future": 0, "private": 0})
        self.assertEqual(run.report_json["target_status"], {"published": 2, "draft": 2})
        self.assertEqual(run.report_json["ecp_status_counts"], {"published": 2, "draft": 2, "restricted_draft": 1})
        self.assertEqual(
            dict(BlogPost.objects.values_list("wp_post_id", "status")),
            {301: "published", 302: "published", 303: "draft", 304: "draft"},
        )
        self.assertTrue(all(BlogPost.objects.values_list("wp_status_managed", flat=True)))

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
        self.assertEqual(hrefs["locked"], "https://www.imaa.test/blog/members-post/", "Draft target keeps WP URL")
        self.assertEqual(hrefs["course"], f"{SITE}/courses/pmi/")
        self.assertEqual(hrefs["external"], "https://example.org/x")
        self.assertEqual(hrefs["missing"], f"{SITE}/blog/not-imported-anywhere/")
        self.assertEqual(run.links_rewritten_count, 1)
        links = run.report_json["links"]
        self.assertEqual((links["rewritten"], links["unpublished_target"], links["unresolved"]), (1, 1, 1))

        self.assertEqual(run.media_migrated_count, 4, "published, members-only and draft media all migrated")
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
                         (0, 0, 4, 1, 0))
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
        self.assertEqual((run.created_count, run.updated_count, run.skipped_count), (0, 1, 3))
        self.assertEqual(BlogPost.objects.get(wp_post_id=302).pk, second.pk)
        self.assertEqual(BlogPost.objects.get(wp_post_id=302).title, "Second, revised")
        self.assertEqual(BlogPost.objects.filter(imported_from_wordpress=True).count(), 4)

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
        self.assertEqual(post.status, "draft", "ECP owns status after a manual unpublish")
        self.assertFalse(post.wp_status_managed)

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
        self.assertEqual(run.created_count, 4)
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
        self.assertEqual((run.created_count, run.failed_count), (3, 1))
        self.assertIn("import failed and was rolled back: RuntimeError", run.report_json["errors"][0]["message"])
        self.assertNotIn("/srv/data", str(run.report_json), "no server paths in the admin report")


@override_settings(WP_IMAA_BLOG_BASE_URL=SITE, WP_IMAA_BLOG_CATEGORY_ID=58, **CREDENTIALS)
class TaskTests(SyncHarness, TestCase):
    def patches(self):
        client = mock.patch("blogs.wordpress.sync.WordPressBlogClient.from_settings",
                            side_effect=lambda **kw: WordPressBlogClient(SITE, session=self.wp, retries=0, auth=AUTH))
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
        self.assertEqual((result, run.status, run.created_count), ("succeeded", "succeeded", 4))
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
        self.assertEqual(BlogPost.objects.filter(imported_from_wordpress=True).count(), 4, "committed posts kept")
        assets = BlogMediaAsset.objects.count()

        client, fetcher, storage = self.patches()
        second = BlogImportRun.objects.create()
        with client, fetcher, storage:
            run_wordpress_blog_import.apply(args=[str(second.pk)])
        second.refresh_from_db()
        self.assertEqual(second.status, "succeeded")
        self.assertEqual((second.created_count, second.skipped_count), (0, 4))
        self.assertEqual(second.links_rewritten_count, 1, "the interrupted phase completes on the rerun")
        self.assertEqual(BlogPost.objects.filter(imported_from_wordpress=True).count(), 4)
        self.assertEqual(BlogMediaAsset.objects.count(), assets)

    def test_duplicate_delivery_of_a_finished_run_is_a_no_op(self):
        run = BlogImportRun.objects.create(status="succeeded")
        with mock.patch("blogs.tasks.execute_import_run") as execute:
            self.assertEqual(run_wordpress_blog_import.apply(args=[str(run.pk)]).get(), "succeeded")
        execute.assert_not_called()


@override_settings(WP_IMAA_BLOG_BASE_URL=SITE, **CREDENTIALS)
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


@override_settings(WP_IMAA_BLOG_BASE_URL=SITE, WP_IMAA_BLOG_CATEGORY_ID=58)
class StatusSyncTests(SyncHarness, TestCase):
    """WordPress editorial status -> ECP status, and ECP admin ownership."""

    def status_of(self, wp_post_id):
        post = BlogPost.objects.get(wp_post_id=wp_post_id)
        return post.status, post.wp_status, post.wp_status_managed

    def set_wp_status(self, post_id, status):
        post = post_in(self.wp, post_id)
        post["status"] = status
        post["link"] = f"{SITE}/blog/{post['slug'] or post['generated_slug']}/" if status == "publish" else f"{SITE}/?p={post_id}"
        if status == "publish" and not post["slug"]:
            post["slug"] = post["generated_slug"]

    def test_every_supported_status_maps_to_the_right_ecp_status(self):
        self.wp.posts += [
            make_post(305, slug="pending-post", status="pending", featured=False),
            make_post(306, slug="scheduled-post", status="future", featured=False, date_gmt="2099-01-01T09:00:00"),
            make_post(307, slug="private-post", status="private", featured=False),
        ]
        run = self.run_import()
        self.assertEqual(run.status, "succeeded")
        self.assertEqual(run.report_json["source_status_counts"],
                         {"publish": 3, "draft": 1, "pending": 1, "future": 1, "private": 1})
        expected = {301: ("published", "publish"), 302: ("published", "publish"), 303: ("draft", "publish"),
                    304: ("draft", "draft"), 305: ("draft", "pending"), 306: ("draft", "future"),
                    307: ("draft", "private")}
        for wp_post_id, (ecp_status, wp_status) in expected.items():
            self.assertEqual(self.status_of(wp_post_id), (ecp_status, wp_status, True), wp_post_id)

    def test_unsupported_statuses_are_never_requested_or_imported(self):
        self.wp.posts += [make_post(308, slug="trashed", status="trash", featured=False),
                          make_post(309, slug="auto", status="auto-draft", featured=False)]
        self.run_import()
        self.assertFalse(BlogPost.objects.filter(wp_post_id__in=[308, 309]).exists())
        requested = {params.get("status") for path, params in self.wp.calls if path == "/posts"}
        for status in requested:
            self.assertNotIn("any", status)
            self.assertNotIn("trash", status)
            self.assertNotIn("auto-draft", status)

    def test_draft_to_publish_publishes_the_same_blog(self):
        self.run_import()
        draft = BlogPost.objects.get(wp_post_id=304)
        self.assertEqual((draft.status, draft.slug), ("draft", "draft-idea"))
        self.set_wp_status(304, "publish")
        run = self.run_import()
        self.assertEqual(run.updated_count, 1)
        post = BlogPost.objects.get(wp_post_id=304)
        self.assertEqual((post.pk, post.status, post.wp_status, post.wp_status_managed), (draft.pk, "published", "publish", True))
        self.assertIsNotNone(post.published_at)
        self.assertEqual(run.report_json["status_changes"], {"published": 1, "unpublished": 0})
        self.assertEqual(BlogPost.objects.filter(wp_post_id=304).count(), 1)

    def test_publish_to_draft_or_private_unpublishes_without_deleting(self):
        self.run_import()
        for wp_status in ("draft", "private"):
            with self.subTest(wp_status=wp_status):
                self.set_wp_status(302, "publish")
                self.run_import()
                self.assertEqual(self.status_of(302), ("published", "publish", True))
                self.set_wp_status(302, wp_status)
                run = self.run_import()
                self.assertEqual(self.status_of(302), ("draft", wp_status, True))
                self.assertEqual(run.report_json["status_changes"]["unpublished"], 1)
        self.assertEqual(BlogPost.objects.filter(wp_post_id=302).count(), 1)

    def test_admin_unpublish_takes_ownership_from_wordpress(self):
        self.run_import()
        BlogPost.objects.get(wp_post_id=302).unpublish()
        self.assertEqual(self.status_of(302), ("draft", "publish", False))
        post_in(self.wp, 302)["content"]["rendered"] = "<p>Second article body, revised in WordPress.</p>"
        run = self.run_import()
        self.assertEqual(run.updated_count, 1)
        post = BlogPost.objects.get(wp_post_id=302)
        self.assertIn("revised in WordPress", post.content_html, "content still follows WordPress")
        self.assertEqual(post.status, "draft", "ECP keeps the status")
        for wp_status in ("private", "publish"):
            self.set_wp_status(302, wp_status)
            self.run_import()
            self.assertEqual(self.status_of(302), ("draft", wp_status, False))
        self.assertEqual(self.run_import().report_json["ecp_owned_status"], 1)

    def test_admin_publish_of_a_wordpress_draft_takes_ownership(self):
        self.run_import()
        BlogPost.objects.get(wp_post_id=304).publish()
        post_in(self.wp, 304)["title"]["rendered"] = "Draft idea, retitled"
        self.run_import()
        post = BlogPost.objects.get(wp_post_id=304)
        self.assertEqual((post.title, post.status, post.wp_status_managed), ("Draft idea, retitled", "published", False))
        self.set_wp_status(304, "private")
        self.run_import()
        self.assertEqual(self.status_of(304), ("published", "private", False))

    def test_blogs_imported_before_status_tracking_adopt_management_only_when_consistent(self):
        self.run_import()
        # Simulate Batch 4 rows: no WordPress status recorded yet.
        BlogPost.objects.update(wp_status="", wp_status_managed=False)
        BlogPost.objects.filter(wp_post_id=302).update(status="draft")  # an admin unpublished it back then
        first = self.run_import()
        self.assertEqual(first.updated_count, 4, "one-time metadata backfill")
        self.assertEqual(self.status_of(301), ("published", "publish", True))
        self.assertEqual(self.status_of(302), ("draft", "publish", False), "admin decision kept")
        self.assertEqual(self.status_of(303), ("draft", "publish", True))
        second = self.run_import()
        self.assertEqual((second.created_count, second.updated_count, second.skipped_count, second.failed_count),
                         (0, 0, 4, 0))

    def test_empty_wordpress_draft_is_imported_as_a_draft(self):
        self.wp.posts.append(make_post(310, slug="empty-draft", status="draft", content="", featured=False))
        run = self.run_import()
        self.assertEqual(run.failed_count, 0)
        self.assertEqual(self.status_of(310), ("draft", "draft", True))


@override_settings(WP_IMAA_BLOG_BASE_URL=SITE, WP_IMAA_BLOG_CATEGORY_ID=58)
class RestrictedContentTests(SyncHarness, BlogAPITestCase):
    def test_full_members_only_article_is_imported_as_a_hidden_draft(self):
        run = self.run_import()
        post = BlogPost.objects.get(wp_post_id=303)
        self.assertEqual((post.status, post.wp_status, post.wp_membership_restricted), ("draft", "publish", True))
        self.assertIn("Full members-only analysis", post.content_html)
        self.assertNotIn("wc-memberships", post.content_html)
        self.assertNotIn("only available to members", post.content_html, "no teaser stored")
        self.assertTrue(post.featured_image.name.startswith(MEDIA_PREFIX))
        self.assertIn(MEDIA_PREFIX, BeautifulSoup(post.content_html, "html.parser").find("img")["src"])
        self.assertEqual(run.report_json["restricted"]["detected"], 1)

        self.client.force_authenticate(make_user("reader"))
        self.assertEqual(self.client.get(reverse("blogs:post-detail", args=[post.slug])).status_code, 404)
        self.assertNotIn(303, [p["id"] for p in self.client.get(reverse("blogs:post-list")).data["results"]])
        self.client.force_authenticate(make_superuser())
        admin = self.client.get(reverse("blogs:admin-post-detail", args=[post.pk]))
        self.assertEqual((admin.status_code, admin.data["wp_membership_restricted"]), (200, True))

    def test_restriction_is_detected_from_the_public_teaser_without_the_post_class(self):
        post_in(self.wp, 303)["_members_only"] = "unflagged"
        run = self.run_import()
        post = BlogPost.objects.get(wp_post_id=303)
        self.assertEqual((post.status, post.wp_membership_restricted), ("draft", True))
        self.assertIn("Full members-only analysis", post.content_html)
        self.assertEqual(run.report_json["restricted_post_ids"], [303])

    def test_teaser_only_source_is_never_imported(self):
        # The account cannot read the article either: WordPress returns the teaser to everyone.
        post_in(self.wp, 303).update(_members_only=False, content={"rendered": TEASER})
        run = self.run_import()
        self.assertFalse(BlogPost.objects.filter(wp_post_id=303).exists(), "no teaser Blog is created")
        self.assertEqual(run.report_json["restricted"]["teaser_only_not_imported"], 1)
        self.assertEqual(run.restricted_count, 1)

    def test_teaser_never_overwrites_an_imported_article(self):
        self.run_import()
        post_in(self.wp, 303).update(_members_only=False, content={"rendered": TEASER})
        self.run_import()
        self.assertIn("Full members-only analysis", BlogPost.objects.get(wp_post_id=303).content_html)

    def test_restriction_removed_publishes_when_wordpress_manages_status(self):
        self.run_import()
        post_in(self.wp, 303)["_members_only"] = False
        post_in(self.wp, 303)["class_list"].remove("membership-content")
        self.run_import()
        post = BlogPost.objects.get(wp_post_id=303)
        self.assertEqual((post.status, post.wp_membership_restricted), ("published", False))

    def test_restriction_removed_keeps_ecp_owned_status(self):
        self.run_import()
        BlogPost.objects.get(wp_post_id=303).unpublish()
        post_in(self.wp, 303)["_members_only"] = False
        post_in(self.wp, 303)["class_list"].remove("membership-content")
        self.run_import()
        self.assertEqual(BlogPost.objects.get(wp_post_id=303).status, "draft")

    def test_public_posts_are_read_anonymously_and_the_rest_with_credentials(self):
        self.run_import()
        content_calls = [(params, auth) for (path, params), auth in zip(self.wp.calls, self.wp.call_auth)
                         if path == "/posts" and params.get("_embed")]
        public = {int(i) for params, auth in content_calls if auth is None for i in params["include"].split(",")}
        private = {int(i) for params, auth in content_calls if auth is not None for i in params["include"].split(",")}
        self.assertEqual((public, private), ({301, 302}, {303, 304}))
        edit_calls = [params for path, params in self.wp.calls if params.get("context") == "edit"]
        self.assertTrue(edit_calls and all("_fields" in p and "_embed" not in p for p in edit_calls),
                        "context=edit is only used for the light editorial listing")
        self.assertFalse([path for path, _ in self.wp.calls if path.startswith("/posts/")], "no single-post endpoint")

    def test_edit_context_rendering_is_not_used_for_content(self):
        self.wp.edit_rendered = {301: "<div data-elementor-id='96366'><h1>Wrong page</h1></div>",
                                 304: "<p>Wrong document</p>"}
        self.run_import()
        for wp_post_id in (301, 304):
            self.assertNotIn("Wrong", BlogPost.objects.get(wp_post_id=wp_post_id).content_html)


@override_settings(WP_IMAA_BLOG_BASE_URL=SITE, WP_IMAA_BLOG_CATEGORY_ID=58)
class DraftLinkTests(SyncHarness, TestCase):
    def setUp(self):
        super().setUp()
        post_in(self.wp, 302)["content"]["rendered"] = (
            f'<p>See <a href="{SITE}/blog/first-post/#part">first</a> for context.</p>')

    def href(self, wp_post_id, text):
        doc = BeautifulSoup(BlogPost.objects.get(wp_post_id=wp_post_id).content_html, "html.parser")
        return next(a["href"] for a in doc.find_all("a") if a.get_text() == text)

    def test_link_to_a_blog_that_becomes_published_is_rewritten_next_sync(self):
        post_in(self.wp, 301)["status"] = "draft"
        post_in(self.wp, 301)["link"] = f"{SITE}/?p=301"
        run = self.run_import()
        self.assertEqual(self.href(302, "first"), f"{SITE}/blog/first-post/#part", "Draft target keeps WP URL")
        self.assertEqual(run.report_json["links"]["unpublished_target"], 2, "301 -> members-post, 302 -> first-post")
        post_in(self.wp, 301)["status"] = "publish"
        post_in(self.wp, 301)["link"] = f"{SITE}/blog/first-post/"
        self.run_import()
        self.assertEqual(self.href(302, "first"), "/blogs/first-post#part")
        again = self.run_import()
        self.assertEqual((again.updated_count, again.links_rewritten_count), (0, 0), "idempotent")
        self.assertEqual(self.href(302, "first"), "/blogs/first-post#part")

    def test_link_to_a_blog_that_is_unpublished_is_restored_to_wordpress(self):
        self.run_import()
        self.assertEqual(self.href(302, "first"), "/blogs/first-post#part")
        post_in(self.wp, 301)["status"] = "draft"
        post_in(self.wp, 301)["link"] = f"{SITE}/?p=301"
        run = self.run_import()
        self.assertEqual(BlogPost.objects.get(wp_post_id=301).status, "draft")
        self.assertEqual(self.href(302, "first"), f"{SITE}/blog/first-post/#part", "no link into a Draft")
        self.assertEqual(run.report_json["links"]["restored"], 1)
        self.assertEqual(self.run_import().report_json["links"].get("restored", 0), 0, "idempotent")

    def test_downloads_and_external_links_are_unchanged(self):
        post_in(self.wp, 302)["content"]["rendered"] += (
            f'<p><a href="{SITE}/wp-content/uploads/report.pdf">pdf</a> <a href="https://example.org/y">ext</a></p>')
        self.run_import()
        self.assertEqual(self.href(302, "pdf"), f"{SITE}/wp-content/uploads/report.pdf")
        self.assertEqual(self.href(302, "ext"), "https://example.org/y")


@override_settings(WP_IMAA_BLOG_BASE_URL=SITE, WP_IMAA_BLOG_CATEGORY_ID=58)
class ReaderVisibilityTests(SyncHarness, BlogAPITestCase):
    def test_only_public_published_imports_reach_readers(self):
        self.wp.posts += [
            make_post(305, slug="pending-post", status="pending", featured=False),
            make_post(306, slug="scheduled-post", status="future", featured=False),
            make_post(307, slug="private-post", status="private", featured=False),
        ]
        self.run_import()
        self.client.force_authenticate(make_user("reader"))
        listed = {p["slug"] for p in self.client.get(reverse("blogs:post-list")).data["results"]}
        self.assertEqual(listed, {"first-post", "second-post"})
        for slug in ("members-post", "draft-idea", "pending-post", "scheduled-post", "private-post"):
            self.assertEqual(self.client.get(reverse("blogs:post-detail", args=[slug])).status_code, 404, slug)
        self.client.force_authenticate(make_superuser())
        drafts = self.client.get(reverse("blogs:admin-post-list"), {"status": "draft"}).data["results"]
        self.assertEqual({p["slug"] for p in drafts},
                         {"members-post", "draft-idea", "pending-post", "scheduled-post", "private-post"})


@override_settings(WP_IMAA_BLOG_BASE_URL=SITE, WP_IMAA_BLOG_CATEGORY_ID=58, **CREDENTIALS)
class CredentialSafetyTests(SyncHarness, BlogAPITestCase):
    def test_credentials_never_reach_report_serializer_or_logs(self):
        import logging

        records = []
        handler = logging.Handler()
        handler.emit = lambda record: records.append(record.getMessage())
        logger = logging.getLogger("blogs")
        logger.addHandler(handler)
        previous = logger.level
        logger.setLevel(logging.DEBUG)
        try:
            run = self.run_import()
        finally:
            logger.removeHandler(handler)
            logger.setLevel(previous)
        self.assertTrue(any(auth == AUTH for auth in self.wp.call_auth), "Basic Auth was used")
        self.client.force_authenticate(make_superuser())
        detail = self.client.get(reverse("blogs:admin-wordpress-import-detail", args=[run.pk]))
        for text in (str(run.report_json), str(detail.data), run.error_message, "\n".join(records)):
            self.assertNotIn(WP_APP_PASSWORD, text)
            self.assertNotIn(WP_USER, text)

    def test_rejected_credentials_fail_the_task_without_retry_or_leak(self):
        self.wp.credentials = ("someone-else", "other")
        run = BlogImportRun.objects.create()
        with mock.patch("blogs.wordpress.sync.WordPressBlogClient.from_settings",
                        side_effect=lambda **kw: WordPressBlogClient(SITE, session=self.wp, retries=0, auth=AUTH)), \
                mock.patch.object(run_wordpress_blog_import, "retry") as retry:
            run_wordpress_blog_import.apply(args=[str(run.pk)])
        retry.assert_not_called()
        run.refresh_from_db()
        self.assertEqual(run.status, "failed")
        self.assertIn("HTTP 401", run.error_message)
        self.assertNotIn(WP_APP_PASSWORD, run.error_message)
        self.assertNotIn("invalid application password", run.error_message, "WordPress wording not echoed")
        self.assertFalse(BlogPost.objects.exists())

    def test_forbidden_account_fails_safely(self):
        self.wp.forbid_auth = True
        run = BlogImportRun.objects.create()
        with mock.patch("blogs.wordpress.sync.WordPressBlogClient.from_settings",
                        side_effect=lambda **kw: WordPressBlogClient(SITE, session=self.wp, retries=0, auth=AUTH)):
            run_wordpress_blog_import.apply(args=[str(run.pk)])
        run.refresh_from_db()
        self.assertEqual(run.status, "failed")
        self.assertIn("HTTP 403", run.error_message)

    @override_settings(WP_IMAA_BLOG_APP_PASSWORD="")
    def test_task_refuses_to_run_without_credentials(self):
        run = BlogImportRun.objects.create()
        run_wordpress_blog_import.apply(args=[str(run.pk)])
        run.refresh_from_db()
        self.assertEqual(run.status, "failed")
        self.assertIn("Authenticated WordPress Blog import is not configured.", run.error_message)
        self.assertFalse(self.wp.calls, "no silent public-only fallback")


@override_settings(WP_IMAA_BLOG_BASE_URL=SITE, **CREDENTIALS)
class ImportApiCredentialTests(BlogAPITestCase):
    def setUp(self):
        super().setUp()
        self.client.force_authenticate(make_superuser())
        self.enqueue = mock.patch.object(BlogWordPressImportViewSet, "enqueue", return_value="task-1")
        self.enqueued = self.enqueue.start()
        self.addCleanup(self.enqueue.stop)

    def start(self):
        with self.captureOnCommitCallbacks(execute=True):
            return self.client.post(reverse("blogs:admin-wordpress-import-list"), {}, format="json")

    def test_missing_username_or_password_is_a_safe_503_without_fallback(self):
        for missing in ("WP_IMAA_BLOG_API_USER", "WP_IMAA_BLOG_APP_PASSWORD"):
            with self.subTest(missing=missing), override_settings(**{missing: ""}):
                response = self.start()
                self.assertEqual(response.status_code, http.HTTP_503_SERVICE_UNAVAILABLE)
                self.assertEqual(response.data["detail"], "Authenticated WordPress Blog import is not configured.")
                self.assertNotIn(WP_APP_PASSWORD, str(response.data))
        self.assertFalse(BlogImportRun.objects.exists())
        self.enqueued.assert_not_called()

    def test_start_response_never_contains_credentials(self):
        response = self.start()
        self.assertEqual(response.status_code, http.HTTP_202_ACCEPTED)
        self.assertNotIn(WP_APP_PASSWORD, str(response.data))
        self.assertNotIn(WP_USER, str(response.data))
