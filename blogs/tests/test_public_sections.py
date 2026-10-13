"""Public website article sections (In The News, M&A Publications): anonymous APIs, separation from the
member Blogs, and the section import (dry run and category scoping)."""

from datetime import timedelta
from io import StringIO
from unittest import mock

from django.core.management import CommandError, call_command
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from blogs.models import BlogCategory, BlogPost
from blogs.tests.factories import make_post, make_user
from blogs.tests.wp_fixtures import SITE, FakeWordPress
from blogs.tests.wp_fixtures import make_post as make_wp_post
from blogs.wordpress.client import WordPressBlogClient
from blogs.wordpress.importer import ImportAborted


class PublicSectionApiTests(TestCase):
    def setUp(self):
        now = timezone.now()
        self.news, self.publications, self.blog = (BlogCategory.objects.create(name=n, slug=s) for n, s in
                                                   (("News", "news"), ("Publications", "publications"), ("Blog", "blog")))

        def post(title, category, days=0, **extra):
            item = make_post(title=title, slug=title.lower().replace(" ", "-"), status=BlogPost.STATUS_PUBLISHED,
                             published_at=now - timedelta(days=days), excerpt=f"{title} excerpt", **extra)
            item.categories.set([category])
            return item

        self.older = post("Older news", self.news, days=10)
        self.newer = post("Newer news", self.news, days=1)
        draft = make_post(title="Draft news", slug="draft-news", status=BlogPost.STATUS_DRAFT)
        draft.categories.set([self.news])
        post("Members news", self.news, wp_membership_restricted=True)
        self.publication = post("A publication", self.publications, days=3)
        self.member_blog = post("Member blog", self.blog, days=2)
        self.anonymous = APIClient()

    def test_sections_are_anonymous_scoped_and_newest_first(self):
        response = self.anonymous.get("/api/blogs/public/in-the-news/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([p["slug"] for p in response.json()["results"]], ["newer-news", "older-news"],
                         "published, not members-only, this section only, newest first")
        self.assertEqual([p["slug"] for p in self.anonymous.get("/api/blogs/public/publications/").json()["results"]],
                         ["a-publication"])
        self.assertEqual(self.anonymous.get("/api/blogs/public/in-the-news/", {"page_size": 1}).json()["count"], 2)

    def test_detail_only_within_its_section(self):
        detail = self.anonymous.get("/api/blogs/public/in-the-news/newer-news/")
        self.assertEqual(detail.status_code, 200)
        self.assertIn("content_html", detail.json())
        self.assertEqual(self.anonymous.get("/api/blogs/public/in-the-news/a-publication/").status_code, 404)
        self.assertEqual(self.anonymous.get("/api/blogs/public/in-the-news/draft-news/").status_code, 404)
        self.assertEqual(self.anonymous.get("/api/blogs/public/in-the-news/members-news/").status_code, 404)
        self.assertEqual(self.anonymous.get("/api/blogs/public/member-blog-section/").status_code, 404)
        self.assertEqual(self.anonymous.get("/api/blogs/public/publications/member-blog/").status_code, 404)

    def test_tag_and_year_filters_with_section_wide_options(self):
        from blogs.models import BlogTag

        survey = BlogTag.objects.create(name="Survey", slug="survey")
        rare = BlogTag.objects.create(name="Rare", slug="rare")
        for post in (self.older, self.newer):
            post.tags.add(survey)
        self.newer.tags.add(rare)
        extra = make_post(title="Third news", slug="third-news", status=BlogPost.STATUS_PUBLISHED,
                          published_at=timezone.now() - timedelta(days=400), excerpt="x")
        extra.categories.set([self.news])
        extra.tags.add(survey)
        self.member_blog.tags.add(survey)  # other categories never count

        body = self.anonymous.get("/api/blogs/public/in-the-news/", {"tag": "survey"}).json()
        self.assertEqual([p["slug"] for p in body["results"]], ["newer-news", "older-news", "third-news"])
        self.assertEqual(body["filters"]["tags"], [{"slug": "survey", "name": "Survey", "count": 3}],
                         "tags used by fewer than three posts are not offered")
        years = {row["year"]: row["count"] for row in body["filters"]["years"]}
        self.assertEqual(sum(years.values()), 3)
        year = extra.published_at.year
        filtered = self.anonymous.get("/api/blogs/public/in-the-news/", {"year": year}).json()
        self.assertIn("third-news", [p["slug"] for p in filtered["results"]])
        self.assertEqual(filtered["filters"], body["filters"], "options stay those of the whole section")
        self.assertEqual(self.anonymous.get("/api/blogs/public/in-the-news/", {"tag": "nope"}).json()["count"], 0)
        self.assertEqual(self.anonymous.get("/api/blogs/public/in-the-news/", {"year": "20x6"}).status_code, 404)

    def test_detail_html_is_sanitised_for_server_rendering(self):
        BlogPost.objects.filter(pk=self.newer.pk).update(
            content_html='<p onclick="x()">Hi<script>alert(1)</script></p><img src="javascript:alert(1)">')
        html = self.anonymous.get("/api/blogs/public/in-the-news/newer-news/").json()["content_html"]
        self.assertIn("Hi", html)
        for unsafe in ("onclick", "<script", "javascript:"):
            self.assertNotIn(unsafe, html)

    def test_member_blogs_leave_the_public_sections_out(self):
        member = APIClient()
        member.force_authenticate(make_user("reader"))
        slugs = [p["slug"] for p in member.get("/api/blogs/").json()["results"]]
        self.assertEqual(slugs, ["member-blog"])
        self.assertEqual(member.get("/api/blogs/newer-news/").status_code, 404)
        self.assertEqual(member.get("/api/blogs/member-blog/").status_code, 200)
        self.assertEqual(self.anonymous.get("/api/blogs/").status_code, 401, "member Blogs still need a login")


class SectionImportTests(TestCase):
    def test_placeholder_publications_are_held_for_review(self):
        from blogs.management.commands.import_wordpress_section import REVIEW_HOLD, Command

        held_id, editor_id = REVIEW_HOLD["publications"][:2]
        held = make_post(title="Held", slug="held", status=BlogPost.STATUS_PUBLISHED, wp_post_id=held_id, wp_status_managed=True)
        decided = make_post(title="Decided", slug="decided", status=BlogPost.STATUS_PUBLISHED, wp_post_id=editor_id,
                            wp_status_managed=False)
        other = make_post(title="Other", slug="other", status=BlogPost.STATUS_PUBLISHED, wp_post_id=1, wp_status_managed=True)
        self.assertEqual(Command.hold_for_review("publications"), [held_id])
        for post, status in ((held, BlogPost.STATUS_DRAFT), (decided, BlogPost.STATUS_PUBLISHED), (other, BlogPost.STATUS_PUBLISHED)):
            post.refresh_from_db()
            self.assertEqual(post.status, status)
        held.refresh_from_db()
        self.assertFalse(held.wp_status_managed, "ECP now owns the status: a later sync keeps it unpublished")
        self.assertEqual(Command.hold_for_review("in-the-news"), [])

    def test_a_stopped_import_marks_its_run_failed(self):
        from blogs.models import BlogImportRun
        from blogs.wordpress.client import WordPressBlogAuthError

        with mock.patch("blogs.management.commands.import_wordpress_section.execute_import_run",
                        side_effect=WordPressBlogAuthError("WordPress rejected the Blog import credentials (HTTP 401).")):
            with self.assertRaisesMessage(CommandError, "HTTP 401"):
                call_command("import_wordpress_section", "--section", "in-the-news", "--commit", stdout=StringIO(), stderr=StringIO())
        run = BlogImportRun.objects.get()
        self.assertEqual(run.status, BlogImportRun.STATUS_FAILED, "a stopped run never blocks the next import")
        self.assertIn("HTTP 401", run.error_message)

    def test_dry_run_reads_the_section_category_and_writes_nothing(self):
        news = {"id": 66, "name": "News", "slug": "news", "count": 1, "taxonomy": "category"}
        fake = FakeWordPress(posts=[make_wp_post(101, categories=(66,))], category=news)
        out = StringIO()
        with mock.patch("blogs.management.commands.import_wordpress_section.WordPressBlogClient.from_settings",
                        side_effect=lambda **kwargs: WordPressBlogClient(SITE, session=fake)):
            call_command("import_wordpress_section", "--section", "in-the-news", stdout=out, stderr=StringIO())
        self.assertIn("Would create: 1", out.getvalue())
        self.assertIn("nothing was changed", out.getvalue())
        self.assertEqual(BlogPost.objects.count(), 0)
        self.assertEqual(BlogCategory.objects.count(), 0)

    def test_a_wrong_category_is_refused(self):
        fake = FakeWordPress(posts=[], category={"id": 66, "name": "Blog", "slug": "blog", "count": 0, "taxonomy": "category"})
        with mock.patch("blogs.management.commands.import_wordpress_section.WordPressBlogClient.from_settings",
                        side_effect=lambda **kwargs: WordPressBlogClient(SITE, session=fake)):
            with self.assertRaisesMessage(CommandError, "Dry run failed"):
                call_command("import_wordpress_section", "--section", "in-the-news", stdout=StringIO(), stderr=StringIO())

    def test_the_sync_imports_the_requested_category(self):
        from blogs.models import BlogImportRun
        from blogs.wordpress import sync

        importer = mock.Mock()
        importer.validate_category.side_effect = ImportAborted("stop here")
        with mock.patch.object(sync, "WordPressBlogImporter", return_value=importer) as cls, \
                mock.patch.object(sync.WordPressBlogClient, "from_settings", return_value=mock.Mock(base_url=SITE)):
            with self.assertRaises(ImportAborted):
                sync.execute_import_run(BlogImportRun.objects.create(), category_id=59, category_slug="publications")
        self.assertEqual((cls.call_args.kwargs["category_id"], cls.call_args.kwargs["expected_category_slug"]), (59, "publications"))
        BlogImportRun.objects.update(status=BlogImportRun.STATUS_FAILED)  # one active run at a time
        with mock.patch.object(sync, "WordPressBlogImporter", return_value=importer) as cls, \
                mock.patch.object(sync.WordPressBlogClient, "from_settings", return_value=mock.Mock(base_url=SITE)):
            with self.assertRaises(ImportAborted):
                sync.execute_import_run(BlogImportRun.objects.create())
        self.assertEqual((cls.call_args.kwargs["category_id"], cls.call_args.kwargs["expected_category_slug"]), (None, None),
                         "the Blog import keeps its configured category")
