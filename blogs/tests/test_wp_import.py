import json
import tempfile
from datetime import datetime, timezone
from io import StringIO
from unittest import mock

import requests

from django.contrib.auth.models import User
from django.core.management import CommandError, call_command
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from blogs.models import BlogCategory, BlogPost, BlogTag
from blogs.wordpress.client import WordPressBlogClient
from blogs.wordpress.importer import ImportAborted, WordPressBlogImporter, WritesDisabledError, apply_plan
from blogs.wordpress.parser import parse_wordpress_post
from blogs.wordpress.planner import plan_import
from users.models import UserProfile

from .factories import make_post as make_blog
from .wp_fixtures import (
    AUTH,
    CLASSIC_HTML,
    ELEMENTOR_HTML,
    GUTENBERG_HTML,
    JSON_LD_HTML,
    MIXED_HTML,
    SITE,
    UNSAFE_HTML,
    WP_APP_PASSWORD,
    WP_USER,
    FakeWordPress,
    make_post,
)

WRITE_SQL = ("INSERT", "UPDATE", "DELETE")


def normalized(**kwargs):
    return parse_wordpress_post(make_post(**kwargs), site_url=SITE)


def codes(plan):
    return {w.code for w in plan.warnings}


def mapped_user(wp_id, first="Jane", last="Writer", username="jane"):
    user = User.objects.create_user(username=username, email=f"{username}@example.com", first_name=first, last_name=last)
    UserProfile.objects.update_or_create(user=user, defaults={"wordpress_id": wp_id})
    return user


class AuthorMappingTests(TestCase):
    def test_mapped_by_wordpress_id_with_matching_name(self):
        user = mapped_user(7)
        plan = plan_import(normalized(author=7, author_name="Jane Writer"))
        self.assertEqual(plan.author_user_id, user.pk)
        self.assertEqual(plan.values["author_id"], user.pk)
        self.assertEqual(plan.values["legacy_author_name"], "Jane Writer")

    def test_unmapped_author_uses_legacy_name(self):
        plan = plan_import(normalized(author=8, author_name="Historic Author"))
        self.assertIsNone(plan.author_user_id)
        self.assertEqual(plan.values["legacy_author_name"], "Historic Author")
        self.assertIn("unmapped_author", codes(plan))

    def test_id_match_with_different_name_is_not_trusted(self):
        mapped_user(7, first="Someone", last="Else")
        plan = plan_import(normalized(author=7, author_name="Jane Writer"))
        self.assertIsNone(plan.author_user_id)
        self.assertIn("author_mapping_name_mismatch", codes(plan))

    def test_missing_embedded_author_still_maps_via_profile(self):
        user = mapped_user(7)
        raw = make_post(author=7, yoast={"title": "T", "description": "D", "canonical": "c"})
        raw["_embedded"]["author"] = []
        plan = plan_import(parse_wordpress_post(raw, site_url=SITE))
        self.assertEqual(plan.author_user_id, user.pk)
        self.assertIn("author_mapping_unverified", codes(plan))

    def test_no_user_is_ever_created(self):
        before = User.objects.count()
        plan_import(normalized(author=12345, author_name="New Person"))
        self.assertEqual(User.objects.count(), before)


class TaxonomyPlanningTests(TestCase):
    def test_existing_category_and_tag_reused_by_slug_or_name(self):
        blog = BlogCategory.objects.create(name="Blog", slug="blog")
        tag = BlogTag.objects.create(name="CROSS-BORDER M&A", slug="xb")
        plan = plan_import(normalized())
        self.assertEqual(plan.categories, [{"name": "Blog", "slug": "blog", "existing_id": blog.pk}])
        self.assertEqual(plan.tags[0]["existing_id"], tag.pk, "case-insensitive name match")
        self.assertEqual(plan.taxonomy_changes["tags"], {"reuse": ["xb"], "create": []})

    def test_missing_terms_are_planned_not_created(self):
        plan = plan_import(normalized())
        self.assertEqual(plan.taxonomy_changes["categories"], {"reuse": [], "create": ["blog"]})
        self.assertEqual(plan.taxonomy_changes["tags"], {"reuse": [], "create": ["cross-border-ma"]})
        self.assertFalse(BlogCategory.objects.exists())
        self.assertFalse(BlogTag.objects.exists())

    def test_duplicate_terms_in_one_post_collapse(self):
        plan = plan_import(normalized(tags=((5, "Deals", "deals"), (6, "DEALS", "deals-2"))))
        self.assertEqual(len(plan.tags), 1)


class PlannerTests(TestCase):
    def test_new_post_is_create(self):
        plan = plan_import(normalized(post_id=1))
        self.assertEqual(plan.action, "CREATE")
        self.assertEqual(plan.slug, "ma-outlook")
        self.assertEqual(plan.values["published_at"], datetime(2024, 3, 1, 10, tzinfo=timezone.utc))
        self.assertNotIn("canonical_url", plan.values, "old WordPress canonical is not copied into ECP")
        self.assertNotIn("status", plan.values)
        self.assertEqual((plan.ecp_status, plan.status_managed), ("published", True))

    def test_changed_source_is_update_and_unchanged_is_skip(self):
        post = normalized(post_id=1)
        apply_plan(plan_import(post), commit=True)
        self.assertEqual(plan_import(post).action, "SKIP")
        changed = normalized(post_id=1, title="M&amp;A Outlook 2025", modified_gmt="2024-04-01T00:00:00")
        plan = plan_import(changed)
        self.assertEqual(plan.action, "UPDATE")
        self.assertEqual(set(plan.field_changes), {"title", "wp_modified_at"})

    def test_manual_post_with_same_title_is_ignored(self):
        manual = make_blog(title="M&A Outlook", slug="manual-ma")
        plan = plan_import(normalized(post_id=1))
        self.assertEqual(plan.action, "CREATE")
        self.assertIsNone(plan.existing_post_id)
        manual.refresh_from_db()
        self.assertIsNone(manual.wp_post_id)

    def test_manual_post_with_same_slug_gets_deterministic_suffix(self):
        manual = make_blog(title="Manual", slug="ma-outlook")
        plan = plan_import(normalized(post_id=77))
        self.assertEqual(plan.action, "CREATE")
        self.assertEqual(plan.slug, "ma-outlook-wp77")
        self.assertIn("slug_collision", codes(plan))
        self.assertEqual(plan_import(normalized(post_id=77)).slug, "ma-outlook-wp77")
        manual.refresh_from_db()
        self.assertEqual(manual.slug, "ma-outlook")

    def test_both_slug_and_fallback_taken_is_error(self):
        make_blog(title="A", slug="ma-outlook")
        make_blog(title="B", slug="ma-outlook-wp77")
        self.assertEqual(plan_import(normalized(post_id=77)).action, "ERROR")

    def test_updates_match_only_by_wp_post_id(self):
        apply_plan(plan_import(normalized(post_id=1, slug="first")), commit=True)
        plan = plan_import(normalized(post_id=2, slug="second"))
        self.assertEqual(plan.action, "CREATE")
        self.assertIsNone(plan.existing_post_id)

    def test_members_only_teaser_is_never_imported(self):
        teaser = ('<p>Opening paragraph.</p><div class="woocommerce"><div class="woocommerce-info wc-memberships-restriction-message">'
                  'To access this post, you must purchase <a href="https://imaa.test/product/membership/">Membership</a>.</div></div>')
        plan = plan_import(normalized(content=teaser))
        self.assertEqual(plan.action, "RESTRICTED", "expected source limitation, not an error")
        self.assertEqual(plan.values, {}, "nothing is ever written for a teaser")
        self.assertIn("members_only_teaser", codes(plan))
        self.assertIn("members-only", plan.reasons[0])

    def test_invalid_content_and_status_are_errors(self):
        self.assertEqual(plan_import(normalized(content="<script>x()</script>")).action, "ERROR")
        for status in ("trash", "auto-draft", "inherit", "mystery"):
            self.assertEqual(plan_import(normalized(status=status)).action, "ERROR", status)
        self.assertEqual(plan_import(normalized(title="<b> </b>")).action, "ERROR")


class ImporterHarness:
    posts = ()

    def setUp(self):
        super().setUp()
        self.fake = FakeWordPress(posts=[
            make_post(201, slug="gutenberg-post", content=GUTENBERG_HTML, author=7, author_name="Jane Writer"),
            make_post(202, slug="elementor-post", content=ELEMENTOR_HTML, author=8, author_name="Historic Author", featured=False),
            make_post(203, slug="classic-post", content=CLASSIC_HTML, tags=((5, "Cross-border M&amp;A", "cross-border-ma"), (6, "Deals", "deals"))),
            make_post(204, slug="mixed-post", content=MIXED_HTML, yoast={"title": "Mixed", "canonical": f"{SITE}/blog/mixed-post/"}),
            make_post(205, slug="broken-post", content="<script>only()</script>"),
        ])
        self.client_patch = mock.patch(
            "blogs.management.commands.import_wordpress_blogs.WordPressBlogClient.from_settings",
            side_effect=lambda authenticated=False: WordPressBlogClient(
                SITE, session=self.fake, retries=0, auth=AUTH if authenticated else None),
        )
        self.client_patch.start()
        self.addCleanup(self.client_patch.stop)

    def run_command(self, *args):
        out = StringIO()
        call_command("import_wordpress_blogs", *args, stdout=out, stderr=StringIO())
        return out.getvalue()

    def counts(self):
        return BlogPost.objects.count(), BlogCategory.objects.count(), BlogTag.objects.count()


@override_settings(WP_IMAA_BLOG_BASE_URL=SITE, WP_IMAA_BLOG_CATEGORY_ID=58)
class DryRunTests(ImporterHarness, TestCase):
    def test_dry_run_makes_no_writes_at_all(self):
        with CaptureQueriesContext(connection) as ctx:
            self.run_command("--dry-run")
        writes = [q["sql"] for q in ctx.captured_queries if q["sql"].lstrip().upper().startswith(WRITE_SQL)]
        self.assertEqual(writes, [])
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_bare_command_is_a_dry_run(self):
        output = self.run_command()
        self.assertIn("Dry Run", output)
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_dry_run_does_not_touch_existing_import(self):
        apply_plan(plan_import(parse_wordpress_post(make_post(201, slug="gutenberg-post", title="Old title", content=GUTENBERG_HTML), site_url=SITE)), commit=True)
        before = BlogPost.objects.values().get(wp_post_id=201)
        output = self.run_command("--dry-run")
        self.assertEqual(BlogPost.objects.values().get(wp_post_id=201), before)
        self.assertIn("Would update: 1", output)

    def test_report_counts(self):
        with tempfile.NamedTemporaryFile(suffix=".json") as handle:
            output = self.run_command("--dry-run", "--report-json", handle.name)
            report = json.load(open(handle.name))
        self.assertEqual(report["plan"], {"create": 4, "update": 0, "skip": 0, "restricted": 0, "error": 1})
        self.assertEqual(report["formats"], {"gutenberg": 1, "elementor": 1, "classic": 2, "mixed": 1, "unknown": 0})
        self.assertEqual(report["fetch"]["api_total"], 5)
        self.assertEqual(report["fetch"]["content_pages_fetched"], 1)
        self.assertEqual(report["authors"]["unique_wp_authors"], 2)
        self.assertEqual(report["authors"]["unmapped"], 2)
        self.assertEqual(report["featured_media"]["missing"], 1)
        self.assertEqual(report["content"]["links_by_class"]["blog"], 1)
        self.assertEqual(report["seo"]["missing_description"], 1)
        self.assertIn("mixed_content", report["warnings"])
        self.assertEqual(report["errors"][0]["wp_post_id"], 205)
        self.assertEqual(report["sample_candidates"]["gutenberg"], [201])
        for text in ("Gutenberg: 1", "Would create: 4", "Errors: 1", "Unique WP authors: 2", "Missing SEO description: 1"):
            self.assertIn(text, output)

    def test_mapped_authors_are_reported(self):
        mapped_user(7)
        report = WordPressBlogImporter(WordPressBlogClient(SITE, session=self.fake)).run()
        self.assertEqual((report["authors"]["mapped"], report["authors"]["unmapped"]), (1, 1))

    def test_one_bad_post_does_not_break_the_run(self):
        self.fake.posts.insert(0, {"id": 999, "categories": [58]})  # malformed
        report = WordPressBlogImporter(WordPressBlogClient(SITE, session=self.fake)).run()
        self.assertEqual(report["plan"]["create"], 4)
        self.assertEqual(report["plan"]["error"], 2)

    def test_failing_content_page_falls_back_to_single_posts(self):
        original = self.fake.get

        def page_fails(url, params=None, timeout=None, headers=None, auth=None):
            params = dict(params or {})
            include = str(params.get("include", ""))
            if url.endswith("/posts") and "_embed" in params and ("," in include or include == "202"):
                raise requests.Timeout("page too slow" if "," in include else "this post is stuck")
            return original(url, params, timeout, headers, auth)

        self.fake.get = page_fails
        report = WordPressBlogImporter(WordPressBlogClient(SITE, session=self.fake, retries=0)).run()
        self.assertEqual(report["fetch"]["single_post_fallbacks"], 5)
        self.assertFalse([path for path, _ in self.fake.calls if path.startswith("/posts/")],
                         "fallback stays on the collection endpoint")
        self.assertEqual(report["plan"], {"create": 3, "update": 0, "skip": 0, "restricted": 0, "error": 2})
        self.assertIn("fetch failed", " ".join(e["reasons"][0] for e in report["errors"]))

    def test_limit_restricts_what_is_fetched(self):
        report = WordPressBlogImporter(WordPressBlogClient(SITE, session=self.fake)).run(limit=2)
        self.assertEqual(report["fetch"]["posts_processed"], 2)
        self.assertEqual(report["fetch"]["api_total"], 5)

    def test_selected_posts_use_the_same_list_context_as_bulk(self):
        WordPressBlogImporter(WordPressBlogClient(SITE, session=self.fake)).run(post_ids=[203, 201])
        single_post_calls = [path for path, _ in self.fake.calls if path.startswith("/posts/")]
        self.assertEqual(single_post_calls, [], "never the single-post endpoint (different excerpt rendering)")
        include_calls = [params["include"] for path, params in self.fake.calls if path == "/posts" and "include" in params]
        self.assertEqual(include_calls, ["203,201"])

    def test_single_post_dry_run(self):
        output = self.run_command("--post-id", "203")
        self.assertIn("Would create: 1", output)
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_category_mismatch_aborts(self):
        self.fake.category = {"id": 58, "name": "News", "slug": "news", "taxonomy": "category"}
        with self.assertRaisesMessage(CommandError, "expected slug 'blog'"):
            self.run_command("--dry-run")

    def test_post_outside_category_is_rejected(self):
        self.fake.posts.append(make_post(300, slug="other", categories=(12,)))
        report = WordPressBlogImporter(WordPressBlogClient(SITE, session=self.fake)).run(post_ids=[300])
        self.assertEqual(report["plan"]["error"], 1)
        self.assertIn("not in WordPress category 58", report["errors"][0]["reasons"][0])

    def test_apply_refuses_in_dry_run(self):
        plan = plan_import(normalized())
        with self.assertRaises(WritesDisabledError):
            apply_plan(plan, commit=False)


@override_settings(WP_IMAA_BLOG_BASE_URL=SITE, WP_IMAA_BLOG_CATEGORY_ID=58)
class CommittedImportTests(ImporterHarness, TestCase):
    def test_bulk_commit_is_refused(self):
        with self.assertRaisesMessage(CommandError, "Bulk commit is disabled"):
            self.run_command("--commit")
        with self.assertRaises(ImportAborted):
            WordPressBlogImporter(WordPressBlogClient(SITE, session=self.fake), commit=True).run()
        with self.assertRaises(ImportAborted):
            WordPressBlogImporter(WordPressBlogClient(SITE, session=self.fake), commit=True).run(post_ids=list(range(1, 12)))
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_commit_selected_post_maps_all_fields(self):
        user = mapped_user(7)
        output = self.run_command("--post-id", "201", "--commit")
        self.assertIn("CREATE -> BlogPost", output)
        post = BlogPost.objects.get(wp_post_id=201)
        self.assertEqual(BlogPost.objects.count(), 1, "only the selected post is imported")
        self.assertEqual(post.status, "published")
        self.assertEqual(post.title, "M&A Outlook")
        self.assertEqual(post.slug, "gutenberg-post")
        self.assertEqual(post.excerpt, "Short excerpt about deals…")
        self.assertIn("<h2>Deal trends</h2>", post.content_html)
        self.assertNotIn("<!--", post.content_html)
        self.assertEqual(post.published_at, datetime(2024, 3, 1, 10, tzinfo=timezone.utc))
        self.assertEqual(post.wp_modified_at, datetime(2024, 3, 5, 12, 30, tzinfo=timezone.utc))
        self.assertEqual(post.wp_source_url, f"{SITE}/blog/gutenberg-post/")
        self.assertEqual(post.wp_author_id, 7)
        self.assertTrue(post.imported_from_wordpress)
        self.assertEqual(post.author, user)
        self.assertEqual(post.seo_title, "M&A Outlook - IMAA")
        self.assertEqual(post.seo_description, "Fictional SEO description.")
        self.assertEqual(post.canonical_url, "")
        self.assertFalse(post.featured_image, "featured images are not migrated in Batch 3")
        self.assertEqual([c.slug for c in post.categories.all()], ["blog"])
        self.assertEqual([t.name for t in post.tags.all()], ["Cross-border M&A"])

    def test_unmapped_author_uses_legacy_name(self):
        self.run_command("--post-id", "202", "--commit")
        post = BlogPost.objects.get(wp_post_id=202)
        self.assertIsNone(post.author)
        self.assertEqual(post.legacy_author_name, "Historic Author")

    def test_second_identical_import_skips_without_duplicates(self):
        self.run_command("--post-id", "203", "--commit")
        first = BlogPost.objects.get(wp_post_id=203)
        output = self.run_command("--post-id", "203", "--commit")
        self.assertIn("skip: 1", output.lower())
        self.assertEqual(self.counts(), (1, 1, 2))
        self.assertEqual(BlogPost.objects.get(wp_post_id=203).pk, first.pk)

    def test_changed_source_updates_same_record_and_keeps_ecp_fields(self):
        self.run_command("--post-id", "203", "--commit")
        post = BlogPost.objects.get(wp_post_id=203)
        post.unpublish()  # an ECP editorial decision
        BlogPost.objects.filter(pk=post.pk).update(canonical_url="https://connect.example/blogs/classic-post")
        self.fake.posts[2]["title"]["rendered"] = "Classic, revised"
        self.fake.posts[2]["tags"] = [6]
        self.fake.posts[2]["_embedded"]["wp:term"][1] = [{"id": 6, "name": "Deals", "slug": "deals", "taxonomy": "post_tag"}]
        output = self.run_command("--post-id", "203", "--commit")
        self.assertIn("UPDATE -> BlogPost", output)
        post.refresh_from_db()
        self.assertEqual(BlogPost.objects.count(), 1)
        self.assertEqual(post.title, "Classic, revised")
        self.assertEqual([t.slug for t in post.tags.all()], ["deals"])
        self.assertEqual(post.status, "draft", "status is ECP-owned on update")
        self.assertEqual(post.canonical_url, "https://connect.example/blogs/classic-post")

    def test_failed_post_rolls_back_completely(self):
        with mock.patch.object(BlogPost, "save", side_effect=RuntimeError("disk full")):
            output = self.run_command("--post-id", "203", "--commit")
        self.assertIn("Errors: 1", output)
        self.assertEqual(self.counts(), (0, 0, 0), "no half-created taxonomy or post")

    def test_manual_post_is_never_overwritten(self):
        manual = make_blog(title="Manual", slug="classic-post", content_html="<p>Manual body</p>")
        self.run_command("--post-id", "203", "--commit")
        manual.refresh_from_db()
        self.assertEqual((manual.slug, manual.content_html, manual.wp_post_id), ("classic-post", "<p>Manual body</p>", None))
        self.assertEqual(BlogPost.objects.get(wp_post_id=203).slug, "classic-post-wp203")

    def test_imported_post_is_visible_in_reader_api(self):
        self.run_command("--post-id", "201", "--commit")
        reader = User.objects.create_user(username="reader", password="x")
        self.client.force_login(reader)
        response = self.client.get("/api/blogs/gutenberg-post/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["title"], "M&A Outlook")
        self.assertNotIn("wp_post_id", response.data)


class PlannerStatusTests(TestCase):
    def test_target_status_mapping(self):
        from blogs.wordpress.planner import target_ecp_status

        cases = {("publish", False): "published", ("publish", True): "draft", ("draft", False): "draft",
                 ("pending", False): "draft", ("future", False): "draft", ("private", False): "draft"}
        for (wp_status, restricted), expected in cases.items():
            self.assertEqual(target_ecp_status(wp_status, restricted), expected, (wp_status, restricted))

    def test_drafts_are_created_as_ecp_drafts(self):
        for status in ("draft", "pending", "future", "private"):
            plan = plan_import(normalized(post_id=10, status=status))
            self.assertEqual((plan.action, plan.ecp_status, plan.values["wp_status"]), ("CREATE", "draft", status))

    def test_members_only_full_article_is_planned_as_draft(self):
        post = parse_wordpress_post(make_post(11, content="<p>Full article.</p>"), site_url=SITE,
                                    editorial={"restricted": True, "restriction_source": "class_list"})
        plan = plan_import(post)
        self.assertEqual((plan.action, plan.ecp_status), ("CREATE", "draft"))
        self.assertTrue(plan.values["wp_membership_restricted"])

    def test_draft_may_lack_content_or_date_but_publish_may_not(self):
        self.assertEqual(plan_import(normalized(status="draft", content="")).action, "CREATE")
        self.assertEqual(plan_import(normalized(status="draft", date_gmt=None)).action, "CREATE")
        self.assertEqual(plan_import(normalized(content="")).action, "ERROR")
        self.assertEqual(plan_import(normalized(date_gmt=None)).action, "ERROR")

    def test_draft_slug_falls_back_to_generated_slug(self):
        for slug in ("", "__trashed"):
            post = parse_wordpress_post(make_post(12, status="draft", slug=slug, generated_slug="proposed-slug"),
                                        site_url=SITE)
            self.assertEqual(plan_import(post).slug, "proposed-slug", slug)
        self.assertEqual(plan_import(normalized(slug="old-name__trashed", status="draft")).slug, "old-name")

    def test_status_managed_is_not_part_of_the_source_hash(self):
        post = normalized(post_id=13)
        blog = apply_plan(plan_import(post), commit=True)
        BlogPost.objects.filter(pk=blog.pk).update(wp_status_managed=False)
        plan = plan_import(post)
        self.assertEqual(plan.action, "SKIP", "ownership is ECP state, not a source change")
        self.assertFalse(plan.status_managed)


@override_settings(WP_IMAA_BLOG_BASE_URL=SITE, WP_IMAA_BLOG_CATEGORY_ID=58,
                   WP_IMAA_BLOG_API_USER=WP_USER, WP_IMAA_BLOG_APP_PASSWORD=WP_APP_PASSWORD)
class AllStatusCommandTests(ImporterHarness, TestCase):
    def setUp(self):
        super().setUp()
        self.fake.posts = [p for p in self.fake.posts if p["id"] != 205] + [
            make_post(206, slug="members-deals", content="<p>Full members article.</p>", members_only=True),
            make_post(207, slug="", generated_slug="idea-draft", status="draft", content=CLASSIC_HTML),
            make_post(208, slug="soon", status="future", content=GUTENBERG_HTML),
        ]

    def test_all_statuses_dry_run_reports_the_editorial_source_without_writes(self):
        with tempfile.NamedTemporaryFile(suffix=".json") as handle, CaptureQueriesContext(connection) as ctx:
            output = self.run_command("--all-statuses", "--dry-run", "--report-json", handle.name)
            report = json.load(open(handle.name))
        writes = [q["sql"] for q in ctx.captured_queries if q["sql"].lstrip().upper().startswith(WRITE_SQL)]
        self.assertEqual(writes, [])
        self.assertEqual(report["source_status_counts"], {"publish": 5, "draft": 1, "pending": 0, "future": 1, "private": 0})
        self.assertEqual(report["plan"], {"create": 7, "update": 0, "skip": 0, "restricted": 0, "error": 0})
        self.assertEqual(report["target_status"], {"published": 4, "draft": 3})
        self.assertEqual(report["restricted"]["imported_as_draft"], 1)
        self.assertEqual(report["restricted_post_ids"], [206])
        for text in ("WORDPRESS SOURCE STATUS", "draft: 1", "Total: 7", "Members-only imported as Draft: 1"):
            self.assertIn(text, output)
        self.assertNotIn(WP_APP_PASSWORD, output + json.dumps(report))
        edit_statuses = [params["status"] for path, params in self.fake.calls if params.get("context") == "edit"]
        self.assertEqual(edit_statuses, ["publish", "draft", "pending", "future", "private"])

    def test_bare_command_stays_public_only(self):
        report_output = self.run_command("--dry-run")
        self.assertIn("Would create: 4", report_output)
        self.assertIn("Restricted, teaser only (not imported): 1 [206]", report_output)
        self.assertEqual(set(self.fake.call_auth), {None}, "no credentials without --all-statuses")
        self.assertFalse([p for _, p in self.fake.calls if p.get("context") == "edit" or p.get("status") != "publish"
                          and "status" in p])

    def test_all_statuses_sample_commit_creates_drafts(self):
        self.run_command("--all-statuses", "--post-id", "207", "--post-id", "206", "--commit")
        self.assertEqual(dict(BlogPost.objects.values_list("wp_post_id", "status")), {206: "draft", 207: "draft"})
        self.assertEqual(BlogPost.objects.get(wp_post_id=207).slug, "idea-draft")
        with self.assertRaisesMessage(CommandError, "Bulk commit is disabled"):
            self.run_command("--all-statuses", "--commit")

    @override_settings(WP_IMAA_BLOG_APP_PASSWORD="")
    def test_all_statuses_without_credentials_is_refused(self):
        self.client_patch.stop()  # use the real settings-based factory
        try:
            with self.assertRaisesMessage(CommandError, "Authenticated WordPress Blog import is not configured."):
                self.run_command("--all-statuses", "--dry-run")
        finally:
            self.client_patch.start()
        self.assertFalse(self.fake.calls)


class EditorialNormalizationRegressionTests(TestCase):
    """Draft and members-only content goes through the exact same normalizer."""

    def test_same_output_and_sanitising_for_every_format(self):
        for name, html in (("gutenberg", GUTENBERG_HTML), ("elementor", ELEMENTOR_HTML), ("classic", CLASSIC_HTML),
                           ("mixed", MIXED_HTML), ("faq", JSON_LD_HTML), ("unsafe", UNSAFE_HTML)):
            public = parse_wordpress_post(make_post(1, content=html), site_url=SITE)
            for status, restricted in (("draft", False), ("publish", True)):
                with self.subTest(name=name, status=status, restricted=restricted):
                    post = parse_wordpress_post(make_post(1, content=html, status=status), site_url=SITE,
                                                editorial={"restricted": restricted})
                    self.assertEqual(post.content_html, public.content_html)
                    self.assertEqual(post.source_format, public.source_format)
                    for dangerous in ("<script", "onerror", "onclick", "javascript:", "<iframe", "<form"):
                        self.assertNotIn(dangerous, post.content_html)
