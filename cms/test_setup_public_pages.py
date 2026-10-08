"""Tests for ``manage.py setup_public_pages``.

The starting state mirrors a real environment: the default Site's root is the IMAA Connect
HomePage and a Privacy Policy page already exists, published with real content and several
revisions. The command must never touch it.
"""

from datetime import timedelta
from io import StringIO
from unittest import mock

from django.core.management import CommandError, call_command
from django.db import connection, transaction
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient
from wagtail.contrib.redirects.models import Redirect
from wagtail.models import Page, PageLogEntry, PageViewRestriction, Revision, Site

from wagtail.images import get_image_model

from cms.management.commands.setup_public_pages import Command, _DryRunWriteGuard
from cms.models import AboutPage, HomePage, StandardPage
from cms.public_page_content import NOT_MIGRATED, load_public_page_content
from cms.public_page_setup import MEDIA_COLLECTION_NAME, find_media_images, import_media_images, render_cms_body
from cms.public_page_testing import (
    IN_MEMORY_STORAGES,
    assert_api_body_matches_content,
    content_loader,
    trimmed_references,
)

LOADER = "cms.management.commands.setup_public_pages.load_public_page_content"

BY_PATH = "/api/cms/public/pages/by-path/"
REAL_PRIVACY_BODY = "<h2>1. Who we are</h2><p>Real privacy policy content entered by an editor.</p>"


def run(*args):
    out = StringIO()
    call_command("setup_public_pages", *args, stdout=out, stderr=StringIO())
    return out.getvalue()


def counts():
    return (Page.objects.count(), Revision.objects.count(), PageLogEntry.objects.count(), get_image_model().objects.count())


def snapshot(page):
    page = Page.objects.get(pk=page.pk).specific
    return {
        "title": page.title,
        "slug": page.slug,
        "body": getattr(page, "body", None),
        "seo_title": page.seo_title,
        "search_description": page.search_description,
        "live": page.live,
        "has_unpublished_changes": page.has_unpublished_changes,
        "first_published_at": page.first_published_at,
        "last_published_at": page.last_published_at,
        "latest_revision_id": page.latest_revision_id,
        "live_revision_id": page.live_revision_id,
        "revisions": page.revisions.count(),
        "archived": getattr(page, "cms_is_deleted", None),
        "restrictions": list(page.get_view_restrictions().values_list("id", flat=True)),
        "url_path": page.url_path,
    }


@override_settings(STORAGES=IN_MEMORY_STORAGES)
class SetupPublicPagesTestCase(TestCase):
    def setUp(self):
        # References with 3 of its 258 logos keeps these tests fast; FullReferencesTests uses all.
        self.references = trimmed_references()
        patcher = mock.patch(LOADER, side_effect=content_loader(references=self.references))
        patcher.start()
        self.addCleanup(patcher.stop)

        root = Page.get_first_root_node()
        self.home = HomePage(title="IMAA Connect", slug="imaa-connect", live=True)
        root.add_child(instance=self.home)
        self.site = Site.objects.get(is_default_site=True)
        self.site.root_page = self.home
        self.site.save()

        self.privacy = StandardPage(
            title="Privacy Policy",
            slug="privacy-policy",
            body="<p>First version</p>",
            seo_title="Privacy Policy | IMAA Institute",
            search_description="Our privacy policy",
            live=False,
        )
        self.home.add_child(instance=self.privacy)
        self.privacy.save_revision().publish()
        self.privacy.body = REAL_PRIVACY_BODY
        self.privacy.save_revision().publish()
        self.privacy_before = snapshot(self.privacy)

    def child(self, slug):
        page = Page.objects.child_of(self.home).filter(slug=slug).first()
        return page.specific if page else None


class DryRunTests(SetupPublicPagesTestCase):
    def test_default_is_a_dry_run_that_writes_nothing(self):
        before = counts()
        with CaptureQueriesContext(connection) as queries:
            output = run()
        self.assertEqual(counts(), before)
        self.assertTrue(queries.captured_queries)
        for query in queries.captured_queries:
            self.assertTrue(query["sql"].lstrip().upper().startswith("SELECT"), query["sql"])
        self.assertIn("DRY RUN", output)
        for slug in ("frequently-asked-questions", "references", "terms-and-conditions", "imprint"):
            self.assertRegex(output, rf"/{slug}\s+missing\s+would create draft")
        self.assertRegex(output, r"/privacy-policy\s+exists\s+would keep")
        self.assertIn("live; served publicly; left unchanged", output)
        self.assertEqual(snapshot(self.privacy), self.privacy_before)

    def test_explicit_dry_run_with_publish_new_previews_only(self):
        before = counts()
        output = run("--dry-run", "--publish-new")
        self.assertEqual(counts(), before)
        self.assertRegex(output, r"/imprint\s+missing\s+would create and publish")
        self.assertRegex(output, r"/references\s+missing\s+would create and publish")
        self.assertIn("3 bundled images: 0 already in the Wagtail image library, 3 to import", output)
        self.assertIn("run again with --apply --publish-new", output)
        self.assertNotIn("Use --apply --publish-new", output)

    def test_publish_new_keeps_pages_without_content_as_drafts(self):
        imprint = load_public_page_content("imprint")
        empty_imprint = type(imprint)(**{**imprint.__dict__, "body_lines": (), "migration_status": NOT_MIGRATED})
        with mock.patch(LOADER, side_effect=content_loader(references=self.references, imprint=empty_imprint)):
            output = run("--dry-run", "--publish-new")
        self.assertRegex(output, r"/imprint\s+missing\s+would create draft")
        self.assertIn("stays a draft: no approved initial content", output)
        self.assertNotIn("Use --apply --publish-new", output)

    def test_plain_dry_run_suggests_publish_new_for_drafts_with_content(self):
        output = run("--dry-run")
        self.assertIn("Use --apply --publish-new to publish new pages that have approved content instead.", output)
        self.assertIn("Dry run: run again with --apply to create these pages.", output)

    def test_guard_refuses_writes(self):
        with self.assertRaisesMessage(CommandError, "Dry run attempted a database write (UPDATE)"):
            with transaction.atomic():  # savepoint opened before the guard, so the test can continue
                with connection.execute_wrapper(_DryRunWriteGuard()):
                    Page.objects.filter(pk=self.home.pk).update(title="changed")
        self.assertEqual(Page.objects.get(pk=self.home.pk).title, "IMAA Connect")

    def test_dry_run_and_apply_are_mutually_exclusive(self):
        with self.assertRaises(CommandError):
            run("--dry-run", "--apply")


class ApplyTests(SetupPublicPagesTestCase):
    def test_apply_creates_missing_pages_as_drafts_with_initial_content(self):
        output = run("--apply")
        for slug in ("frequently-asked-questions", "references", "terms-and-conditions", "imprint"):
            with self.subTest(slug=slug):
                page = self.child(slug)
                content = load_public_page_content(slug)
                self.assertIsInstance(page, StandardPage)
                self.assertFalse(page.live)
                self.assertIsNone(page.first_published_at)
                self.assertEqual(page.title, content.title)
                self.assertEqual(page.seo_title, content.seo_title)
                self.assertEqual(page.search_description, content.search_description)
                if slug == "references":
                    images, missing = find_media_images(self.references)
                    self.assertEqual(missing, [])
                    self.assertEqual(page.body, render_cms_body(self.references, images))
                    self.assertEqual({image.collection.name for image in images.values()}, {MEDIA_COLLECTION_NAME})
                else:
                    self.assertEqual(page.body, content.body_html)
                self.assertEqual(page.revisions.count(), 1)
                self.assertTrue(PageLogEntry.objects.filter(page=page, action="wagtail.create").exists())
                self.assertRegex(output, rf"/{slug}\s+missing\s+created draft")
        self.assertEqual(snapshot(self.privacy), self.privacy_before)
        self.assertIn("a draft occupies its path", output)

        # A draft must not let the frontend fall back to its defaults.
        response = APIClient().get(BY_PATH, {"path": "/imprint/"})
        self.assertEqual(response.json(), {"detail": "Not found", "code": "page_unavailable"})

    def test_second_apply_changes_nothing(self):
        run("--apply")
        before = counts()
        snapshots = {slug: snapshot(self.child(slug)) for slug in ("frequently-asked-questions", "imprint")}
        output = run("--apply")
        self.assertEqual(counts(), before)
        self.assertIn("Nothing to create.", output)
        for slug, snap in snapshots.items():
            self.assertEqual(snapshot(self.child(slug)), snap)
        self.assertEqual(snapshot(self.privacy), self.privacy_before)

    def test_publish_new_publishes_new_pages_with_content(self):
        output = run("--apply", "--publish-new")
        for slug in ("frequently-asked-questions", "references", "terms-and-conditions", "imprint"):
            with self.subTest(slug=slug):
                page = self.child(slug)
                self.assertTrue(page.live)
                self.assertIsNotNone(page.live_revision_id)
                self.assertRegex(output, rf"/{slug}\s+missing\s+created and published")
                response = APIClient().get(BY_PATH, {"path": f"/{slug}/"})
                self.assertEqual(response.status_code, 200)
                content = self.references if slug == "references" else load_public_page_content(slug)
                assert_api_body_matches_content(self, response.json()["body_html"], content)
        self.assertEqual(snapshot(self.privacy), self.privacy_before)

    def test_logos_are_imported_once_and_identical_files_reused(self):
        existing, _created = import_media_images(trimmed_references(count=1))  # already in the library
        before = get_image_model().objects.count()
        output = run("--apply")
        self.assertEqual(get_image_model().objects.count(), before + 2)
        images, missing = find_media_images(self.references)
        self.assertEqual(missing, [])
        first_key = self.references.media[0].key
        self.assertEqual(images[first_key].pk, existing[first_key].pk)
        self.assertIn("3 bundled images: 2 imported into the 'Public website pages' collection, 1 reused", output)
        run("--apply")
        self.assertEqual(get_image_model().objects.count(), before + 2)

    def test_existing_pages_in_every_state_are_preserved(self):
        draft_terms = StandardPage(title="Terms draft", slug="terms-and-conditions", body="", live=False)
        self.home.add_child(instance=draft_terms)
        draft_terms.save_revision()
        archived = StandardPage(title="Imprint (old)", slug="imprint", body="<p>Old</p>", live=False)
        self.home.add_child(instance=archived)
        archived.save_revision().publish()
        archived.soft_delete(reason="test")
        restricted = StandardPage(title="FAQ (members)", slug="frequently-asked-questions", body="<p>x</p>", live=False)
        self.home.add_child(instance=restricted)
        restricted.save_revision().publish()
        PageViewRestriction.objects.create(page=restricted, restriction_type="login")
        expired = StandardPage(
            title="References (expired)", slug="references", body="<p>x</p>", live=False,
            expire_at=timezone.now() - timedelta(days=1),
        )
        self.home.add_child(instance=expired)
        expired.save_revision().publish()

        pages = [self.privacy, draft_terms, archived, restricted, expired]
        before = {page.pk: snapshot(page) for page in pages}
        before_counts = counts()
        output = run("--apply", "--publish-new")
        self.assertEqual(counts(), before_counts)
        for page in pages:
            self.assertEqual(snapshot(page), before[page.pk])
        self.assertIn("draft, never published", output)
        self.assertIn("archived", output)
        self.assertIn("view-restricted", output)
        self.assertIn("expired", output)
        self.assertIn("Nothing to create.", output)

    def test_collision_with_another_page_type_is_reported_and_skipped(self):
        about = AboutPage(title="Our references", slug="references", live=True)
        self.home.add_child(instance=about)
        output = run("--apply")
        self.assertIsInstance(self.child("references"), AboutPage)
        self.assertRegex(output, r"/references\s+collision\s+skipped")
        self.assertIn("already belongs to AboutPage", output)
        self.assertIsInstance(self.child("imprint"), StandardPage)

    def test_redirected_path_is_skipped(self):
        Redirect.add_redirect("/imprint/", redirect_to="/legal/imprint/", site=self.site)
        output = run("--apply")
        self.assertIsNone(self.child("imprint"))
        self.assertRegex(output, r"/imprint\s+blocked\s+skipped")
        self.assertIn("Wagtail redirect", output)

    def test_restricted_root_blocks_creation(self):
        PageViewRestriction.objects.create(page=self.home, restriction_type="login")
        output = run("--apply")
        self.assertIsNone(self.child("imprint"))
        self.assertIn("view restriction", output)

    def test_page_created_concurrently_is_not_duplicated(self):
        original_plan = Command._plan
        state = {"calls": 0}

        def plan_then_simulate_editor(command, site, root, contents, publish_new):
            plans = original_plan(command, site, root, contents, publish_new)
            state["calls"] += 1
            if state["calls"] == 1:  # another process creates /imprint after the first look
                other = StandardPage(title="Imprint (editor)", slug="imprint", body="<p>Editor</p>", live=False)
                Page.objects.get(pk=root.pk).add_child(instance=other)
            return plans

        with mock.patch.object(Command, "_plan", plan_then_simulate_editor):
            run("--apply")
        imprints = Page.objects.child_of(self.home).filter(slug="imprint")
        self.assertEqual(imprints.count(), 1)
        self.assertEqual(imprints.get().title, "Imprint (editor)")
        self.assertIsNotNone(self.child("frequently-asked-questions"))


class ConfigurationErrorTests(SetupPublicPagesTestCase):
    def test_wrong_site_root_is_an_error_and_changes_nothing(self):
        welcome = Page.objects.get(depth=2, slug="home")
        self.site.root_page = welcome
        self.site.save()
        before = counts()
        with self.assertRaisesMessage(CommandError, "not the IMAA Connect HomePage"):
            run("--apply", "--publish-new")
        self.assertEqual(counts(), before)
        site = Site.objects.get(pk=self.site.pk)
        self.assertEqual(site.root_page_id, welcome.pk)
        with self.assertRaisesMessage(CommandError, "'IMAA Connect' (slug 'imaa-connect', live)"):
            run()

    def test_archived_root_is_an_error(self):
        HomePage.objects.filter(pk=self.home.pk).update(cms_is_deleted=True)
        with self.assertRaisesMessage(CommandError, "an archived HomePage"):
            run("--apply")
        self.assertIsNone(self.child("imprint"))

    def test_ambiguous_sites_are_an_error(self):
        other = HomePage(title="Other", slug="other", live=True)
        Page.get_first_root_node().add_child(instance=other)
        Site.objects.create(hostname="other.test", port=80, root_page=other, is_default_site=False)
        Site.objects.update(is_default_site=False)
        before = counts()
        with self.assertRaisesMessage(CommandError, "Cannot choose the public Wagtail Site"):
            run("--apply")
        self.assertEqual(counts(), before)

    def test_configured_hostname_selects_the_site(self):
        other = HomePage(title="Other Connect", slug="other-connect", live=True)
        Page.get_first_root_node().add_child(instance=other)
        Site.objects.create(hostname="other.test", port=80, root_page=other, is_default_site=False)
        with override_settings(CMS_PUBLIC_SITE_HOSTNAME="other.test"):
            run("--apply")
        self.assertTrue(Page.objects.child_of(other).filter(slug="imprint").exists())
        self.assertIsNone(self.child("imprint"))

    def test_invalid_content_aborts_before_any_change(self):
        from cms.public_page_content import PublicPageContentError

        before = counts()
        with mock.patch(
            "cms.management.commands.setup_public_pages.load_public_page_content",
            side_effect=PublicPageContentError("imprint.json: content_sha256 mismatch"),
        ):
            with self.assertRaisesMessage(CommandError, "Initial content is invalid"):
                run("--apply")
        self.assertEqual(counts(), before)


class FullReferencesTests(SetupPublicPagesTestCase):
    def test_full_logo_wall_is_imported_and_served(self):
        full = load_public_page_content("references")
        with mock.patch(LOADER, side_effect=load_public_page_content):
            run("--apply", "--publish-new")
        self.assertTrue(self.child("references").live)
        images, missing = find_media_images(full)
        self.assertEqual((len(images), missing), (258, []))
        self.assertEqual(len({image.pk for image in images.values()}), 258)
        response = APIClient().get(BY_PATH, {"path": "/references/"})
        self.assertEqual(response.status_code, 200)
        assert_api_body_matches_content(self, response.json()["body_html"], full)
