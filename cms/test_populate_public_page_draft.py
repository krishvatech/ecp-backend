"""Tests for ``manage.py populate_public_page_draft``.

The starting state mirrors the real local database: the IMAA Connect HomePage is the Site
root, Privacy Policy is published, Terms and Conditions is an empty draft created by hand and
never published, and References is the title-only draft an earlier setup run created.
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
from wagtail.images import get_image_model
from wagtail.models import Page, PageLogEntry, PageViewRestriction, Revision, Site

from cms.management.commands.populate_public_page_draft import Command
from cms.models import AboutPage, HomePage, StandardPage
from cms.public_page_content import load_public_page_content
from cms.public_page_setup import MEDIA_COLLECTION_NAME, find_media_images, import_media_images, render_cms_body
from cms.public_page_testing import (
    IN_MEMORY_STORAGES,
    assert_api_body_matches_content,
    content_loader,
    trimmed_references,
)

BY_PATH = "/api/cms/public/pages/by-path/"
LOADER = "cms.management.commands.populate_public_page_draft.load_public_page_content"


def run(*args):
    out = StringIO()
    call_command("populate_public_page_draft", *args, stdout=out, stderr=StringIO())
    return out.getvalue()


def counts():
    return (
        Page.objects.count(),
        Revision.objects.count(),
        PageLogEntry.objects.count(),
        get_image_model().objects.count(),
    )


def page_state(page):
    page = Page.objects.get(pk=page.pk).specific
    latest = page.get_latest_revision()
    return {
        "title": page.title,
        "slug": page.slug,
        "body": page.body,
        "seo_title": page.seo_title,
        "search_description": page.search_description,
        "live": page.live,
        "first_published_at": page.first_published_at,
        "latest_revision_id": page.latest_revision_id,
        "latest_body": latest.as_object().body if latest else None,
        "revisions": page.revisions.count(),
        "restrictions": list(PageViewRestriction.objects.filter(page=page).values_list("id", flat=True)),
    }


def make_draft(parent, slug, title, body="", **fields):
    page = StandardPage(title=title, slug=slug, body=body, live=False, **fields)
    parent.add_child(instance=page)
    page.save_revision()
    return StandardPage.objects.get(pk=page.pk)


@override_settings(STORAGES=IN_MEMORY_STORAGES)
class PopulateDraftTestCase(TestCase):
    def setUp(self):
        self.references_content = trimmed_references()
        patcher = mock.patch(LOADER, side_effect=content_loader(references=self.references_content))
        patcher.start()
        self.addCleanup(patcher.stop)

        root = Page.get_first_root_node()
        self.home = HomePage(title="IMAA Connect", slug="imaa-connect", live=True)
        root.add_child(instance=self.home)
        self.site = Site.objects.get(is_default_site=True)
        self.site.root_page = self.home
        self.site.save()

        self.privacy = StandardPage(title="Privacy Policy", slug="privacy-policy", body="<p>Real policy</p>", live=False)
        self.home.add_child(instance=self.privacy)
        self.privacy.save_revision().publish()
        self.terms = make_draft(self.home, "terms-and-conditions", "Terms and Conditions")
        self.references = make_draft(self.home, "references", "References")
        self.privacy_before = page_state(self.privacy)

    def api(self, slug):
        return APIClient().get(BY_PATH, {"path": f"/{slug}/"})

    def assert_refused(self, page, args, message):
        before_counts, before = counts(), page_state(page)
        with self.assertRaisesMessage(CommandError, message):
            run(*args)
        self.assertEqual(counts(), before_counts)
        self.assertEqual(page_state(page), before)


class PreviewTests(PopulateDraftTestCase):
    def test_preview_is_the_default_and_writes_nothing(self):
        before = counts()
        with CaptureQueriesContext(connection) as queries:
            output = run("terms-and-conditions")
        self.assertEqual(counts(), before)
        for query in queries.captured_queries:
            self.assertTrue(query["sql"].lstrip().upper().startswith("SELECT"), query["sql"])
        self.assertIn("PREVIEW (no database changes)", output)
        self.assertIn("body: empty in the page record and in the latest revision", output)
        self.assertIn("body                 empty -> approved content", output)
        self.assertIn("seo_title            empty -> 'Terms and Conditions - IMAA", output)
        self.assertIn("search_description   empty; no approved value, left empty", output)
        self.assertIn("title                kept: 'Terms and Conditions'", output)
        self.assertIn("run again with --apply", output)

    def test_preview_with_publish_reports_publishing(self):
        output = run("references", "--publish")
        self.assertIn("publish: allowed", output)
        self.assertIn("3 bundled: 0 already in the Wagtail image library, 3 to import", output)
        self.assertEqual(get_image_model().objects.count(), 0)

    def test_dry_run_and_apply_are_mutually_exclusive(self):
        with self.assertRaises(CommandError):
            run("terms-and-conditions", "--dry-run", "--apply")

    def test_only_terms_and_references_are_supported(self):
        for slug in ("privacy-policy", "imprint", "frequently-asked-questions", "about"):
            with self.subTest(slug=slug), self.assertRaises(CommandError):
                run(slug)


class ApplyTests(PopulateDraftTestCase):
    def test_apply_populates_the_empty_draft(self):
        output = run("terms-and-conditions", "--apply")
        content = load_public_page_content("terms-and-conditions")
        page = StandardPage.objects.get(pk=self.terms.pk)
        latest = page.get_latest_revision().as_object()
        self.assertEqual(latest.body, content.body_html)
        self.assertEqual(latest.seo_title, content.seo_title)
        self.assertEqual(latest.search_description, "")
        self.assertEqual(latest.title, "Terms and Conditions")
        self.assertEqual(page.revisions.count(), 2)
        self.assertFalse(page.live)
        self.assertIsNone(page.first_published_at)
        self.assertTrue(page.has_unpublished_changes)
        entry = PageLogEntry.objects.filter(page=page, action="wagtail.edit").latest("pk")
        self.assertEqual(entry.data["source"], "populate_public_page_draft")
        self.assertIn("Saved draft revision", output)
        self.assertIn("still a draft", output)
        # Still a draft: the public endpoint keeps reporting it as unavailable (no defaults).
        self.assertEqual(self.api("terms-and-conditions").json(), {"detail": "Not found", "code": "page_unavailable"})
        self.assertEqual(page_state(self.privacy), self.privacy_before)

    def test_repeated_apply_changes_nothing(self):
        run("terms-and-conditions", "--apply")
        before, state = counts(), page_state(self.terms)
        output = run("terms-and-conditions", "--apply")
        self.assertIn("Already populated with the approved content; nothing changed.", output)
        self.assertEqual(counts(), before)
        self.assertEqual(page_state(self.terms), state)

    def test_apply_and_publish_in_one_run(self):
        run("terms-and-conditions", "--apply", "--publish")
        page = StandardPage.objects.get(pk=self.terms.pk)
        self.assertTrue(page.live)
        self.assertEqual(page.revisions.count(), 2)
        response = self.api("terms-and-conditions")
        self.assertEqual(response.status_code, 200)
        content = load_public_page_content("terms-and-conditions")
        self.assertEqual(response.json()["body_html"], content.body_html)
        self.assertEqual(response.json()["seo_title"], content.seo_title)

    def test_publish_a_previously_populated_draft(self):
        run("terms-and-conditions", "--apply")
        revisions = Revision.objects.count()
        output = run("terms-and-conditions", "--apply", "--publish")
        self.assertEqual(Revision.objects.count(), revisions)  # publishes the populated revision
        self.assertIn("Published /terms-and-conditions/", output)
        self.assertTrue(StandardPage.objects.get(pk=self.terms.pk).live)
        # Once live, the command refuses: live pages are edited in Wagtail.
        self.assert_refused(self.terms, ("terms-and-conditions", "--apply", "--publish"), "the page is live")

    def test_nonempty_seo_fields_and_draft_title_are_kept(self):
        draft = self.terms.get_latest_revision().as_object()
        draft.title = "Terms and Conditions (draft title)"
        draft.seo_title = "Editor SEO title"
        draft.save_revision()
        run("terms-and-conditions", "--apply")
        latest = StandardPage.objects.get(pk=self.terms.pk).get_latest_revision().as_object()
        self.assertEqual(latest.seo_title, "Editor SEO title")
        self.assertEqual(latest.title, "Terms and Conditions (draft title)")
        self.assertEqual(latest.body, load_public_page_content("terms-and-conditions").body_html)

    def test_references_imports_the_logos_and_publishes(self):
        output = run("references", "--apply", "--publish")
        self.assertIn("Images: 3 imported, 0 already in the Wagtail image library.", output)
        images, missing = find_media_images(self.references_content)
        self.assertEqual(missing, [])
        self.assertEqual({image.collection.name for image in images.values()}, {MEDIA_COLLECTION_NAME})
        page = StandardPage.objects.get(pk=self.references.pk)
        self.assertTrue(page.live)
        self.assertEqual(page.body, render_cms_body(self.references_content, images))
        response = self.api("references")
        self.assertEqual(response.status_code, 200)
        assert_api_body_matches_content(self, response.json()["body_html"], self.references_content)

    def test_references_reuses_identical_images(self):
        import_media_images(trimmed_references(count=2))
        before = get_image_model().objects.count()
        output = run("references", "--apply")
        self.assertIn("Images: 1 imported, 2 already in the Wagtail image library.", output)
        self.assertEqual(get_image_model().objects.count(), before + 1)
        run("references", "--apply")  # already populated: nothing imported again
        self.assertEqual(get_image_model().objects.count(), before + 1)

    def test_draft_changed_during_the_run_is_not_overwritten(self):
        original = Command._inspect
        calls = {"n": 0}

        def inspect_then_editor_saves(command, site, root, slug, content):
            result = original(command, site, root, slug, content)
            calls["n"] += 1
            if calls["n"] == 1:  # an editor saves a draft after the first look
                draft = StandardPage.objects.get(pk=self.terms.pk)
                draft.body = "<p>Editor's own terms</p>"
                draft.save_revision()
            return result

        with mock.patch.object(Command, "_inspect", inspect_then_editor_saves):
            with self.assertRaisesMessage(CommandError, "changed while this command was running"):
                run("terms-and-conditions", "--apply")
        latest = StandardPage.objects.get(pk=self.terms.pk).get_latest_revision().as_object()
        self.assertEqual(latest.body, "<p>Editor's own terms</p>")


class RefusalTests(PopulateDraftTestCase):
    def test_body_in_the_page_record_is_never_overwritten(self):
        StandardPage.objects.filter(pk=self.terms.pk).update(body="<p>Saved by an editor</p>")
        self.assert_refused(self.terms, ("terms-and-conditions", "--apply"), "already has content")

    def test_unsaved_to_live_editor_draft_is_never_overwritten(self):
        draft = self.terms.get_latest_revision().as_object()
        draft.body = "<p>Draft text an editor saved</p>"
        draft.save_revision()  # the page record's body stays empty; only the revision has it
        self.assertEqual(StandardPage.objects.get(pk=self.terms.pk).body, "")
        self.assert_refused(self.terms, ("terms-and-conditions", "--apply"), "already has content")

    def test_live_and_previously_published_pages_are_refused(self):
        self.terms.save_revision().publish()
        self.assert_refused(self.terms, ("terms-and-conditions", "--apply"), "the page is live")
        StandardPage.objects.get(pk=self.terms.pk).unpublish()
        self.assert_refused(self.terms, ("terms-and-conditions", "--apply"), "was published before")

    def test_archived_page_is_refused(self):
        StandardPage.objects.get(pk=self.terms.pk).soft_delete(reason="test")
        self.assert_refused(self.terms, ("terms-and-conditions", "--apply"), "archived")

    def test_view_restrictions_on_the_page_or_an_ancestor_are_refused(self):
        restriction = PageViewRestriction.objects.create(page=self.terms, restriction_type="login")
        self.assert_refused(self.terms, ("terms-and-conditions", "--apply"), "view restriction")
        restriction.delete()
        PageViewRestriction.objects.create(page=self.home, restriction_type="password", password="x")
        self.assert_refused(self.terms, ("terms-and-conditions", "--apply"), "view restriction")

    def test_scheduled_and_editorial_states_are_refused(self):
        cases = {
            "go-live date": lambda: StandardPage.objects.filter(pk=self.terms.pk).update(go_live_at=timezone.now() + timedelta(days=1)),
            "expiry date": lambda: StandardPage.objects.filter(pk=self.terms.pk).update(expire_at=timezone.now() + timedelta(days=1)),
            "scheduled for publishing": lambda: Revision.objects.filter(pk=self.terms.latest_revision_id).update(approved_go_live_at=timezone.now() + timedelta(days=1)),
            "locked in Wagtail": lambda: StandardPage.objects.filter(pk=self.terms.pk).update(locked=True),
        }
        for message, apply_state in cases.items():
            with self.subTest(message=message):
                savepoint = transaction.savepoint()
                try:
                    apply_state()
                    self.assert_refused(self.terms, ("terms-and-conditions", "--apply"), message)
                finally:
                    transaction.savepoint_rollback(savepoint)

    def test_workflow_in_progress_is_refused(self):
        with mock.patch.object(StandardPage, "workflow_in_progress", new_callable=mock.PropertyMock, return_value=True):
            self.assert_refused(self.terms, ("terms-and-conditions", "--apply"), "workflow is in progress")

    def test_draft_that_changes_the_slug_is_refused(self):
        draft = self.terms.get_latest_revision().as_object()
        draft.slug = "terms"
        draft.save_revision()
        self.assert_refused(self.terms, ("terms-and-conditions", "--apply"), "changes the slug to 'terms'")

    def test_wrong_page_type_and_missing_page_are_refused(self):
        Page.objects.get(pk=self.references.pk).delete()
        about = AboutPage(title="Our references", slug="references", live=True)
        self.home.add_child(instance=about)
        with self.assertRaisesMessage(CommandError, "not a StandardPage"):
            run("references", "--apply")
        Page.objects.get(pk=about.pk).delete()
        with self.assertRaisesMessage(CommandError, "No page exists at /references/"):
            run("references", "--apply")

    def test_wrong_site_root_is_refused(self):
        self.site.root_page = Page.objects.get(depth=2, slug="home")
        self.site.save()
        self.assert_refused(self.terms, ("terms-and-conditions", "--apply"), "not the IMAA Connect HomePage")

    def test_publish_is_refused_when_a_redirect_claims_the_path(self):
        Redirect.add_redirect("/terms-and-conditions/", redirect_to="/legal/", site=self.site)
        self.assert_refused(self.terms, ("terms-and-conditions", "--apply", "--publish"), "redirect")
        run("terms-and-conditions", "--apply")  # populating the draft is still allowed
        self.assertFalse(StandardPage.objects.get(pk=self.terms.pk).live)

    def test_publish_requires_apply(self):
        before = counts()
        output = run("terms-and-conditions", "--publish")
        self.assertEqual(counts(), before)
        self.assertIn("--publish without --apply", output)
        self.assertFalse(StandardPage.objects.get(pk=self.terms.pk).live)
