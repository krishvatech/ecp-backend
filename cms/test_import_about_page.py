"""``import_about_page``: importing the approved About content into an existing AboutPage that holds
the earlier IMAA Connect content, reusing image originals that are already in storage.

Storage is an in-memory storage seeded with originals at ``original_images/<file>``, standing in
for the S3 objects; every test asserts that nothing is written to it by the command. The image
binaries are not part of the repository, so most tests use generated originals (same file names
and dimensions as the approved files, content mapped through their SHA-256) and run in a clean
checkout; ``RealOriginalsTests`` uses the approved files when they are present locally. In every
test the content package's ``images/`` directory is unavailable to the importer.
"""

import copy
import hashlib
import re
import tempfile
from datetime import datetime, timedelta, timezone as dt_timezone
from io import StringIO
from pathlib import Path
from unittest import mock, skipUnless

from django.core.files.base import ContentFile
from django.core.files.storage import storages
from django.core.management import CommandError, call_command
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient
from wagtail.blocks import StreamValue
from wagtail.images import get_image_model
from wagtail.models import Page, PageLogEntry, Revision, Site
from wagtail.utils.file import hash_filelike

from cms import about_page_content as content_module
from cms.about_page_content import IMAGES_DIR, AboutContentError, load_about_content
from cms.about_page_testing import APPROVED, REAL_FILES_PRESENT, first_per_file, generated_originals
from cms.management.commands import import_about_page as command_module
from cms.management.commands.import_about_page import BackupNotVerified, verify_rds_snapshot
from cms.models import AboutPage, HomePage, StandardPage, Testimonial
from cms.public_page_testing import IN_MEMORY_STORAGES

BY_PATH = "/api/cms/public/pages/by-path/"
CONTENT, ORIGINALS = generated_originals()
TOKEN_RE = re.compile(r"Confirmation token: (about-\d+-[0-9a-f]{16})")
OLD_INTRO = "<p>IMAA Connect brings M&amp;A professionals together.</p>"


def run(*args):
    out = StringIO()
    call_command("import_about_page", *args, stdout=out, stderr=StringIO())
    return out.getvalue()


def token_from(output):
    return TOKEN_RE.search(output).group(1)


class ImportAboutPageTestCase(TestCase):
    content, originals = CONTENT, ORIGINALS

    def setUp(self):
        # The deployed code has no image binaries: the package's images/ directory is empty here.
        self.enterContext(mock.patch.object(content_module, "IMAGES_DIR", Path(self.enterContext(tempfile.TemporaryDirectory()))))
        if self.content is not APPROVED:
            self.enterContext(mock.patch.object(command_module, "load_about_content",
                                                side_effect=lambda **kwargs: copy.deepcopy(self.content)))
        self.enterContext(override_settings(STORAGES=IN_MEMORY_STORAGES))
        self.storage = storages["default"]
        for name, data in self.originals.items():
            self.storage.save(f"original_images/{name}", ContentFile(data))
        # From here on, any write to storage is a failure: the command must only read.
        self.storage_writes_allowed = False
        storage_class = type(self.storage)
        original_save, original_delete = storage_class._save, storage_class.delete

        def guarded(original):
            def method(storage, *args, **kwargs):
                if not self.storage_writes_allowed:
                    raise AssertionError(f"storage write: {original.__name__}{args[:1]}")
                return original(storage, *args, **kwargs)
            return method

        self.enterContext(mock.patch.object(storage_class, "_save", guarded(original_save)))
        self.enterContext(mock.patch.object(storage_class, "delete", guarded(original_delete)))

        root = Page.get_first_root_node()
        self.home = HomePage(title="IMAA Connect", slug="imaa-connect", live=True)
        root.add_child(instance=self.home)
        site = Site.objects.get(is_default_site=True)
        site.root_page = self.home
        site.save()
        # The page as on the deployed server: published with the earlier IMAA Connect content.
        about = AboutPage(title="About Us", slug="about", live=False, intro_html=OLD_INTRO,
                          mission_html="<p>Connect the M&amp;A community.</p>")
        self.home.add_child(instance=about)
        about.features = StreamValue(about.features.stream_block, [
            {"type": "feature", "value": {"image": None, "title": "Join events", "desc": "Live and online."}},
        ], is_lazy=True)
        about.save_revision().publish()
        self.about = AboutPage.objects.get(pk=about.pk)
        self.privacy = StandardPage(title="Privacy Policy", slug="privacy-policy", body="<p>x</p>", live=False)
        self.home.add_child(instance=self.privacy)
        self.privacy.save_revision().publish()

    def counts(self):
        return (Page.objects.count(), Revision.objects.count(), PageLogEntry.objects.count(),
                get_image_model().objects.count(), Testimonial.objects.count())

    def preview(self, *extra):
        return run("--replace-existing-content", *extra)

    def apply(self, token=None, *extra):
        token = token or token_from(self.preview())
        return run("--apply", "--page-id", str(self.about.pk), "--confirm", token, "--replace-existing-content", *extra)

    def assert_refused(self, message, *args):
        before = self.counts()
        with self.assertRaisesMessage(CommandError, message):
            run(*args)
        self.assertEqual(self.counts(), before)


class PreviewTests(ImportAboutPageTestCase):
    def test_preview_is_read_only_and_shows_the_plan(self):
        before = self.counts()
        with CaptureQueriesContext(connection) as queries:
            output = self.preview()
        self.assertEqual(self.counts(), before)
        for query in queries.captured_queries:
            self.assertTrue(query["sql"].lstrip().upper().startswith("SELECT"), query["sql"])
        self.assertIn("PREVIEW (read-only, no changes)", output)
        self.assertIn(f"AboutPage #{self.about.pk} 'About Us' at /", output)
        self.assertIn("hero_title             empty    'About IMAA Connect' -> 'Setting and Advancing", output)
        self.assertRegex(output, r"intro_html\s+replace\s+\d+ characters: '<p>IMAA Connect brings")
        self.assertIn("0 existing Wagtail images reused, 40 image records to create", output)
        self.assertIn("0 uploads", output)
        self.assertIn("Testimonials: 10 approved: 0 existing reused unchanged, 10 to create", output)
        self.assertIn("Existing content that WILL be replaced: intro_html, mission_html, features", output)
        self.assertIn(f"--apply --page-id {self.about.pk} --confirm about-{self.about.pk}-", output)

    def test_no_flags_is_the_dry_run_and_existing_content_needs_explicit_replacement(self):
        with self.assertRaisesMessage(CommandError, "these fields hold other content: intro_html, mission_html, features"):
            run()
        with self.assertRaisesMessage(CommandError, "these fields hold other content"):
            run("--dry-run")

    def test_the_token_changes_with_the_page_content_and_the_options(self):
        first = token_from(self.preview())
        self.assertEqual(first, token_from(self.preview()), "the token is stable while nothing changes")
        page = AboutPage.objects.get(pk=self.about.pk)
        page.mission_html = "<p>Edited by an editor</p>"
        page.save_revision().publish()
        self.assertNotEqual(first, token_from(self.preview()))


class ApplyTests(ImportAboutPageTestCase):
    def test_apply_imports_the_approved_content_and_keeps_the_page(self):
        revisions_before = list(self.about.revisions.values_list("pk", flat=True))
        privacy_revision = StandardPage.objects.get(pk=self.privacy.pk).live_revision_id
        images_before = get_image_model().objects.count()
        output = self.apply()
        self.assertIn("Created 40 image records (no files uploaded) and 10 testimonials", output)

        page = AboutPage.objects.get(pk=self.about.pk)
        self.assertEqual((page.pk, page.title, page.slug, page.get_parent().pk), (self.about.pk, "About Us", "about", self.home.pk))
        self.assertTrue(page.live)
        self.assertFalse(page.has_unpublished_changes)
        self.assertEqual(set(revisions_before) - set(page.revisions.values_list("pk", flat=True)), set(), "history kept")
        self.assertEqual(page.revisions.count(), len(revisions_before) + 1)
        self.assertEqual(page.hero_title, CONTENT["hero_title"])
        self.assertEqual(page.features_title, "")
        self.assertNotIn("IMAA Connect brings", page.intro_html)
        self.assertEqual([b.value["value"] for b in page.stats], [s["value"] for s in CONTENT["stats"]])
        self.assertEqual([b.value["title"] for b in page.features], [f["title"] for f in CONTENT["features"]])
        self.assertEqual([b.block_type for b in page.sections], [s["type"] for s in CONTENT["sections"]])
        self.assertEqual(page.seo_title, CONTENT["seo_title"])

        # Image records point at the stored originals; the stored bytes are the approved files.
        self.assertEqual(get_image_model().objects.count(), images_before + 40)
        hero = page.hero_background_image
        self.assertEqual(hero.file.name, "original_images/2024-12-Website-Banner-2025.jpg")
        self.assertEqual((hero.width, hero.height), (1570, 450))
        with hero.open_file() as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(),
                             next(m["sha256"] for m in CONTENT["media"] if m["file"] == hero.file.name.split("/")[-1]))
        testimonials = page.sections[4].value["testimonials"]
        self.assertEqual([t.wordpress_id for t in testimonials],
                         [i["wordpress_id"] for i in CONTENT["sections"][4]["items"]])

        entry = PageLogEntry.objects.filter(page=page, action="wagtail.edit").latest("pk")
        self.assertEqual(entry.data["source"], "import_about_page")
        self.assertEqual(entry.data["replaced_existing_content"], ["intro_html", "mission_html", "features"])
        self.assertEqual(entry.data["backup"], "local database")
        self.assertEqual(StandardPage.objects.get(pk=self.privacy.pk).live_revision_id, privacy_revision, "other pages untouched")

    def test_the_public_api_serves_the_imported_page(self):
        self.apply()
        # Renditions are written by the API on first request (not by the command): allow storage writes now.
        self.storage_writes_allowed = True
        response = APIClient().get(BY_PATH, {"path": "/about/"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["type"], "AboutPage")
        self.assertEqual(data["hero_title"], CONTENT["hero_title"])
        self.assertEqual(len(data["stats"]), len(CONTENT["stats"]))
        self.assertEqual([s["type"] for s in data["sections"]], [s["type"] for s in CONTENT["sections"]])
        testimonials = next(s for s in data["sections"] if s["type"] == "testimonials")
        self.assertEqual(len(testimonials["items"]), 10)
        offices = next(s for s in data["sections"] if s["type"] == "offices")
        self.assertTrue(all(o["image"] and o["image"]["url"] for o in offices["offices"]))

    def test_repeat_runs_change_nothing(self):
        token = token_from(self.preview())
        self.apply(token)
        before = self.counts()
        self.assertIn("Already imported: the page holds the approved content; nothing to do.", run())
        self.assertIn("Already imported", self.apply(token))
        self.assertEqual(self.counts(), before)

    def test_existing_images_and_testimonials_are_reused_unchanged(self):
        item = next(m for m in CONTENT["media"] if m["file"] == "2024-07-USA.webp")
        existing = get_image_model()(title="USA (already in the library)", width=1080, height=1080,
                                     file_size=len(self.originals[item["file"]]))
        existing.file.name = f"original_images/{item['file']}"
        with existing.open_file() as fh:
            existing.file_hash = hash_filelike(fh)
        existing.save()
        first = CONTENT["sections"][4]["items"][0]
        kept = Testimonial.objects.create(name=first["name"], slug=first["slug"], quote="<p>Edited in Wagtail</p>",
                                          wordpress_id=first["wordpress_id"])
        images_before = get_image_model().objects.count()
        output = self.apply()
        self.assertIn("Created 39 image records (no files uploaded) and 9 testimonials", output)
        self.assertEqual(get_image_model().objects.count(), images_before + 39)
        self.assertEqual(Testimonial.objects.count(), 10)
        kept.refresh_from_db()
        self.assertEqual(kept.quote, "<p>Edited in Wagtail</p>", "existing testimonials are never changed")
        page = AboutPage.objects.get(pk=self.about.pk)
        office_images = [o["image"] for o in page.sections[7].value["offices"]]
        self.assertIn(existing.pk, [image.pk for image in office_images if image])

    def test_image_records_take_hash_and_size_from_the_stored_bytes_read_once(self):
        opened = []
        original_open = type(self.storage).open

        def counting_open(storage, name, mode="rb"):
            opened.append(name)
            return original_open(storage, name, mode)

        token = token_from(self.preview())
        with mock.patch.object(type(self.storage), "open", counting_open):
            self.apply(token)
        self.assertEqual(len(opened), 40, "each original is downloaded once per run, not again under the lock")
        self.assertEqual(len(set(opened)), 40)
        for name, data in self.originals.items():
            image = get_image_model().objects.get(file=f"original_images/{name}")
            self.assertEqual(image.file_hash, hashlib.sha1(data).hexdigest())
            self.assertEqual(image.file_size, len(data))
            item = next(m for m in self.content["media"] if m["file"] == name)
            self.assertEqual((image.width, image.height), (item["width"], item["height"]))
            self.assertEqual(image.collection.name, "Public website pages")

    def test_an_existing_image_stored_under_another_key_is_verified_and_reused(self):
        name = "2024-07-UK.webp"
        data = self.originals[name]
        self.storage_writes_allowed = True
        self.storage.save("original_images/uk-uploaded-in-wagtail.webp", ContentFile(data))
        self.storage_writes_allowed = False
        item = next(m for m in self.content["media"] if m["file"] == name)
        existing = get_image_model()(title="UK", width=item["width"], height=item["height"], file_size=len(data),
                                     file_hash=hashlib.sha1(data).hexdigest())
        existing.file.name = "original_images/uk-uploaded-in-wagtail.webp"
        existing.save()
        self.assertIn("1 existing Wagtail images reused, 39 image records to create", self.preview())
        self.apply()
        page = AboutPage.objects.get(pk=self.about.pk)
        self.assertIn(existing.pk, [o["image"].pk for o in page.sections[7].value["offices"] if o["image"]])

    def test_the_object_behind_an_existing_record_is_verified_too(self):
        name = "2024-07-UK.webp"
        data = self.originals[name]
        item = next(m for m in self.content["media"] if m["file"] == name)
        existing = get_image_model()(title="UK", width=item["width"], height=item["height"], file_size=len(data),
                                     file_hash=hashlib.sha1(data).hexdigest())
        existing.file.name = "original_images/uk-missing-object.webp"  # no such object in storage
        existing.save()
        self.assert_refused(f"Wagtail image #{existing.pk} points at 'original_images/uk-missing-object.webp'",
                            "--replace-existing-content")


class RefusalTests(ImportAboutPageTestCase):
    def test_missing_and_different_storage_objects_block_everything(self):
        with mock.patch.object(type(self.storage), "exists",
                               side_effect=lambda name: name != "original_images/2024-07-UK.webp"):
            self.assert_refused("image file 2024-07-UK.webp: no object at 'original_images/2024-07-UK.webp'",
                                "--replace-existing-content")
        original_open = type(self.storage).open

        def tampered(storage, name, mode="rb"):
            if name == "original_images/2024-07-PH.webp":
                return ContentFile(b"not the approved file", name=name)
            return original_open(storage, name, mode)

        with mock.patch.object(type(self.storage), "open", tampered):
            self.assert_refused("2024-07-PH.webp: the object at 'original_images/2024-07-PH.webp' differs from the approved file",
                                "--replace-existing-content")

    def test_wrong_dimensions_and_unreadable_objects_are_refused(self):
        self.content = copy.deepcopy(self.content)
        for m in self.content["media"]:
            if m["file"] == "2024-07-Singapore.webp":
                m["width"] = 999
        self.assert_refused("2024-07-Singapore.webp: 'original_images/2024-07-Singapore.webp' is 1080x1080, expected 999x1080",
                            "--replace-existing-content")
        self.content = CONTENT
        with mock.patch.object(type(self.storage), "open", side_effect=OSError("connection reset")):
            self.assert_refused("cannot read 'original_images/", "--replace-existing-content")

    def test_an_existing_record_with_other_dimensions_is_refused(self):
        name = "2024-07-PH.webp"
        item = next(m for m in self.content["media"] if m["file"] == name)
        existing = get_image_model()(title="PH", width=500, height=500, file_size=1, file_hash="")
        existing.file.name = f"original_images/{name}"
        existing.save()
        self.assert_refused(f"Wagtail image #{existing.pk} records 500x500, expected {item['width']}x{item['height']}",
                            "--replace-existing-content")

    def test_unpublished_changes_locks_and_restrictions_block(self):
        draft = AboutPage.objects.get(pk=self.about.pk)
        draft.intro_html = "<p>Draft by an editor</p>"
        draft.save_revision()
        self.assert_refused("the page has unpublished changes in Wagtail; they are never overwritten", "--replace-existing-content")
        AboutPage.objects.get(pk=self.about.pk).save_revision().publish()
        AboutPage.objects.filter(pk=self.about.pk).update(locked=True)
        self.assert_refused("the page is locked in Wagtail", "--replace-existing-content")

    def test_apply_needs_the_page_id_and_the_reviewed_token(self):
        token = token_from(self.preview())
        self.assert_refused("--apply needs --page-id and --confirm", "--apply", "--replace-existing-content")
        self.assert_refused("does not match the AboutPage at /about/ in this database",
                            "--apply", "--page-id", "999999", "--confirm", token, "--replace-existing-content")
        self.assert_refused("the confirmation token does not match", "--apply", "--page-id", str(self.about.pk),
                            "--confirm", "about-0-0000000000000000", "--replace-existing-content")
        # The same token without the reviewed option is not valid either.
        self.assert_refused("these fields hold other content", "--apply", "--page-id", str(self.about.pk), "--confirm", token)

    def test_an_edit_after_the_preview_invalidates_the_token(self):
        token = token_from(self.preview())
        page = AboutPage.objects.get(pk=self.about.pk)
        page.intro_html = "<p>Changed after the review</p>"
        page.save_revision().publish()
        self.assert_refused("the confirmation token does not match", "--apply", "--page-id", str(self.about.pk),
                            "--confirm", token, "--replace-existing-content")

    def test_an_edit_while_the_command_runs_is_detected_under_the_lock(self):
        token = token_from(self.preview())

        def editor_publishes(command, options):
            # Runs after the first checks and before the locked re-check: an editor publishes meanwhile.
            page = AboutPage.objects.get(pk=self.about.pk)
            page.mission_title = "Edited concurrently"
            page.save_revision().publish()
            return {"backup": "local database"}

        with mock.patch.object(command_module.Command, "_verify_backup", editor_publishes):
            with self.assertRaisesMessage(CommandError, "The page changed while this command was running"):
                run("--apply", "--page-id", str(self.about.pk), "--confirm", token, "--replace-existing-content")
        page = AboutPage.objects.get(pk=self.about.pk)
        self.assertEqual(page.mission_title, "Edited concurrently", "the editor's change is kept")
        self.assertEqual(page.intro_html, OLD_INTRO)
        self.assertEqual(Testimonial.objects.count(), 0)

    def test_a_failure_while_publishing_rolls_everything_back(self):
        token = token_from(self.preview())
        before = self.counts()
        with mock.patch("wagtail.models.Revision.publish", side_effect=RuntimeError("publish failed")):
            with self.assertRaisesMessage(RuntimeError, "publish failed"):
                self.apply(token)
        self.assertEqual(self.counts(), before)
        self.assertEqual(AboutPage.objects.get(pk=self.about.pk).intro_html, OLD_INTRO)

    def test_wrong_database_and_wrong_site_are_refused(self):
        token = token_from(self.preview())
        remote = {**connection.settings_dict, "HOST": "ecp.abc123.eu-central-1.rds.amazonaws.com"}
        with mock.patch.object(connection, "settings_dict", remote):
            self.assert_refused("needs --backup-snapshot", "--apply", "--page-id", str(self.about.pk), "--confirm", token,
                                "--replace-existing-content")
            # Same page, but the token was reviewed on another database.
            self.assert_refused("the confirmation token does not match", "--apply", "--page-id", str(self.about.pk),
                                "--confirm", token, "--replace-existing-content", "--backup-snapshot", "snap-1",
                                "--backup-verified-externally")
        site = Site.objects.get(is_default_site=True)
        site.root_page = Page.get_first_root_node().get_children().exclude(pk=self.home.pk).first() or Page.get_first_root_node()
        site.save()
        self.assert_refused("not the IMAA Connect HomePage", "--replace-existing-content")

    def test_backup_is_verified_on_a_remote_database(self):
        remote = {**connection.settings_dict, "HOST": "ecp.abc123.eu-central-1.rds.amazonaws.com"}
        with mock.patch.object(connection, "settings_dict", remote):
            token = token_from(self.preview())
            with mock.patch.object(command_module, "verify_rds_snapshot", side_effect=BackupNotVerified("snapshot 'x' is 'creating'")):
                self.assert_refused("the backup is not verified: snapshot 'x' is 'creating'", "--apply", "--page-id",
                                    str(self.about.pk), "--confirm", token, "--replace-existing-content", "--backup-snapshot", "x")
            verified = {"snapshot": "pre-about", "source": "ecp-prod", "status": "available", "created": "2026-10-12T08:00:00+00:00"}
            with mock.patch.object(command_module, "verify_rds_snapshot", return_value=verified):
                self.apply(token, "--backup-snapshot", "pre-about")
        entry = PageLogEntry.objects.filter(page=self.about, action="wagtail.edit").latest("pk")
        self.assertEqual((entry.data["backup_snapshot"], entry.data["backup_verification"]), ("pre-about", "rds-api"))

    def test_invalid_content_or_missing_page_is_refused(self):
        with mock.patch.object(command_module, "load_about_content", side_effect=AboutContentError("about.json is missing")):
            self.assert_refused("Approved content is invalid, nothing was changed: about.json is missing")
        with mock.patch.object(command_module, "editor_rich_text", return_value=({}, ["intro_html: cannot load"])):
            self.assert_refused("Approved rich text is not editor-safe")
        with mock.patch.object(command_module, "schema_missing", return_value=["database table cms_testimonial (...)"]):
            self.assert_refused("the database schema is not ready")
        Page.objects.get(pk=self.about.pk).delete()
        self.assert_refused("No page exists at /about/", "--replace-existing-content")


class SnapshotVerificationTests(TestCase):
    NOW = datetime(2026, 10, 12, 12, 0, tzinfo=dt_timezone.utc)
    HOST = "ecp.abc123.eu-central-1.rds.amazonaws.com"

    def rds(self, snapshot=None, instances=None):
        client = mock.Mock()
        client.describe_db_snapshots.return_value = {"DBSnapshots": [snapshot] if snapshot else []}
        client.describe_db_cluster_snapshots.return_value = {"DBClusterSnapshots": []}
        paginator = mock.Mock()
        if instances is None:
            instances = [{"DBInstanceIdentifier": "ecp-prod", "Endpoint": {"Address": self.HOST}}]
        paginator.paginate.return_value = [{"DBInstances": instances}]
        client.get_paginator.return_value = paginator
        return client

    def snapshot(self, **overrides):
        return {"DBSnapshotIdentifier": "pre-about", "DBInstanceIdentifier": "ecp-prod", "Status": "available",
                "SnapshotCreateTime": self.NOW - timedelta(hours=2), **overrides}

    def verify(self, client, **kwargs):
        return verify_rds_snapshot("pre-about", self.HOST, timedelta(hours=24), client=client, now=self.NOW, **kwargs)

    def test_a_recent_available_snapshot_of_this_database_is_accepted(self):
        self.assertEqual(self.verify(self.rds(self.snapshot()))["source"], "ecp-prod")

    def test_unverifiable_snapshots_are_refused(self):
        cases = [
            (self.rds(None), "no RDS snapshot named"),
            (self.rds(self.snapshot(DBInstanceIdentifier="ecp-staging")), "is of 'ecp-staging', not of this database"),
            (self.rds(self.snapshot(Status="creating")), "is 'creating', not 'available'"),
            (self.rds(self.snapshot(SnapshotCreateTime=self.NOW - timedelta(days=3))), "more than 1 day"),
            (self.rds(self.snapshot(), instances=[]), "is not an RDS instance endpoint"),
        ]
        for client, message in cases:
            with self.subTest(message=message), self.assertRaisesMessage(BackupNotVerified, message):
                self.verify(client)
        broken = self.rds(self.snapshot())
        broken.describe_db_snapshots.side_effect = RuntimeError("AccessDenied")
        with self.assertRaisesMessage(BackupNotVerified, "the RDS API could not be queried"):
            self.verify(broken)

    def test_an_rds_proxy_host_needs_the_instance_identifier(self):
        client = self.rds(self.snapshot(), instances=[])
        self.assertEqual(self.verify(client, db_identifier="ecp-prod")["snapshot"], "pre-about")



class CleanCheckoutTests(ImportAboutPageTestCase):
    """The production image: about.json and the real loader, no images/ directory."""

    content = APPROVED

    def test_the_real_loader_needs_no_image_files_and_storage_decides(self):
        with self.assertRaisesMessage(AboutContentError, "Missing media file images/"):
            load_about_content()  # the local check used by populate_about_page still requires the files
        self.assertEqual(load_about_content(verify_files=False)["content_sha256"], APPROVED["content_sha256"])
        # Storage holds generated files, not the approved ones: every original is refused by its SHA-256.
        with self.assertRaises(CommandError) as refused:
            self.preview()
        self.assertEqual(str(refused.exception).count("SHA-256 mismatch"), 40)
        self.assertNotIn("Missing media file", str(refused.exception))


@skipUnless(REAL_FILES_PRESENT, "the approved image files are not in this checkout")
class RealOriginalsTests(ImportAboutPageTestCase):
    """The approved originals in storage (as in S3); the package's images/ directory unavailable."""

    content = APPROVED
    originals = ({m["file"]: (IMAGES_DIR / m["file"]).read_bytes() for m in first_per_file(APPROVED).values()}
                 if REAL_FILES_PRESENT else {})

    def test_preview_and_apply_verify_the_40_approved_originals_from_storage(self):
        output = self.preview()
        self.assertIn("40 distinct files, all verified in storage by SHA-256: 0 existing Wagtail images reused, "
                      "40 image records to create for stored originals, 0 problems; 0 uploads", output)
        self.assertIn("Created 40 image records (no files uploaded) and 10 testimonials", self.apply(token_from(output)))
        hero = AboutPage.objects.get(pk=self.about.pk).hero_background_image
        data = self.originals["2024-12-Website-Banner-2025.jpg"]
        self.assertEqual((hero.file.name, hero.file_hash, hero.file_size, hero.width, hero.height),
                         ("original_images/2024-12-Website-Banner-2025.jpg", hashlib.sha1(data).hexdigest(), len(data), 1570, 450))
        self.assertIn("Already imported", run())


class PopulateAboutPageStillLocalTests(TestCase):
    def test_populate_about_page_still_verifies_the_local_files(self):
        empty = Path(self.enterContext(tempfile.TemporaryDirectory()))
        with mock.patch.object(content_module, "IMAGES_DIR", empty), override_settings(STORAGES=IN_MEMORY_STORAGES):
            with self.assertRaisesMessage(CommandError, "Approved content is invalid, nothing was changed: Missing media file images/"):
                call_command("populate_about_page", stdout=StringIO(), stderr=StringIO())
