"""About page: approved content package, section blocks, public API serialisation and the local
``populate_about_page`` command.

The AboutPage schema change (intro_image, stats, sections, Testimonial) is pending approval, so
tests that need it are skipped until it is applied (see docs/about-page-schema.md).
"""

import json
import shutil
import tempfile
import uuid
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock, skipIf

from django.core.exceptions import ValidationError
from django.core.files.images import ImageFile
from django.core.management import CommandError, call_command
from django.db import connection
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from wagtail import blocks
from wagtail.images import get_image_model
from wagtail.models import Page, PageLogEntry, Revision, Site

from cms import about_page_content as content_module
from cms.about_blocks import SECTION_BLOCKS, STAT_BLOCKS, LinkBlock, tel_href, validate_safe_url
from cms.about_page_api import _testimonials, about_page_extras, serialise_sections, serialise_stats
from cms.about_page_content import AboutContentError, compute_content_hash, load_about_content, rich_text_problems
from cms.api import build_cms_page_data
from cms.management.commands.populate_about_page import draftail_problem
from cms.models import AboutPage, HomePage, StandardPage
from cms.public_page_setup import editor_line_breaks
from cms.public_page_testing import IN_MEMORY_STORAGES

# The model side of the schema (no database access at import time; the test database is
# migrated by the test runner, so model and tables agree there).
SCHEMA_PENDING = not {"intro_image", "stats", "sections"} <= {f.name for f in AboutPage._meta.get_fields()}
S3_STORAGES = {
    "default": {"BACKEND": "storages.backends.s3boto3.S3Boto3Storage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


def run(*args):
    out = StringIO()
    call_command("populate_about_page", *args, stdout=out, stderr=StringIO())
    return out.getvalue()


# ------------------------------------------------------------------ content package --


class AboutContentTests(SimpleTestCase):
    def test_the_package_is_complete_and_matches_its_hashes(self):
        data = load_about_content()
        self.assertEqual(data["hero_title"], "Setting and Advancing the Standards of M&A Globally")
        self.assertEqual(data["stats"], [
            {"value": "100+", "label": "Number of countries"},
            {"value": "4100+", "label": "Number of participants"},
            {"value": "2000+", "label": "Number of companies"},
        ])
        self.assertEqual([f["title"] for f in data["features"]],
                         ["Research", "Integrator", "Resources", "International Forum", "Education", "Collaboration"])
        types = [s["type"] for s in data["sections"]]
        self.assertEqual(types, ["accordion", "cta_band", "card_group", "card_group", "testimonials",
                                 "contact_callout", "logo_strip", "offices"])
        by_type = {}
        for s in data["sections"]:
            by_type.setdefault(s["type"], []).append(s)
        self.assertEqual(len(by_type["accordion"][0]["items"]), 16)
        self.assertEqual([len(s["cards"]) for s in by_type["card_group"]], [4, 7])
        self.assertEqual(len(by_type["testimonials"][0]["items"]), 10)
        self.assertEqual(len(by_type["logo_strip"][0]["logos"]), 12)
        self.assertEqual([o["city"] for o in by_type["offices"][0]["offices"]],
                         ["NEW YORK", "ZURICH", "VIENNA", "LONDON", "SINGAPORE", "MANILA"])
        self.assertEqual(len(data["media"]), 41)

    def test_the_package_is_outside_any_git_ignored_media_directory(self):
        self.assertNotIn("media", content_module.IMAGES_DIR.relative_to(content_module.CONTENT_DIR.parent.parent).parts)

    def test_an_edited_file_without_a_new_hash_is_rejected(self):
        data = json.loads(content_module.CONTENT_FILE.read_text())
        data["stats"][0]["value"] = "200+"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "about.json"
            target.write_text(json.dumps(data))
            with mock.patch.object(content_module, "CONTENT_FILE", target):
                with self.assertRaisesMessage(AboutContentError, "content_sha256 does not match"):
                    load_about_content(verify_files=False)

    def test_a_changed_media_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            images = Path(tmp) / "images"
            shutil.copytree(content_module.IMAGES_DIR, images)
            first = json.loads(content_module.CONTENT_FILE.read_text())["media"][0]["file"]
            (images / first).write_bytes(b"not the original")
            with mock.patch.object(content_module, "IMAGES_DIR", images):
                with self.assertRaisesMessage(AboutContentError, "does not match its recorded sha256"):
                    load_about_content()

    def test_unsafe_links_and_markup_are_rejected(self):
        data = json.loads(content_module.CONTENT_FILE.read_text())
        data["sections"][1]["button"]["url"] = "javascript:alert(1)"
        data["content_sha256"] = compute_content_hash(data)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "about.json"
            target.write_text(json.dumps(data))
            with mock.patch.object(content_module, "CONTENT_FILE", target):
                with self.assertRaisesMessage(AboutContentError, "unsafe or empty link"):
                    load_about_content(verify_files=False)
        self.assertEqual(rich_text_problems('<p onclick="x">a</p><script>x</script><a href="javascript:x">y</a>'),
                         ["tag <script>", "attribute p[onclick]", "link 'javascript:x'"])

    def test_every_approved_rich_text_loads_in_draftail_once_line_breaks_are_editor_format(self):
        from cms.management.commands.populate_about_page import Command

        stored = Command(stdout=StringIO())._stored_rich_text(load_about_content(verify_files=False))
        self.assertTrue(stored)
        self.assertFalse(any("<br>" in value for value in stored.values()))
        # The same text with a plain <br> inside bold is what breaks the editor.
        self.assertIn("cannot load", draftail_problem("<p><b>Title<br></b>Text</p>"))
        self.assertIsNone(draftail_problem(editor_line_breaks("<p><b>Title<br></b>Text</p>")))


# ------------------------------------------------------------------ blocks --


class AboutBlockTests(SimpleTestCase):
    def test_links_accept_only_safe_destinations(self):
        for good in ("https://imaa-institute.org/x/", "/references", "mailto:info@imaa.org", "tel:+41435051799"):
            validate_safe_url(good)
        for bad in ("javascript:alert(1)", "//evil.example", "ftp://x", "data:text/html,x", "references"):
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                validate_safe_url(bad)

    def test_a_button_needs_both_label_and_link(self):
        block = LinkBlock()
        block.clean(block.to_python({"label": "", "url": ""}))
        block.clean(block.to_python({"label": "Book", "url": "/m-and-a-trainings"}))
        with self.assertRaises(blocks.StructBlockValidationError):
            block.clean(block.to_python({"label": "Book", "url": ""}))

    def test_phone_numbers_become_tel_links(self):
        self.assertEqual(tel_href("+41 43 505 17 99"), "tel:+41435051799")
        self.assertEqual(tel_href("+63 2 3224 2088"), "tel:+63232242088")
        self.assertEqual(tel_href("call us"), "")


# ------------------------------------------------------------------ API serialisation --


@override_settings(STORAGES=IN_MEMORY_STORAGES)
class AboutSerialisationTests(TestCase):
    def setUp(self):
        self.request = RequestFactory().get("/api/cms/public/pages/by-path/", HTTP_HOST="cms.example.test")
        path = content_module.IMAGES_DIR / "2024-07-USA.webp"
        self.image = get_image_model()(title="USA")
        with open(path, "rb") as fh:
            self.image.file.save(path.name, ImageFile(fh, name=path.name), save=False)
        self.image._set_image_file_metadata()
        self.image.save()

    def stream(self, raw, definitions=SECTION_BLOCKS):
        return blocks.StreamBlock([d for d in definitions if d[0] != "testimonials"]).to_python(raw)

    def test_sections_are_serialised_sanitised_and_empty_blocks_left_out(self):
        # ListBlock items need an "id" to be read as items (the command stores them that way).
        item = lambda value: {"type": "item", "value": value, "id": str(uuid.uuid4())}  # noqa: E731
        stream = self.stream([
            {"type": "accordion", "value": {"heading": "Accreditation", "image": self.image.pk, "items": [
                item({"title": "ACCA", "body": '<p>See <a href="https://www.accaglobal.com/">ACCA</a><script>x</script></p>', "logo": None}),
            ]}},
            {"type": "accordion", "value": {"heading": "Empty", "image": None, "items": []}},
            {"type": "cta_band", "value": {"text": "<p>ISO</p>", "logos": [item({"image": self.image.pk, "name": "Amazon"})],
                                           "button": {"label": "Book a Training", "url": "/m-and-a-trainings"}}},
            {"type": "card_group", "value": {"heading": "Programs", "layout": "carousel", "prompt": "", "button": {"label": "", "url": ""},
                                             "cards": [item({"image": self.image.pk, "icon": "", "title": "IM&A", "text": "x",
                                                             "link": {"label": "Learn", "url": "javascript:alert(1)"}})]}},
            {"type": "contact_callout", "value": {"heading": "Media", "text": "<p>Ask</p>", "email": "info@imaa.org", "button_label": "Email us"}},
            {"type": "offices", "value": {"heading": "Contact", "email": "info@imaa-institute.org", "offices": [
                item({"city": "ZURICH", "country": "Switzerland", "phone": "+41 43 505 17 99", "image": self.image.pk}),
            ]}},
        ])
        out = serialise_sections(self.request, stream)
        self.assertEqual([s["type"] for s in out], ["accordion", "cta_band", "card_group", "contact_callout", "offices"])
        accordion = out[0]
        self.assertIn('<a href="https://www.accaglobal.com/" rel="noopener noreferrer">ACCA</a>', accordion["items"][0]["body_html"])
        self.assertNotIn("<script", accordion["items"][0]["body_html"])
        self.assertTrue(accordion["image"]["url"].startswith("http://cms.example.test/"))
        self.assertEqual((accordion["image"]["width"], accordion["image"]["height"]), (1080, 314))  # fill-1600x464 crop, never upscaled
        self.assertEqual(out[1]["logos"][0]["alt"], "Amazon")
        self.assertEqual(out[1]["button"], {"label": "Book a Training", "url": "/m-and-a-trainings"})
        self.assertIsNone(out[2]["cards"][0]["link"], "an unsafe link stored before validation is never served")
        self.assertIsNone(out[2]["button"])
        self.assertEqual(out[4]["offices"][0]["phone_href"], "tel:+41435051799")

    def test_statistics_keep_their_displayed_values(self):
        stream = blocks.StreamBlock(STAT_BLOCKS).to_python([
            {"type": "stat", "value": {"value": "100+", "label": "Number of countries"}},
            {"type": "stat", "value": {"value": "", "label": "incomplete"}},
        ])
        self.assertEqual(serialise_stats(stream), [{"value": "100+", "label": "Number of countries"}])

    def test_testimonials_are_read_from_their_snippets(self):
        person = SimpleNamespace(name="Chuck Adams", role="Managing Partner", company="Coeptis Consulting Group",
                                 programme="IM&A, M&AP", quote="<p>Impressed<br/>by the rigor</p>", photo=self.image,
                                 url="https://imaa-institute.org/testimonials/chuck-adams/")
        out = _testimonials(self.request, {"heading": "Participant Testimonials", "testimonials": [person, None],
                                           "button": {"label": "See All Testimonials", "url": "https://imaa-institute.org/testimonials/"}})
        self.assertEqual(len(out["items"]), 1)
        item = out["items"][0]
        self.assertEqual((item["name"], item["programme"]), ("Chuck Adams", "IM&A, M&AP"))
        self.assertEqual(item["quote_html"], "<p>Impressed<br>by the rigor</p>")
        self.assertEqual(item["photo"]["alt"], "Chuck Adams")
        self.assertEqual((item["photo"]["width"], item["photo"]["height"]), (240, 240))

    @skipIf(not SCHEMA_PENDING, "the schema change is applied")
    def test_until_the_schema_change_the_api_response_is_unchanged(self):
        page = AboutPage(title="About Us", slug="about")
        self.assertEqual(about_page_extras(self.request, page), {})
        data = build_cms_page_data(self.request, page, page)
        self.assertNotIn("sections", data)
        self.assertNotIn("stats", data)


# ------------------------------------------------------------------ command --


@override_settings(STORAGES=IN_MEMORY_STORAGES)
class PopulateAboutPageTests(TestCase):
    def setUp(self):
        root = Page.get_first_root_node()
        self.home = HomePage(title="IMAA Connect", slug="imaa-connect", live=True)
        root.add_child(instance=self.home)
        site = Site.objects.get(is_default_site=True)
        site.root_page = self.home
        site.save()
        about = AboutPage(title="About Us", slug="about", live=False)
        self.home.add_child(instance=about)
        about.save_revision()
        about.save_revision().publish()  # published while empty, as in the local database
        self.about = AboutPage.objects.get(pk=about.pk)
        self.privacy = StandardPage(title="Privacy Policy", slug="privacy-policy", body="<p>x</p>", live=False)
        self.home.add_child(instance=self.privacy)
        self.privacy.save_revision().publish()

    def counts(self):
        return Page.objects.count(), Revision.objects.count(), PageLogEntry.objects.count(), get_image_model().objects.count()

    def test_preview_writes_nothing_and_shows_the_plan(self):
        before = self.counts()
        with CaptureQueriesContext(connection) as queries:
            output = run()
        self.assertEqual(self.counts(), before)
        for query in queries.captured_queries:
            self.assertTrue(query["sql"].lstrip().upper().startswith("SELECT"), query["sql"])
        self.assertIn("PREVIEW (no database changes)", output)
        self.assertIn("ok: local PostgreSQL database and local file storage", output)
        self.assertIn("rich-text values load in the Wagtail editor", output)
        self.assertIn(f"AboutPage #{self.about.pk} 'About Us' (live", output)
        self.assertIn("hero_title             empty  About IMAA Connect -> Setting and Advancing", output)
        self.assertIn("Media: 41 references, 40 distinct files: 0 already in the image library, 40 to import", output)
        self.assertIn("accordion        Accreditation & Recognition        16 items", output)
        self.assertIn("offices          Contact Us                         6 offices", output)

    @skipIf(not SCHEMA_PENDING, "the schema change is applied")
    def test_apply_is_refused_until_the_schema_change(self):
        output = run()
        self.assertIn("--apply is refused until the schema change is applied", output)
        before = self.counts()
        with self.assertRaisesMessage(CommandError, "the AboutPage schema change is not applied"):
            run("--apply")
        self.assertEqual(self.counts(), before)

    def test_remote_storage_is_refused_before_anything_is_read(self):
        with override_settings(STORAGES=S3_STORAGES):
            with CaptureQueriesContext(connection) as queries:
                with self.assertRaisesMessage(CommandError, "AWS_BUCKET_NAME="):
                    run()
            self.assertEqual(queries.captured_queries, [])

    def test_a_remote_database_is_refused(self):
        remote = {**connection.settings_dict, "HOST": "ecp.abc123.eu-central-1.rds.amazonaws.com"}
        with mock.patch.object(connection, "settings_dict", remote):
            with self.assertRaisesMessage(CommandError, "not this machine"):
                run("--apply")

    def test_unpublished_editor_changes_and_editor_content_are_reported(self):
        draft = AboutPage.objects.get(pk=self.about.pk)
        draft.intro_html = "<p>Written by an editor</p>"
        draft.save_revision()
        before = self.counts()
        with self.assertRaisesMessage(CommandError, "the page has unpublished changes in Wagtail; they are never overwritten"):
            run()
        draft.save_revision().publish()
        with self.assertRaisesMessage(CommandError, "these fields already hold other content and are never overwritten: intro_html"):
            run("--apply")
        self.assertEqual(self.counts()[3], before[3], "no images were imported")

    def test_a_page_that_is_not_an_about_page_is_refused(self):
        Page.objects.get(pk=self.about.pk).delete()
        with self.assertRaisesMessage(CommandError, "No page exists at /about/"):
            run()

    @skipIf(SCHEMA_PENDING, "needs the AboutPage schema change (docs/about-page-schema.md)")
    def test_apply_populates_publishes_and_repeats_without_changes(self):
        output = run("--apply")
        self.assertIn("Imported 40 images and 10 testimonials", output)
        page = AboutPage.objects.get(pk=self.about.pk)
        self.assertTrue(page.live)
        self.assertFalse(page.has_unpublished_changes)
        self.assertEqual(page.title, "About Us")
        self.assertEqual(page.hero_title, "Setting and Advancing the Standards of M&A Globally")
        self.assertEqual(len(page.stats), 3)
        self.assertEqual(len(page.sections), 8)
        self.assertEqual(page.revisions.count(), 3)
        before = self.counts()
        self.assertIn("Already populated with the approved content; nothing changed.", run("--apply"))
        self.assertEqual(self.counts(), before)
