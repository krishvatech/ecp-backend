"""Testimonials and Contact Us: content packages, public APIs, the enquiry endpoint and the batch import.

Storage is in-memory, seeded with generated originals (cms/batch3_testing.py) at
``original_images/<file>``; the importer must never write to it. E-mail uses Django's locmem backend.
"""

import copy
import json
import re
import tempfile
import time
from io import StringIO
from pathlib import Path
from unittest import mock

from django.core import mail
from django.core.cache import cache
from django.core.files.base import ContentFile
from django.core.files.storage import storages
from django.core.management import CommandError, call_command
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient
from wagtail.images import get_image_model
from wagtail.models import Page, Revision, Site

from cms import contact as contact_module
from cms import contact_page_content, testimonials_content
from cms.batch3_testing import CONTACT, TESTIMONIALS, generated_packages
from cms.management.commands import import_batch3_content as command_module
from cms.models import ContactPage, HomePage, Programme, StandardPage, Testimonial, TestimonialsPage
from cms.public_page_testing import IN_MEMORY_STORAGES

BY_PATH = "/api/cms/public/pages/by-path/"
TOKEN_RE = re.compile(r"Confirmation token: (batch3-[0-9a-f]{16})")
LOCMEM = {"EMAIL_BACKEND": "django.core.mail.backends.locmem.EmailBackend", "DEFAULT_FROM_EMAIL": "no-reply@imaa.test",
          # Never the developer's Redis: duplicate and rate-limit keys live in an isolated in-memory cache.
          "CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "cms-contact-tests"}}}


def run(*args):
    out = StringIO()
    call_command("import_batch3_content", *args, stdout=out, stderr=StringIO())
    return out.getvalue()


def token_from(output):
    return TOKEN_RE.search(output).group(1)


def make_home():
    root = Page.get_first_root_node()
    home = HomePage(title="IMAA Connect", slug="imaa-connect", live=True)
    root.add_child(instance=home)
    site = Site.objects.get(is_default_site=True)
    site.root_page = home
    site.save()
    return home


# ------------------------------------------------------------------ content packages --


class ContentPackageTests(TestCase):
    def test_the_packages_match_the_wordpress_inventory(self):
        items = TESTIMONIALS["testimonials"]
        self.assertEqual(len(items), 77)
        self.assertEqual(sum(1 for t in items if t["is_public"]), 60, "17 have no quote on WordPress and stay hidden")
        self.assertTrue(all(t["quote_html"].strip() for t in items if t["is_public"]))
        self.assertEqual([t["archive_position"] for t in sorted(items, key=lambda t: t["published_at"], reverse=True)][:3], [1, 2, 3])
        self.assertEqual(len(CONTACT["form"]["countries"]), 241)
        self.assertIn("privacy-policy", CONTACT["page"]["consent_html"])

    def test_edits_without_a_new_hash_and_quote_less_public_testimonials_are_rejected(self):
        data = json.loads(testimonials_content.CONTENT_FILE.read_text())
        data["testimonials"][0]["name"] = "Someone else"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "testimonials.json"
            target.write_text(json.dumps(data))
            with mock.patch.object(testimonials_content, "CONTENT_FILE", target):
                with self.assertRaisesMessage(testimonials_content.TestimonialsContentError, "content_sha256 does not match"):
                    testimonials_content.load_testimonials_content()
            hidden = next(t for t in data["testimonials"] if not t["is_public"])
            hidden["is_public"] = True
            data["content_sha256"] = testimonials_content.compute_content_hash(data)
            target.write_text(json.dumps(data))
            with mock.patch.object(testimonials_content, "CONTENT_FILE", target):
                with self.assertRaisesMessage(testimonials_content.TestimonialsContentError, "a public testimonial needs a quote"):
                    testimonials_content.load_testimonials_content()


# ------------------------------------------------------------------ public APIs --


@override_settings(STORAGES=IN_MEMORY_STORAGES)
class PublicApiTests(TestCase):
    def setUp(self):
        self.home = make_home()
        self.ima = Programme.objects.create(code="IM&A", slug="ima", sort_order=1)
        self.cpmi = Programme.objects.create(code="CPMI", slug="cpmi", sort_order=2)
        Programme.objects.create(code="SCDE", slug="scde", sort_order=6)
        from datetime import datetime, timezone as tz

        def testimonial(slug, year, programmes, **extra):
            t = Testimonial.objects.create(name=slug.title(), slug=slug, quote="<p>Great course.</p>",
                                           published_at=datetime(year, 1, 1, tzinfo=tz.utc), **extra)
            t.programmes.set(programmes)
            return t

        testimonial("older", 2020, [self.ima])
        testimonial("newer", 2024, [self.ima, self.cpmi])
        testimonial("hidden", 2025, [self.ima], is_public=False)
        Testimonial.objects.create(name="No quote", slug="no-quote", quote="")
        page = TestimonialsPage(title="Testimonials", slug="testimonials", hero_title="Testimonials", live=False)
        self.home.add_child(instance=page)
        page.save_revision().publish()
        contact = ContactPage(title="Contact Us", slug="contact-us", hero_title="Contact Us", live=False,
                              consent_text='<p>I agree. <a href="/privacy-policy">Privacy Policy</a></p>')
        self.home.add_child(instance=contact)
        contact.save_revision().publish()

    def test_testimonials_page_lists_public_testimonials_newest_first_with_used_filters(self):
        data = APIClient().get(BY_PATH, {"path": "/testimonials/"}).json()
        self.assertEqual(data["type"], "TestimonialsPage")
        self.assertEqual([t["slug"] for t in data["testimonials"]], ["newer", "older"])
        self.assertEqual(data["programmes"], [{"code": "IM&A", "slug": "ima"}, {"code": "CPMI", "slug": "cpmi"}])
        self.assertEqual(data["testimonials"][0]["programmes"], ["ima", "cpmi"])
        self.assertIn("Great course", data["testimonials"][0]["quote_html"])

    def test_contact_page_reports_the_form_unavailable_without_recipients(self):
        with override_settings(CONTACT_FORM_RECIPIENTS=[]):
            data = APIClient().get(BY_PATH, {"path": "/contact-us/"}).json()
        self.assertEqual(data["type"], "ContactPage")
        self.assertFalse(data["form"]["enabled"])
        self.assertEqual(len(data["form"]["countries"]), 241)
        self.assertIn('href="/privacy-policy"', data["consent_html"])
        with override_settings(CONTACT_FORM_RECIPIENTS=["info@imaa.test"]):
            self.assertTrue(APIClient().get(BY_PATH, {"path": "/contact-us/"}).json()["form"]["enabled"])


# ------------------------------------------------------------------ contact endpoint --


@override_settings(CONTACT_FORM_RECIPIENTS=["info@imaa.test"], CONTACT_FORM_RATE="100/hour", **LOCMEM)
class ContactSubmissionTests(TestCase):
    URL = "/api/cms/public/contact/"

    def setUp(self):
        cache.clear()

    def form(self, **overrides):
        data = {"first_name": "Ada", "last_name": "Lovelace", "email": "ada@example.com", "phone": "+41 43 505 17 99",
                "country": "Switzerland", "message": "I would like to know more about CPMI.", "consent": True,
                "website": "", "form_token": contact_module.new_form_token(now=time.time() - 30)}
        data.update(overrides)
        return data

    def post(self, **overrides):
        return APIClient().post(self.URL, self.form(**overrides), format="json")

    def test_a_valid_enquiry_is_emailed_once_as_plain_text(self):
        response = self.post(first_name="Ada\r\nBcc: x@evil.test")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual((message.to, message.reply_to, message.from_email), (["info@imaa.test"], ["ada@example.com"], "no-reply@imaa.test"))
        self.assertNotIn("\n", message.subject)
        self.assertIn("Country: Switzerland", message.body)
        self.assertIn("I would like to know more about CPMI.", message.body)
        self.assertEqual(self.post().json(), {"status": "sent", "duplicate": True})
        self.assertEqual(len(mail.outbox), 1, "the same enquiry again is accepted once")

    def test_validation_and_consent(self):
        cases = [({"country": "Atlantis"}, "country"), ({"consent": False}, "consent"), ({"email": "not-an-email"}, "email"),
                 ({"message": "   "}, "message"), ({"phone": "<script>"}, "phone"), ({"message": "x" * 2001}, "message")]
        for overrides, field in cases:
            with self.subTest(field=field):
                response = self.post(**overrides)
                self.assertEqual(response.status_code, 400)
                self.assertIn(field, json.dumps(response.json()))
        self.assertEqual(len(mail.outbox), 0)

    def test_spam_protection(self):
        self.assertEqual(self.post(website="http://spam.test").json(), {"status": "sent"})
        self.assertEqual(self.post(form_token=contact_module.new_form_token()).json()["code"], "too_fast")
        self.assertEqual(self.post(form_token=contact_module.new_form_token(now=time.time() - 7 * 3600)).json()["code"], "form_expired")
        self.assertEqual(self.post(form_token="forged").json()["code"], "form_invalid")
        self.assertEqual(len(mail.outbox), 0, "nothing was sent")
        with override_settings(CONTACT_FORM_RATE="2/hour"):
            cache.clear()
            codes = [self.post(message=f"Message {i}").status_code for i in range(3)]
        self.assertEqual(codes, [200, 200, 429])

    def test_failures_are_reported_and_nothing_is_lost_silently(self):
        with override_settings(CONTACT_FORM_RECIPIENTS=[]):
            self.assertEqual(self.post().status_code, 503)
        with mock.patch("django.core.mail.EmailMessage.send", side_effect=OSError("SMTP down")):
            response = self.post()
        self.assertEqual((response.status_code, response.json()["code"]), (502, "delivery_failed"))
        self.assertEqual(self.post().status_code, 200, "a failed delivery does not count as a duplicate")
        self.assertEqual(len(mail.outbox), 1)


# ------------------------------------------------------------------ batch import --


class BatchImportTestCase(TestCase):
    def setUp(self):
        self.testimonials, self.contact, self.originals = generated_packages()
        self.enterContext(mock.patch.object(command_module, "load_testimonials_content", side_effect=lambda **kw: copy.deepcopy(self.testimonials)))
        self.enterContext(mock.patch.object(command_module, "load_contact_content", side_effect=lambda **kw: copy.deepcopy(self.contact)))
        self.enterContext(override_settings(STORAGES=IN_MEMORY_STORAGES))
        self.storage = storages["default"]
        for name, data in self.originals.items():
            self.storage.save(f"original_images/{name}", ContentFile(data))
        self.writes_allowed = False
        storage_class = type(self.storage)
        original_save = storage_class._save

        def guarded(storage, *args, **kwargs):
            if not self.writes_allowed:
                raise AssertionError(f"storage write {args[:1]}")
            return original_save(storage, *args, **kwargs)

        self.enterContext(mock.patch.object(storage_class, "_save", guarded))
        self.home = make_home()
        self.privacy = StandardPage(title="Privacy Policy", slug="privacy-policy", body="<p>x</p>", live=False)
        self.home.add_child(instance=self.privacy)
        self.privacy.save_revision().publish()
        # A testimonial the About import created (no programmes, no date yet).
        first = next(t for t in self.testimonials["testimonials"] if t["wordpress_id"] == 157372)
        self.about_made = Testimonial.objects.create(name=first["name"], slug=first["slug"], quote="<p>Edited in Wagtail</p>",
                                                     wordpress_id=first["wordpress_id"])

    def counts(self):
        return (Page.objects.count(), Revision.objects.count(), Testimonial.objects.count(), Programme.objects.count(),
                get_image_model().objects.count())

    def apply(self, *extra, token=None):
        token = token or token_from(run(*extra))
        return run("--apply", "--confirm", token, *extra)


class BatchImportTests(BatchImportTestCase):
    def test_preview_is_read_only(self):
        before = self.counts()
        with CaptureQueriesContext(connection) as queries:
            output = run("--publish")
        self.assertEqual(self.counts(), before)
        self.assertTrue(all(q["sql"].lstrip().upper().startswith("SELECT") for q in queries.captured_queries))
        self.assertIn("Page /testimonials/: none -> a TestimonialsPage will be created and published", output)
        self.assertIn("Page /contact-us/: none -> a ContactPage will be created and published", output)
        self.assertIn("Testimonials: 76 to create (59 public, 17 hidden: no quote on WordPress), 1 existing to complete", output)
        self.assertIn("0 uploads", output)

    def test_apply_imports_reuses_existing_testimonials_and_is_idempotent(self):
        privacy_revision = StandardPage.objects.get(pk=self.privacy.pk).live_revision_id
        output = self.apply("--publish")
        self.assertIn("76 testimonials; filled 1 existing testimonials", output)
        self.assertEqual(Testimonial.objects.count(), 77)
        self.about_made.refresh_from_db()
        self.assertEqual(self.about_made.quote, "<p>Edited in Wagtail</p>", "existing text is never overwritten")
        self.assertTrue(self.about_made.programmes.exists())
        self.assertIsNotNone(self.about_made.published_at)
        self.assertTrue(TestimonialsPage.objects.get().live)
        contact = ContactPage.objects.get()
        self.assertTrue(contact.live)
        self.assertEqual([b.block_type for b in contact.sections], ["card_group", "logo_strip", "offices"])
        self.assertEqual(len(contact.stats), 3)
        self.assertEqual(StandardPage.objects.get(pk=self.privacy.pk).live_revision_id, privacy_revision)
        before = self.counts()
        self.assertIn("Already imported", run("--publish"))
        self.assertEqual(self.counts(), before)

        self.writes_allowed = True  # renditions are new objects (the importer itself never writes)
        rendered = run("--prepare-renditions")
        self.assertIn("0 failed", rendered)
        data = APIClient().get(BY_PATH, {"path": "/testimonials/"}).json()
        self.assertEqual(len(data["testimonials"]), 60)
        # Every imported testimonial has its photo; the pre-existing record keeps its own (none here).
        self.assertTrue(all(t["photo"] for t in data["testimonials"] if t["slug"] != self.about_made.slug))
        self.assertIn("FM&BV", [p["code"] for p in data["programmes"]])

    def test_missing_originals_conflicts_and_stale_tokens_are_refused(self):
        token = token_from(run("--publish"))
        Testimonial.objects.create(name="New meanwhile", slug="new-meanwhile", quote="<p>x</p>")
        with self.assertRaisesMessage(CommandError, "the confirmation token does not match"):
            run("--apply", "--confirm", token, "--publish")
        Testimonial.objects.filter(slug="new-meanwhile").delete()
        missing = next(m["file"] for m in self.testimonials["media"] if m["key"].startswith("testimonials/") and not m.get("shared_with"))
        with mock.patch.object(type(self.storage), "exists", side_effect=lambda n: n != f"original_images/{missing}"):
            with self.assertRaisesMessage(CommandError, f"no object at 'original_images/{missing}'"):
                run("--publish")
        Testimonial.objects.create(name="Clash", slug="aniruddha-sulake-2", quote="<p>x</p>", wordpress_id=999999)
        clash = next(t for t in self.testimonials["testimonials"] if t["wordpress_id"] != 157372)
        Testimonial.objects.filter(slug="aniruddha-sulake-2").update(slug=clash["slug"])
        with self.assertRaisesMessage(CommandError, f"slug '{clash['slug']}' belongs to WordPress ID 999999"):
            run("--publish")

    def test_remote_databases_need_a_backup(self):
        remote = {**connection.settings_dict, "HOST": "ecp.abc.eu-central-1.rds.amazonaws.com"}
        with mock.patch.object(connection, "settings_dict", remote):
            with self.assertRaisesMessage(CommandError, "needs --backup-snapshot"):
                run("--apply", "--confirm", "batch3-0000000000000000", "--publish")
