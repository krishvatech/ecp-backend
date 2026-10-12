"""Our Team page: approved content package, public API serialisation and the local
``populate_team_page`` command.

Tests that need the Our Team schema (Programme, TeamMember, TeamPage; migration cms.0017) run
only when those models exist; the preview-stop test runs only while they do not.
"""

import json
import tempfile
import uuid
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock, skipIf, skipUnless

from django.apps import apps
from django.core.files.images import ImageFile
from django.core.management import CommandError, call_command
from django.db import connection
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from wagtail import blocks
from wagtail.images import get_image_model
from wagtail.models import Page, Site

from cms import team_page_content as content_module
from cms.about_blocks import LinkBlock, SECTION_BLOCKS
from cms.editor_checks import draftail_problem
from cms.models import AboutPage, HomePage
from cms.public_page_setup import editor_line_breaks
from cms.public_page_testing import IN_MEMORY_STORAGES
from cms.team_page_api import _member, team_page_extras
from cms.team_page_content import TeamContentError, compute_content_hash, load_team_content, rich_text_problems
from cms.team_page_testing import REAL_FILES_PRESENT, write_generated_package
from cms.management.commands import populate_team_page as populate_module


def _schema_pending():
    try:
        for name in ("Programme", "TeamMember", "TeamPage"):
            apps.get_model("cms", name)
    except LookupError:
        return True
    return False


SCHEMA_PENDING = _schema_pending()
S3_STORAGES = {
    "default": {"BACKEND": "storages.backends.s3boto3.S3Boto3Storage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


def run(*args):
    out = StringIO()
    call_command("populate_team_page", *args, stdout=out, stderr=StringIO())
    return out.getvalue()


def rewritten(mutate):
    """A temporary copy of team.json changed by ``mutate`` (hash updated), for loader tests."""
    data = json.loads(content_module.CONTENT_FILE.read_text())
    mutate(data)
    data["content_sha256"] = compute_content_hash(data)
    tmp = tempfile.TemporaryDirectory()
    target = Path(tmp.name) / "team.json"
    target.write_text(json.dumps(data))
    return tmp, target


# ------------------------------------------------------------------ content package --


class TeamContentTests(SimpleTestCase):
    def test_the_package_matches_the_wordpress_inventory(self):
        data = load_team_content(verify_files=False)  # the files themselves: TeamRealMediaTests
        faculty = [m for m in data["members"] if m["member_type"] == "faculty"]
        staff = [m for m in data["members"] if m["member_type"] == "staff"]
        self.assertEqual((len(faculty), len(staff)), (63, 24))
        self.assertEqual([p["code"] for p in data["programmes"]], ["IM&A", "CPMI", "M&AP", "LM&A", "HRM&A", "SCDE", "VALUATION"])
        counts = {p["code"]: sum(p["code"] in m["programmes"] for m in faculty) for p in data["programmes"]}
        self.assertEqual(counts, {"IM&A": 50, "CPMI": 6, "M&AP": 3, "LM&A": 19, "HRM&A": 14, "SCDE": 4, "VALUATION": 1})
        self.assertEqual([m["name"] for m in faculty[:4]],
                         ["Prof. Dr. Christopher Kummer", "Prof. Dr. Aswath Damodaran", "David Olsson", "Tom Allen"])
        self.assertTrue(all(m["profile_url"].startswith("https://imaa-institute.org/team/") for m in faculty))
        self.assertTrue(all(m["location"] for m in staff))
        self.assertEqual(sum(bool(m["biography_html"]) for m in faculty), 61)
        self.assertEqual(len(data["media"]), 98)
        self.assertEqual([s["type"] for s in data["page"]["sections"]], ["card_group", "offices"])

    def test_people_in_both_sections_are_separate_records(self):
        data = load_team_content(verify_files=False)
        both = {m["name"] for m in data["members"] if m["member_type"] == "staff"} & \
               {m["name"] for m in data["members"] if m["member_type"] == "faculty"}
        self.assertEqual(both, {"Prof. Dr. Christopher Kummer", "David Olsson"})
        slugs = [m["slug"] for m in data["members"]]
        self.assertEqual(len(slugs), len(set(slugs)))

    def test_the_package_is_outside_any_git_ignored_media_directory(self):
        self.assertNotIn("media", content_module.IMAGES_DIR.relative_to(content_module.CONTENT_DIR.parent.parent).parts)

    def test_an_edited_file_without_a_new_hash_is_rejected(self):
        data = json.loads(content_module.CONTENT_FILE.read_text())
        data["members"][0]["name"] = "Someone else"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "team.json"
            target.write_text(json.dumps(data))
            with mock.patch.object(content_module, "CONTENT_FILE", target):
                with self.assertRaisesMessage(TeamContentError, "content_sha256 does not match"):
                    load_team_content(verify_files=False)

    def test_a_changed_or_missing_photo_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            content_file, images, content, _originals = write_generated_package(Path(tmp))
            with mock.patch.object(content_module, "CONTENT_FILE", content_file), \
                    mock.patch.object(content_module, "IMAGES_DIR", images):
                self.assertEqual(len(load_team_content()["media"]), 98, "every file matches its hash")
                first = content["media"][0]["file"]
                (images / first).write_bytes(b"not the original")
                with self.assertRaisesMessage(TeamContentError, "does not match its recorded sha256"):
                    load_team_content()
                (images / first).unlink()
                with self.assertRaisesMessage(TeamContentError, "Missing"):
                    load_team_content()
                self.assertEqual(load_team_content(verify_files=False)["content_sha256"], content["content_sha256"])

    def test_duplicates_unknown_programmes_and_unsafe_links_are_rejected(self):
        cases = [
            (lambda d: d["members"][1].update(wordpress_id=d["members"][0]["wordpress_id"]), "Duplicate member wordpress_ids"),
            (lambda d: d["members"][0].update(programmes=["MBA"]), "unknown programmes"),
            (lambda d: d["members"][0].update(linkedin_url="http://www.linkedin.com/in/x"), "LinkedIn URL must be https"),
            (lambda d: d["members"][0].update(profile_url="javascript:alert(1)"), "unsafe or empty link"),
            (lambda d: d["members"][0].update(member_type="alumni"), "unknown member_type"),
        ]
        for mutate, message in cases:
            with self.subTest(message=message):
                tmp, target = rewritten(mutate)
                with tmp, mock.patch.object(content_module, "CONTENT_FILE", target):
                    with self.assertRaisesMessage(TeamContentError, message):
                        load_team_content(verify_files=False)
        self.assertEqual(rich_text_problems('<p style="x">a</p><img src="x">'), ["tag <img>", "attribute p[style]", "attribute img[src]"])

    def test_every_biography_loads_in_draftail(self):
        data = load_team_content(verify_files=False)
        for member in data["members"]:
            if member["biography_html"]:
                with self.subTest(member=member["slug"]):
                    self.assertIsNone(draftail_problem(editor_line_breaks(member["biography_html"]), ["bold", "italic", "link", "ol", "ul"]))


# ------------------------------------------------------------------ API serialisation --


@override_settings(STORAGES=IN_MEMORY_STORAGES)
class TeamSerialisationTests(TestCase):
    def setUp(self):
        self.request = RequestFactory().get("/api/cms/public/pages/by-path/", HTTP_HOST="cms.example.test")
        from io import BytesIO

        from cms.about_page_testing import generated_image

        self.image = get_image_model()(title="Photo")
        data = generated_image(400, 400, "photo.png")
        self.image.file.save("photo.png", ImageFile(BytesIO(data), name="photo.png"), save=False)
        self.image._set_image_file_metadata()
        self.image.save()

    def buttons(self, *pairs):
        return blocks.StreamBlock([("button", LinkBlock())]).to_python(
            [{"type": "button", "value": {"label": label, "url": url}, "id": str(uuid.uuid4())} for label, url in pairs]
        )

    def test_page_texts_buttons_and_sections_are_serialised_safely(self):
        page = SimpleNamespace(
            hero_title="Our Team", hero_intro="Meet our experts.",
            hero_button=self.buttons(("Contact our team", "https://imaa-institute.org/contact-us/")),
            faculty_heading="Experts & Faculty", faculty_subheading="Meet Our Faculty",
            faculty_intro='<p>Faculty <a href="https://example.com">x</a><script>bad</script></p>',
            faculty_buttons=self.buttons(("Schedule A Consultation", "https://imaa-institute.org/contact-us/"), ("Bad", "javascript:alert(1)")),
            staff_heading="Staff of IMAA", staff_subheading="Meet the team", staff_intro="<p>Our team</p>",
            staff_button=self.buttons(),
            sections=blocks.StreamBlock([d for d in SECTION_BLOCKS if d[0] != "testimonials"]).to_python([]),
        )
        data = team_page_extras(self.request, page)
        self.assertEqual(data["hero_button"], {"label": "Contact our team", "url": "https://imaa-institute.org/contact-us/"})
        self.assertEqual([b["label"] for b in data["faculty_buttons"]], ["Schedule A Consultation"], "the unsafe link is dropped")
        self.assertIn('rel="noopener noreferrer"', data["faculty_intro_html"])
        self.assertNotIn("<script", data["faculty_intro_html"])
        self.assertIsNone(data["staff_button"])
        if SCHEMA_PENDING:
            self.assertEqual((data["faculty"], data["staff"], data["programmes"]), ([], [], []))

    def test_other_pages_get_nothing(self):
        self.assertEqual(team_page_extras(self.request, AboutPage(title="About", slug="about")), {})

    def test_a_member_card_carries_no_biography_and_only_safe_links(self):
        programmes = SimpleNamespace(all=lambda: [SimpleNamespace(slug="ima"), SimpleNamespace(slug="cpmi")])
        member = SimpleNamespace(slug="david-olsson", name="David Olsson", position="Faculty", summary="Managing Director of IMAA",
                                 location="London", linkedin_url="http://www.linkedin.com/in/x", profile_url="javascript:x",
                                 programmes=programmes, photo=self.image, biography="<p>Long biography</p>")
        data = _member(self.request, member)
        self.assertEqual(data["programmes"], ["ima", "cpmi"])
        self.assertEqual((data["linkedin_url"], data["profile_url"]), ("", ""))
        self.assertNotIn("biography", data)
        self.assertEqual(data["photo"]["alt"], "David Olsson")
        self.assertTrue(data["photo"]["url"].startswith("http://cms.example.test/"))


# ------------------------------------------------------------------ command --


@override_settings(STORAGES=IN_MEMORY_STORAGES)
class PopulateTeamPageTests(TestCase):
    def setUp(self):
        # The local command imports the package's image files: use a generated package.
        content_file, images, _content, _originals = write_generated_package(Path(self.enterContext(tempfile.TemporaryDirectory())))
        self.enterContext(mock.patch.object(content_module, "CONTENT_FILE", content_file))
        self.enterContext(mock.patch.object(content_module, "IMAGES_DIR", images))
        self.enterContext(mock.patch.object(populate_module, "IMAGES_DIR", images))
        root = Page.get_first_root_node()
        self.home = HomePage(title="IMAA Connect", slug="imaa-connect", live=True)
        root.add_child(instance=self.home)
        site = Site.objects.get(is_default_site=True)
        site.root_page = self.home
        site.save()

    @skipIf(not SCHEMA_PENDING, "the schema change is applied")
    def test_preview_checks_everything_then_stops_until_the_schema_change(self):
        with CaptureQueriesContext(connection) as queries:
            output = run()
        for query in queries.captured_queries:
            self.assertTrue(query["sql"].lstrip().upper().startswith("SELECT"), query["sql"])
        self.assertIn("ok: local PostgreSQL database and local file storage", output)
        self.assertIn("63 faculty, 24 staff, 7 programmes, 98 media files verified", output)
        self.assertIn("rich-text values load in the Wagtail editor", output)
        self.assertIn("Preview stopped: The Our Team schema change is not applied", output)
        with self.assertRaisesMessage(CommandError, "Our Team schema change is not applied"):
            run("--apply")

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

    @skipIf(SCHEMA_PENDING, "needs the Our Team schema change (docs/team-page-schema.md)")
    def test_apply_creates_records_once_and_repeats_without_changes(self):
        TeamMember = apps.get_model("cms", "TeamMember")
        output = run("--apply", "--publish")
        self.assertIn("created 7 programmes and 87 people", output)
        self.assertEqual(TeamMember.objects.filter(member_type="faculty").count(), 63)
        self.assertEqual(TeamMember.objects.get(slug="david-olsson").programmes.count(), 3)
        kept = TeamMember.objects.get(slug="ajit-sane")
        kept.summary = "Edited by an editor"
        kept.save()
        self.assertIn("Already populated", run("--apply"))
        self.assertEqual(TeamMember.objects.get(slug="ajit-sane").summary, "Edited by an editor")
        self.assertEqual(TeamMember.objects.count(), 87)


# ------------------------------------------------------------------ public API and Wagtail admin --


@skipIf(SCHEMA_PENDING, "needs the Our Team schema change (docs/team-page-schema.md)")
@override_settings(STORAGES=IN_MEMORY_STORAGES)
class TeamPublicApiAndAdminTests(TestCase):
    """The real models end to end: what editors change in Wagtail and what the public API shows."""

    def setUp(self):
        from io import BytesIO

        from cms.about_page_testing import generated_image

        Programme, TeamMember, TeamPage = (apps.get_model("cms", name) for name in ("Programme", "TeamMember", "TeamPage"))
        self.TeamMember, self.TeamPage = TeamMember, TeamPage
        root = Page.get_first_root_node()
        self.home = HomePage(title="IMAA Connect", slug="imaa-connect", live=True)
        root.add_child(instance=self.home)
        site = Site.objects.get(is_default_site=True)
        site.root_page = self.home
        site.save()
        self.photo = get_image_model()(title="Photo")
        self.photo.file.save("photo.png", ImageFile(BytesIO(generated_image(400, 400, "photo.png")), name="photo.png"), save=False)
        self.photo._set_image_file_metadata()
        self.photo.save()
        self.ima = Programme.objects.create(code="IM&A", slug="ima", sort_order=1)
        self.cpmi = Programme.objects.create(code="CPMI", slug="cpmi", sort_order=2)
        Programme.objects.create(code="HRM&A", slug="hrma", sort_order=3)  # nobody public in it
        self.olsson = TeamMember.objects.create(
            name="David Olsson", slug="david-olsson", member_type="faculty", position="Faculty", summary="Managing Director",
            biography="<p>Private long biography</p>", photo=self.photo, linkedin_url="https://www.linkedin.com/in/x/",
            profile_url="https://imaa-institute.org/team/david-olsson/", sort_order=2, wordpress_id=81402)
        self.olsson.programmes.set([self.cpmi, self.ima])
        self.allen = TeamMember.objects.create(name="Tom Allen", slug="tom-allen", member_type="faculty", sort_order=1, wordpress_id=1)
        self.hidden = TeamMember.objects.create(name="Hidden Person", slug="hidden-person", member_type="faculty",
                                                is_public=False, sort_order=0, wordpress_id=2)
        self.hidden.programmes.set([Programme.objects.get(slug="hrma")])
        TeamMember.objects.create(name="Olsson (staff)", slug="david-olsson-staff", member_type="staff",
                                  position="Managing Director", location="London", sort_order=1, wordpress_id=115042)
        page = TeamPage(title="Our Team", slug="our-team", hero_title="Our Team", faculty_heading="Experts & Faculty",
                        staff_heading="Staff of IMAA", seo_title="Our Team of M&A Experts - IMAA", live=False)
        self.home.add_child(instance=page)
        page.save_revision().publish()
        self.page = TeamPage.objects.get(pk=page.pk)

    def api(self):
        from rest_framework.test import APIClient

        return APIClient().get("/api/cms/public/pages/by-path/", {"path": "/our-team/"})

    def test_the_public_api_serves_only_public_people_in_display_order(self):
        response = self.api()
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual((data["type"], data["hero_title"], data["seo_title"]), ("TeamPage", "Our Team", "Our Team of M&A Experts - IMAA"))
        self.assertEqual([m["slug"] for m in data["faculty"]], ["tom-allen", "david-olsson"], "sort_order, then name")
        self.assertEqual([m["slug"] for m in data["staff"]], ["david-olsson-staff"])
        self.assertEqual(data["programmes"], [{"code": "IM&A", "slug": "ima"}, {"code": "CPMI", "slug": "cpmi"}],
                         "only programmes with public faculty, in programme order")
        olsson = data["faculty"][1]
        self.assertEqual(olsson["programmes"], ["ima", "cpmi"])
        self.assertTrue(olsson["photo"]["url"].startswith("http"))
        self.assertEqual((olsson["photo"]["width"], olsson["photo"]["height"]), (400, 400))
        body = response.content.decode()
        self.assertNotIn("Hidden Person", body)
        self.assertNotIn("hrma", body)
        self.assertNotIn("Private long biography", body)

    def test_editor_changes_to_people_show_immediately_and_hiding_removes_them(self):
        self.olsson.sort_order = 0
        self.olsson.save()
        self.assertEqual([m["slug"] for m in self.api().json()["faculty"]], ["david-olsson", "tom-allen"])
        self.olsson.is_public = False
        self.olsson.save()
        data = self.api().json()
        self.assertEqual([m["slug"] for m in data["faculty"]], ["tom-allen"])
        self.assertEqual(data["programmes"], [], "no filters once nobody public is in them")

    def test_page_drafts_stay_private_until_published_and_unpublished_pages_are_gone(self):
        draft = self.TeamPage.objects.get(pk=self.page.pk)
        draft.hero_title = "Draft title"
        revision = draft.save_revision()
        self.assertEqual(self.api().json()["hero_title"], "Our Team")
        revision.publish()
        self.assertEqual(self.api().json()["hero_title"], "Draft title")
        self.TeamPage.objects.get(pk=self.page.pk).unpublish()
        self.assertEqual(self.api().status_code, 404)

    def test_one_team_page_under_the_homepage(self):
        self.assertFalse(self.TeamPage.can_create_at(self.home), "max_count = 1")
        self.assertEqual(self.TeamPage.allowed_parent_page_models(), [HomePage])
        self.assertEqual(self.TeamPage.allowed_subpage_models(), [])

    def test_validation_and_unique_identifiers(self):
        from django.core.exceptions import ValidationError
        from django.db import IntegrityError, transaction

        member = self.TeamMember(name="X", slug="x", member_type="faculty", profile_url="javascript:alert(1)")
        with self.assertRaises(ValidationError) as invalid:
            member.full_clean()
        self.assertIn("profile_url", invalid.exception.message_dict)
        for field, value in (("slug", "david-olsson"), ("wordpress_id", 81402)):
            with self.subTest(field=field), self.assertRaises(IntegrityError), transaction.atomic():
                self.TeamMember.objects.create(**{"name": "Dup", "slug": "dup", "member_type": "staff", field: value})
        with self.assertRaises(IntegrityError), transaction.atomic():
            self.olsson.programmes.through.objects.create(teammember=self.olsson, programme=self.ima)

    def test_editors_can_open_the_wagtail_edit_views(self):
        from django.contrib.auth import get_user_model
        from django.urls import reverse

        from django.contrib.auth.models import Group

        from users.middleware import PLATFORM_ADMIN_GROUP

        admin = get_user_model().objects.create_superuser("team-admin", "team-admin@example.test", "x")
        admin.groups.add(Group.objects.get_or_create(name=PLATFORM_ADMIN_GROUP)[0])  # /cms/ is platform_admin only
        self.client.force_login(admin)
        for url in (
            reverse("wagtailsnippets_cms_teammember:list"),
            reverse("wagtailsnippets_cms_teammember:add"),
            reverse("wagtailsnippets_cms_teammember:edit", args=[self.olsson.pk]),
            reverse("wagtailsnippets_cms_programme:edit", args=[self.ima.pk]),
            reverse("wagtailadmin_pages:edit", args=[self.page.pk]),
        ):
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
        edit = self.client.get(reverse("wagtailsnippets_cms_teammember:edit", args=[self.olsson.pk])).content.decode()
        self.assertIn('name="programmes"', edit)
        self.assertNotIn('name="wordpress_id"', edit, "the WordPress ID is not editable")



# ------------------------------------------------------------------ approved files (optional) --


@skipUnless(REAL_FILES_PRESENT, "the approved image files are not in this checkout (they are verified in storage)")
class TeamRealMediaTests(SimpleTestCase):
    def test_the_approved_files_match_their_hashes_and_dimensions(self):
        from PIL import Image as PILImage

        data = load_team_content()  # every file present and matching its SHA-256
        for item in data["media"]:
            with self.subTest(file=item["file"]), PILImage.open(content_module.IMAGES_DIR / item["file"]) as image:
                self.assertEqual(image.size, (item["width"], item["height"]))
