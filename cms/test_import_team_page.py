"""``import_team_page`` (production import from storage-verified originals) and ``team_media_transfer``.

Storage is an in-memory storage seeded with originals at ``original_images/<file>``, standing in
for the S3 bucket; the importer must never write to it. The image binaries are not in Git, so the
tests use generated originals (cms/team_page_testing.py) and the package's images/ directory is
unavailable to the importer; ``RealTeamOriginalsTests`` uses the approved files when present.
"""

import copy
import hashlib
import re
import tempfile
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
from wagtail.images import get_image_model
from wagtail.models import Page, PageLogEntry, Revision, Site

from cms import team_page_content as content_module
from cms.management.commands import import_team_page as command_module
from cms.management.commands import team_media_transfer as transfer_module
from cms.models import HomePage, Programme, StandardPage, TeamMember, TeamPage
from cms.public_page_testing import IN_MEMORY_STORAGES
from cms.team_page_content import IMAGES_DIR, load_team_content
from cms.team_page_testing import APPROVED, REAL_FILES_PRESENT, generated_originals, write_generated_package

CONTENT, ORIGINALS = generated_originals()
TOKEN_RE = re.compile(r"Confirmation token: (team-(?:new|\d+)-[0-9a-f]{16})")
BY_PATH = "/api/cms/public/pages/by-path/"
PROGRAMME_COUNTS = {"IM&A": 50, "CPMI": 6, "M&AP": 3, "LM&A": 19, "HRM&A": 14, "SCDE": 4, "VALUATION": 1}


def run(*args):
    out = StringIO()
    call_command("import_team_page", *args, stdout=out, stderr=StringIO())
    return out.getvalue()


def token_from(output):
    return TOKEN_RE.search(output).group(1)


class ImportTeamPageTestCase(TestCase):
    content, originals = CONTENT, ORIGINALS

    def setUp(self):
        self.enterContext(mock.patch.object(content_module, "IMAGES_DIR", Path(self.enterContext(tempfile.TemporaryDirectory()))))
        if self.content is not APPROVED:
            self.enterContext(mock.patch.object(command_module, "load_team_content",
                                                side_effect=lambda **kwargs: copy.deepcopy(self.content)))
        self.enterContext(override_settings(STORAGES=IN_MEMORY_STORAGES))
        self.storage = storages["default"]
        for name, data in self.originals.items():
            self.storage.save(f"original_images/{name}", ContentFile(data))
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
        self.privacy = StandardPage(title="Privacy Policy", slug="privacy-policy", body="<p>x</p>", live=False)
        self.home.add_child(instance=self.privacy)
        self.privacy.save_revision().publish()

    def counts(self):
        return (Page.objects.count(), Revision.objects.count(), PageLogEntry.objects.count(), get_image_model().objects.count(),
                Programme.objects.count(), TeamMember.objects.count())

    def apply(self, *extra, token=None):
        token = token or token_from(run(*extra))
        return run("--apply", "--confirm", token, *extra)

    def assert_refused(self, message, *args):
        before = self.counts()
        with self.assertRaisesMessage(CommandError, message):
            run(*args)
        self.assertEqual(self.counts(), before)

    def api(self):
        self.storage_writes_allowed = True  # renditions are written by the API, not by the importer
        return APIClient().get(BY_PATH, {"path": "/our-team/"})


class PreviewAndImportTests(ImportTeamPageTestCase):
    def test_preview_is_read_only_and_shows_the_plan(self):
        before = self.counts()
        with CaptureQueriesContext(connection) as queries:
            output = run("--publish")
        self.assertEqual(self.counts(), before)
        for query in queries.captured_queries:
            self.assertTrue(query["sql"].lstrip().upper().startswith("SELECT"), query["sql"])
        self.assertIn("PREVIEW (read-only, no changes)", output)
        self.assertIn("Page: none at /our-team/ -> a TeamPage 'Our Team' will be created and published", output)
        self.assertIn("Programmes: 7 to create, 0 existing kept unchanged", output)
        self.assertIn("People: 87 to create (63 faculty, 24 staff), 0 existing kept unchanged", output)
        self.assertIn("Images: 98 needed by this run, verified in storage by SHA-256: 0 existing Wagtail images reused, "
                      "98 image records to create, 0 problems; 0 uploads", output)
        self.assertIn("--apply --confirm team-new-", output)

    def test_apply_creates_the_page_people_and_image_records_from_storage(self):
        opened = []
        original_open = type(self.storage).open

        def counting_open(storage, name, mode="rb"):
            opened.append(name)
            return original_open(storage, name, mode)

        privacy_revision = StandardPage.objects.get(pk=self.privacy.pk).live_revision_id
        token = token_from(run("--publish"))
        with mock.patch.object(type(self.storage), "open", counting_open):
            output = self.apply("--publish", token=token)
        self.assertIn("Created 98 image records (no files uploaded), 7 programmes and 87 people; /our-team/ revision", output)
        self.assertEqual(len(opened), 98, "each original is downloaded once per run")
        page = TeamPage.objects.get()
        self.assertTrue(page.live)
        self.assertFalse(page.has_unpublished_changes)
        self.assertEqual((page.get_parent().pk, page.slug, page.title), (self.home.pk, "our-team", "Our Team"))
        self.assertEqual(page.seo_title, CONTENT["page"]["seo_title"])
        self.assertEqual(TeamMember.objects.filter(member_type="faculty").count(), 63)
        self.assertEqual(TeamMember.objects.filter(member_type="staff").count(), 24)
        self.assertEqual(sorted(TeamMember.objects.filter(name="David Olsson").values_list("slug", flat=True)),
                         ["david-olsson", "david-olsson-staff"])
        self.assertEqual({p.code: p.team_members.filter(member_type="faculty").count() for p in Programme.objects.all()},
                         PROGRAMME_COUNTS)
        for name, data in self.originals.items():
            image = get_image_model().objects.get(file=f"original_images/{name}")
            self.assertEqual((image.file_hash, image.file_size), (hashlib.sha1(data).hexdigest(), len(data)))
        entry = PageLogEntry.objects.filter(page=page, action="wagtail.edit").latest("pk")
        self.assertEqual((entry.data["source"], entry.data["backup"]), ("import_team_page", "local database"))
        self.assertEqual(StandardPage.objects.get(pk=self.privacy.pk).live_revision_id, privacy_revision, "other pages untouched")

        data = self.api().json()
        self.assertEqual((len(data["faculty"]), len(data["staff"])), (63, 24))
        self.assertEqual([p["code"] for p in data["programmes"]], list(PROGRAMME_COUNTS))
        for code, count in PROGRAMME_COUNTS.items():
            slug = next(p["slug"] for p in data["programmes"] if p["code"] == code)
            members = [m["slug"] for m in data["faculty"] if slug in m["programmes"]]
            self.assertEqual((len(members), len(set(members))), (count, count), code)
        self.assertTrue(all(m["photo"] and m["photo"]["url"] for m in data["faculty"] + data["staff"]))
        self.assertEqual([s["type"] for s in data["sections"]], ["card_group", "offices"])

    def test_without_publish_the_page_is_a_draft_until_published(self):
        self.apply()
        page = TeamPage.objects.get()
        self.assertFalse(page.live)
        self.assertEqual(self.api().status_code, 404, "a draft is not public")
        self.storage_writes_allowed = False
        self.assertIn("Already imported", run())  # nothing left to import as a draft
        output = self.apply("--publish")
        self.assertIn("published", output)
        self.assertTrue(TeamPage.objects.get().live)
        self.assertEqual(self.api().status_code, 200)

    def test_repeat_runs_change_nothing(self):
        token = token_from(run("--publish"))
        self.apply("--publish", token=token)
        before = self.counts()
        self.assertIn("Already imported", run("--publish"))
        self.assertIn("Already imported", run("--apply", "--confirm", token, "--publish"))
        self.assertEqual(self.counts(), before)

    def test_renditions_are_prepared_after_the_import_and_failures_are_reported(self):
        self.apply("--publish")
        self.assertIn("Renditions: 0 of 98 used by the page exist; run with --prepare-renditions to generate the other 98",
                      run("--publish"))
        self.storage_writes_allowed = True  # rendition files are new objects (the importer itself never writes)
        output = run("--prepare-renditions")
        self.assertIn("Renditions: 98 used by the page; 98 generated, 0 already existed, 0 failed", output)
        self.assertIn("Renditions: 98 of 98 used by the page exist", run("--publish"))
        self.assertIn("0 generated, 98 already existed", run("--prepare-renditions"), "idempotent")
        data = self.api().json()
        self.assertTrue(all(m["photo"] for m in data["faculty"] + data["staff"]))
        with mock.patch("wagtail.images.models.AbstractImage.get_rendition", side_effect=OSError("storage unavailable")):
            with self.assertRaisesMessage(CommandError, "Some renditions could not be generated"):
                run("--prepare-renditions")

    def test_renditions_need_the_page(self):
        with self.assertRaisesMessage(CommandError, "No TeamPage at /our-team/ yet: import the content first."):
            run("--prepare-renditions")

    def test_editor_changes_are_kept_and_only_missing_records_are_created(self):
        self.apply("--publish")
        page = TeamPage.objects.get().get_latest_revision_as_object()
        page.hero_intro = "Edited by an editor"
        page.save_revision().publish()
        edited = TeamMember.objects.get(slug="ajit-sane")
        edited.summary = "Edited summary"
        edited.save()
        TeamMember.objects.get(slug="tom-allen").delete()
        Programme.objects.get(slug="valuation").delete()
        images = get_image_model().objects.count()
        output = run("--publish")
        self.assertIn("hero_intro           kept (already set; never overwritten)", output)
        self.assertIn("Programmes: 1 to create, 6 existing kept unchanged", output)
        self.assertIn("People: 1 to create (1 faculty, 0 staff), 86 existing kept unchanged", output)
        self.assertIn("Images: 1 needed by this run", output)
        self.apply("--publish", token=token_from(output))
        self.assertEqual(TeamPage.objects.get().hero_intro, "Edited by an editor")
        self.assertEqual(TeamMember.objects.get(slug="ajit-sane").summary, "Edited summary")
        self.assertTrue(TeamMember.objects.filter(slug="tom-allen").exists())
        self.assertEqual(get_image_model().objects.count(), images, "Tom Allen's photo record is reused")
        self.assertEqual(TeamPage.objects.get().revisions.count(), 3, "earlier revisions are kept")

    def test_records_from_the_local_importer_are_recognised(self):
        programme = Programme.objects.create(code="IM&A", slug="ima", sort_order=1)
        TeamMember.objects.create(name="Ajit Sane", slug="ajit-sane", member_type="faculty", wordpress_id=next(
            m["wordpress_id"] for m in CONTENT["members"] if m["slug"] == "ajit-sane"))
        output = run("--publish")
        self.assertIn("Programmes: 6 to create, 1 existing kept unchanged", output)
        self.assertIn("People: 86 to create", output)
        self.apply("--publish")
        self.assertEqual(Programme.objects.get(slug="ima").pk, programme.pk)


class RefusalTests(ImportTeamPageTestCase):
    def test_identity_conflicts_are_refused(self):
        olsson = next(m for m in CONTENT["members"] if m["slug"] == "david-olsson")
        TeamMember.objects.create(name="Other", slug="david-olsson", member_type="faculty", wordpress_id=999999)
        self.assert_refused("slug 'david-olsson' belongs to WordPress ID 999999", "--publish")
        TeamMember.objects.filter(slug="david-olsson").delete()
        TeamMember.objects.create(name="A", slug="someone-else", member_type="faculty", wordpress_id=olsson["wordpress_id"])
        TeamMember.objects.create(name="B", slug="david-olsson", member_type="faculty")
        self.assert_refused("WordPress ID", "--publish")
        TeamMember.objects.all().delete()
        Programme.objects.create(code="CPMI", slug="post-merger", sort_order=1)
        self.assert_refused("programme code 'CPMI' is used by programme slug 'post-merger', not 'cpmi'", "--publish")

    def test_a_second_team_page_or_another_page_type_at_the_path_is_refused(self):
        elsewhere = TeamPage(title="Team", slug="team", live=False)
        self.home.add_child(instance=elsewhere)
        self.assert_refused(f"another TeamPage exists (#{elsewhere.pk}", "--publish")
        Page.objects.get(pk=elsewhere.pk).delete()
        other = StandardPage(title="Our Team", slug="our-team", body="<p>x</p>", live=False)
        self.home.add_child(instance=other)
        self.assert_refused(f"/our-team/ is StandardPage #{other.pk}, not a TeamPage", "--publish")

    def test_missing_corrupted_and_wrong_size_originals_are_refused(self):
        with mock.patch.object(type(self.storage), "exists", side_effect=lambda n: n != "original_images/2024-07-UK.webp"):
            self.assert_refused("2024-07-UK.webp: no object at 'original_images/2024-07-UK.webp'", "--publish")
        original_open = type(self.storage).open
        with mock.patch.object(type(self.storage), "open", lambda storage, name, mode="rb": (
                ContentFile(b"corrupted") if name.endswith("2024-07-PH.webp") else original_open(storage, name, mode))):
            self.assert_refused("2024-07-PH.webp: the object at 'original_images/2024-07-PH.webp' differs", "--publish")
        self.content = copy.deepcopy(CONTENT)
        next(m for m in self.content["media"] if m["file"] == "2024-07-USA.webp")["height"] = 999
        self.assert_refused("2024-07-USA.webp: 'original_images/2024-07-USA.webp' is 1080x1080, expected 1080x999", "--publish")

    def test_an_existing_image_record_is_verified_before_reuse(self):
        name = "2024-07-UK.webp"
        data = self.originals[name]
        item = next(m for m in CONTENT["media"] if m["file"] == name)
        existing = get_image_model()(title="UK", width=item["width"], height=item["height"], file_size=len(data),
                                     file_hash=hashlib.sha1(data).hexdigest())
        existing.file.name = "original_images/uk-missing.webp"
        existing.save()
        self.assert_refused(f"Wagtail image #{existing.pk} points at 'original_images/uk-missing.webp'", "--publish")

    def test_invalid_people_are_refused_before_any_write(self):
        self.content = copy.deepcopy(CONTENT)
        self.content["members"][0]["linkedin_url"] = "https://example.com/not-linkedin"
        self.assert_refused("linkedin_url: Enter an https:// address on linkedin.com.", "--publish")

    def test_tokens_backups_and_page_states(self):
        token = token_from(run("--publish"))
        self.assert_refused("--apply needs --confirm", "--apply")
        self.assert_refused("the confirmation token does not match", "--apply", "--confirm", "team-new-0000000000000000", "--publish")
        self.assert_refused("the confirmation token does not match", "--apply", "--confirm", token)  # options differ
        TeamMember.objects.create(name="New", slug="new-person", member_type="staff")
        self.assert_refused("the confirmation token does not match", "--apply", "--confirm", token, "--publish")
        TeamMember.objects.filter(slug="new-person").delete()
        remote = {**connection.settings_dict, "HOST": "ecp.abc.eu-central-1.rds.amazonaws.com"}
        with mock.patch.object(connection, "settings_dict", remote):
            self.assert_refused("needs --backup-snapshot", "--apply", "--confirm", token, "--publish")
            remote_token = token_from(run("--publish"))
            with mock.patch.object(command_module, "verify_rds_snapshot",
                                   side_effect=command_module.BackupNotVerified("snapshot 'x' is 'creating'")):
                self.assert_refused("the backup is not verified", "--apply", "--confirm", remote_token, "--publish", "--backup-snapshot", "x")
        self.apply("--publish")
        draft = TeamPage.objects.get().get_latest_revision_as_object()
        draft.hero_title = "Draft"
        draft.save_revision()
        self.assert_refused("the page has unpublished changes in Wagtail", "--publish")
        TeamPage.objects.update(locked=True)
        self.assert_refused("the page is locked in Wagtail", "--publish")

    def test_a_change_while_running_is_detected_under_the_lock(self):
        token = token_from(run("--publish"))

        def editor_adds_a_person(command, options):
            TeamMember.objects.create(name="Added meanwhile", slug="added-meanwhile", member_type="staff")
            return {"backup": "local database"}

        with mock.patch.object(command_module.Command, "_verify_backup", editor_adds_a_person):
            with self.assertRaisesMessage(CommandError, "The Team content changed while this command was running"):
                run("--apply", "--confirm", token, "--publish")
        self.assertFalse(TeamPage.objects.exists())
        self.assertEqual(TeamMember.objects.count(), 1)

    def test_a_failure_rolls_everything_back(self):
        token = token_from(run("--publish"))
        before = self.counts()
        with mock.patch("wagtail.models.Revision.publish", side_effect=RuntimeError("publish failed")):
            with self.assertRaisesMessage(RuntimeError, "publish failed"):
                run("--apply", "--confirm", token, "--publish")
        self.assertEqual(self.counts(), before)

    def test_wrong_site_root_is_refused(self):
        site = Site.objects.get(is_default_site=True)
        site.root_page = Page.get_first_root_node()
        site.save()
        self.assert_refused("not the IMAA Connect HomePage", "--publish")


class CleanCheckoutTests(ImportTeamPageTestCase):
    """The production image: team.json and the real loader, no images/ directory."""

    content = APPROVED

    def test_no_image_files_are_needed_and_storage_decides(self):
        with self.assertRaises(CommandError) as refused:
            run("--publish")
        self.assertEqual(str(refused.exception).count("SHA-256 mismatch"), 98, "generated objects are not the approved files")
        self.assertNotIn("Missing media file", str(refused.exception))


@skipUnless(REAL_FILES_PRESENT, "the approved image files are not in this checkout")
class RealTeamOriginalsTests(ImportTeamPageTestCase):
    content = APPROVED
    originals = {m["file"]: (IMAGES_DIR / m["file"]).read_bytes() for m in APPROVED["media"]} if REAL_FILES_PRESENT else {}

    def test_the_approved_originals_import_from_storage(self):
        output = run("--publish")
        self.assertIn("98 image records to create, 0 problems; 0 uploads", output)
        self.assertIn("Created 98 image records (no files uploaded), 7 programmes and 87 people", self.apply("--publish", token=token_from(output)))


class LocalImporterTests(TestCase):
    def test_populate_team_page_still_needs_the_local_files(self):
        empty = Path(self.enterContext(tempfile.TemporaryDirectory()))
        with mock.patch.object(content_module, "IMAGES_DIR", empty), override_settings(STORAGES=IN_MEMORY_STORAGES):
            with self.assertRaisesMessage(CommandError, "Approved content is invalid, nothing was changed: Missing media file images/"):
                call_command("populate_team_page", stdout=StringIO(), stderr=StringIO())


# ------------------------------------------------------------------ team_media_transfer --


class FakeS3Storage:
    """Just enough of S3Storage, with a REAL boto3 client of the pinned SDK (requirements.txt).

    Every request is serialised and signed by botocore as in production, then captured on
    ``before-send`` and answered here from an in-memory object store, so nothing leaves the machine.
    PutObject honours ``If-None-Match: *`` like S3: 412 when the key exists. ``self.requests`` holds
    the signed requests (method, key, headers, body).
    """

    bucket_name = "test-bucket"
    region_name = "eu-central-1"

    def __init__(self, objects):
        import boto3
        from botocore.config import Config

        self.objects, self.requests, self.respond_with = dict(objects), [], None
        client = boto3.session.Session().client(
            "s3", region_name=self.region_name, aws_access_key_id="AKIATESTTESTTESTTEST", aws_secret_access_key="test-secret",
            config=Config(retries={"max_attempts": 0}),
        )
        client.meta.events.register("before-send.s3", self._send)
        self.connection = mock.Mock()
        self.connection.meta.client = client

    def _send(self, request, **kwargs):
        from urllib.parse import unquote, urlsplit

        from botocore.awsrequest import AWSResponse

        class Raw:
            def __init__(self, body):
                self.body = body

            def stream(self, **kw):
                yield self.body

            def read(self, *args, **kw):
                return self.body

        parts = urlsplit(request.url)
        key = unquote(parts.path.lstrip("/").split("/", 1)[1] if parts.netloc.startswith("s3.") else parts.path.lstrip("/"))
        body = request.body.read() if hasattr(request.body, "read") else (request.body or b"")
        # Prepared requests hold header values as bytes (as sent on the wire).
        headers = {k: v.decode() if isinstance(v, bytes) else v for k, v in request.headers.items()}
        self.requests.append({"method": request.method, "key": key, "headers": headers, "body": body})

        def error(status, code):
            xml = f"<?xml version='1.0'?><Error><Code>{code}</Code><Message>{code}</Message></Error>".encode()
            return AWSResponse(request.url, status, {"Content-Type": "application/xml"}, Raw(xml))

        if request.method == "PUT":
            if self.respond_with:
                return error(*self.respond_with)
            if headers.get("If-None-Match") == "*" and key in self.objects:
                return error(412, "PreconditionFailed")
            self.objects[key] = body
            return AWSResponse(request.url, 200, {"ETag": f'"{hashlib.md5(body).hexdigest()}"'}, Raw(b""))
        if request.method == "HEAD" and key in self.objects:
            data = self.objects[key]
            return AWSResponse(request.url, 200, {"Content-Length": str(len(data)), "ETag": f'"{hashlib.md5(data).hexdigest()}"'}, Raw(b""))
        return error(404, "NotFound")

    @property
    def puts(self):
        return [r for r in self.requests if r["method"] == "PUT"]

    def exists(self, name):
        return name in self.objects

    def open(self, name, mode="rb"):
        return ContentFile(self.objects[name], name=name)


class TeamMediaTransferTests(TestCase):
    def setUp(self):
        content_file, images, self.content, self.originals = write_generated_package(Path(self.enterContext(tempfile.TemporaryDirectory())))
        self.enterContext(mock.patch.object(content_module, "CONTENT_FILE", content_file))
        self.enterContext(mock.patch.object(content_module, "IMAGES_DIR", images))
        self.enterContext(mock.patch.object(transfer_module, "IMAGES_DIR", images))
        files = list(self.originals)
        self.present, self.missing = files[:13], files[13:]
        self.s3 = FakeS3Storage({f"original_images/{n}": self.originals[n] for n in self.present})
        self.enterContext(mock.patch.object(transfer_module, "storages", {"default": self.s3}))

    def transfer(self, *args):
        out = StringIO()
        call_command("team_media_transfer", *args, stdout=out, stderr=StringIO())
        return out.getvalue()

    def token(self):
        return re.search(r"Confirmation token: (team-media-[0-9a-f]{16})", self.transfer()).group(1)

    def test_dry_run_inventories_without_writing(self):
        manifest = Path(self.enterContext(tempfile.TemporaryDirectory())) / "manifest.json"
        output = self.transfer("--manifest", str(manifest))
        self.assertIn("Storage: FakeS3Storage bucket test-bucket region eu-central-1", output)
        self.assertIn("98 originals: 13 already present (identical), 85 missing (to upload), 0 conflicts", output)
        self.assertTrue(manifest.exists())
        self.assertEqual(self.s3.requests, [], "the dry run sends no request through the client")

    def test_every_signed_put_carries_if_none_match_with_the_pinned_sdk(self):
        import boto3
        import botocore

        output = self.transfer("--apply", "--confirm", self.token())
        self.assertIn("Uploaded 85 originals; 13 were already present.", output)
        puts = self.s3.puts
        self.assertEqual(sorted(p["key"] for p in puts), sorted(f"original_images/{n}" for n in self.missing), "exact keys")
        for put in puts:
            headers = {k.lower(): v for k, v in put["headers"].items()}
            self.assertEqual(headers["if-none-match"], "*", f"{put['key']} (boto3 {boto3.__version__}, botocore {botocore.__version__})")
            signed = re.search(r"SignedHeaders=([^,]+)", headers["authorization"]).group(1).split(";")
            self.assertIn("if-none-match", signed, "the condition is part of the SigV4 signature")
            name = put["key"].split("/", 1)[1]
            self.assertEqual(put["body"], self.originals[name])
            self.assertEqual(headers["content-type"], transfer_module.mimetypes.guess_type(name)[0])
            self.assertTrue(headers["cache-control"])
        self.assertIn("All originals are present; nothing to upload.", self.transfer())

    def test_the_condition_is_scoped_to_the_command_uploads(self):
        self.transfer("--apply", "--confirm", self.token())
        client = self.s3.connection.meta.client
        client.put_object(Bucket="test-bucket", Key="other/unrelated.txt", Body=b"x")
        headers = {k.lower() for k in self.s3.requests[-1]["headers"]}
        self.assertNotIn("if-none-match", headers, "the handler is removed after each upload")

    def test_a_412_or_409_stops_without_overwriting(self):
        token = self.token()
        target = f"original_images/{self.missing[0]}"
        # Another writer creates the object after the inventory: S3 answers 412 to the conditional PUT.
        original_send = self.s3._send

        def appears_meanwhile(request, **kwargs):
            if request.method == "PUT" and target not in self.s3.objects:
                self.s3.objects[target] = b"written by someone else"
            return original_send(request, **kwargs)

        self.s3.connection.meta.client.meta.events.unregister("before-send.s3", original_send)
        self.s3.connection.meta.client.meta.events.register("before-send.s3", appears_meanwhile)
        with self.assertRaisesMessage(CommandError, f"{target}: S3 refused the upload (412 PreconditionFailed)"):
            self.transfer("--apply", "--confirm", token)
        self.assertEqual(self.s3.objects[target], b"written by someone else", "not overwritten")
        self.assertEqual(len(self.s3.puts), 1, "the run stops at the first refusal")

        # The next dry run sees that object and refuses it as a conflict (never overwritten)...
        with self.assertRaisesMessage(CommandError, "objects with different content exist"):
            self.transfer()
        # ...and a 409 (a concurrent conditional write to the same key) also stops the run.
        self.s3.connection.meta.client.meta.events.unregister("before-send.s3", appears_meanwhile)
        self.s3.connection.meta.client.meta.events.register("before-send.s3", original_send)
        del self.s3.objects[target]
        self.s3.respond_with = (409, "ConditionalRequestConflict")
        with self.assertRaisesMessage(CommandError, "(409 ConditionalRequestConflict)"):
            self.transfer("--apply", "--confirm", self.token())
        self.assertNotIn(target, self.s3.objects)

    def test_conflicts_and_stale_tokens_are_refused(self):
        token = self.token()
        self.s3.objects[f"original_images/{self.missing[0]}"] = b"different"
        with self.assertRaisesMessage(CommandError, "objects with different content exist"):
            self.transfer("--apply", "--confirm", token)
        del self.s3.objects[f"original_images/{self.missing[0]}"]
        self.s3.objects[f"original_images/{self.missing[1]}"] = self.originals[self.missing[1]]  # inventory changed
        with self.assertRaisesMessage(CommandError, "the token does not match"):
            self.transfer("--apply", "--confirm", token)
        self.assertEqual(self.s3.puts, [])

    def test_local_files_must_have_the_approved_dimensions(self):
        content = load_team_content(verify_files=False)
        content["media"][0]["width"] += 1
        with mock.patch.object(transfer_module, "load_team_content", return_value=content):
            with self.assertRaisesMessage(CommandError, "team.json says"):
                self.transfer()
        self.assertEqual(self.s3.puts, [])

    def test_local_files_must_be_the_approved_ones(self):
        (content_module.IMAGES_DIR / self.missing[0]).write_bytes(b"changed")
        with self.assertRaisesMessage(CommandError, "do not match team.json"):
            self.transfer()
