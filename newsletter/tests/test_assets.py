from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework.response import Response
from rest_framework.test import APIClient

from newsletter import asset_services as svc
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.mautic.client import MauticClient
from newsletter.mautic.exceptions import MauticIdentityConfigurationError
from newsletter.mautic.operations import ASSERTABLE_OPERATIONS, ASSET_CREATE, ASSET_DELETE, ASSET_UPDATE
from newsletter.models import MauticIdentityAuditLog
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_mautic_template_client import response

User = get_user_model()
LOCMEM = {"CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "asset-tests"}}}
CONFIG = {"allowedExtensions": ["pdf", "png", "docx"], "maxSizeMb": 6, "remote": {"schemes": ["https"]}}
CATEGORIES = [{"id": 3, "title": "Guides"}]
ASSET = {"id": 12, "title": "Guide", "originalFileName": "guide.pdf", "storageLocation": "local", "downloadUrl": "https://m/asset/x"}
RESOLVE = {"files.example.com": ["93.184.216.34"], "intranet.example": ["10.1.2.3"], "meta.example": ["169.254.169.254"],
           "v6.example": ["::1"], "mixed.example": ["93.184.216.34", "192.168.1.5"]}


class FieldTests(SimpleTestCase):
    def test_create_needs_a_title_and_defaults_to_unpublished_english(self):
        with self.assertRaises(svc.AssetError) as raised:
            svc.normalize_fields({"title": " "}, creating=True)
        self.assertEqual(raised.exception.field, "title")
        fields = svc.normalize_fields({"title": " Guide ", "description": " About "}, creating=True)
        self.assertEqual(fields, {"title": "Guide", "description": "About", "language": "en", "isPublished": 0})

    def test_update_changes_only_the_keys_sent(self):
        self.assertEqual(svc.normalize_fields({"isPublished": "true"}, creating=False), {"isPublished": 1})
        self.assertEqual(svc.normalize_fields({"category": ""}, creating=False, categories=CATEGORIES), {"category": ""})

    def test_language_dates_and_category(self):
        fields = svc.normalize_fields({"title": "G", "language": "fr_FR", "publishUp": "2026-11-01T09:00", "publishDown": "2026-12-01 09:00:00",
                                       "category": "3"}, creating=True, categories=CATEGORIES)
        self.assertEqual((fields["language"], fields["publishUp"], fields["publishDown"], fields["category"]),
                         ("fr_FR", "2026-11-01 09:00", "2026-12-01 09:00", "3"))
        for data, field in (
            ({"language": "english!"}, "language"),
            ({"publishUp": "tomorrow"}, "publishUp"),
            ({"publishUp": "2026-12-01 09:00", "publishDown": "2026-11-01 09:00"}, "publishDown"),
            ({"category": "99"}, "category"),
            ({"category": "1 OR 1"}, "category"),
            ({"title": "x" * 192}, "title"),
        ):
            with self.subTest(data=data), self.assertRaises(svc.AssetError) as raised:
                svc.normalize_fields({"title": "G", **data}, creating=True, categories=CATEGORIES)
            self.assertEqual(raised.exception.field, field)


class UploadAndLinkTests(SimpleTestCase):
    def test_uploads_follow_mauticS_extension_and_size_settings(self):
        self.assertEqual(svc.check_upload("Brochure.PDF", 1000, CONFIG), "pdf")
        self.assertEqual(svc.check_upload("C:\\docs\\plan.docx", 1000, CONFIG), "docx")
        for name, size, message in (
            ("page.html", 10, "cannot be uploaded"), ("run.php", 10, "cannot be uploaded"), ("noext", 10, "cannot be uploaded"),
            ("a.pdf", 0, "empty"), ("big.pdf", 6 * 1024 * 1024 + 1, "limit of 6 MB"),
        ):
            with self.subTest(name=name), self.assertRaises(svc.AssetError) as raised:
                svc.check_upload(name, size, CONFIG)
            self.assertIn(message, str(raised.exception))

    def test_remote_links_must_be_public_https(self):
        resolve = lambda host: RESOLVE.get(host, [])  # noqa: E731
        self.assertEqual(svc.check_remote_url(" https://files.example.com/a.pdf ", resolve=resolve), "https://files.example.com/a.pdf")
        for url in ("http://files.example.com/a.pdf", "https://u:p@files.example.com/a.pdf", "https://files.example.com:8443/a.pdf",
                    "https://localhost/a.pdf", "https://127.0.0.1/a.pdf", "https://[::1]/a.pdf", "https://intranet.example/a.pdf",
                    "https://meta.example/latest", "https://v6.example/a", "https://mixed.example/a", "https://nowhere.example/a",
                    "https://files.example.com/a b.pdf", "ftp://files.example.com/a.pdf", "https://printer.local/a.pdf"):
            with self.subTest(url=url), self.assertRaises(svc.AssetError):
                svc.check_remote_url(url, resolve=resolve)

    def test_asset_tokens_list_published_assets_only_when_the_list_is_valid(self):
        client = Mock()
        client.list_assets.return_value = {"assets": [{"id": 12, "title": "Guide"}, {"id": "x"}]}
        with override_settings(**LOCMEM):
            self.assertEqual(svc.asset_link_tokens(client), [{"token": "{assetlink=12}", "label": "Guide", "group": "Assets"}])
            self.assertEqual(client.list_assets.call_args.kwargs["status"], "published")
            broken = Mock()
            broken.list_assets.return_value = Mock()
            self.assertEqual(svc.asset_link_tokens(broken, limit=7), [])


class AssetClientTests(SimpleTestCase):
    def test_writes_require_the_admins_identity(self):
        session = Mock()
        client = MauticClient(session=session)
        for call in (lambda: client.create_asset({"title": "x"}, remote_url="https://a"), lambda: client.update_asset(1, {}),
                     lambda: client.delete_asset(1)):
            with self.assertRaises(MauticIdentityConfigurationError):
                call()
        session.request.assert_not_called()

    def test_writes_are_multipart_to_the_bridge_with_their_own_operations(self):
        session = Mock()
        session.request.return_value = response(201, {"asset": ASSET})
        provider = Mock(return_value="signed.jwt")
        client = MauticClient(session=session, assertion_provider=provider)
        client.create_asset({"title": "Guide", "isPublished": 1}, upload=("guide.pdf", b"%PDF", "application/pdf"))
        method, url = session.request.call_args.args[:2]
        kwargs = session.request.call_args.kwargs
        self.assertEqual((method, url.endswith("/api/ecp/bridge/assets/new")), ("POST", True))
        self.assertEqual(kwargs["data"], {"title": "Guide", "isPublished": "1"})
        self.assertEqual(kwargs["files"], {"file": ("guide.pdf", b"%PDF", "application/pdf")})
        client.update_asset(12, {"title": "New"}, remote_url="https://files.example.com/a.pdf")
        self.assertTrue(session.request.call_args.args[1].endswith("/api/ecp/bridge/assets/12/edit"))
        self.assertEqual(session.request.call_args.kwargs["data"]["remoteUrl"], "https://files.example.com/a.pdf")
        self.assertIsNone(session.request.call_args.kwargs["files"])
        client.delete_asset(12)
        self.assertEqual([c.args[0] for c in provider.call_args_list], [ASSET_CREATE, ASSET_UPDATE, ASSET_DELETE])
        self.assertTrue({ASSET_CREATE, ASSET_UPDATE, ASSET_DELETE} <= ASSERTABLE_OPERATIONS)
        with self.assertRaises(PermanentMauticError):
            client.get_asset("12/../../users")


@override_settings(**LOCMEM)
class AssetApiTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="asset-admin", email="aa@example.test", password="x")
        grant_marketing_access(self.admin)
        self.api = APIClient()
        self.api.force_authenticate(self.admin)
        for target, value in (("newsletter.asset_views.asset_config", CONFIG), ("newsletter.asset_views.asset_categories", CATEGORIES)):
            patcher = patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_create_with_an_upload_runs_as_the_admin(self):
        def mutation(request, action, resource_id, mutate, **kwargs):
            client = Mock()
            client.create_asset.return_value = ASSET
            result = mutate(client)
            fields, upload = client.create_asset.call_args.args[0], client.create_asset.call_args.kwargs["upload"]
            self.assertEqual(fields["title"], "Guide")
            self.assertEqual((upload[0], upload[1]), ("guide.pdf", b"%PDF-1.4"))
            self.assertEqual(kwargs["detail"], "upload .pdf")
            return result, None

        with patch("newsletter.asset_views._mutation", side_effect=mutation) as run:
            r = self.api.post(reverse("newsletter-admin-asset-list"),
                              {"title": "Guide", "file": SimpleUploadedFile("guide.pdf", b"%PDF-1.4", "application/pdf")}, format="multipart")
        self.assertEqual((r.status_code, r.json()["id"]), (201, 12))
        self.assertEqual(run.call_args.args[1], ASSET_CREATE)

    def test_bad_files_and_links_never_reach_mautic(self):
        url = reverse("newsletter-admin-asset-list")
        with patch("newsletter.asset_views._mutation") as run:
            for data in (
                {"title": "Page", "file": SimpleUploadedFile("page.html", b"<html>", "text/html")},
                {"title": "Internal", "remoteUrl": "https://127.0.0.1/a.pdf"},
                {"title": "Both", "remoteUrl": "https://files.example.com/a.pdf", "file": SimpleUploadedFile("a.pdf", b"%PDF")},
                {"title": "Nothing"},
            ):
                with self.subTest(title=data["title"]):
                    self.assertEqual(self.api.post(url, data, format="multipart").status_code, 400)
        run.assert_not_called()

    def test_update_delete_and_refusals(self):
        detail = reverse("newsletter-admin-asset-detail", args=[12])
        self.assertEqual(self.api.patch(detail, {}, format="json").json()["code"], "no_changes")
        with patch("newsletter.asset_views._mutation", return_value=(ASSET, None)) as run:
            self.assertEqual(self.api.patch(detail, {"isPublished": True}, format="json").status_code, 200)
        self.assertEqual(run.call_args.args[1], ASSET_UPDATE)
        with patch("newsletter.asset_views._mutation", return_value=(None, Response({"detail": "no"}, status=403))):
            self.assertEqual(self.api.delete(detail).status_code, 403)
        cases = [
            (PermanentMauticError("Mautic asset update (HTTP 400): The file content does not match its .pdf extension."), 400,
             "The file content does not match its .pdf extension."),
            (PermanentMauticError("Mautic asset update (HTTP 404)"), 404, "That asset was not found in Mautic."),
            (TemporaryMauticError("down"), 502, "Mautic could not be reached. Nothing was saved; try again."),
        ]
        for exc, code, message in cases:
            with self.subTest(code=code), patch("newsletter.asset_views._mutation", side_effect=exc):
                r = self.api.patch(detail, {"title": "x"}, format="json")
            self.assertEqual((r.status_code, r.json()["detail"]), (code, message))

    def test_admin_file_download_is_an_audited_attachment(self):
        upstream = Mock(content=b"%PDF-1.4")
        with patch.object(MauticClient, "get_asset", return_value={**ASSET, "originalFileName": 'evil"\r\nname.pdf'}), \
                patch.object(MauticClient, "get_asset_file", return_value=upstream):
            r = self.api.get(reverse("newsletter-admin-asset-file", args=[12]))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, b"%PDF-1.4")
        self.assertEqual(r["Content-Disposition"], 'attachment; filename="evil___name.pdf"')
        self.assertEqual(r["Content-Type"], "application/octet-stream")
        self.assertTrue(MauticIdentityAuditLog.objects.filter(action="asset.file.download", resource_id="12").exists())
        with patch.object(MauticClient, "get_asset", return_value=ASSET), \
                patch.object(MauticClient, "get_asset_file", side_effect=PermanentMauticError("x (HTTP 409): This asset links to a remote file")):
            self.assertEqual(self.api.get(reverse("newsletter-admin-asset-file", args=[12])).status_code, 409)

    def test_list_and_downloads(self):
        with patch.object(MauticClient, "list_assets", return_value={"total": 30, "assets": [ASSET]}) as listing:
            body = self.api.get(reverse("newsletter-admin-asset-list"), {"page": 2, "page_size": 10, "search": "guide", "status": "published"}).json()
        self.assertEqual((body["count"], body["num_pages"], body["results"][0]["id"]), (30, 3, 12))
        self.assertEqual(listing.call_args.kwargs, {"page": 2, "limit": 10, "search": "guide", "status": "published"})
        data = {"totals": {"downloads": 3}, "daily": [], "recent": []}
        with patch.object(MauticClient, "get_asset_downloads", return_value=data) as downloads:
            r = self.api.get(reverse("newsletter-admin-asset-downloads", args=[12]), {"days": 999})
        self.assertEqual(r.json()["totals"]["downloads"], 3)
        self.assertEqual(downloads.call_args.kwargs["days"], 365)

    def test_non_marketing_users_are_denied(self):
        normal = APIClient()
        normal.force_authenticate(User.objects.create_user(username="asset-normal", email="an@example.test", password="x"))
        for url in (reverse("newsletter-admin-asset-list"), reverse("newsletter-admin-asset-file", args=[12])):
            self.assertIn(normal.get(url).status_code, (401, 403))
