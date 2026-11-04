from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework.response import Response
from rest_framework.test import APIClient

from newsletter import focus_services as svc
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.mautic.client import MauticClient
from newsletter.mautic.exceptions import MauticIdentityConfigurationError
from newsletter.mautic.operations import ASSERTABLE_OPERATIONS, FOCUS_CREATE, FOCUS_DELETE, FOCUS_UPDATE
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_mautic_template_client import response

User = get_user_model()
LOCMEM = {"CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "focus-tests"}}}
FOCUS = {
    "id": 7, "name": "Register bar", "description": "", "type": "link", "style": "bar", "htmlMode": "basic", "editor": None,
    "website": "", "form": None, "category": {"id": 4, "title": "Events", "color": "4e5d9d"}, "isPublished": True,
    "publishUp": None, "publishDown": None, "utmTags": {"utmSource": "imaa", "utmMedium": None},
    "properties": {"bar": {"size": "regular", "placement": "bottom", "allow_hide": 1, "push_page": 0, "sticky": 1},
                   "colors": {"primary": "1b2a4a", "text": "ffffff", "button": "fdb933", "button_text": "1b2a4a"},
                   "content": {"headline": "Register", "link_text": "Go", "link_url": "https://example.test/", "css": None},
                   "when": "immediately", "frequency": "once", "stop_after_conversion": 1},
    "dateAdded": "2026-11-04T09:00:00+00:00", "createdByUser": "Ecp Admin",
}
NO_USAGE = {"totals": {}, "daily": [], "usage": {"campaigns": [], "pages": []}}


def pairs_dict(pairs):
    return dict(pairs)


class FieldTests(SimpleTestCase):
    def test_create_fills_every_setting_and_starts_unpublished(self):
        pairs = pairs_dict(svc.bridge_form({"name": " Bar ", "type": "notice", "style": "bar"}))
        self.assertEqual((pairs["name"], pairs["type"], pairs["style"], pairs["html_mode"], pairs["isPublished"]),
                         ("Bar", "notice", "bar", "basic", "0"))
        # Settings not sent take Mautic's defaults, so the live item never renders with blanks.
        self.assertEqual((pairs["properties[colors][primary]"], pairs["properties[bar][placement]"], pairs["properties[when]"],
                          pairs["properties[content][font]"]), ("4e5d9d", "top", "immediately", svc.FONTS[0]))
        self.assertNotIn("properties[modal][placement]", pairs)
        # As in Mautic's editor: white text on a bar, dark text on the white-box styles.
        self.assertEqual(pairs["properties[colors][text]"], "ffffff")
        modal = pairs_dict(svc.bridge_form({"name": "M", "type": "notice", "style": "modal"}))
        self.assertEqual(modal["properties[colors][text]"], "000000")
        self.assertEqual(pairs_dict(svc.bridge_form({"name": "M", "type": "notice", "style": "modal",
                                                     "properties": {"colors": {"text": "333333"}}}))["properties[colors][text]"], "333333")
        self.assertEqual(svc.DEFAULT_PROPERTIES["colors"]["text"], "ffffff")
        # Mautic's script treats a stored 0 as on, so off goes as "" (stored as null).
        self.assertEqual((pairs["properties[stop_after_close]"], pairs["properties[stop_after_conversion]"], pairs["properties[animate]"]),
                         ("", "1", "1"))

    def test_update_sends_only_what_was_sent_and_checks_against_the_stored_item(self):
        current = svc.normalize_focus(FOCUS)
        self.assertEqual(svc.bridge_form({"isPublished": False}, current=current), [("isPublished", "0")])
        pairs = pairs_dict(svc.bridge_form({"properties": {"bar": {"placement": "top"}, "colors": {"primary": "#AABBCC"}}}, current=current))
        self.assertEqual(pairs, {"properties[bar][placement]": "top", "properties[colors][primary]": "aabbcc"})
        with self.assertRaises(svc.FocusError) as raised:
            svc.bridge_form({}, current=current)
        self.assertEqual(raised.exception.code, "no_changes")
        # A bar placement is checked against the stored style.
        with self.assertRaises(svc.FocusError) as raised:
            svc.bridge_form({"properties": {"bar": {"placement": "middle"}}}, current=current)
        self.assertEqual(raised.exception.field, "placement")

    def test_public_website_rules(self):
        base = {"name": "F", "type": "link", "style": "bar"}
        for data, field in (
            ({"htmlMode": "html"}, "htmlMode"),
            ({"htmlMode": "editor", "editor": "<p>Hi</p><script>alert(1)</script>"}, "editor"),
            ({"htmlMode": "editor", "editor": '<a href="javascript:alert(1)">x</a>'}, "editor"),
            ({"htmlMode": "editor", "editor": '<img src=x onerror="alert(1)">'}, "editor"),
            ({"properties": {"content": {"css": ".x{}</style><script>alert(1)</script>"}}}, "css"),
            ({"properties": {"content": {"link_url": "javascript:alert(1)"}}}, "link_url"),
            ({"properties": {"content": {"link_url": "//evil.example"}}}, "link_url"),
            ({"website": "ftp://example.test"}, "website"),
            ({"properties": {"colors": {"text": "red"}}}, "colors.text"),
            ({"properties": {"content": {"font": "Comic Sans"}}}, "font"),
            ({"properties": {"when": "always"}}, "when"),
            ({"properties": {"timeout": "3601"}}, "timeout"),
            ({"properties": {"content": {"headline": "x" * 256}}}, "headline"),
            ({"type": "popup"}, "type"),
            ({"style": "banner"}, "style"),
            ({"name": "x" * 192}, "name"),
            ({"type": "form"}, "form"),
            ({"publishUp": "2026-12-01T09:00:00Z", "publishDown": "2026-11-01T09:00:00Z"}, "publishDown"),
        ):
            with self.subTest(data=data), self.assertRaises(svc.FocusError) as raised:
                svc.bridge_form({**base, **data})
            self.assertEqual(raised.exception.field, field)
        pairs = pairs_dict(svc.bridge_form({**base, "htmlMode": "editor", "editor": "<p><strong>Hi</strong> <a href='https://x.test'>there</a></p>",
                                            "publishUp": "2026-11-05T10:00:00+05:30"}))
        self.assertEqual((pairs["html_mode"], pairs["publishUp"]), ("editor", "2026-11-05 04:30"))

    def test_a_form_type_needs_a_form_and_clearing_sends_empty(self):
        pairs = pairs_dict(svc.bridge_form({"name": "F", "type": "form", "style": "modal", "form": {"id": 9}}))
        self.assertEqual((pairs["form"], pairs["properties[modal][placement]"]), ("9", "middle"))
        current = svc.normalize_focus({**FOCUS, "type": "form", "form": {"id": 9, "name": "Signup"}})
        self.assertEqual(svc.bridge_form({"type": "link", "form": None}, current=current), [("type", "link"), ("form", "")])
        with self.assertRaises(svc.FocusError):
            svc.bridge_form({"form": None}, current=current)

    def test_category_uses_the_shared_focus_category_check(self):
        with patch("newsletter.focus_services.category_choice", return_value=4) as check:
            self.assertIn(("category", "4"), svc.bridge_form({"name": "F", "type": "link", "style": "bar", "category": 4}))
        self.assertEqual(check.call_args.args[:2], (4, "plugin:focus"))
        with patch("newsletter.focus_services.category_choice", side_effect=ValueError("That category is unpublished.")):
            with self.assertRaises(svc.FocusError) as raised:
                svc.bridge_form({"name": "F", "type": "link", "style": "bar", "category": 5})
        self.assertEqual((raised.exception.field, str(raised.exception)), ("category", "That category is unpublished."))

    def test_preview_needs_no_name_and_skips_admin_only_fields(self):
        pairs = pairs_dict(svc.bridge_form({"type": "notice", "style": "page", "name": "", "category": 99, "isPublished": True}, preview=True))
        self.assertNotIn("name", pairs)
        self.assertNotIn("category", pairs)
        self.assertNotIn("isPublished", pairs)
        self.assertEqual(pairs["style"], "page")
        self.assertIn("<!doctype html>", svc.preview_document("<div class='mautic-focus'></div>"))
        document = svc.preview_document("<form class='mauticform'></form><script type='text/javascript'>\nMauticSDK.x();\n</SCRIPT >")
        self.assertIn("mauticform", document)
        self.assertNotIn("MauticSDK", document)

    def test_normalize_duplicate_and_embed(self):
        focus = svc.normalize_focus(FOCUS, stats={"views": 3})
        self.assertEqual((focus["properties"]["bar"]["push_page"], focus["properties"]["animate"], focus["properties"]["content"]["css"],
                          focus["utmTags"]["utmMedium"], focus["category"]["title"], focus["stats"]), (False, True, "", "", "Events", {"views": 3}))
        # Flags read as Mautic's script reads them: a stored 0 is on, null is off, missing is the default.
        flags = svc.normalize_focus({**FOCUS, "properties": {"stop_after_close": 0, "stop_after_conversion": None, "animate": ""}})["properties"]
        self.assertEqual((flags["stop_after_close"], flags["stop_after_conversion"], flags["animate"], flags["link_activation"]),
                         (True, False, False, True))
        copy = svc.duplicate_payload(focus)
        self.assertEqual((copy["name"], copy["isPublished"], copy["category"], copy["form"]), ("Copy of Register bar", False, 4, None))
        self.assertEqual(svc.duplicate_payload({**focus, "name": "x" * 191})["name"], ("Copy of " + "x" * 191)[:191])
        self.assertEqual(svc.embed_codes(7, "https://m.example"),
                         {"script": '<script src="https://m.example/focus/7.js" type="text/javascript" charset="utf-8" async="async"></script>',
                          "token": "{focus=7}"})
        self.assertIsNone(svc.embed_codes(7, None)["script"])


class FocusClientTests(SimpleTestCase):
    def test_writes_require_the_admins_identity(self):
        session = Mock()
        client = MauticClient(session=session)
        for call in (lambda: client.create_focus_item([]), lambda: client.update_focus_item(1, []), lambda: client.delete_focus_item(1)):
            with self.assertRaises(MauticIdentityConfigurationError):
                call()
        session.request.assert_not_called()

    def test_writes_go_to_the_bridge_with_their_own_operations(self):
        session = Mock()
        session.request.return_value = response(201, {"focus": FOCUS})
        provider = Mock(return_value="signed.jwt")
        client = MauticClient(session=session, assertion_provider=provider)
        client.create_focus_item([("name", "Bar"), ("properties[when]", "leave")])
        method, url = session.request.call_args.args[:2]
        self.assertEqual((method, url.endswith("/api/ecp/bridge/focus/new")), ("POST", True))
        self.assertEqual(session.request.call_args.kwargs["data"], [("name", "Bar"), ("properties[when]", "leave")])
        client.update_focus_item(7, [("isPublished", "1")])
        self.assertEqual(session.request.call_args.args[:1], ("PATCH",))
        self.assertTrue(session.request.call_args.args[1].endswith("/api/ecp/bridge/focus/7/edit"))
        client.delete_focus_item(7)
        self.assertEqual([c.args[0] for c in provider.call_args_list], [FOCUS_CREATE, FOCUS_UPDATE, FOCUS_DELETE])
        self.assertTrue({FOCUS_CREATE, FOCUS_UPDATE, FOCUS_DELETE} <= ASSERTABLE_OPERATIONS)
        with self.assertRaises(PermanentMauticError):
            client.get_focus_item("7/../../users")

    def test_reads_validate_their_shape(self):
        session = Mock()
        client = MauticClient(session=session)
        session.request.return_value = response(200, {"stats": {"7": {"views": 2}, "x": {}}})
        self.assertEqual(client.get_focus_stats([7, "8"]), {7: {"views": 2}})
        self.assertEqual(session.request.call_args.kwargs["params"], {"ids": "7,8"})
        self.assertEqual(client.get_focus_stats([]), {})
        session.request.return_value = response(200, {"totals": {}, "daily": "x", "usage": {}})
        with self.assertRaises(TemporaryMauticError):
            client.get_focus_insights(7)
        session.request.return_value = response(200, {"html": None})
        with self.assertRaises(TemporaryMauticError):
            client.preview_focus_item([("type", "notice")])


@override_settings(**LOCMEM)
class FocusApiTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="focus-admin", email="fa@example.test", password="x")
        grant_marketing_access(self.admin)
        self.api = APIClient()
        self.api.force_authenticate(self.admin)
        for target, value in (("newsletter.focus_views.mautic_public_base_url", "https://m.example"),
                              ("newsletter.focus_services.category_choice", 4)):
            patcher = patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def mutation_returning(self, result):
        def mutation(request, action, resource_id, mutate, **kwargs):
            client = Mock()
            for name in ("create_focus_item", "update_focus_item"):
                getattr(client, name).return_value = result
            client.delete_focus_item.return_value = None
            self.sent = None
            value = mutate(client)
            calls = [c for c in client.method_calls]
            self.sent = calls[0].args[-1] if calls and calls[0].args else None
            return value, None
        return mutation

    def test_create_runs_as_the_admin_and_returns_the_embed_code(self):
        with patch("newsletter.focus_views._mutation", side_effect=self.mutation_returning(FOCUS)) as run:
            r = self.api.post(reverse("newsletter-admin-focus-list"),
                              {"name": "Register bar", "type": "link", "style": "bar", "category": 4,
                               "properties": {"content": {"headline": "Register", "link_text": "Go", "link_url": "https://example.test/"}}},
                              format="json")
        self.assertEqual(r.status_code, 201, r.content)
        body = r.json()
        self.assertEqual((body["id"], body["embed"]["token"], body["isLive"]), (7, "{focus=7}", True))
        self.assertIn("https://m.example/focus/7.js", body["embed"]["script"])
        self.assertEqual((run.call_args.args[1], run.call_args.kwargs["detail"]), (FOCUS_CREATE, "Register bar"))
        sent = dict(self.sent)
        self.assertEqual((sent["category"], sent["isPublished"], sent["properties[content][link_url]"]), ("4", "0", "https://example.test/"))

    def test_bad_settings_never_reach_mautic(self):
        url = reverse("newsletter-admin-focus-list")
        with patch("newsletter.focus_views._mutation") as run:
            for data in ({"name": "", "type": "link", "style": "bar"}, {"name": "x", "type": "link", "style": "bar", "htmlMode": "html"},
                         {"name": "x", "type": "link", "style": "bar", "properties": {"content": {"css": "</style>"}}}):
                r = self.api.post(url, data, format="json")
                self.assertEqual(r.status_code, 400)
                self.assertIn("field", r.json())
        run.assert_not_called()

    def test_update_and_provider_refusals(self):
        detail = reverse("newsletter-admin-focus-detail", args=[7])
        with patch.object(MauticClient, "get_focus_item", return_value=FOCUS):
            self.assertEqual(self.api.patch(detail, {}, format="json").json()["code"], "no_changes")
            with patch("newsletter.focus_views._mutation", side_effect=self.mutation_returning({**FOCUS, "isPublished": False})) as run:
                r = self.api.patch(detail, {"isPublished": False}, format="json")
            self.assertEqual((r.status_code, r.json()["isPublished"], run.call_args.args[1]), (200, False, FOCUS_UPDATE))
            self.assertEqual(self.sent, [("isPublished", "0")])
            cases = [
                (PermanentMauticError("Mautic focus item update (HTTP 422): Choose a published Form."), 400, "Choose a published Form."),
                (PermanentMauticError("Mautic focus item update (HTTP 404)"), 404, "That Focus Item was not found in Mautic."),
                (TemporaryMauticError("down"), 502, "Mautic could not be reached. Nothing was saved; try again."),
            ]
            for exc, code, message in cases:
                with self.subTest(code=code), patch("newsletter.focus_views._mutation", side_effect=exc):
                    r = self.api.patch(detail, {"name": "x"}, format="json")
                self.assertEqual((r.status_code, r.json()["detail"]), (code, message))
            with patch("newsletter.focus_views._mutation", return_value=(None, Response({"detail": "no"}, status=403))):
                self.assertEqual(self.api.patch(detail, {"name": "x"}, format="json").status_code, 403)

    def test_delete_is_refused_while_used_and_fails_closed(self):
        detail = reverse("newsletter-admin-focus-detail", args=[7])
        used = {**NO_USAGE, "usage": {"campaigns": [{"id": 3, "name": "Welcome", "published": True}], "pages": []}}
        with patch.object(MauticClient, "get_focus_insights", return_value=used), patch("newsletter.focus_views._mutation") as run:
            r = self.api.delete(detail)
        self.assertEqual((r.status_code, r.json()["code"], r.json()["usage"]["campaigns"][0]["name"]), (409, "focus_in_use", "Welcome"))
        run.assert_not_called()
        with patch.object(MauticClient, "get_focus_insights", side_effect=TemporaryMauticError("down")), \
                patch("newsletter.focus_views._mutation") as run:
            self.assertEqual(self.api.delete(detail).status_code, 502)
        run.assert_not_called()
        with patch.object(MauticClient, "get_focus_insights", return_value=NO_USAGE), \
                patch("newsletter.focus_views._mutation", side_effect=self.mutation_returning(None)) as run:
            self.assertEqual(self.api.delete(detail).status_code, 204)
        self.assertEqual(run.call_args.args[1], FOCUS_DELETE)

    def test_duplicate_creates_an_unpublished_copy(self):
        with patch.object(MauticClient, "get_focus_item", return_value=FOCUS), \
                patch("newsletter.focus_views._mutation", side_effect=self.mutation_returning({**FOCUS, "id": 8, "name": "Copy of Register bar"})) as run:
            r = self.api.post(reverse("newsletter-admin-focus-duplicate", args=[7]))
        self.assertEqual((r.status_code, r.json()["id"], run.call_args.args[1]), (201, 8, FOCUS_CREATE))
        sent = dict(self.sent)
        self.assertEqual((sent["name"], sent["isPublished"], sent["properties[bar][placement]"], sent["utmTags[utmSource]"]),
                         ("Copy of Register bar", "0", "bottom", "imaa"))
        # A raw HTML item (built in Mautic) is not copied: its HTML cannot be saved through ECP.
        with patch.object(MauticClient, "get_focus_item", return_value={**FOCUS, "htmlMode": "html", "html": "<b>x</b>"}), \
                patch("newsletter.focus_views._mutation") as run:
            r = self.api.post(reverse("newsletter-admin-focus-duplicate", args=[7]))
        self.assertEqual((r.status_code, r.json()["code"]), (400, "focus_raw_html"))
        run.assert_not_called()

    def test_preview_list_and_insights(self):
        with patch.object(MauticClient, "preview_focus_item", return_value="<div class='mautic-focus'>Hi</div>") as preview:
            r = self.api.post(reverse("newsletter-admin-focus-preview"), {"type": "notice", "style": "modal"}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertIn("mautic-focus", r.json()["document"])
        self.assertEqual(r["Cache-Control"], "no-store")
        self.assertIn(("style", "modal"), preview.call_args.args[0])
        self.assertEqual(self.api.post(reverse("newsletter-admin-focus-preview"), {"type": "form", "style": "modal"}, format="json").json()["field"],
                         "form")
        scheduled = {**FOCUS, "id": 8, "publishUp": "2099-01-01T09:00:00+00:00"}
        with patch.object(MauticClient, "list_focus_items", return_value={"total": 30, "focus": {"7": FOCUS, "8": scheduled}}) as listing, \
                patch.object(MauticClient, "get_focus_stats", return_value={7: {"views": 5, "uniqueViews": 2, "clicks": 1, "submissions": 0}}):
            body = self.api.get(reverse("newsletter-admin-focus-list"), {"page": 2, "page_size": 10, "search": " reg ", "status": "unpublished"}).json()
        self.assertEqual((body["count"], body["num_pages"], body["results"][0]["stats"]["views"]), (30, 3, 5))
        self.assertEqual([(item["id"], item["isLive"]) for item in body["results"]], [(7, True), (8, False)])
        self.assertEqual(listing.call_args.kwargs, {"start": 10, "limit": 10, "orderBy": "id", "orderByDir": "DESC", "search": "reg is:unpublished"})
        with patch.object(MauticClient, "get_focus_insights", return_value=NO_USAGE) as insights:
            r = self.api.get(reverse("newsletter-admin-focus-insights", args=[7]), {"days": 999})
        self.assertEqual((r.status_code, insights.call_args.kwargs["days"]), (200, 365))

    def test_non_marketing_users_are_denied(self):
        normal = APIClient()
        normal.force_authenticate(User.objects.create_user(username="focus-normal", email="fn@example.test", password="x"))
        for url in (reverse("newsletter-admin-focus-list"), reverse("newsletter-admin-focus-detail", args=[7]),
                    reverse("newsletter-admin-focus-insights", args=[7])):
            self.assertIn(normal.get(url).status_code, (401, 403))
        self.assertIn(normal.post(reverse("newsletter-admin-focus-preview"), {}, format="json").status_code, (401, 403))
