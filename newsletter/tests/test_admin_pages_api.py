from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.mautic.client import MauticClient
from newsletter.mautic.exceptions import (
    MauticBridgeRejectedError,
    MauticIdentityConfigurationError,
    MauticRequestNotSentError,
)
from newsletter.mautic.operations import (
    ASSERTABLE_OPERATIONS,
    PAGE_CREATE,
    PAGE_DELETE,
    PAGE_DUPLICATE,
    PAGE_UPDATE,
)
from newsletter.models import MauticIdentityAuditLog
from newsletter.page_html_policy import find_active_content
from newsletter.page_views import (
    PagePolicyError,
    _require_script_permission,
    blocking_usage,
    normalize_page_detail,
    parse_page_settings,
    validate_redirect_url,
)
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_mautic_template_client import MAUTIC_SETTINGS, response
from newsletter.tests.test_mautic_user_identity import IDENTITY_SETTINGS

User = get_user_model()
PER_USER_ON = {**IDENTITY_SETTINGS, "ECP_MAUTIC_PER_USER_EXECUTION_ENABLED": True}
PUBLIC_BASE = "https://mautic.example"
NOT_FOUND = PermanentMauticError("Mautic API request failed (HTTP 404): Item was not found.")
UNUSED = {
    "campaignEvents": [], "preferenceCenterEmails": [], "pointActions": [],
    "variantChildren": 0, "translationChildren": 0, "hasHeadScript": False, "hasFooterScript": False,
}


def native_page(**overrides):
    data = {
        "id": 51,
        "title": "Spring Summit",
        "alias": "spring-summit",
        "isPublished": False,
        "isPreferenceCenter": None,
        "customHtml": "<html><body><h1>Join us</h1></body></html>",
        "template": "blank",
        "language": "en",
        "metaDescription": None,
        "noIndex": None,
        "redirectType": None,
        "redirectUrl": None,
        "category": None,
        "hits": 12,
        "uniqueHits": 9,
        "variantParent": None,
        "variantChildren": [],
        "translationParent": None,
        "translationChildren": [],
        "createdByUser": "Ecp DevProof",
        "modifiedByUser": "Ecp DevProof",
        "dateAdded": "2026-10-27T06:00:00+00:00",
        "dateModified": "2026-10-27T06:00:00+00:00",
    }
    data.update(overrides)
    return data


class PageOperationContractTests(SimpleTestCase):
    def test_page_operations_are_assertable_and_match_the_bridge(self):
        self.assertEqual(
            (PAGE_CREATE, PAGE_UPDATE, PAGE_DELETE, PAGE_DUPLICATE),
            ("page.create", "page.update", "page.delete", "page.duplicate"),
        )
        for operation in (PAGE_CREATE, PAGE_UPDATE, PAGE_DELETE, PAGE_DUPLICATE):
            self.assertIn(operation, ASSERTABLE_OPERATIONS)


class ActiveContentTests(SimpleTestCase):
    def test_plain_marketing_html_runs_no_code(self):
        html = (
            '<html><head><title>T</title><style>h1{color:red}</style></head><body>'
            '<a href="https://imaa.example">Go</a><img src="/media/x.png" alt="">'
            '<iframe src="https://www.youtube.com/embed/x"></iframe>{form=3}{contactfield=firstname}</body></html>'
        )
        self.assertEqual(find_active_content(html), [])

    def test_every_kind_of_active_content_is_reported_once(self):
        html = (
            '<script>a()</script><SCRIPT src="x.js"></SCRIPT><object data="x"></object><embed src="x">'
            '<base href="https://evil.example/"><div onclick="x()"></div><img src=x onerror=y>'
            '<a href="java\tscript:alert(1)">j</a><a href="&#106;avascript:alert(1)">k</a>'
            '<iframe srcdoc="<script>x</script>"></iframe><meta http-equiv="Refresh" content="0;url=x">'
            '<form action="data:text/html,x"></form>'
        )
        findings = find_active_content(html)
        self.assertEqual(findings[0], "a <script> element")
        self.assertEqual(findings.count("a <script> element"), 1)
        for expected in (
            "an <object> element", "an <embed> element", "a <base> element",
            "an event-handler attribute (onclick)", "an event-handler attribute (onerror)",
            "a script URL in href", "an <iframe srcdoc> document", "a <meta http-equiv=refresh> redirect",
            "a script URL in action",
        ):
            self.assertIn(expected, findings)

    def test_findings_are_capped(self):
        html = "".join(f'<div on{name}="x"></div>' for name in "abcdefghijklmnop")
        self.assertEqual(len(find_active_content(html)), 10)

    def test_only_superusers_may_save_html_that_runs_code(self):
        request = SimpleNamespace(user=SimpleNamespace(is_superuser=False))
        refusal = _require_script_permission(request, "<p onclick='x()'>Hi</p>")
        self.assertEqual(refusal.status_code, 403)
        self.assertEqual(refusal.data["code"], "page_scripts_superuser_only")
        self.assertEqual(refusal.data["errors"].keys(), {"customHtml"})
        self.assertIsNone(_require_script_permission(request, "<p>Hi</p>"))
        superuser = SimpleNamespace(user=SimpleNamespace(is_superuser=True))
        self.assertIsNone(_require_script_permission(superuser, "<script>x()</script>"))

    def test_scripted_html_is_locked_for_non_superusers_only(self):
        page = native_page(customHtml="<script>track()</script><p>x</p>")
        locked = normalize_page_detail(page, base=PUBLIC_BASE, user=SimpleNamespace(is_superuser=False))
        open_ = normalize_page_detail(page, base=PUBLIC_BASE, user=SimpleNamespace(is_superuser=True))
        self.assertEqual((locked["htmlLocked"], open_["htmlLocked"]), (True, False))
        self.assertEqual(locked["activeContent"], ["a <script> element"])


class PageSettingsValidationTests(SimpleTestCase):
    def test_create_sends_only_supplied_editable_settings(self):
        self.assertEqual(
            parse_page_settings({"title": "  Summit ", "alias": "spring-summit", "customHtml": "<p>x</p>",
                                 "noIndex": True, "language": "en_US", "category": "4"}),
            {"title": "Summit", "alias": "spring-summit", "customHtml": "<p>x</p>", "noIndex": True,
             "language": "en_US", "category": 4},
        )

    def test_edit_sends_only_what_was_supplied(self):
        self.assertEqual(parse_page_settings({"metaDescription": " Hi "}, current=native_page()), {"metaDescription": "Hi"})
        self.assertEqual(parse_page_settings({"category": None}, current=native_page()), {"category": ""})

    def test_redirects_need_a_type_and_a_web_address(self):
        self.assertEqual(
            parse_page_settings({"redirectType": "301", "redirectUrl": "https://imaa.example/new"}, current=native_page()),
            {"redirectType": "301", "redirectUrl": "https://imaa.example/new"},
        )
        # Clearing the type clears the address too.
        self.assertEqual(
            parse_page_settings({"redirectType": ""}, current=native_page(redirectType="302", redirectUrl="https://x.example")),
            {"redirectType": "", "redirectUrl": ""},
        )
        for data in ({"redirectType": "302"}, {"redirectType": "200", "redirectUrl": "https://x.example"},
                     {"redirectType": "302", "redirectUrl": "javascript:alert(1)"}):
            with self.subTest(data=data), self.assertRaises(PagePolicyError):
                parse_page_settings(data, current=native_page())

    def test_invalid_and_refused_settings_have_codes(self):
        cases = [
            ({}, "invalid_setting", "title"),
            ({"title": "  "}, "invalid_setting", "title"),
            ({"title": "x" * 192}, "invalid_setting", "title"),
            ({"title": "T\x00"}, "invalid_setting", "title"),
            ({"title": 5}, "invalid_setting", "title"),
            ({"title": "T", "alias": "Spring Summit"}, "invalid_setting", "alias"),
            ({"title": "T", "alias": "a--b"}, "invalid_setting", "alias"),
            ({"title": "T", "alias": "api"}, "invalid_setting", "alias"),
            ({"title": "T", "language": "english"}, "invalid_setting", "language"),
            ({"title": "T", "category": "abc"}, "invalid_setting", "category"),
            ({"title": "T", "category": True}, "invalid_setting", "category"),
            ({"title": "T", "noIndex": "yes"}, "invalid_setting", "noIndex"),
            ({"title": "T", "customHtml": ["x"]}, "invalid_setting", "customHtml"),
            ({"title": "T", "customHtml": "x" * 1_000_001}, "invalid_setting", "customHtml"),
            ({"title": "T", "headScript": "<script>x</script>"}, "setting_not_allowed", "headScript"),
            ({"title": "T", "footerScript": "x"}, "setting_not_allowed", "footerScript"),
            ({"title": "T", "isPreferenceCenter": True}, "setting_not_allowed", "isPreferenceCenter"),
            ({"title": "T", "isPublished": True}, "setting_not_allowed", "isPublished"),
            ({"title": "T", "variantParent": 3}, "unsupported_setting", ""),
        ]
        for data, code, field in cases:
            with self.subTest(data=data):
                with self.assertRaises(PagePolicyError) as raised:
                    parse_page_settings(data)
                self.assertEqual((raised.exception.code, raised.exception.field), (code, field))

    def test_redirect_urls_must_be_absolute_web_addresses_without_tokens(self):
        self.assertEqual(validate_redirect_url("https://imaa.example/t?a=1"), "https://imaa.example/t?a=1")
        for value in ("javascript:alert(1)", "/thanks", "//host/x", "https://", "https://host/{x}",
                      "https://host/a b", "https://u:p@host/x", "https://" + "a" * 2050):
            with self.subTest(value=value), self.assertRaises(PagePolicyError):
                validate_redirect_url(value)

    def test_blocking_usage_lists_everything_that_must_go_first(self):
        self.assertEqual(blocking_usage({**UNUSED, "pointActions": [{"id": 1, "name": "Visit"}]}), {})
        blocking = blocking_usage({
            **UNUSED,
            "campaignEvents": [
                {"id": 9, "campaignId": 5, "campaignName": "Nurture"},
                {"id": 10, "campaignId": 5, "campaignName": "Nurture"},
            ],
            "preferenceCenterEmails": [{"id": 8, "name": "Weekly"}],
            "variantChildren": 1,
        })
        self.assertEqual(sorted(blocking), ["campaigns", "children", "preferenceCenterEmails"])
        self.assertEqual(blocking["campaigns"], [{"id": "5", "name": "Nurture"}])
        self.assertEqual(blocking["preferenceCenterEmails"], [{"id": "8", "name": "Weekly"}])
        self.assertEqual(blocking["children"], {"variants": 1, "translations": 0})


@override_settings(**MAUTIC_SETTINGS)
class PageClientTests(SimpleTestCase):
    def test_page_writes_refuse_the_service_account(self):
        session = Mock()
        client = MauticClient(session=session)
        for call in (
            lambda: client.create_page({"title": "P"}),
            lambda: client.update_page(51, {"title": "P"}),
            lambda: client.duplicate_page(51),
            lambda: client.delete_page(51),
        ):
            with self.assertRaises(MauticIdentityConfigurationError):
                call()
        session.request.assert_not_called()

    def test_page_writes_use_the_bridge_with_their_operation(self):
        session = Mock()
        session.request.return_value = response(200, {"page": {"id": 51}})
        provider = Mock(return_value="signed.jwt")
        client = MauticClient(session=session, assertion_provider=provider)

        client.create_page({"title": "P", "noIndex": True})
        client.update_page(51, {"isPublished": False})
        client.duplicate_page(51, title="Copy")
        session.request.return_value = response(200, {"page": {"id": None, "title": "P"}})
        self.assertEqual(client.delete_page(51)["title"], "P")

        calls = [(c.args[0], c.args[1].split("/api/")[1]) for c in session.request.call_args_list]
        self.assertEqual(calls, [
            ("POST", "ecp/bridge/pages/new"),
            ("PATCH", "ecp/bridge/pages/51/edit"),
            ("POST", "ecp/bridge/pages/51/duplicate"),
            ("DELETE", "ecp/bridge/pages/51/delete"),
        ])
        self.assertEqual([c.args[0] for c in provider.call_args_list], [PAGE_CREATE, PAGE_UPDATE, PAGE_DUPLICATE, PAGE_DELETE])
        self.assertEqual(dict(session.request.call_args_list[0].kwargs["data"]), {"title": "P", "noIndex": "1"})
        self.assertEqual(dict(session.request.call_args_list[1].kwargs["data"]), {"isPublished": "0"})

    def test_page_ids_must_be_numeric(self):
        client = MauticClient(session=Mock())
        for call in (lambda: client.get_page("../contacts"), lambda: client.get_page_usage("1;2")):
            with self.assertRaises(PermanentMauticError):
                call()

    def test_usage_is_read_with_the_service_account(self):
        session = Mock()
        session.request.return_value = response(200, {"usage": UNUSED})
        self.assertEqual(MauticClient(session=session).get_page_usage(51), UNUSED)
        self.assertTrue(session.request.call_args.args[1].endswith("/api/ecp/bridge/pages/51/usage"))


class _PagesApiBase(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.admin = User.objects.create_superuser(
            username="pages-admin", email="pages-admin@example.test", password="test-password",
        )
        grant_marketing_access(self.admin, mautic_user_id=6)
        self.api.force_authenticate(self.admin)

        self.service = Mock(name="service-client")
        self.service._uses_asserted_user.return_value = False
        self.service.get_page.return_value = native_page()
        self.asserted = Mock(name="asserted-client")
        self.asserted._uses_asserted_user.return_value = True
        self.asserted.last_assertion_jti = "jti-page"
        self.asserted.create_page.return_value = {"id": 51}
        self.asserted.update_page.return_value = {"id": 51}
        self.asserted.duplicate_page.return_value = {"id": 52}

        def factory(*args, **kwargs):
            if kwargs.get("assertion_provider") is not None:
                self.asserted.execution_identity = kwargs["execution_identity"]
                return self.asserted
            if "execution_identity" in kwargs:
                self.service.execution_identity = kwargs["execution_identity"]
            return self.service

        for target, kwargs in (
            ("newsletter.page_views.MauticClient", {"side_effect": factory}),
            # Mautic's public address comes from the plugin's capabilities.
            ("newsletter.page_views.mautic_public_base_url", {"return_value": PUBLIC_BASE}),
        ):
            patcher = patch(target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

        self.list_url = reverse("newsletter-admin-page-list")
        self.detail_url = reverse("newsletter-admin-page-detail", args=["51"])
        self.publish_url = reverse("newsletter-admin-page-publish", args=["51"])
        self.unpublish_url = reverse("newsletter-admin-page-unpublish", args=["51"])
        self.duplicate_url = reverse("newsletter-admin-page-duplicate", args=["51"])
        self.usage_url = reverse("newsletter-admin-page-usage", args=["51"])

    def audit(self):
        return list(MauticIdentityAuditLog.objects.order_by("id"))

    def assert_no_writes(self):
        for client in (self.asserted, self.service):
            for method in ("create_page", "update_page", "duplicate_page", "delete_page"):
                getattr(client, method).assert_not_called()


@override_settings(**PER_USER_ON)
class PagesReadApiTests(_PagesApiBase):
    def test_guests_and_non_marketing_users_are_denied(self):
        anonymous = APIClient()
        normal = APIClient()
        normal.force_authenticate(User.objects.create_user(username="pages-normal", email="n@example.test", password="x"))
        for client in (anonymous, normal):
            for method, url in (("get", self.list_url), ("get", self.detail_url), ("post", self.list_url),
                                ("patch", self.detail_url), ("delete", self.detail_url), ("post", self.publish_url),
                                ("post", self.unpublish_url), ("post", self.duplicate_url), ("get", self.usage_url)):
                with self.subTest(method=method, url=url):
                    self.assertIn(getattr(client, method)(url, {}, format="json").status_code, (401, 403))
        self.assert_no_writes()

    def test_list_combines_status_search_sort_and_pagination(self):
        self.service.list_pages.return_value = {"total": 26, "pages": {"51": native_page()}}

        response = self.api.get(self.list_url, {"status": "unpublished", "search": "Summit", "sort": "title",
                                                "page": 2, "page_size": 25})

        self.assertEqual(response.status_code, 200)
        self.service.list_pages.assert_called_once_with(
            start=25, limit=25, orderBy="title", orderByDir="ASC", search="is:unpublished Summit",
        )
        body = response.json()
        self.assertEqual((body["count"], body["num_pages"], body["publicBaseUrl"]), (26, 2, PUBLIC_BASE))
        row = body["results"][0]
        self.assertEqual(
            (row["id"], row["publicUrl"], row["hits"], row["uniqueHits"], row["isPublished"]),
            ("51", "https://mautic.example/spring-summit", 12, 9, False),
        )
        self.assertNotIn("customHtml", row)

    def test_list_rejects_unknown_filters(self):
        for params in ({"status": "deleted"}, {"sort": "random"}):
            self.assertEqual(self.api.get(self.list_url, params).status_code, 400)
        self.service.list_pages.assert_not_called()

    def test_detail_reports_publish_readiness_and_editability(self):
        body = self.api.get(self.detail_url).json()
        self.assertEqual((body["publishable"], body["editable"], body["htmlLocked"]), (True, True, False))
        self.assertEqual(body["customHtml"], native_page()["customHtml"])

        self.service.get_page.return_value = native_page(customHtml="  ", isPreferenceCenter=True)
        body = self.api.get(self.detail_url).json()
        self.assertEqual((body["publishable"], body["editable"]), (False, False))
        self.assertEqual(len(body["publishBlockers"]), 2)

    def test_detail_errors(self):
        self.assertEqual(self.api.get(reverse("newsletter-admin-page-detail", args=["abc"])).status_code, 400)
        self.service.get_page.side_effect = NOT_FOUND
        self.assertEqual(self.api.get(self.detail_url).status_code, 404)
        self.service.get_page.side_effect = TemporaryMauticError("Mautic API request failed (HTTP 500)")
        self.assertEqual(self.api.get(self.detail_url).status_code, 502)

    def test_categories_are_page_and_global_only(self):
        self.service.list_categories.return_value = {"categories": [
            {"id": 1, "title": "Events", "bundle": "page"},
            {"id": 2, "title": "Everywhere", "bundle": "global"},
            {"id": 3, "title": "Newsletters", "bundle": "email"},
        ]}
        with patch("newsletter.marketing_cache.enabled", return_value=False):
            body = self.api.get(reverse("newsletter-admin-page-categories")).json()
        self.assertEqual([c["id"] for c in body["results"]], ["1", "2"])

    def test_usage_is_normalized_with_its_blocking_summary(self):
        self.service.get_page_usage.return_value = {
            **UNUSED, "preferenceCenterEmails": [{"id": 8, "name": "Weekly", "published": True}], "hasHeadScript": True,
        }
        body = self.api.get(self.usage_url).json()
        self.assertEqual(body["preferenceCenterEmails"], [{"id": "8", "name": "Weekly", "published": True}])
        self.assertTrue(body["hasHeadScript"])
        self.assertEqual(body["blocking"], {"preferenceCenterEmails": [{"id": "8", "name": "Weekly"}]})


@override_settings(**PER_USER_ON)
class PagesCreateApiTests(_PagesApiBase):
    payload = {"title": "Spring Summit", "alias": "spring-summit", "customHtml": "<p>Join us</p>"}

    def test_create_runs_as_the_admin_and_returns_the_stored_page(self):
        response = self.api.post(self.list_url, self.payload, format="json")

        self.assertEqual(response.status_code, 201)
        self.asserted.create_page.assert_called_once_with(self.payload)
        self.service.get_page.assert_called_once_with("51")
        body = response.json()
        self.assertEqual((body["isPublished"], body["aliasAdjusted"], body["publicUrl"]),
                         (False, False, "https://mautic.example/spring-summit"))
        [entry] = self.audit()
        self.assertEqual(
            (entry.action, entry.status, entry.resource, entry.resource_id, entry.mautic_user_id, entry.auth_mode),
            (PAGE_CREATE, "succeeded", "page", "51", 6, "asserted_user"),
        )

    def test_a_renamed_alias_is_reported(self):
        self.service.get_page.return_value = native_page(alias="spring-summit1")
        body = self.api.post(self.list_url, self.payload, format="json").json()
        self.assertTrue(body["aliasAdjusted"])
        self.assertEqual(body["alias"], "spring-summit1")

    def test_invalid_input_never_reaches_mautic(self):
        for data in ({"title": ""}, {**self.payload, "alias": "Bad Alias"}, {**self.payload, "headScript": "x"},
                     {**self.payload, "isPublished": True}, {**self.payload, "template": "x"}):
            with self.subTest(data=data):
                response = self.api.post(self.list_url, data, format="json")
                self.assertEqual(response.status_code, 400)
                self.assertIn("code", response.json())
        self.assert_no_writes()
        self.assertEqual(self.audit(), [])

    def test_superusers_may_create_pages_with_scripts(self):
        response = self.api.post(self.list_url, {**self.payload, "customHtml": "<script>track()</script>"}, format="json")
        self.assertEqual(response.status_code, 201)

    @override_settings(**{**PER_USER_ON, "ECP_MAUTIC_PER_USER_EXECUTION_ENABLED": False})
    def test_flag_off_fails_closed_without_a_service_account_write(self):
        response = self.api.post(self.list_url, self.payload, format="json")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["code"], "mautic_identity_not_configured")
        self.assert_no_writes()
        [entry] = self.audit()
        self.assertEqual((entry.action, entry.status), (PAGE_CREATE, "failed"))

    def test_bridge_permission_refusal_is_reported_and_audited(self):
        self.asserted.create_page.side_effect = MauticBridgeRejectedError("Mautic API request failed (HTTP 403): Access denied.")
        response = self.api.post(self.list_url, self.payload, format="json")
        self.assertEqual((response.status_code, response.json()["code"]), (403, "mautic_permission_denied"))
        self.assertEqual(self.audit()[0].status, "denied")

    def test_uncertain_create_reports_matching_pages_without_retry(self):
        self.asserted.create_page.side_effect = TemporaryMauticError("Mautic API request failed")
        recent = timezone.now().isoformat()
        self.service.list_pages.return_value = {"total": 3, "pages": [
            native_page(id=60, dateAdded=recent),
            native_page(id=12, dateAdded="2020-01-01T00:00:00+00:00"),
            native_page(id=61, title="Spring Summit v2", dateAdded=recent),
        ]}

        response = self.api.post(self.list_url, self.payload, format="json")

        self.assertEqual((response.status_code, response.json()["code"]), (502, "page_create_uncertain"))
        self.assertEqual([c["id"] for c in response.json()["candidates"]], ["60"])
        self.asserted.create_page.assert_called_once()

    def test_request_not_sent_is_safe_to_retry(self):
        self.asserted.create_page.side_effect = MauticRequestNotSentError("refused")
        response = self.api.post(self.list_url, self.payload, format="json")
        self.assertEqual((response.status_code, response.json()["code"]), (503, "mautic_unavailable"))


@override_settings(**PER_USER_ON)
class PagesUpdateApiTests(_PagesApiBase):
    def test_edit_sends_only_supplied_settings(self):
        response = self.api.patch(self.detail_url, {"title": "Summit 2027", "noIndex": True}, format="json")

        self.assertEqual(response.status_code, 200)
        self.asserted.update_page.assert_called_once_with("51", {"title": "Summit 2027", "noIndex": True})
        self.assertEqual(self.audit()[0].action, PAGE_UPDATE)

    def test_empty_or_invalid_edits_write_nothing(self):
        for data in ({}, {"alias": ""}, {"footerScript": "x"}):
            with self.subTest(data=data):
                self.assertEqual(self.api.patch(self.detail_url, data, format="json").status_code, 400)
        self.assert_no_writes()

    def test_preference_center_pages_are_read_only(self):
        self.service.get_page.return_value = native_page(isPreferenceCenter=True)
        for method, url in (("patch", self.detail_url), ("delete", self.detail_url), ("post", self.publish_url),
                            ("post", self.duplicate_url)):
            with self.subTest(method=method):
                response = getattr(self.api, method)(url, {"title": "X"}, format="json")
                self.assertEqual((response.status_code, response.json()["code"]), (409, "page_managed_in_mautic"))
        self.assert_no_writes()

    def test_a_published_page_cannot_lose_all_its_content(self):
        self.service.get_page.return_value = native_page(isPublished=True)
        response = self.api.patch(self.detail_url, {"customHtml": "   "}, format="json")
        self.assertEqual((response.status_code, response.json()["code"]), (400, "page_content_required"))
        self.assert_no_writes()

    def test_uncertain_update_returns_the_verified_state(self):
        self.asserted.update_page.side_effect = TemporaryMauticError("read timeout")
        response = self.api.patch(self.detail_url, {"title": "X"}, format="json")
        body = response.json()
        self.assertEqual((response.status_code, body["code"], body["verified"]), (502, "page_update_uncertain", True))
        self.assertEqual(body["page"]["id"], "51")


@override_settings(**PER_USER_ON)
class PagesPublicationApiTests(_PagesApiBase):
    def test_publish_confirms_the_provider_state(self):
        self.service.get_page.side_effect = [native_page(), native_page(isPublished=True)]
        response = self.api.post(self.publish_url)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["isPublished"])
        self.asserted.update_page.assert_called_once_with("51", {"isPublished": True})
        self.assertEqual(self.audit()[0].detail, "published")

    def test_publish_is_refused_for_a_page_without_content(self):
        self.service.get_page.return_value = native_page(customHtml="")
        response = self.api.post(self.publish_url)
        self.assertEqual((response.status_code, response.json()["code"]), (409, "page_not_publishable"))
        self.assert_no_writes()

    def test_unconfirmed_publish_is_not_reported_as_success(self):
        response = self.api.post(self.publish_url)
        self.assertEqual((response.status_code, response.json()["code"]), (409, "page_publication_not_applied"))

    def test_unpublish_confirms_the_provider_state(self):
        self.service.get_page.side_effect = [native_page(isPublished=True), native_page()]
        response = self.api.post(self.unpublish_url)
        self.assertEqual(response.status_code, 200)
        self.asserted.update_page.assert_called_once_with("51", {"isPublished": False})


@override_settings(**PER_USER_ON)
class PagesDuplicateApiTests(_PagesApiBase):
    def test_duplicate_runs_as_the_admin_and_returns_the_copy(self):
        self.service.get_page.side_effect = [native_page(), native_page(id=52, title="Spring Summit Copy", alias="spring-summit-copy")]
        response = self.api.post(self.duplicate_url, {"title": ""}, format="json")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["id"], "52")
        self.asserted.duplicate_page.assert_called_once_with("51", title=None)
        self.assertEqual(self.audit()[0].action, PAGE_DUPLICATE)


@override_settings(**PER_USER_ON)
class PagesDeleteApiTests(_PagesApiBase):
    def setUp(self):
        super().setUp()
        self.service.get_page_usage.return_value = UNUSED
        self.service.get_page.side_effect = [native_page(), NOT_FOUND]
        self.asserted.delete_page.return_value = {"id": None, "title": "Spring Summit"}

    def test_delete_runs_as_the_admin_and_confirms_the_page_is_gone(self):
        response = self.api.delete(self.detail_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"deleted": True, "id": "51", "title": "Spring Summit"})
        self.asserted.delete_page.assert_called_once_with("51")
        [entry] = self.audit()
        self.assertEqual((entry.action, entry.resource_id, entry.mautic_user_id), (PAGE_DELETE, "51", 6))

    def test_a_page_still_in_use_is_not_deleted(self):
        self.service.get_page.side_effect = None
        for usage in (
            {**UNUSED, "campaignEvents": [{"id": 9, "campaignId": 5, "campaignName": "Nurture"}]},
            {**UNUSED, "preferenceCenterEmails": [{"id": 8, "name": "Weekly"}]},
            {**UNUSED, "translationChildren": 1},
        ):
            with self.subTest(usage=usage):
                self.service.get_page_usage.return_value = usage
                response = self.api.delete(self.detail_url)
                self.assertEqual((response.status_code, response.json()["code"]), (409, "page_in_use"))
                self.assertTrue(response.json()["blocking"])
        self.asserted.delete_page.assert_not_called()

    def test_point_actions_do_not_block_delete(self):
        self.service.get_page_usage.return_value = {**UNUSED, "pointActions": [{"id": 2, "name": "Visit points"}]}
        self.assertEqual(self.api.delete(self.detail_url).status_code, 200)

    def test_unreadable_usage_fails_closed(self):
        self.service.get_page_usage.side_effect = TemporaryMauticError("timeout")
        response = self.api.delete(self.detail_url)
        self.assertEqual((response.status_code, response.json()["code"]), (503, "page_usage_unavailable"))
        self.asserted.delete_page.assert_not_called()

    def test_bridge_conflict_is_shown(self):
        self.asserted.delete_page.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 409): The landing page is used by Campaign(s): Nurture (#5). Remove it from them first."
        )
        response = self.api.delete(self.detail_url)
        self.assertEqual((response.status_code, response.json()["code"]), (409, "page_in_use"))
        self.assertIn("Nurture (#5)", response.json()["detail"])

    def test_a_page_still_readable_after_delete_is_not_success(self):
        self.service.get_page.side_effect = [native_page(), native_page()]
        response = self.api.delete(self.detail_url)
        self.assertEqual((response.status_code, response.json()["code"]), (502, "page_delete_unconfirmed"))

    def test_uncertain_delete_checks_mautic(self):
        self.asserted.delete_page.side_effect = TemporaryMauticError("read timeout")
        self.assertEqual(self.api.delete(self.detail_url).status_code, 200)

        self.service.get_page.side_effect = [native_page(), native_page()]
        response = self.api.delete(self.detail_url)
        self.assertEqual((response.status_code, response.json()["code"]), (502, "page_delete_uncertain"))


class PagesAuditFilterTests(TestCase):
    def test_page_actions_are_filterable_under_their_own_domain(self):
        admin = User.objects.create_superuser(username="pages-audit", email="pa@example.test", password="x")
        grant_marketing_access(admin)
        MauticIdentityAuditLog.objects.create(ecp_user=admin, action=PAGE_CREATE, status="succeeded", resource="page", resource_id="51")
        api = APIClient()
        api.force_authenticate(admin)
        url = reverse("newsletter-admin-marketing-audit")

        by_action = api.get(url, {"action": PAGE_CREATE})
        by_domain = api.get(url, {"domain": "pages"})

        self.assertEqual(by_action.status_code, 200)
        self.assertEqual(by_action.json()["count"], 1)
        self.assertEqual(by_domain.json()["count"], 1)
        self.assertIn(PAGE_DELETE, by_action.json()["filters"]["actions"])


# A/B variants and translations (LP3) ------------------------------------------

from newsletter.mautic.operations import (  # noqa: E402
    PAGE_TRANSLATION_CREATE,
    PAGE_VARIANT_CREATE,
    PAGE_VARIANT_UPDATE,
    PAGE_VARIANT_WINNER,
)
from newsletter.page_views import normalize_abtest, normalize_page_summary  # noqa: E402


def variant_page(**overrides):
    return native_page(
        id=52, title="Spring Summit (Variant)", alias="spring-summit-variant",
        variantParent={"id": 51, "title": "Spring Summit", "alias": "spring-summit"},
        variantSettings={"weight": 30, "winnerCriteria": "page.dwelltime"}, **overrides,
    )


def translation_page(**overrides):
    return native_page(
        id=53, title="Spring Summit (FR)", alias="spring-summit-fr", language="fr",
        translationParent={"id": 51, "title": "Spring Summit", "alias": "spring-summit"}, **overrides,
    )


class PageFamilyContractTests(SimpleTestCase):
    def test_family_operations_are_assertable(self):
        self.assertEqual(
            (PAGE_VARIANT_CREATE, PAGE_VARIANT_UPDATE, PAGE_VARIANT_WINNER, PAGE_TRANSLATION_CREATE),
            ("page.variant.create", "page.variant.update", "page.variant.winner", "page.translation.create"),
        )
        for operation in (PAGE_VARIANT_CREATE, PAGE_VARIANT_UPDATE, PAGE_VARIANT_WINNER, PAGE_TRANSLATION_CREATE):
            self.assertIn(operation, ASSERTABLE_OPERATIONS)

    def test_public_addresses_follow_how_mautic_serves_each_role(self):
        self.assertEqual(normalize_page_summary(native_page(), base=PUBLIC_BASE)["role"], "main")
        variant = normalize_page_summary(variant_page(), base=PUBLIC_BASE)
        self.assertEqual((variant["role"], variant["publicUrl"]), ("variant", "https://mautic.example/spring-summit"))
        self.assertEqual(variant["familyParent"], {"id": "51", "title": "Spring Summit", "alias": "spring-summit"})
        translation = normalize_page_summary(translation_page(), base=PUBLIC_BASE)
        self.assertEqual((translation["role"], translation["publicUrl"]), ("translation", "https://mautic.example/fr/spring-summit-fr"))

    def test_abtest_is_normalized_with_labels_and_leaders(self):
        test = normalize_abtest({
            "parentId": 51, "criteria": "page.bouncerate", "mixedCriteria": False,
            "versions": [
                {"id": 51, "title": "Main", "isMain": True, "isPublished": True, "weight": 70, "variantHits": 7, "uniqueHits": 7},
                {"id": 52, "title": "B", "isMain": False, "isPublished": True, "weight": 30, "variantHits": 3, "uniqueHits": 3},
            ],
            "winners": [52], "support": [{"pageId": 51, "value": 40}, {"pageId": 52, "value": 20}],
        })
        self.assertTrue(test["running"])
        self.assertEqual(test["criteriaLabel"], "Bounce rate (lowest wins)")
        self.assertEqual([(v["id"], v["weight"], v["result"], v["isLeading"]) for v in test["versions"]],
                         [("51", 70, 40, False), ("52", 30, 20, True)])


@override_settings(**MAUTIC_SETTINGS)
class PageFamilyClientTests(SimpleTestCase):
    def test_family_writes_use_the_bridge_with_their_operation(self):
        session = Mock()
        session.request.return_value = response(200, {"page": {"id": 52}})
        provider = Mock(return_value="signed.jwt")
        client = MauticClient(session=session, assertion_provider=provider)

        client.create_page_variant(51, weight=30, winner_criteria="page.dwelltime")
        client.update_page_variant(52, weight=40)
        client.make_page_variant_winner(52)
        client.create_page_translation(51, language="fr", title="FR")

        calls = [(c.args[0], c.args[1].split("/api/")[1]) for c in session.request.call_args_list]
        self.assertEqual(calls, [
            ("POST", "ecp/bridge/pages/51/variants/new"),
            ("PATCH", "ecp/bridge/pages/52/variant/edit"),
            ("POST", "ecp/bridge/pages/52/winner"),
            ("POST", "ecp/bridge/pages/51/translations/new"),
        ])
        self.assertEqual([c.args[0] for c in provider.call_args_list],
                         [PAGE_VARIANT_CREATE, PAGE_VARIANT_UPDATE, PAGE_VARIANT_WINNER, PAGE_TRANSLATION_CREATE])
        self.assertEqual(session.request.call_args_list[0].kwargs["data"], {"weight": 30, "winnerCriteria": "page.dwelltime"})

    def test_family_writes_refuse_the_service_account(self):
        session = Mock()
        client = MauticClient(session=session)
        for call in (lambda: client.create_page_variant(51, weight=10, winner_criteria="page.dwelltime"),
                     lambda: client.make_page_variant_winner(52), lambda: client.create_page_translation(51, language="fr")):
            with self.assertRaises(MauticIdentityConfigurationError):
                call()
        session.request.assert_not_called()


@override_settings(**PER_USER_ON)
class PageFamilyApiTests(_PagesApiBase):
    def setUp(self):
        super().setUp()
        self.asserted.create_page_variant.return_value = {"id": 52}
        self.asserted.create_page_translation.return_value = {"id": 53}
        self.asserted.update_page_variant.return_value = {"id": 52}
        self.asserted.make_page_variant_winner.return_value = {"id": 52}
        self.variants_url = reverse("newsletter-admin-page-variants", args=["51"])
        self.translations_url = reverse("newsletter-admin-page-translations", args=["51"])

    def test_variant_create_validates_then_runs_as_the_admin(self):
        for data in ({"weight": 0, "winnerCriteria": "page.dwelltime"}, {"weight": "x", "winnerCriteria": "page.dwelltime"},
                     {"weight": 30, "winnerCriteria": "email.openrate"}, {"weight": True, "winnerCriteria": "page.dwelltime"}):
            with self.subTest(data=data):
                self.assertEqual(self.api.post(self.variants_url, data, format="json").status_code, 400)
        self.asserted.create_page_variant.assert_not_called()

        self.service.get_page.side_effect = [native_page(), variant_page()]
        r = self.api.post(self.variants_url, {"weight": 30, "winnerCriteria": "page.dwelltime"}, format="json")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.json()["role"], "variant")
        self.asserted.create_page_variant.assert_called_once_with("51", weight=30, winner_criteria="page.dwelltime", title=None)
        self.assertEqual(self.audit()[0].action, PAGE_VARIANT_CREATE)

    def test_only_main_pages_get_variants_or_translations(self):
        self.service.get_page.return_value = variant_page()
        for url, data in ((reverse("newsletter-admin-page-variants", args=["52"]), {"weight": 10, "winnerCriteria": "page.dwelltime"}),
                          (reverse("newsletter-admin-page-translations", args=["52"]), {"language": "fr"})):
            r = self.api.post(url, data, format="json")
            self.assertEqual((r.status_code, r.json()["code"]), (409, "page_not_main"))
        self.asserted.create_page_variant.assert_not_called()
        self.asserted.create_page_translation.assert_not_called()

    def test_bridge_weight_refusal_is_shown(self):
        self.asserted.create_page_variant.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 409): The variants' weights would total 110%."
        )
        r = self.api.post(self.variants_url, {"weight": 60, "winnerCriteria": "page.dwelltime"}, format="json")
        self.assertEqual(r.status_code, 409)
        self.assertIn("110%", r.json()["detail"])

    def test_translation_create_validates_the_language(self):
        self.assertEqual(self.api.post(self.translations_url, {"language": "French"}, format="json").status_code, 400)
        self.service.get_page.side_effect = [native_page(), translation_page()]
        r = self.api.post(self.translations_url, {"language": "fr"}, format="json")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.json()["publicUrl"], "https://mautic.example/fr/spring-summit-fr")
        self.asserted.create_page_translation.assert_called_once_with("51", language="fr", title=None)

    def test_a_language_cannot_be_used_twice_in_one_family(self):
        main = native_page(translationChildren=[{"id": 53, "language": "fr"}, {"id": 54, "language": "de"}])
        self.service.get_page.side_effect = lambda pid: main if str(pid) == "51" else translation_page()
        r = self.api.patch(reverse("newsletter-admin-page-detail", args=["53"]), {"language": "de"}, format="json")
        self.assertEqual((r.status_code, r.json()["code"]), (409, "page_language_taken"))
        r = self.api.patch(self.detail_url, {"language": "fr"}, format="json")
        self.assertEqual((r.status_code, r.json()["code"]), (409, "page_language_taken"))
        self.asserted.update_page.assert_not_called()

    def test_abtest_patch_validates_and_returns_the_test(self):
        url = reverse("newsletter-admin-page-abtest", args=["52"])
        for data in ({}, {"weight": 0}, {"winnerCriteria": "x"}, {"weight": 10, "other": 1}):
            with self.subTest(data=data):
                self.assertEqual(self.api.patch(url, data, format="json").status_code, 400)
        self.service.get_page_abtest.return_value = {"parentId": 51, "criteria": "page.dwelltime", "versions": [], "winners": [], "support": []}
        r = self.api.patch(url, {"weight": 40}, format="json")
        self.assertEqual(r.status_code, 200)
        self.asserted.update_page_variant.assert_called_once_with("52", weight=40, winner_criteria=None)
        self.assertEqual(self.audit()[0].action, PAGE_VARIANT_UPDATE)

    def test_winner_requires_a_variant_and_confirms_the_switch(self):
        url = reverse("newsletter-admin-page-winner", args=["52"])
        self.service.get_page.return_value = native_page(id=52)
        r = self.api.post(url)
        self.assertEqual((r.status_code, r.json()["code"]), (409, "page_not_variant"))
        self.asserted.make_page_variant_winner.assert_not_called()

        self.service.get_page.return_value = None
        self.service.get_page.side_effect = [variant_page(), native_page(id=52, alias="spring-summit")]
        r = self.api.post(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual((r.json()["winner"]["role"], r.json()["previousMainId"]), ("main", "51"))
        self.assertEqual(self.audit()[0].action, PAGE_VARIANT_WINNER)

    def test_an_unconfirmed_winner_is_not_reported_as_success(self):
        self.service.get_page.side_effect = [variant_page(), variant_page()]
        r = self.api.post(reverse("newsletter-admin-page-winner", args=["52"]))
        self.assertEqual((r.status_code, r.json()["code"]), (502, "page_winner_unconfirmed"))
