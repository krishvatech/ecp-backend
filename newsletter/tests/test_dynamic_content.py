import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework.response import Response
from rest_framework.test import APIClient

from newsletter import dynamic_content_services as svc
from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.mautic.client import MauticClient
from newsletter.mautic.exceptions import MauticIdentityConfigurationError
from newsletter.mautic.operations import (
    ASSERTABLE_OPERATIONS,
    DYNAMIC_CONTENT_CREATE,
    DYNAMIC_CONTENT_DELETE,
    DYNAMIC_CONTENT_UPDATE,
)
from newsletter.native_campaign_views import _validate_connection_rules
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_mautic_template_client import response

User = get_user_model()
LOCMEM = {"CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "dwc-tests"}}}
ITEM = {
    "id": 5, "name": "India banner", "description": "", "type": "html", "slotName": "home-banner", "isCampaignBased": False,
    "isPublished": True, "publishUp": None, "publishDown": None, "filterCount": 1, "language": "en", "category": {"id": 3, "title": "Web"},
    "content": "<p>Hello India</p>", "filters": [{"glue": "and", "field": "country", "object": "lead", "type": "country", "operator": "=", "filter": "India"}],
    "utmTags": {"utmSource": "imaa"}, "stats": {"shown": 4, "contacts": 2}, "dateAdded": "2026-11-04T09:00:00+00:00",
}
RULE = {"field": "country", "operator": "=", "filter": "India"}


def pairs_dict(pairs):
    return dict(pairs)


class FieldTests(SimpleTestCase):
    def test_rules_mode_needs_a_slot_and_a_rule_and_starts_unpublished(self):
        pairs = pairs_dict(svc.bridge_form({"name": " Banner ", "slotName": "home-banner", "filters": [RULE], "content": "<p>Hi</p>"}))
        self.assertEqual((pairs["name"], pairs["type"], pairs["isCampaignBased"], pairs["isPublished"], pairs["slotName"]),
                         ("Banner", "html", "0", "0", "home-banner"))
        self.assertEqual(json.loads(pairs["filters"]), [{"glue": "and", "field": "country", "operator": "=", "filter": "India"}])
        for data, field in (({"name": "B", "filters": [RULE]}, "slotName"), ({"name": "B", "slotName": "s"}, "filters"),
                            ({"name": "B", "slotName": "bad slot", "filters": [RULE]}, "slotName")):
            with self.subTest(data=data), self.assertRaises(svc.DynamicContentError) as raised:
                svc.bridge_form(data)
            self.assertEqual(raised.exception.field, field)

    def test_campaign_mode_needs_neither_slot_nor_rules(self):
        pairs = pairs_dict(svc.bridge_form({"name": "Camp", "isCampaignBased": True, "content": "x"}))
        self.assertEqual(pairs["isCampaignBased"], "1")
        self.assertNotIn("slotName", pairs)

    def test_rules_follow_what_mautic_can_check_for_a_visitor(self):
        base = {"name": "B", "slotName": "s"}
        for rule, message in (
            ({"field": "city", "operator": "between", "filter": "a"}, "cannot be checked"),
            ({"field": "city", "operator": "inLast", "filter": "a"}, "cannot be checked"),
            ({"field": "", "operator": "=", "filter": "a"}, "choose a contact field"),
            ({"field": "city", "operator": "=", "filter": " "}, "enter a value"),
            ({"field": "city", "operator": "in", "filter": []}, "at least one value"),
            ({"field": "city", "operator": "regexp", "filter": "(["}, "pattern is not valid"),
        ):
            with self.subTest(rule=rule), self.assertRaises(svc.DynamicContentError) as raised:
                svc.bridge_form({**base, "filters": [rule]})
            self.assertIn(message, str(raised.exception))
        with self.assertRaises(svc.DynamicContentError):
            svc.bridge_form({**base, "filters": [RULE] * 21})
        rules = json.loads(pairs_dict(svc.bridge_form({**base, "filters": [
            {"field": "city", "operator": "empty", "filter": "ignored"},
            {"glue": "or", "field": "country", "operator": "in", "filter": ["India", " ", "Japan"]},
            {"glue": "or", "field": "city", "operator": "=", "properties": {"filter": "Pune"}},
        ]}))["filters"])
        self.assertEqual([(r["glue"], r["operator"], r["filter"]) for r in rules],
                         [("and", "empty", None), ("or", "in", ["India", "Japan"]), ("or", "=", "Pune")])

    def test_content_runs_no_script_and_cannot_nest(self):
        base = {"name": "B", "isCampaignBased": True}
        for content in ("<p>x</p><script>alert(1)</script>", '<a href="javascript:alert(1)">x</a>', '<img src=x onerror="a()">', "{dwc=other}"):
            with self.subTest(content=content), self.assertRaises(svc.DynamicContentError) as raised:
                svc.bridge_form({**base, "content": content})
            self.assertEqual(raised.exception.field, "content")
        html = '<h2>Hi {contactfield=firstname}</h2><img src="https://x.test/a.png" alt=""><a href="https://x.test">x</a>'
        self.assertEqual(pairs_dict(svc.bridge_form({**base, "content": html}))["content"], html)

    def test_update_checks_against_the_stored_item(self):
        self.assertEqual(svc.bridge_form({"content": "<p>new</p>"}, current=ITEM), [("content", "<p>new</p>")])
        # Switching to a campaign drops the need for a slot and rules.
        pairs = pairs_dict(svc.bridge_form({"isCampaignBased": True, "slotName": "", "filters": []}, current=ITEM))
        self.assertEqual((pairs["isCampaignBased"], pairs["slotName"], pairs["filters"]), ("1", "", "[]"))
        with self.assertRaises(svc.DynamicContentError) as raised:
            svc.bridge_form({"filters": []}, current=ITEM)
        self.assertEqual(raised.exception.field, "filters")
        with self.assertRaises(svc.DynamicContentError) as raised:
            svc.bridge_form({}, current=ITEM)
        self.assertEqual(raised.exception.code, "no_changes")

    def test_category_and_window(self):
        with patch("newsletter.dynamic_content_services.category_choice", return_value=3) as check:
            pairs = pairs_dict(svc.bridge_form({"name": "B", "isCampaignBased": True, "category": 3,
                                                "publishUp": "2026-11-05T10:00:00+05:30", "publishDown": None}))
        self.assertEqual(check.call_args.args[:2], (3, "dynamicContent"))
        self.assertEqual((pairs["category"], pairs["publishUp"], pairs["publishDown"]), ("3", "2026-11-05 04:30", ""))

    def test_duplicate_and_place_codes(self):
        copy = svc.duplicate_payload(ITEM)
        self.assertEqual((copy["name"], copy["isPublished"], copy["slotName"], copy["category"], copy["content"]),
                         ("Copy of India banner", False, "home-banner", 3, "<p>Hello India</p>"))
        place = svc.place_codes(ITEM, "https://m.example")
        self.assertEqual(place["token"], "{dwc=home-banner}")
        self.assertIn('data-slot="dwc" data-param-slot-name="home-banner"', place["slot"])
        self.assertIn("'https://m.example/mtc.js'", place["tracking"])
        campaign = svc.place_codes({**ITEM, "isCampaignBased": True}, None)
        self.assertEqual((campaign["slot"], campaign["token"], campaign["tracking"]), (None, None, None))

    def test_rule_metadata_keeps_contact_fields_and_visitor_operators(self):
        metadata = {"objects": ["lead"], "operators": [{"value": "="}, {"value": "between"}], "glue": ["and", "or"], "source": "x", "fields": [
            {"alias": "city", "object": "lead", "operators": [{"value": "="}, {"value": "between"}]},
            {"alias": "tags", "object": "lead", "operators": [{"value": "in"}]},
            {"alias": "leadlist", "object": "lead", "operators": [{"value": "in"}]},
            {"alias": "companyname", "object": "company", "operators": [{"value": "="}]},
            {"alias": "date_added", "object": "lead", "operators": [{"value": "between"}]},
        ]}
        with patch("newsletter.dynamic_content_services.marketing_cache.segment_filter_metadata", return_value=metadata), \
                patch("newsletter.dynamic_content_services.marketing_cache.fields",
                      return_value={"fields": {"1": {"alias": "city"}, "2": {"alias": "date_added"}}}):
            result = svc.rule_metadata(Mock())
        self.assertEqual([(f["alias"], [o["value"] for o in f["operators"]]) for f in result["fields"]], [("city", ["="])])
        self.assertEqual(result["operators"], [{"value": "="}])


class ConnectionRuleTests(SimpleTestCase):
    CAPS = {
        "actions": [{"key": "dwc.push_content", "label": "Push dynamic content"}, {"key": "focus.show", "label": "Show focus item"},
                    {"key": "email.send", "label": "Send email"}],
        "decisions": [{"key": "dwc.decision", "label": "Request dynamic content"}, {"key": "page.pagehit", "label": "Visits a page"},
                      {"key": "email.open", "label": "Opens email"}],
        "conditions": [],
        "connectionRestrictions": {
            "anchor": {"decision": {"dwc.push_content": ["inaction"], "focus.show": ["inaction"]}},
            "dwc.push_content": {"source": {"action": [], "condition": [], "decision": ["dwc.decision"]}, "target": {}},
            "focus.show": {"source": {"action": [], "condition": [], "decision": ["page.pagehit"]}, "target": {}},
            "email.open": {"source": {"action": ["email.send"], "condition": [], "decision": []}, "target": {}},
            "dwc.decision": {"source": {}, "target": {}},
        },
    }

    def check(self, events):
        _validate_connection_rules(events, self.CAPS)

    def test_steps_where_mautic_runs_them_are_accepted(self):
        self.check([
            {"id": "a", "type": "dwc.decision", "eventType": "decision"},
            {"id": "b", "type": "dwc.push_content", "eventType": "action", "parent": "a", "decisionPath": "yes"},
            {"id": "c", "type": "page.pagehit", "eventType": "decision"},
            {"id": "d", "type": "focus.show", "eventType": "action", "parent": "c", "decisionPath": "yes"},
            {"id": "e", "type": "email.send", "eventType": "action"},
            {"id": "f", "type": "email.open", "eventType": "decision", "parent": "e"},
        ])
        _validate_connection_rules([{"id": "b", "type": "dwc.push_content", "eventType": "action"}], None)  # no capabilities: no check

    def test_steps_where_mautic_never_runs_them_are_refused(self):
        for events, message in (
            ([{"id": "b", "type": "dwc.push_content", "eventType": "action"}],
             '"Push dynamic content" cannot start the campaign: it must follow "Request dynamic content".'),
            ([{"id": "c", "type": "page.pagehit", "eventType": "decision"},
              {"id": "b", "type": "dwc.push_content", "eventType": "action", "parent": "c", "decisionPath": "yes"}],
             '"Push dynamic content" can only follow "Request dynamic content", not "Visits a page".'),
            ([{"id": "c", "type": "page.pagehit", "eventType": "decision"},
              {"id": "d", "type": "focus.show", "eventType": "action", "parent": "c", "decisionPath": "no"}],
             '"Show focus item" can only be on the YES path of "Visits a page".'),
            ([{"id": "f", "type": "email.open", "eventType": "decision"}],
             '"Opens email" cannot start the campaign: it must follow "Send email".'),
        ):
            with self.subTest(message=message), self.assertRaises(ValueError) as raised:
                self.check(events)
            self.assertEqual(str(raised.exception), message)


class DynamicContentClientTests(SimpleTestCase):
    def test_writes_require_the_admins_identity(self):
        session = Mock()
        client = MauticClient(session=session)
        for call in (lambda: client.create_dynamic_content([]), lambda: client.update_dynamic_content(1, []), lambda: client.delete_dynamic_content(1)):
            with self.assertRaises(MauticIdentityConfigurationError):
                call()
        session.request.assert_not_called()

    def test_writes_go_to_the_bridge_and_reads_validate_their_shape(self):
        session = Mock()
        session.request.return_value = response(201, {"dynamicContent": ITEM})
        provider = Mock(return_value="signed.jwt")
        client = MauticClient(session=session, assertion_provider=provider)
        client.create_dynamic_content([("name", "B"), ("filters", "[]")])
        self.assertTrue(session.request.call_args.args[1].endswith("/api/ecp/bridge/dynamic-content/new"))
        self.assertEqual(session.request.call_args.kwargs["data"], [("name", "B"), ("filters", "[]")])
        client.update_dynamic_content(5, [("content", "x")])
        self.assertTrue(session.request.call_args.args[1].endswith("/api/ecp/bridge/dynamic-content/5/edit"))
        client.delete_dynamic_content(5)
        self.assertEqual([c.args[0] for c in provider.call_args_list], [DYNAMIC_CONTENT_CREATE, DYNAMIC_CONTENT_UPDATE, DYNAMIC_CONTENT_DELETE])
        self.assertTrue({DYNAMIC_CONTENT_CREATE, DYNAMIC_CONTENT_UPDATE, DYNAMIC_CONTENT_DELETE} <= ASSERTABLE_OPERATIONS)
        with self.assertRaises(PermanentMauticError):
            client.get_dynamic_content("5/../x")
        reader = MauticClient(session=Mock())
        reader.session.request.return_value = response(200, {"slots": "x"})
        with self.assertRaises(TemporaryMauticError):
            reader.get_dynamic_content_slots()
        reader.session.request.return_value = response(200, {"total": 1, "dynamicContents": {}})
        with self.assertRaises(TemporaryMauticError):
            reader.list_dynamic_contents()


@override_settings(**LOCMEM)
class DynamicContentApiTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="dwc-admin", email="da@example.test", password="x")
        grant_marketing_access(self.admin)
        self.api = APIClient()
        self.api.force_authenticate(self.admin)
        for target, value in (("newsletter.dynamic_content_views.mautic_public_base_url", "https://m.example"),
                              ("newsletter.dynamic_content_services.category_choice", 3)):
            patcher = patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def mutation_returning(self, result):
        def mutation(request, action, resource_id, mutate, **kwargs):
            client = Mock()
            client.create_dynamic_content.return_value = result
            client.update_dynamic_content.return_value = result
            client.delete_dynamic_content.return_value = None
            value = mutate(client)
            self.sent = client.method_calls[0].args[-1]
            return value, None
        return mutation

    def test_create_runs_as_the_admin_and_returns_how_to_place_it(self):
        with patch("newsletter.dynamic_content_views._mutation", side_effect=self.mutation_returning(ITEM)) as run:
            r = self.api.post(reverse("newsletter-admin-dynamic-content-list"),
                              {"name": "India banner", "slotName": "home-banner", "filters": [RULE], "content": "<p>Hello India</p>"}, format="json")
        self.assertEqual(r.status_code, 201, r.content)
        self.assertEqual((r.json()["place"]["token"], r.json()["isLive"]), ("{dwc=home-banner}", True))
        self.assertEqual((run.call_args.args[1], run.call_args.kwargs["detail"]), (DYNAMIC_CONTENT_CREATE, "India banner"))
        self.assertEqual(dict(self.sent)["content"], "<p>Hello India</p>")

    def test_bad_settings_never_reach_mautic(self):
        with patch("newsletter.dynamic_content_views._mutation") as run:
            for data in ({"name": "B", "filters": [RULE]}, {"name": "B", "slotName": "s", "filters": [{"field": "city", "operator": "between", "filter": "a"}]},
                         {"name": "B", "isCampaignBased": True, "content": "<script>x</script>"}):
                r = self.api.post(reverse("newsletter-admin-dynamic-content-list"), data, format="json")
                self.assertEqual(r.status_code, 400)
                self.assertIn("field", r.json())
        run.assert_not_called()

    def test_update_refusals_and_provider_errors(self):
        detail = reverse("newsletter-admin-dynamic-content-detail", args=[5])
        with patch.object(MauticClient, "get_dynamic_content", return_value=ITEM):
            with patch("newsletter.dynamic_content_views._mutation", side_effect=self.mutation_returning({**ITEM, "content": "<p>x</p>"})) as run:
                r = self.api.patch(detail, {"content": "<p>x</p>"}, format="json")
            self.assertEqual((r.status_code, r.json()["content"], run.call_args.args[1]), (200, "<p>x</p>", DYNAMIC_CONTENT_UPDATE))
            self.assertEqual(self.sent, [("content", "<p>x</p>")])
            for exc, code in ((PermanentMauticError("x (HTTP 400): type: This slot already has HTML content."), 400),
                              (PermanentMauticError("x (HTTP 404)"), 404), (TemporaryMauticError("down"), 502)):
                with self.subTest(code=code), patch("newsletter.dynamic_content_views._mutation", side_effect=exc):
                    self.assertEqual(self.api.patch(detail, {"name": "y"}, format="json").status_code, code)
            with patch("newsletter.dynamic_content_views._mutation", return_value=(None, Response({"detail": "no"}, status=403))):
                self.assertEqual(self.api.patch(detail, {"name": "y"}, format="json").status_code, 403)

    def test_delete_is_refused_while_a_campaign_uses_it_and_fails_closed(self):
        detail = reverse("newsletter-admin-dynamic-content-detail", args=[5])
        used = {"totals": {}, "daily": [], "usage": {"campaigns": [{"id": 9, "name": "Welcome", "roles": ["pushed"]}], "pages": []}}
        with patch.object(MauticClient, "get_dynamic_content_insights", return_value=used), patch("newsletter.dynamic_content_views._mutation") as run:
            r = self.api.delete(detail)
        self.assertEqual((r.status_code, r.json()["code"]), (409, "dynamic_content_in_use"))
        run.assert_not_called()
        with patch.object(MauticClient, "get_dynamic_content_insights", side_effect=TemporaryMauticError("down")), \
                patch("newsletter.dynamic_content_views._mutation") as run:
            self.assertEqual(self.api.delete(detail).status_code, 502)
        run.assert_not_called()
        # Pages showing its slot do not block: they fall back to their default text.
        pages_only = {"totals": {}, "daily": [], "usage": {"campaigns": [], "pages": [{"id": 2, "title": "Home"}]}}
        with patch.object(MauticClient, "get_dynamic_content_insights", return_value=pages_only), \
                patch("newsletter.dynamic_content_views._mutation", side_effect=self.mutation_returning(None)) as run:
            self.assertEqual(self.api.delete(detail).status_code, 204)
        self.assertEqual(run.call_args.args[1], DYNAMIC_CONTENT_DELETE)

    def test_duplicate_list_insights_slots_and_metadata(self):
        with patch.object(MauticClient, "get_dynamic_content", return_value=ITEM), \
                patch("newsletter.dynamic_content_views._mutation", side_effect=self.mutation_returning({**ITEM, "id": 6, "name": "Copy of India banner"})):
            r = self.api.post(reverse("newsletter-admin-dynamic-content-duplicate", args=[5]))
        self.assertEqual((r.status_code, r.json()["id"]), (201, 6))
        sent = dict(self.sent)
        self.assertEqual((sent["name"], sent["isPublished"], sent["slotName"], sent["content"]), ("Copy of India banner", "0", "home-banner", "<p>Hello India</p>"))
        with patch.object(MauticClient, "list_dynamic_contents", return_value={"total": 30, "dynamicContents": [ITEM]}) as listing:
            body = self.api.get(reverse("newsletter-admin-dynamic-content-list"), {"page": 2, "page_size": 10, "search": " ban ", "status": "published",
                                                                                 "mode": "rules"}).json()
        self.assertEqual((body["count"], body["num_pages"], body["results"][0]["isLive"]), (30, 3, True))
        self.assertEqual(listing.call_args.kwargs, {"start": 10, "limit": 10, "search": "ban", "status": "published", "mode": "rules"})
        with patch.object(MauticClient, "get_dynamic_content_insights", return_value={"totals": {}, "daily": [], "usage": {}}) as insights:
            self.assertEqual(self.api.get(reverse("newsletter-admin-dynamic-content-insights", args=[5]), {"days": 999}).status_code, 200)
        self.assertEqual(insights.call_args.kwargs["days"], 365)
        with patch.object(MauticClient, "get_dynamic_content_slots", return_value=[{"slot": "home-banner"}]):
            self.assertEqual(self.api.get(reverse("newsletter-admin-dynamic-content-slots")).json(), {"count": 1, "results": [{"slot": "home-banner"}]})
        with patch("newsletter.dynamic_content_views.rule_metadata", return_value={"fields": []}):
            self.assertEqual(self.api.get(reverse("newsletter-admin-dynamic-content-rule-metadata")).json(), {"fields": []})

    def test_non_marketing_users_are_denied(self):
        normal = APIClient()
        normal.force_authenticate(User.objects.create_user(username="dwc-normal", email="dn@example.test", password="x"))
        for url in (reverse("newsletter-admin-dynamic-content-list"), reverse("newsletter-admin-dynamic-content-detail", args=[5]),
                    reverse("newsletter-admin-dynamic-content-slots"), reverse("newsletter-admin-dynamic-content-rule-metadata")):
            self.assertIn(normal.get(url).status_code, (401, 403))
