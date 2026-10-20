"""The "Clicks email" decision may be saved with no URL limit (any link).

Mautic 7.1.3 (EmailBundle CampaignSubscriber::onCampaignTriggerDecision) runs
``email.click`` for any tracked link of the parent Send email when
``urls.list`` is empty or absent, and otherwise only when the clicked URL
contains one of the entries (UrlMatcher::hasMatch, a string-typed matcher).
"""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.tests.marketing_actors import grant_marketing_access


User = get_user_model()

# email.send and email.click as Mautic 7.1.3's capability endpoint reports them.
CAPABILITIES = {
    "actions": [
        {
            "key": "email.send", "type": "email.send", "eventType": "action", "label": "Send email",
            "formSchema": {"available": True, "fields": [
                {"name": "email", "label": "Email to send", "required": True, "renderable": True,
                 "choices": [{"label": "Welcome (23)", "value": "23"}]},
                {"name": "email_type", "label": "Email type", "required": False, "renderable": True,
                 "data": "marketing", "choices": [{"label": "Transactional", "value": "transactional"},
                                                  {"label": "Marketing", "value": "marketing"}]},
            ]},
        },
        {
            "key": "lead.changetags", "type": "lead.changetags", "eventType": "action", "label": "Modify tags",
            "formSchema": {"available": True, "fields": [
                {"name": "add_tags", "label": "Add tags", "multiple": True, "renderable": True,
                 "choices": [{"label": "Gold", "value": "Gold"}]},
                {"name": "remove_tags", "label": "Remove tags", "multiple": True, "renderable": True,
                 "choices": [{"label": "Gold", "value": "Gold"}]},
            ]},
        },
    ],
    "decisions": [
        {
            "key": "email.click", "type": "email.click", "eventType": "decision", "label": "Clicks email",
            "formSchema": {"available": True, "fields": [
                {"name": "urls", "label": "Limit to Urls contains", "required": False, "renderable": True,
                 "type": "Mautic\\CoreBundle\\Form\\Type\\SortableListType",
                 "blockPrefixes": ["form", "sortablelist"], "data": {"list": []},
                 "children": [{"name": "list", "label": False, "required": False, "renderable": True,
                               "type": "Symfony\\Component\\Form\\Extension\\Core\\Type\\CollectionType",
                               "blockPrefixes": ["form", "collection"], "data": []}]},
            ]},
        },
    ],
    "conditions": [],
    "connectionRestrictions": {},
}


def events(click_properties, *, yes_child=True):
    rows = [
        {"id": "new_1", "key": "email.send", "eventType": "action",
         "properties": {"email": "23", "email_type": "marketing"}, "order": 1, "parent": None,
         "triggerMode": "immediate"},
        {"id": "new_2", "key": "email.click", "eventType": "decision", "properties": click_properties,
         "order": 2, "parent": "new_1"},
    ]
    if yes_child:
        rows.append({"id": "new_3", "key": "lead.changetags", "eventType": "action",
                     "properties": {"add_tags": ["Gold"]}, "order": 3, "parent": "new_2",
                     "decisionPath": "yes", "triggerMode": "immediate"})
    return rows


class ClickDecisionValidationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        staff = User.objects.create_user(username="click-staff", email="click-staff@example.test",
                                         password="pw", is_staff=True, is_superuser=True)
        grant_marketing_access(staff)
        self.client.force_authenticate(user=staff)

    def _create(self, client_cls, rows):
        client_cls.return_value.get_campaign_builder_capabilities.return_value = CAPABILITIES
        client_cls.return_value.create_campaign.return_value = {"id": 9, "name": "Click", "events": []}
        return self.client.post(reverse("newsletter-admin-mautic-campaign-list"), {
            "name": "Click", "isPublished": False, "sources": {"segments": [10], "forms": []},
            "events": rows, "canvasSettings": {"nodes": [], "connections": []},
        }, format="json")

    def _sent_click(self, client_cls):
        payload = client_cls.return_value.create_campaign.call_args.args[0]
        return next(e for e in payload["events"] if e["type"] == "email.click"), payload

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_any_link_decision_with_no_url_limit_is_accepted(self, client_cls):
        for properties in ({}, {"urls": {"list": []}}, {"urls": {"list": ""}}, {"urls": {}}):
            with self.subTest(properties=properties):
                response = self._create(client_cls, events(properties))
                self.assertEqual(response.status_code, 201, response.data)
                click, _ = self._sent_click(client_cls)
                self.assertEqual(click["properties"], properties, "forwarded unchanged")

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_specific_url_limits_are_preserved(self, client_cls):
        for properties in ({"urls": {"list": ["https://example.test/one"]}},
                           {"urls": {"list": ["example.test/one", "example.test/two"]}},
                           {"urls": {"list": "https://example.test/one"}}):
            with self.subTest(properties=properties):
                response = self._create(client_cls, events(properties))
                self.assertEqual(response.status_code, 201, response.data)
                click, _ = self._sent_click(client_cls)
                self.assertEqual(click["properties"], properties)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_invalid_url_configurations_are_rejected(self, client_cls):
        for properties in ({"urls": "https://example.test/one"}, {"urls": {"list": [5]}},
                           {"urls": {"list": ["", "example.test/one"]}}, {"urls": {"list": ["   "]}},
                           {"urls": {"list": [{"url": "x"}]}}):
            with self.subTest(properties=properties):
                response = self._create(client_cls, events(properties))
                self.assertEqual(response.status_code, 400)
        client_cls.return_value.create_campaign.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_other_events_still_need_configuration(self, client_cls):
        rows = events({})
        rows[2]["properties"] = {}
        response = self._create(client_cls, rows)

        self.assertEqual(response.status_code, 400)
        self.assertIn("needs at least one of", response.data["detail"])

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_yes_no_paths_parents_and_email_safety_are_unchanged(self, client_cls):
        rows = events({})
        rows.append({"id": "new_4", "key": "lead.changetags", "eventType": "action",
                     "properties": {"remove_tags": ["Gold"]}, "order": 4, "parent": "new_2",
                     "decisionPath": "no", "triggerMode": "interval", "triggerInterval": 1,
                     "triggerIntervalUnit": "d"})
        response = self._create(client_cls, rows)

        self.assertEqual(response.status_code, 201, response.data)
        _, payload = self._sent_click(client_cls)
        by_id = {e["id"]: e for e in payload["events"]}
        self.assertEqual(by_id["new_2"]["parent"], "new_1")
        self.assertEqual((by_id["new_3"]["decisionPath"], by_id["new_4"]["decisionPath"]), ("yes", "no"))
        self.assertEqual((by_id["new_4"]["triggerInterval"], by_id["new_4"]["triggerIntervalUnit"]), (1, "d"))
        self.assertEqual(by_id["new_1"]["properties"]["email_type"], "marketing")
        anchors = {c["targetId"]: c["anchors"]["source"] for c in payload["canvasSettings"]["connections"]}
        self.assertEqual((anchors["new_3"], anchors["new_4"]), ("yes", "no"))

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_unconfirmed_transactional_send_is_still_refused(self, client_cls):
        rows = events({})
        rows[0]["properties"]["email_type"] = "transactional"
        response = self._create(client_cls, rows)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], "transactional_email_confirmation_required")
