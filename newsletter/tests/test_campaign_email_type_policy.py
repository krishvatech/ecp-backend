"""Send email actions keep an explicit Mautic email type.

Mautic 7.1.3 sends an ``email.send`` campaign action stored without
``email_type`` as transactional (Do Not Contact ignored, no repeat-send guard),
so ECP must never save a new one without it, and must never silently reclassify
a saved one.
"""

import copy
import json
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.campaign_email_types import (
    CONFIRMATION_REQUIRED_CODE,
    TransactionalEmailConfirmationRequired,
    apply_email_type_policy,
    classify_email_type,
    stored_email_types,
)
from newsletter.tests.marketing_actors import grant_marketing_access


User = get_user_model()


def _capabilities():
    return {
        "actions": [
            {
                "key": "email.send",
                "type": "email.send",
                "eventType": "action",
                "label": "Send email",
                "formSchema": {
                    "available": True,
                    "fields": [
                        {
                            "name": "email",
                            "label": "Email to send",
                            "required": True,
                            "renderable": True,
                            "choices": [{"label": "QA Email (23)", "value": "23"}],
                        },
                        {
                            # As Mautic 7.1.3's capability reports it.
                            "name": "email_type",
                            "label": "Email type",
                            "required": False,
                            "renderable": True,
                            "data": "marketing",
                            "choices": [
                                {"label": "Transactional", "value": "transactional"},
                                {"label": "Marketing", "value": "marketing"},
                            ],
                        },
                        {
                            "name": "priority",
                            "label": "Priority",
                            "renderable": True,
                            "choices": [
                                {"label": "Normal", "value": "2"},
                                {"label": "High", "value": "1"},
                            ],
                        },
                        {"name": "attempts", "label": "Attempts", "renderable": True},
                    ],
                },
            },
            {
                "key": "lead.changepoints",
                "type": "lead.changepoints",
                "eventType": "action",
                "label": "Adjust contact points",
                "formTypeOptions": {"points": {"required": False}},
            },
        ],
        "conditions": [
            {
                "key": "lead.field_value",
                "type": "lead.field_value",
                "eventType": "condition",
                "label": "Contact field value",
            }
        ],
        "decisions": [],
        "connectionRestrictions": {},
    }


def _send(event_id="new_1", **properties):
    return {
        "id": event_id,
        "key": "email.send",
        "eventType": "action",
        "properties": {"email": "23", **properties},
        "order": 1,
        "parent": None,
        "triggerMode": "immediate",
    }


class EmailTypeApiTestBase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="email-type-staff",
            email="email-type-staff@example.test",
            password="test-password",
            is_staff=True,
            is_superuser=True,
        )
        grant_marketing_access(self.staff)
        self.client.force_authenticate(user=self.staff)
        self.list_url = reverse("newsletter-admin-mautic-campaign-list")
        self.detail_url = reverse("newsletter-admin-mautic-campaign-detail", args=["7"])

    def _create(self, client_cls, events):
        client = client_cls.return_value
        client.get_campaign_builder_capabilities.return_value = _capabilities()
        client.create_campaign.return_value = {"id": 7, "name": "Lead nurture", "events": []}
        return self.client.post(
            self.list_url,
            {
                "name": "Lead nurture",
                "isPublished": False,
                "sources": {"segments": [10], "forms": []},
                "events": events,
                "canvasSettings": {"nodes": [], "connections": []},
            },
            format="json",
        )

    def _update(self, client_cls, events, stored_events, **fields):
        client = client_cls.return_value
        client.get_campaign_builder_capabilities.return_value = _capabilities()
        client.get_campaign.return_value = {"id": 7, "events": stored_events}
        client.update_campaign.return_value = {"id": 7, "name": "Lead nurture", "events": []}
        body = {
            "name": "Lead nurture",
            "sources": {"segments": [10], "forms": []},
            "events": events,
            "canvasSettings": {"nodes": [], "connections": []},
        }
        body.update(fields)
        return self.client.patch(self.detail_url, body, format="json")

    @staticmethod
    def _created(client_cls):
        return client_cls.return_value.create_campaign.call_args.args[0]

    @staticmethod
    def _updated(client_cls):
        return client_cls.return_value.update_campaign.call_args.args[1]


class NewEmailSendActionTests(EmailTypeApiTestBase):
    @patch("newsletter.native_campaign_views.MauticClient")
    def test_new_action_without_type_is_saved_as_marketing(self, client_cls):
        response = self._create(client_cls, [_send()])

        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(
            self._created(client_cls)["events"][0]["properties"],
            {"email": "23", "email_type": "marketing"},
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_blank_type_on_new_action_is_saved_as_marketing(self, client_cls):
        response = self._create(client_cls, [_send(email_type="")])

        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(
            self._created(client_cls)["events"][0]["properties"]["email_type"],
            "marketing",
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_explicit_marketing_and_other_properties_are_kept(self, client_cls):
        response = self._create(
            client_cls,
            [_send(email_type="marketing", priority="1", attempts="5")],
        )

        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(
            self._created(client_cls)["events"][0]["properties"],
            {"email": "23", "email_type": "marketing", "priority": "1", "attempts": "5"},
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_new_transactional_action_requires_confirmation(self, client_cls):
        response = self._create(client_cls, [_send(email_type="transactional")])

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], CONFIRMATION_REQUIRED_CODE)
        self.assertEqual(response.data["events"], [{"id": "new_1", "name": "Send email"}])
        self.assertIn("Do Not Contact", response.data["detail"])
        client_cls.return_value.create_campaign.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_confirmed_transactional_is_saved_and_flag_is_not_forwarded(self, client_cls):
        event = _send(email_type="transactional")
        event["transactionalEmailConfirmed"] = True

        response = self._create(client_cls, [event])

        self.assertEqual(response.status_code, 201, response.data)
        sent = self._created(client_cls)["events"][0]
        self.assertEqual(sent["properties"]["email_type"], "transactional")
        self.assertNotIn("transactionalEmailConfirmed", sent)
        self.assertNotIn("transactionalEmailConfirmed", json.dumps(self._created(client_cls)))

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_confirmation_must_be_literally_true(self, client_cls):
        event = _send(email_type="transactional")
        event["transactionalEmailConfirmed"] = "yes"

        response = self._create(client_cls, [event])

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], CONFIRMATION_REQUIRED_CODE)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_unsupported_type_is_rejected(self, client_cls):
        for value in ("Marketing", "list", "template", 1, True):
            with self.subTest(value=value):
                response = self._create(client_cls, [_send(email_type=value)])
                self.assertEqual(response.status_code, 400)
        client_cls.return_value.create_campaign.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_other_actions_are_untouched(self, client_cls):
        response = self._create(
            client_cls,
            [
                {
                    "id": "new_1",
                    "key": "lead.changepoints",
                    "eventType": "action",
                    "properties": {"points": 5},
                }
            ],
        )

        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(self._created(client_cls)["events"][0]["properties"], {"points": 5})


class SavedEmailSendActionTests(EmailTypeApiTestBase):
    @staticmethod
    def _stored(event_id=12, **properties):
        return {
            "id": event_id,
            "type": "email.send",
            "eventType": "action",
            "properties": {"email": "23", **properties},
        }

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_unrelated_field_update_does_not_read_or_rewrite_events(self, client_cls):
        client_cls.return_value.update_campaign.return_value = {"id": 7, "events": []}

        response = self.client.patch(self.detail_url, {"name": "Renamed"}, format="json")

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self._updated(client_cls), {"name": "Renamed"})
        client_cls.return_value.get_campaign.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_unpublish_does_not_touch_events(self, client_cls):
        client_cls.return_value.update_campaign.return_value = {"id": 7, "events": []}

        response = self.client.patch(self.detail_url, {"isPublished": False}, format="json")

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self._updated(client_cls), {"isPublished": False})

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_legacy_action_without_type_is_preserved_on_save(self, client_cls):
        response = self._update(
            client_cls,
            [_send("12", priority="1")],
            [self._stored(priority="1")],
            name="Renamed",
        )

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(
            self._updated(client_cls)["events"][0]["properties"],
            {"email": "23", "priority": "1"},
        )
        client_cls.return_value.get_campaign.assert_called_once_with("7")

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_legacy_action_resolved_to_marketing_explicitly(self, client_cls):
        response = self._update(
            client_cls, [_send("12", email_type="marketing")], [self._stored()]
        )

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(
            self._updated(client_cls)["events"][0]["properties"]["email_type"],
            "marketing",
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_legacy_action_resolved_to_transactional_needs_confirmation(self, client_cls):
        response = self._update(
            client_cls, [_send("12", email_type="transactional")], [self._stored()]
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], CONFIRMATION_REQUIRED_CODE)
        client_cls.return_value.update_campaign.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_stored_transactional_action_is_kept_without_reconfirmation(self, client_cls):
        response = self._update(
            client_cls,
            [_send("12", email_type="transactional")],
            [self._stored(email_type="transactional")],
        )

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(
            self._updated(client_cls)["events"][0]["properties"]["email_type"],
            "transactional",
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_marketing_to_transactional_needs_confirmation(self, client_cls):
        response = self._update(
            client_cls,
            [_send("12", email_type="transactional")],
            [self._stored(email_type="marketing")],
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], CONFIRMATION_REQUIRED_CODE)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_stored_type_dropped_by_request_is_restored(self, client_cls):
        response = self._update(
            client_cls, [_send("12")], [self._stored(email_type="marketing")]
        )

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(
            self._updated(client_cls)["events"][0]["properties"],
            {"email": "23", "email_type": "marketing"},
        )

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_new_action_next_to_saved_one_defaults_alone(self, client_cls):
        response = self._update(
            client_cls,
            [_send("12"), {**_send("new_2"), "order": 2}],
            [self._stored()],
        )

        self.assertEqual(response.status_code, 200, response.data)
        events = self._updated(client_cls)["events"]
        self.assertEqual([event["id"] for event in events], ["12", "new_2"])
        self.assertNotIn("email_type", events[0]["properties"])
        self.assertEqual(events[1]["properties"]["email_type"], "marketing")

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_graph_ids_timing_and_decision_paths_are_unchanged(self, client_cls):
        events = [
            {
                "id": "5",
                "key": "lead.field_value",
                "eventType": "condition",
                "properties": {},
                "order": 1,
                "parent": None,
                "triggerMode": "immediate",
            },
            {
                **_send("12"),
                "order": 2,
                "parent": "5",
                "decisionPath": "yes",
                "triggerMode": "interval",
                "triggerInterval": 2,
                "triggerIntervalUnit": "d",
            },
            {
                **_send("new_3"),
                "order": 3,
                "parent": "5",
                "decisionPath": "no",
                "triggerMode": "immediate",
            },
        ]
        submitted = copy.deepcopy(events)

        response = self._update(client_cls, events, [self._stored()])

        self.assertEqual(response.status_code, 200, response.data)
        sent = self._updated(client_cls)
        by_id = {event["id"]: event for event in sent["events"]}
        self.assertEqual(list(by_id), ["5", "12", "new_3"])
        for original in submitted:
            event = by_id[original["id"]]
            for field in ("parent", "decisionPath", "triggerMode", "triggerInterval",
                          "triggerIntervalUnit", "order"):
                self.assertEqual(event.get(field), original.get(field), (original["id"], field))
        self.assertEqual(by_id["12"]["properties"], {"email": "23"})
        self.assertEqual(by_id["new_3"]["properties"]["email_type"], "marketing")
        anchors = {
            connection["targetId"]: connection["anchors"]["source"]
            for connection in sent["canvasSettings"]["connections"]
        }
        self.assertEqual(anchors["12"], "yes")
        self.assertEqual(anchors["new_3"], "no")

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_reload_returns_the_saved_type(self, client_cls):
        client = client_cls.return_value
        client.get_campaign.return_value = {
            "id": 7,
            "name": "Lead nurture",
            "isPublished": False,
            "lists": [{"id": 10, "name": "Leads"}],
            "forms": [],
            "events": [
                {
                    **self._stored(email_type="marketing", priority=2),
                    "name": "Send email",
                    "order": 1,
                    "parent": None,
                    "triggerMode": "immediate",
                }
            ],
            "canvasSettings": {"nodes": [], "connections": []},
        }
        client.get_campaign_event_states.return_value = {"activeEventIds": [12]}

        response = self.client.get(
            reverse("newsletter-admin-mautic-campaign-builder", args=["7"])
        )

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(
            response.data["events"][0]["properties"],
            {"email": "23", "email_type": "marketing", "priority": 2},
        )


class EmailTypePolicyUnitTests(SimpleTestCase):
    def test_raw_provider_event_shape_is_covered(self):
        events = [{"id": "new_1", "type": "email.send", "eventType": "action", "properties": []}]

        apply_email_type_policy(events)

        self.assertEqual(events[0]["properties"], {"email_type": "marketing"})

    def test_confirmation_flag_is_removed_from_every_event(self):
        events = [
            {"id": "new_1", "type": "lead.changepoints", "eventType": "action",
             "properties": {}, "transactionalEmailConfirmed": True},
        ]

        apply_email_type_policy(events)

        self.assertNotIn("transactionalEmailConfirmed", events[0])

    def test_unconfirmed_events_are_all_listed(self):
        events = [
            {"id": "new_1", "name": "Receipt", "type": "email.send", "eventType": "action",
             "properties": {"email_type": "transactional"}},
            {"id": "new_2", "name": "Invoice", "type": "email.send", "eventType": "action",
             "properties": {"email_type": "transactional"}},
        ]

        with self.assertRaises(TransactionalEmailConfirmationRequired) as raised:
            apply_email_type_policy(events)

        self.assertEqual([event["id"] for event in raised.exception.events], ["new_1", "new_2"])

    def test_stored_types_and_classification(self):
        stored = stored_email_types(
            {
                "events": {
                    "1": {"id": 1, "type": "email.send", "properties": {"email": "2"}},
                    "2": {"id": 2, "type": "email.send", "properties": {"email_type": "marketing"}},
                    "3": {"id": 3, "type": "lead.changepoints", "properties": {}},
                }
            }
        )

        self.assertEqual(stored, {"1": None, "2": "marketing"})
        self.assertEqual(classify_email_type({}), "missing")
        self.assertEqual(classify_email_type([]), "missing")
        self.assertEqual(classify_email_type({"email_type": "transactional"}), "transactional")
        self.assertEqual(classify_email_type({"email_type": "bulk"}), "invalid")


class AuditCampaignEmailTypesCommandTests(SimpleTestCase):
    @patch("newsletter.management.commands.audit_campaign_email_types.MauticClient")
    def test_reports_types_and_never_writes(self, client_cls):
        client = client_cls.return_value
        client.list_campaigns.return_value = {
            "total": 1,
            "campaigns": {"54": {"id": 54}},
        }
        client.get_campaign.return_value = {
            "id": 54,
            "name": "Lead nurture",
            "isPublished": True,
            "events": {
                "72": {"id": 72, "name": "Welcome", "type": "email.send",
                       "properties": {"email": "5"}},
                "73": {"id": 73, "name": "Offer", "type": "email.send",
                       "properties": {"email": "6", "email_type": "marketing"}},
                "74": {"id": 74, "name": "Old", "type": "email.send",
                       "properties": {"email": "7"}},
                "75": {"id": 75, "name": "Points", "type": "lead.changepoints",
                       "properties": {"points": 1}},
            },
        }
        # 74 was deleted in Mautic.
        client.get_campaign_event_states.return_value = {"activeEventIds": [72, 73, 75]}
        out = StringIO()

        call_command("audit_campaign_email_types", "--json", stdout=out)

        report = json.loads(out.getvalue())
        self.assertEqual(report["mode"], "read-only")
        self.assertEqual(report["summary"]["missing"], 1)
        self.assertEqual(report["summary"]["marketing"], 1)
        self.assertEqual(report["summary"]["potentially_affected"], 1)
        rows = {row["event_id"]: row for row in report["events"]}
        self.assertEqual(sorted(rows), ["72", "73"])
        self.assertEqual(rows["72"]["email_type_state"], "missing")
        self.assertTrue(rows["72"]["campaign_published"])
        self.assertTrue(rows["72"]["potentially_affected"])
        self.assertFalse(rows["73"]["potentially_affected"])
        for method in ("update_campaign", "create_campaign", "delete_campaign",
                       "delete_campaign_event"):
            getattr(client, method).assert_not_called()


class PublishGateTests(EmailTypeApiTestBase):
    """A workflow is never put into service with an untyped Send email step."""

    @staticmethod
    def _stored(event_id=12, **properties):
        return {
            "id": event_id,
            "name": "Welcome",
            "type": "email.send",
            "eventType": "action",
            "properties": {"email": "23", **properties},
        }

    def _stub_stored(self, client_cls, events, *, published, active=None):
        client = client_cls.return_value
        client.get_campaign.return_value = {"id": 7, "isPublished": published, "events": events}
        client.get_campaign_event_states.return_value = {
            "activeEventIds": active if active is not None else [e["id"] for e in events]
        }
        client.update_campaign.return_value = {"id": 7, "name": "Lead nurture", "events": []}

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_new_campaign_published_on_create_gets_typed_steps(self, client_cls):
        client = client_cls.return_value
        client.get_campaign_builder_capabilities.return_value = _capabilities()
        client.create_campaign.return_value = {"id": 7, "name": "Lead nurture", "events": []}

        response = self.client.post(
            self.list_url,
            {
                "name": "Lead nurture",
                "isPublished": True,
                "sources": {"segments": [10], "forms": []},
                "events": [_send()],
                "canvasSettings": {"nodes": [], "connections": []},
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(self._created(client_cls)["events"][0]["properties"]["email_type"], "marketing")

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_publish_with_legacy_step_in_payload_is_refused(self, client_cls):
        response = self._update(client_cls, [_send("12")], [self._stored()], isPublished=True)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], "email_type_unresolved")
        self.assertEqual(response.data["events"], [{"id": "12", "name": "Send email", "state": "missing"}])
        self.assertIn("unpublishing it, is still possible", response.data["detail"])
        client_cls.return_value.update_campaign.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_publish_with_legacy_step_resolved_in_same_request_is_allowed(self, client_cls):
        response = self._update(
            client_cls, [_send("12", email_type="marketing")], [self._stored()], isPublished=True
        )

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self._updated(client_cls)["events"][0]["properties"]["email_type"], "marketing")

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_publish_only_request_checks_the_stored_active_workflow(self, client_cls):
        self._stub_stored(client_cls, [self._stored()], published=False)

        response = self.client.patch(self.detail_url, {"isPublished": True}, format="json")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], "email_type_unresolved")
        self.assertEqual(response.data["events"][0]["id"], "12")
        client_cls.return_value.update_campaign.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_publish_only_ignores_deleted_legacy_steps(self, client_cls):
        self._stub_stored(
            client_cls,
            [self._stored(12), self._stored(13, email_type="marketing")],
            published=False,
            active=[13],
        )

        response = self.client.patch(self.detail_url, {"isPublished": True}, format="json")

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self._updated(client_cls), {"isPublished": True})

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_publish_only_without_active_step_report_fails_closed(self, client_cls):
        self._stub_stored(client_cls, [self._stored()], published=False)
        client_cls.return_value.get_campaign_event_states.return_value = {}

        response = self.client.patch(self.detail_url, {"isPublished": True}, format="json")

        self.assertEqual(response.status_code, 502)
        client_cls.return_value.update_campaign.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_unpublishing_a_published_legacy_campaign_stays_possible(self, client_cls):
        self._stub_stored(client_cls, [self._stored()], published=True)

        response = self.client.patch(self.detail_url, {"isPublished": False}, format="json")

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self._updated(client_cls), {"isPublished": False})
        client_cls.return_value.get_campaign.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_draft_with_legacy_step_still_saves_unchanged(self, client_cls):
        response = self._update(client_cls, [_send("12")], [self._stored()], isPublished=False)

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self._updated(client_cls)["events"][0]["properties"], {"email": "23"})

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_workflow_change_on_published_campaign_is_checked(self, client_cls):
        client = client_cls.return_value
        client.get_campaign_builder_capabilities.return_value = _capabilities()
        client.get_campaign.return_value = {"id": 7, "isPublished": True, "events": [self._stored()]}
        client.update_campaign.return_value = {"id": 7, "events": []}
        body = {
            "sources": {"segments": [10], "forms": []},
            "canvasSettings": {"nodes": [], "connections": []},
        }

        refused = self.client.patch(self.detail_url, {**body, "events": [_send("12")]}, format="json")
        allowed = self.client.patch(
            self.detail_url, {**body, "events": [_send("12", email_type="marketing")]}, format="json"
        )

        self.assertEqual(refused.status_code, 400)
        self.assertEqual(refused.data["code"], "email_type_unresolved")
        self.assertEqual(allowed.status_code, 200, allowed.data)
        self.assertEqual(client.update_campaign.call_count, 1)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_rename_of_published_legacy_campaign_does_not_touch_events(self, client_cls):
        client_cls.return_value.update_campaign.return_value = {"id": 7, "events": []}

        response = self.client.patch(self.detail_url, {"name": "Renamed"}, format="json")

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self._updated(client_cls), {"name": "Renamed"})
        client_cls.return_value.get_campaign.assert_not_called()

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_transactional_confirmation_still_applies_when_publishing(self, client_cls):
        response = self._update(
            client_cls, [_send("12", email_type="transactional")], [self._stored()], isPublished=True
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], CONFIRMATION_REQUIRED_CODE)

    @patch("newsletter.native_campaign_views.MauticClient")
    def test_invalid_type_is_rejected_on_publish(self, client_cls):
        response = self._update(
            client_cls, [_send("12", email_type="bulk")], [self._stored()], isPublished=True
        )

        self.assertEqual(response.status_code, 400)
        client_cls.return_value.update_campaign.assert_not_called()


class DuplicateLegacyEmailTypeTests(TestCase):
    def setUp(self):
        from newsletter.tests.test_mautic_campaign_duplicate import FakeMautic

        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="dup-email-type", email="dup-email-type@example.test", password="pw",
            is_staff=True, is_superuser=True,
        )
        grant_marketing_access(self.staff)
        self.client.force_authenticate(user=self.staff)
        source = {
            "id": 88, "name": "Legacy nurture", "description": "", "isPublished": True,
            "allowRestart": False, "republishBehavior": None, "category": None,
            "publishUp": None, "publishDown": None,
            "lists": [{"id": 10, "name": "Leads", "alias": "leads"}], "forms": [],
            "events": [{
                "id": 301, "name": "Welcome", "description": None, "type": "email.send",
                "eventType": "action", "order": 1, "properties": {"email": "23"},
                "channel": None, "channelId": None, "children": [], "parent": None,
                "decisionPath": None, "triggerMode": "immediate", "triggerDate": None,
                "triggerInterval": 0, "triggerIntervalUnit": None, "triggerHour": None,
                "triggerRestrictedStartHour": None, "triggerRestrictedStopHour": None,
                "triggerRestrictedDaysOfWeek": [],
            }],
            "canvasSettings": {
                "nodes": [{"id": "lists", "positionX": 100, "positionY": 0},
                          {"id": "301", "positionX": 100, "positionY": 100}],
                "connections": [{"sourceId": "lists", "targetId": "301",
                                 "anchors": {"source": "leadsource", "target": "top"}}],
            },
        }
        self.fake = FakeMautic(source)
        self.fake.get_campaign_builder_capabilities = lambda: copy.deepcopy(_capabilities())

    def test_copy_keeps_the_legacy_step_verbatim_and_names_it(self):
        with patch("newsletter.native_campaign_views.MauticClient", return_value=self.fake):
            response = self.client.post(
                reverse("newsletter-admin-mautic-campaign-duplicate", args=["88"]), {}, format="json"
            )

        self.assertEqual(response.status_code, 201, response.data)
        self.assertFalse(response.data["isPublished"])
        copy_ = self.fake.campaigns[response.data["id"]]
        self.assertFalse(copy_["isPublished"])
        self.assertEqual(copy_["events"][0]["properties"], {"email": "23"}, "not silently converted")
        self.assertEqual(
            response.data["emailTypeUnresolved"],
            [{"id": str(copy_["events"][0]["id"]), "name": "Welcome", "state": "missing"}],
        )

    def test_the_copy_cannot_be_published_until_resolved(self):
        with patch("newsletter.native_campaign_views.MauticClient", return_value=self.fake):
            created = self.client.post(
                reverse("newsletter-admin-mautic-campaign-duplicate", args=["88"]), {}, format="json"
            )
            response = self.client.patch(
                reverse("newsletter-admin-mautic-campaign-detail", args=[created.data["id"]]),
                {"isPublished": True},
                format="json",
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], "email_type_unresolved")
        self.assertFalse(self.fake.campaigns[created.data["id"]]["isPublished"])
