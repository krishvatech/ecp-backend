"""Read-only reporting that informs the consent-scope and autoresponder decisions."""

import json
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase

from newsletter.form_campaign_consent import email_consent_scope, form_contact_autoresponders
from newsletter.models import NewsletterCategory


def gate(event_id, segments):
    return {"id": event_id, "type": "lead.segments", "eventType": "condition", "properties": {"segments": segments}}


def send(event_id, parent, path="yes", email="5"):
    return {"id": event_id, "type": "email.send", "eventType": "action", "parent": {"id": parent} if parent else None,
            "decisionPath": path, "properties": {"email": email, "email_type": "marketing"}}


class ConsentScopeTests(SimpleTestCase):
    def test_each_email_reports_the_lists_its_gate_checks(self):
        events = [gate("1", [61, 7]), send("2", "1"), send("3", None, path=None, email="9"), send("4", "1", path="no")]
        scope = email_consent_scope(events, {"61": "updates", "62": "events"})
        self.assertEqual(scope[0], {"step": "2", "email": "5", "lists": ["updates"], "otherSegments": ["7"]})
        self.assertEqual(scope[1]["lists"], [])  # ungated: authorised by no list
        self.assertEqual(scope[2]["lists"], [])  # NO path is not consent

    def test_only_contact_autoresponders_are_reported(self):
        actions = [{"id": 1, "type": "email.send.lead", "name": "Thanks", "properties": {"email": 12}},
                   {"id": 2, "type": "email.send.user", "properties": {"useremail": {"email": 3}}},
                   {"id": 3, "type": "lead.changetags", "properties": {}}]
        self.assertEqual(form_contact_autoresponders(actions), [{"id": "1", "name": "Thanks", "email": "12"}])


class AuditCommandScopeTests(TestCase):
    def audit(self, events, email_alias):
        with patch("newsletter.management.commands.audit_form_submission_safety.MauticClient") as client_cls, \
                patch("newsletter.form_views.MauticClient") as caps, \
                patch("newsletter.form_views.marketing_cache.cached_value", side_effect=lambda n, p, b, ttl: b()):
            caps.return_value.get_marketing_bridge_capabilities.return_value = {"publicUrl": "https://mautic.example.org"}
            client = client_cls.return_value
            client.get_form.return_value = {"id": 31, "name": "F", "isPublished": True, "cachedHtml": "",
                                            "actions": [{"id": 1, "type": "email.send.lead", "name": "Thanks", "properties": {"email": 12}}]}
            client.get_campaign.return_value = {"id": 5, "name": "C", "isPublished": True, "forms": [{"id": 31}], "lists": [], "events": events}
            client.get_campaign_event_states.return_value = {"activeEventIds": [e["id"] for e in events]}
            client.get_segment.return_value = {"isPublished": True, "category": {"alias": "ecp-subscription-lists"}}
            client.get_email.return_value = {"id": 5, "category": {"alias": email_alias} if email_alias else None}
            out = StringIO()
            call_command("audit_form_submission_safety", "--json", "--form-id", "31", "--campaign-id", "5", "--skip-lists", stdout=out)
        written = [name for name, *_ in client.method_calls if not name.startswith(("list_", "get_"))]
        self.assertEqual(written, [])
        return json.loads(out.getvalue())

    def test_audit_reports_scope_and_autoresponders_read_only(self):
        updates = NewsletterCategory.objects.create(name="Updates", slug="updates", mautic_segment_id="61", is_active=True)
        report = self.audit([gate("1", [61]), send("2", "1")], f"ecp-list-{updates.pk}")
        self.assertEqual(report["campaigns"][0]["consentScope"], [{"step": "2", "email": "5", "lists": ["updates"], "otherSegments": [],
                                                                   "ecpScope": {"list": "updates", "refusal": None}}])
        self.assertEqual(report["campaigns"][0]["runtimeEffect"], "sends only to contacts ECP verifies as currently subscribed")
        self.assertEqual(report["summary"]["forms_with_contact_autoresponders"], ["31"])

    def test_email_without_list_scope_is_reported_as_refused_at_send_time(self):
        NewsletterCategory.objects.create(name="Updates", slug="updates", mautic_segment_id="61", is_active=True)
        campaign = self.audit([gate("1", [61]), send("2", "1")], None)["campaigns"][0]
        self.assertEqual(campaign["consentScope"][0]["ecpScope"], {"list": None, "refusal": "email_scope_missing"})
        self.assertEqual(campaign["runtimeEffect"], "email steps refused at send time")

    def test_delay_blocks_publishing_but_not_verified_sends(self):
        updates = NewsletterCategory.objects.create(name="Updates", slug="updates", mautic_segment_id="61", is_active=True)
        delayed = dict(send("2", "1"), triggerMode="interval", triggerInterval=1, triggerIntervalUnit="d")
        campaign = self.audit([gate("1", [61]), delayed], f"ecp-list-{updates.pk}")["campaigns"][0]
        self.assertEqual([s["reason"] for s in campaign["unsafeSteps"]], ["delayed"])
        self.assertEqual(campaign["runtimeEffect"], "sends only to contacts ECP verifies as currently subscribed")
