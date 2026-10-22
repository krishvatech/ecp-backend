"""Read-only audits for Subscription List consent evidence in Mautic."""

import json
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase

from newsletter.form_campaign_consent import subscription_list_writes
from newsletter.mautic import TemporaryMauticError
from newsletter.models import MauticContactMapping, NewsletterCategory, NewsletterSubscription, NewsletterSyncEvent

User = get_user_model()


class SubscriptionListWriteRuleTests(TestCase):
    def test_only_additions_to_list_segments_are_reported(self):
        events = [
            {"id": "1", "type": "lead.changelist", "properties": {"addToLists": [61, 7], "removeFromLists": []}},
            {"id": "2", "type": "lead.changelist", "properties": {"addToLists": [], "removeFromLists": [61]}},
            {"id": "3", "type": "lead.changelist", "properties": {"addToLists": ["7"]}},
            {"id": "4", "type": "lead.changetags", "properties": {"add_tags": ["61"]}},
        ]
        self.assertEqual([step["id"] for step in subscription_list_writes(events, {"61"})], ["1"])


class MembershipAuditTests(TestCase):
    def setUp(self):
        self.list = NewsletterCategory.objects.create(name="Updates", slug="updates", mautic_segment_id="61", is_active=True)
        self.users = {}
        for role, contact in (("ok", "101"), ("withdrawn", "102"), ("merged", "103"), ("missing", "104"), ("never", "105")):
            user = User.objects.create_user(username=f"audit-{role}", email=f"audit-{role}@example.test", password="x")
            MauticContactMapping.objects.create(user=user, mautic_contact_id=contact)
            self.users[role] = user
        for role, subscribed in (("ok", True), ("withdrawn", False), ("merged", True), ("missing", True)):
            NewsletterSubscription.objects.create(user=self.users[role], category=self.list, is_subscribed=subscribed)
        NewsletterSyncEvent.objects.create(idempotency_key="pending-withdrawal", user_id=str(self.users["withdrawn"].pk),
                                           category=self.list, desired_subscribed=False)

    def run_audit(self, members, survivors):
        with patch("newsletter.management.commands.audit_subscription_list_membership.MauticClient") as client_cls:
            client = client_cls.return_value
            client.list_segment_contacts_via_bridge.return_value = {"total": len(members), "contacts": [{"id": m} for m in members]}
            client.get_contact.side_effect = lambda cid: {"id": survivors.get(str(cid), cid)}
            out = StringIO()
            call_command("audit_subscription_list_membership", "--json", stdout=out)
        written = [name for name, *_ in client.method_calls if not name.startswith(("list_", "get_"))]
        self.assertEqual(written, [])  # read-only
        return json.loads(out.getvalue())["lists"][0]["issues"]

    def test_every_disagreement_is_classified(self):
        # Mautic lists: ok(101), withdrawn(102), merged survivor 203 (of 103), forged 999 and never-subscribed 105.
        issues = self.run_audit(["101", "102", "203", "999", "105"], {"103": "203"})
        users = {key: [entry["user"] for entry in value] for key, value in issues.items()}
        self.assertEqual(users["stale_withdrawn"], [self.users["withdrawn"].pk])
        self.assertTrue(issues["stale_withdrawn"][0]["syncPending"])
        self.assertEqual([e["contact"] for e in issues["unlinked"]], ["999"])
        self.assertEqual(users["no_ecp_consent"], [self.users["never"].pk])
        self.assertEqual(users["missing_in_mautic"], [self.users["missing"].pk])
        self.assertEqual([(e["contact"], e["mappedTo"]) for e in issues["mapping_stale_after_merge"]], [("203", "103")])
        self.assertEqual(issues["inactive_list"], [])

    def test_archived_list_members_are_all_reported(self):
        NewsletterCategory.objects.filter(pk=self.list.pk).update(is_active=False)
        issues = self.run_audit(["101"], {})
        self.assertEqual([e["contact"] for e in issues["inactive_list"]], ["101"])

    def test_provider_failure_stops_the_audit(self):
        from django.core.management.base import CommandError

        with patch("newsletter.management.commands.audit_subscription_list_membership.MauticClient") as client_cls:
            client_cls.return_value.list_segment_contacts_via_bridge.side_effect = TemporaryMauticError("down")
            with self.assertRaises(CommandError):
                call_command("audit_subscription_list_membership", stdout=StringIO())
