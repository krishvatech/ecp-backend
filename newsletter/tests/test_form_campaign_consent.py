"""Form-sourced Campaigns only put marketing email into service behind a
Subscription List consent check that Mautic evaluates when the email is sent."""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.form_campaign_consent import (
    DELAYED,
    NO_PATH,
    NOT_GATED,
    NOT_MARKETING,
    NOT_SUBSCRIPTION_LIST,
    subscription_list_consent_segment_ids,
    unsafe_email_steps,
)
from newsletter.models import MauticIdentityAuditLog, NewsletterCategory
from newsletter.tests.marketing_actors import grant_marketing_access

User = get_user_model()

LIST_SEGMENT = "61"


def _capabilities():
    return {
        "actions": [
            {"key": "email.send", "type": "email.send", "eventType": "action", "label": "Send email",
             "formTypeOptions": {"email": {"required": True}}},
            {"key": "lead.changepoints", "type": "lead.changepoints", "eventType": "action", "label": "Points",
             "formTypeOptions": {"points": {"required": False}}},
            {"key": "lead.changelist", "type": "lead.changelist", "eventType": "action", "label": "Modify segments",
             "formTypeOptions": {}},
        ],
        "conditions": [
            {"key": "lead.segments", "type": "lead.segments", "eventType": "condition", "label": "Contact segments",
             "formTypeOptions": {"segments": {"required": True}}},
        ],
        "decisions": [],
        "connectionRestrictions": {},
    }


def marked_segment(segment_id, *, alias="ecp-subscription-lists", published=True):
    return {"id": int(segment_id), "isPublished": published, "category": {"id": 1, "alias": alias} if alias else None}


def gate(event_id="c1", segments=(LIST_SEGMENT,), **extra):
    return {"id": event_id, "key": "lead.segments", "type": "lead.segments", "eventType": "condition", "name": "Subscribed?",
            "properties": {"segments": list(segments)}, "parent": None, "triggerMode": "immediate", **extra}


def send(event_id="e1", parent="c1", path="yes", email_type="marketing", **extra):
    properties = {"email": "23"} if email_type is None else {"email": "23", "email_type": email_type}
    return {"id": event_id, "key": "email.send", "type": "email.send", "eventType": "action", "name": "Welcome",
            "properties": properties, "parent": parent, "decisionPath": path, "triggerMode": "immediate", **extra}


def points(event_id="p1"):
    return {"id": event_id, "key": "lead.changepoints", "type": "lead.changepoints", "eventType": "action",
            "name": "Score", "properties": {"points": 5}, "parent": None, "triggerMode": "immediate"}


class ConsentRuleTests(TestCase):
    def setUp(self):
        NewsletterCategory.objects.create(name="Updates", slug="updates", mautic_segment_id=LIST_SEGMENT, is_active=True)
        NewsletterCategory.objects.create(name="Old", slug="old", mautic_segment_id="62", is_active=False)

    def reasons(self, events):
        return [step["reason"] for step in unsafe_email_steps(events, subscription_list_consent_segment_ids())]

    def test_only_active_subscription_lists_are_consent_evidence(self):
        self.assertEqual(subscription_list_consent_segment_ids(), {LIST_SEGMENT})

    def test_marketing_email_directly_on_the_yes_path_of_a_list_check_is_safe(self):
        self.assertEqual(self.reasons([gate(), send()]), [])
        # Stored provider shape: parent object, integer segment ids.
        self.assertEqual(self.reasons([gate(segments=[61]), send(parent={"id": "c1"})]), [])
        # A delay on the condition is fine: Mautic evaluates it when the delay ends.
        self.assertEqual(self.reasons([gate(triggerMode="interval", triggerInterval=2), send()]), [])

    def test_each_unsafe_shape_is_named(self):
        self.assertEqual(self.reasons([send(parent=None)]), [NOT_GATED])
        self.assertEqual(self.reasons([points("c1"), send()]), [NOT_GATED])
        self.assertEqual(self.reasons([gate(), send(path="no")]), [NO_PATH])
        self.assertEqual(self.reasons([gate(segments=["7"]), send()]), [NOT_SUBSCRIPTION_LIST])
        self.assertEqual(self.reasons([gate(segments=[LIST_SEGMENT, "7"]), send()]), [NOT_SUBSCRIPTION_LIST])
        self.assertEqual(self.reasons([gate(segments=["62"]), send()]), [NOT_SUBSCRIPTION_LIST])  # inactive list
        self.assertEqual(self.reasons([gate(segments=[]), send()]), [NOT_SUBSCRIPTION_LIST])
        self.assertEqual(self.reasons([gate(), send(triggerMode="interval", triggerInterval=1)]), [DELAYED])

    def test_transactional_and_untyped_email_cannot_bypass_the_check(self):
        self.assertEqual(self.reasons([gate(), send(email_type="transactional")]), [NOT_MARKETING])
        self.assertEqual(self.reasons([gate(), send(email_type=None)]), [NOT_MARKETING])  # Mautic runs it as transactional

    def test_non_email_steps_are_not_restricted(self):
        self.assertEqual(self.reasons([points(), gate(), points("p2")]), [])


class ConsentApiBase(TestCase):
    def setUp(self):
        NewsletterCategory.objects.create(name="Updates", slug="updates", mautic_segment_id=LIST_SEGMENT, is_active=True)
        self.api = APIClient()
        self.staff = User.objects.create_superuser(username="consent-admin", email="consent-admin@example.test", password="x")
        grant_marketing_access(self.staff)
        self.api.force_authenticate(self.staff)
        self.list_url = reverse("newsletter-admin-mautic-campaign-list")
        self.detail_url = reverse("newsletter-admin-mautic-campaign-detail", args=["7"])
        patcher = patch("newsletter.native_campaign_views.MauticClient")
        self.client_cls = patcher.start()
        self.addCleanup(patcher.stop)
        # Segments as Mautic reports them when ECP confirms the consent marker.
        self.segments = {LIST_SEGMENT: marked_segment(LIST_SEGMENT)}
        reader = patch("newsletter.form_campaign_consent._read_segment", side_effect=lambda sid: self.segments[str(sid)])
        self.reader = reader.start()
        self.addCleanup(reader.stop)
        self.mautic = self.client_cls.return_value
        self.mautic.get_campaign_builder_capabilities.return_value = _capabilities()
        self.mautic.create_campaign.return_value = {"id": 7, "name": "Journey", "events": []}
        self.mautic.update_campaign.return_value = {"id": 7, "name": "Journey", "events": []}

    def stored(self, events, *, published, forms=(31,), lists=()):
        self.mautic.get_campaign.return_value = {
            "id": 7, "isPublished": published, "events": events,
            "forms": [{"id": f} for f in forms], "lists": [{"id": s} for s in lists],
        }
        self.mautic.get_campaign_event_states.return_value = {"activeEventIds": [e["id"] for e in events]}

    def create(self, events, *, forms=(31,), segments=(), published=True):
        return self.api.post(self.list_url, {
            "name": "Journey", "isPublished": published, "sources": {"segments": list(segments), "forms": list(forms)},
            "events": events, "canvasSettings": {"nodes": [], "connections": []},
        }, format="json")

    def assert_refused(self, response, reason):
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(response.data["code"], "form_source_marketing_consent_required")
        self.assertEqual([step["reason"] for step in response.data["events"]], [reason])
        self.assertIn("does not automatically subscribe a Contact to marketing emails", response.data["detail"])


class ConsentApiTests(ConsentApiBase):
    def test_publishing_a_form_sourced_ungated_marketing_email_is_refused_and_audited(self):
        response = self.create([send(parent=None, path=None)])
        self.assert_refused(response, NOT_GATED)
        self.mautic.create_campaign.assert_not_called()
        audit = MauticIdentityAuditLog.objects.get()
        self.assertEqual((audit.action, audit.status, audit.error_code), ("campaign.create", "denied", "form_source_marketing_consent_required"))
        self.assertNotIn("@", audit.detail)

    def test_gated_form_sourced_email_can_be_published(self):
        response = self.create([gate("new_1"), send("new_2", parent="new_1")])
        self.assertEqual(response.status_code, 201, response.data)

    def test_transactional_email_cannot_bypass_the_consent_check(self):
        events = [gate("new_1"), {**send("new_2", parent="new_1", email_type="transactional"), "transactionalEmailConfirmed": True}]
        self.assert_refused(self.create(events), NOT_MARKETING)

    def test_mixed_form_and_segment_sources_are_checked_as_a_whole(self):
        self.assert_refused(self.create([send(parent=None, path=None)], segments=[10]), NOT_GATED)

    def test_drafts_and_segment_only_campaigns_are_unaffected(self):
        self.assertEqual(self.create([send(parent=None, path=None)], published=False).status_code, 201)
        self.assertEqual(self.create([send(parent=None, path=None)], forms=(), segments=[10]).status_code, 201)

    def test_publish_only_request_checks_the_stored_workflow(self):
        self.stored([send("12", parent=None, path=None)], published=False)
        self.assert_refused(self.api.patch(self.detail_url, {"isPublished": True}, format="json"), NOT_GATED)
        self.mautic.update_campaign.assert_not_called()

    def test_adding_a_form_source_to_a_published_campaign_with_email_is_refused(self):
        self.stored([send("12", parent=None, path=None)], published=True, forms=(), lists=(10,))
        response = self.api.patch(self.detail_url, {"sources": {"segments": [10], "forms": [31]}}, format="json")
        self.assert_refused(response, NOT_GATED)
        self.mautic.update_campaign.assert_not_called()

    def test_changing_only_the_gate_of_a_published_campaign_is_checked_against_the_merged_workflow(self):
        # Mautic's PATCH merges events, so the untouched email keeps its new parent's rules.
        self.stored([gate("11", segments=[61]), send("12", parent={"id": 11})], published=True)
        response = self.api.patch(self.detail_url, {"events": [gate("11", segments=["7"])]}, format="json")
        self.assert_refused(response, NOT_SUBSCRIPTION_LIST)

    def test_existing_unsafe_published_campaigns_keep_working_until_their_workflow_changes(self):
        self.stored([send("12", parent=None, path=None)], published=True)
        self.assertEqual(self.api.patch(self.detail_url, {"name": "Renamed"}, format="json").status_code, 200)
        self.assertEqual(self.api.patch(self.detail_url, {"isPublished": False}, format="json").status_code, 200)

    def test_missing_active_step_report_fails_closed(self):
        self.stored([send("12", parent=None, path=None)], published=False)
        self.mautic.get_campaign_event_states.return_value = {}
        response = self.api.patch(self.detail_url, {"isPublished": True}, format="json")
        self.assertEqual(response.status_code, 502)
        self.mautic.update_campaign.assert_not_called()

    def test_revoking_subscription_list_status_blocks_new_activation(self):
        self.stored([gate("11", segments=[61]), send("12", parent={"id": 11})], published=False)
        NewsletterCategory.objects.filter(mautic_segment_id=LIST_SEGMENT).update(is_active=False)
        self.assert_refused(self.api.patch(self.detail_url, {"isPublished": True}, format="json"), NOT_SUBSCRIPTION_LIST)

    def test_publish_is_refused_while_the_list_segment_lacks_the_mautic_consent_marker(self):
        # The plugin only accepts published segments in the Subscription List category when it sends.
        for segment in (marked_segment(LIST_SEGMENT, alias=None), marked_segment(LIST_SEGMENT, alias="other"),
                        marked_segment(LIST_SEGMENT, published=False)):
            with self.subTest(segment=segment):
                self.segments[LIST_SEGMENT] = segment
                self.assert_refused(self.create([gate("new_1"), send("new_2", parent="new_1")]), "subscription_list_not_marked")
        self.mautic.create_campaign.assert_not_called()

    def test_marker_lookup_failure_fails_closed(self):
        from newsletter.mautic.exceptions import TemporaryMauticError

        self.reader.side_effect = TemporaryMauticError("down")
        self.assert_refused(self.create([gate("new_1"), send("new_2", parent="new_1")]), "unverifiable")


def change_lists(event_id="l1", add=(), remove=()):
    return {"id": event_id, "key": "lead.changelist", "type": "lead.changelist", "eventType": "action", "name": "Segments",
            "properties": {"addToLists": list(add), "removeFromLists": list(remove)}, "parent": None, "triggerMode": "immediate"}


class SubscriptionListWriteTests(ConsentApiBase):
    """Any Campaign adding contacts to a Subscription List forges consent."""

    def assert_write_refused(self, response):
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(response.data["code"], "subscription_list_write_forbidden")
        self.assertIn("only the member's choice in ECP may set it", response.data["detail"])

    def test_adding_to_a_subscription_list_is_refused_with_or_without_a_form_source(self):
        self.assert_write_refused(self.create([change_lists("new_1", add=[LIST_SEGMENT])]))
        self.assert_write_refused(self.create([change_lists("new_1", add=[LIST_SEGMENT])], forms=(), segments=[10]))
        self.mautic.create_campaign.assert_not_called()
        self.assertTrue(MauticIdentityAuditLog.objects.filter(error_code="subscription_list_write_forbidden").exists())

    def test_archived_lists_are_protected_too(self):
        NewsletterCategory.objects.create(name="Old", slug="old", mautic_segment_id="62", is_active=False)
        self.assert_write_refused(self.create([change_lists("new_1", add=["62"])], forms=(), segments=[10]))

    def test_removing_from_a_list_and_ordinary_segments_are_allowed(self):
        self.assertEqual(self.create([change_lists("new_1", remove=[LIST_SEGMENT])], forms=(), segments=[10]).status_code, 201)
        self.assertEqual(self.create([change_lists("new_1", add=["7"])], forms=(), segments=[10]).status_code, 201)

    def test_drafts_are_not_checked(self):
        self.assertEqual(self.create([change_lists("new_1", add=[LIST_SEGMENT])], published=False).status_code, 201)

    def test_live_workflow_change_is_checked_against_the_merged_workflow(self):
        self.stored([gate("11", segments=[61]), send("12", parent={"id": 11})], published=True)
        response = self.api.patch(self.detail_url, {"events": [change_lists("new_1", add=[LIST_SEGMENT])]}, format="json")
        self.assert_write_refused(response)
