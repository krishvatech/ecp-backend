"""Withdrawn Subscription List consent reaches Mautic before it can authorise a
marketing email, and stale sync work never restores it."""

from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings

from newsletter.category_segment_services import (
    CONSENT_CATEGORY_ALIAS,
    consent_category_id,
    segment_payload_for_category,
)
from newsletter.form_campaign_consent import (
    CONSENT_CONDITION,
    NO_PATH,
    NOT_GATED,
    NOT_MARKETING,
    NOT_SUBSCRIPTION_LIST,
    segment_is_marked,
    unsafe_email_steps,
)
from newsletter.mautic import TemporaryMauticError
from newsletter.models import MauticContactMapping, NewsletterCategory, NewsletterSubscription, NewsletterSyncEvent
from newsletter.processor import process_newsletter_sync_event
from newsletter.services import update_user_preferences

User = get_user_model()
SYNC_ON = {"MAUTIC_SYNC_ENABLED": True, "MAUTIC_BASE_URL": "http://mautic.local", "MAUTIC_USERNAME": "u", "MAUTIC_PASSWORD": "p"}


class SharedPolicyContractTests(SimpleTestCase):
    """The bridge plugin (EcpFormSourceEmailPolicy) enforces this rule when it
    sends; these are the same cases its in-container check runs."""

    def test_constants_match_the_plugin(self):
        self.assertEqual(CONSENT_CATEGORY_ALIAS, "ecp-subscription-lists")
        self.assertEqual(CONSENT_CONDITION, "lead.segments")

    def test_shared_cases(self):
        gate = {"id": "1", "type": "lead.segments", "eventType": "condition", "properties": {"segments": [61]}}

        def send(**overrides):
            return {"id": "2", "type": "email.send", "eventType": "action", "parent": {"id": "1"}, "decisionPath": "yes",
                    "properties": {"email": 5, "email_type": "marketing"}, **overrides}

        cases = [
            ([gate, send()], []),
            ([gate, send(properties={"email": 5, "email_type": "transactional"})], [NOT_MARKETING]),
            ([gate, send(properties={"email": 5})], [NOT_MARKETING]),
            ([send(parent=None)], [NOT_GATED]),
            ([gate, send(decisionPath="no")], [NO_PATH]),
            ([{**gate, "properties": {"segments": [7]}}, send()], [NOT_SUBSCRIPTION_LIST]),
            ([{"id": "3", "type": "message.send", "eventType": "action", "parent": None, "properties": {"marketingMessage": 1}}], [NOT_MARKETING]),
        ]
        for events, expected in cases:
            with self.subTest(events=events):
                self.assertEqual([s["reason"] for s in unsafe_email_steps(events, {"61"})], expected)

    def test_marker_semantics_match_the_plugin(self):
        self.assertTrue(segment_is_marked({"isPublished": True, "category": {"alias": CONSENT_CATEGORY_ALIAS}}))
        self.assertFalse(segment_is_marked({"isPublished": False, "category": {"alias": CONSENT_CATEGORY_ALIAS}}))
        self.assertFalse(segment_is_marked({"isPublished": True, "category": {"alias": "newsletters"}}))
        self.assertFalse(segment_is_marked({"isPublished": True, "category": None}))


class ConsentMarkerTests(TestCase):
    def setUp(self):
        self.list = NewsletterCategory.objects.create(name="Updates", slug="updates", is_active=True)

    def reader(self, *pages):
        reader = Mock()
        reader.list_categories.side_effect = list(pages)
        return reader

    def test_category_is_found_by_exact_alias_and_bundle(self):
        reader = self.reader({"total": 3, "categories": [
            {"id": 4, "alias": CONSENT_CATEGORY_ALIAS, "bundle": "email"},
            {"id": 5, "alias": "ecp-subscription-lists-old", "bundle": "segment"},
            {"id": 6, "alias": CONSENT_CATEGORY_ALIAS, "bundle": "segment"}]})
        self.assertEqual(consent_category_id(reader), 6)

    def test_missing_category_or_provider_error_marks_nothing(self):
        self.assertIsNone(consent_category_id(self.reader({"total": 0, "categories": []})))
        self.assertIsNone(consent_category_id(self.reader(TemporaryMauticError("down"))))

    def test_list_segment_payload_carries_the_marker_only_when_known(self):
        self.assertEqual(segment_payload_for_category(self.list, consent_category=6)["category"], 6)
        with patch("newsletter.category_segment_services.consent_category_id", return_value=None):
            self.assertNotIn("category", segment_payload_for_category(self.list))


@override_settings(**SYNC_ON)
class WithdrawalSyncTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="sync-safety", email="sync-safety@example.test", password="x")
        self.list = NewsletterCategory.objects.create(name="Updates", slug="updates", is_active=True, mautic_segment_id="61")
        MauticContactMapping.objects.create(user=self.user, mautic_contact_id="501")
        patcher = patch("newsletter.processor.MauticClient")
        self.mautic = patcher.start().return_value
        self.addCleanup(patcher.stop)
        self.mautic.get_contact.return_value = {"id": 501, "fields": {"all": {"email": "sync-safety@example.test"}}}
        self.mautic.update_contact.return_value = {"id": 501}
        dispatch = patch("newsletter.tasks.process_newsletter_sync_event")
        self.worker = dispatch.start()
        self.addCleanup(dispatch.stop)

    def subscribe(self, subscribed):
        with self.captureOnCommitCallbacks(execute=True):
            update_user_preferences(self.user, [{"slug": "updates", "subscribed": subscribed}])
        return NewsletterSyncEvent.objects.filter(user_id=str(self.user.pk)).order_by("-id").first()

    def test_withdrawal_is_removed_from_mautic_before_the_request_returns(self):
        self.subscribe(True)
        self.mautic.reset_mock()
        event = self.subscribe(False)
        event.refresh_from_db()
        self.assertEqual(event.status, NewsletterSyncEvent.Status.SUCCEEDED)
        self.mautic.remove_contact_from_segment.assert_called_once_with("61", "501")

    def test_withdrawal_stays_queued_when_mautic_is_unreachable(self):
        self.subscribe(True)
        self.mautic.remove_contact_from_segment.side_effect = TemporaryMauticError("down")
        self.worker.reset_mock()
        event = self.subscribe(False)
        event.refresh_from_db()
        self.assertEqual(event.status, NewsletterSyncEvent.Status.RETRYING)
        self.assertFalse(NewsletterSubscription.objects.get(user=self.user).is_subscribed)  # the choice itself is saved
        self.worker.delay.assert_called_once_with(event.pk)

    def test_subscribe_still_goes_to_the_worker(self):
        self.worker.reset_mock()
        event = self.subscribe(True)
        self.worker.delay.assert_called_once_with(event.pk)
        self.mautic.add_contact_to_segment.assert_not_called()

    def test_older_subscribe_processed_after_a_newer_unsubscribe_is_skipped(self):
        subscribe_event = NewsletterSyncEvent.objects.create(
            idempotency_key="old-subscribe", user_id=str(self.user.pk), category=self.list, desired_subscribed=True)
        NewsletterSubscription.objects.create(user=self.user, category=self.list, is_subscribed=False)
        result = process_newsletter_sync_event(subscribe_event.pk)
        self.assertEqual(result.get("reason"), "superseded")
        self.mautic.add_contact_to_segment.assert_not_called()

    def test_unsubscribe_saved_while_an_add_is_in_flight_removes_the_membership_again(self):
        subscription = NewsletterSubscription.objects.create(user=self.user, category=self.list, is_subscribed=True)
        event = NewsletterSyncEvent.objects.create(
            idempotency_key="in-flight", user_id=str(self.user.pk), category=self.list, desired_subscribed=True)
        self.mautic.add_contact_to_segment.side_effect = lambda *a: NewsletterSubscription.objects.filter(
            pk=subscription.pk).update(is_subscribed=False)
        result = process_newsletter_sync_event(event.pk)
        self.assertEqual(result["reason"], "superseded_after_add")
        self.mautic.remove_contact_from_segment.assert_called_once_with("61", "501")

    def test_failed_compensation_queues_a_durable_unsubscribe(self):
        subscription = NewsletterSubscription.objects.create(user=self.user, category=self.list, is_subscribed=True)
        event = NewsletterSyncEvent.objects.create(
            idempotency_key="in-flight-2", user_id=str(self.user.pk), category=self.list, desired_subscribed=True)
        self.mautic.add_contact_to_segment.side_effect = lambda *a: NewsletterSubscription.objects.filter(
            pk=subscription.pk).update(is_subscribed=False)
        self.mautic.remove_contact_from_segment.side_effect = TemporaryMauticError("down")
        process_newsletter_sync_event(event.pk)
        follow_up = NewsletterSyncEvent.objects.exclude(pk=event.pk).get()
        self.assertFalse(follow_up.desired_subscribed)
        self.assertEqual(follow_up.status, NewsletterSyncEvent.Status.PENDING)
