from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.mautic import PermanentMauticError, TemporaryMauticError
from newsletter.models import (
    NewsletterCampaign,
    NewsletterCampaignTrackingEvent,
    NewsletterCategory,
    NewsletterSyncEvent,
)


User = get_user_model()


MAUTIC_SETTINGS = {
    "MAUTIC_SYNC_ENABLED": True,
    "MAUTIC_BASE_URL": "https://mautic.example.test",
    "MAUTIC_USERNAME": "api-user",
    "MAUTIC_PASSWORD": "super-secret",
    "MAUTIC_WEBHOOK_SECRET": "webhook-secret",
    "MAUTIC_REQUEST_TIMEOUT": 3,
    "CELERY_BROKER_URL": "redis://redis.example.test/0",
    "CELERY_BEAT_SCHEDULE": {
        "dispatch-due-newsletter-sync-events": {
            "task": "newsletter.dispatch_due_sync_events",
        },
    },
}


@override_settings(**MAUTIC_SETTINGS)
class NewsletterAdminMauticDiagnosticsAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="diagnostics-staff",
            email="diagnostics-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="diagnostics-normal",
            email="diagnostics-normal@example.test",
            password="test-password",
        )
        self.url = reverse("newsletter-admin-mautic-diagnostics")

    def _authenticate(self, user=None):
        self.client.force_authenticate(user=user or self.staff)

    def _create_sync_event(self, *, category, key, user_id, status, created_at=None, **kwargs):
        event = NewsletterSyncEvent.objects.create(
            idempotency_key=key,
            user_id=user_id,
            category=category,
            desired_subscribed=kwargs.pop("desired_subscribed", True),
            status=status,
            **kwargs,
        )
        if created_at is not None:
            NewsletterSyncEvent.objects.filter(pk=event.pk).update(created_at=created_at)
            event.created_at = created_at
        return event

    def _mock_healthy_mautic(self, client_cls):
        client_cls.return_value.health_check.return_value = True
        client_cls.return_value.get_marketing_bridge_capabilities.return_value = {"capabilities": []}
        client_cls.return_value.get_campaign_builder_capabilities.return_value = {
            "actions": [],
            "conditions": [],
            "decisions": [],
            "connectionRestrictions": {},
        }

    def test_auth_is_preserved(self):
        response = self.client.get(self.url)
        self.assertIn(response.status_code, (401, 403))

        self._authenticate(self.normal_user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_fully_healthy_response_uses_runtime_capabilities(self, client_cls):
        client = client_cls.return_value
        client.health_check.return_value = True
        client.get_marketing_bridge_capabilities.return_value = {
            "plugin": "EcpMarketingBridgeBundle",
            "version": "0.1.0",
            "mauticVersion": "7.2.0",
            "capabilities": ["segment_counts", "field_types"],
        }
        client.get_campaign_builder_capabilities.return_value = {
            "actions": [{"key": "email.send"}],
            "conditions": [{"key": "lead.field_value"}],
            "decisions": [],
            "connectionRestrictions": {},
            "formSchema": {"available": False},
        }
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["connection"]["status"], "Configured")
        self.assertTrue(response.data["api"]["authenticated"])
        self.assertEqual(response.data["connection"]["version"], "7.2.0")
        self.assertEqual(
            response.data["bridges"]["marketing"]["capabilities"],
            ["segment_counts", "field_types"],
        )
        self.assertEqual(
            response.data["bridges"]["campaign_builder"]["capabilities"]["actions"],
            1,
        )

    @override_settings(MAUTIC_BASE_URL="", MAUTIC_PASSWORD="super-secret")
    def test_missing_configuration_is_safe_and_does_not_call_provider(self):
        self._authenticate()
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["connection"]["status"], "Not Configured")
        self.assertFalse(response.data["api"]["available"])
        self.assertEqual(response.data["bridges"]["marketing"]["status"], "Not Configured")

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_mautic_unreachable_returns_partial_diagnostics(self, client_cls):
        client = client_cls.return_value
        client.health_check.side_effect = TemporaryMauticError("timeout")
        client.get_marketing_bridge_capabilities.side_effect = TemporaryMauticError("bridge timeout")
        client.get_campaign_builder_capabilities.side_effect = TemporaryMauticError("campaign bridge timeout")
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["api"]["status"], "Unavailable")
        self.assertEqual(response.data["bridges"]["marketing"]["status"], "Unavailable")
        self.assertEqual(response.data["webhook"]["receiver"], "Ready")
        self.assertEqual(response.data["diagnostics"]["status"], "Degraded")

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_authentication_failure_is_distinguished(self, client_cls):
        client = client_cls.return_value
        client.health_check.side_effect = PermanentMauticError("Mautic API request failed (HTTP 401)")
        client.get_marketing_bridge_capabilities.return_value = {"capabilities": []}
        client.get_campaign_builder_capabilities.return_value = {
            "actions": [],
            "conditions": [],
            "decisions": [],
            "connectionRestrictions": {},
        }
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["api"]["status"], "Authentication Failed")
        self.assertFalse(response.data["api"]["authenticated"])

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_credentials_and_secrets_are_not_returned(self, client_cls):
        client_cls.return_value.health_check.return_value = True
        client_cls.return_value.get_marketing_bridge_capabilities.return_value = {
            "capabilities": [],
        }
        client_cls.return_value.get_campaign_builder_capabilities.return_value = {
            "actions": [],
            "conditions": [],
            "decisions": [],
            "connectionRestrictions": {},
        }
        self._authenticate()

        response = self.client.get(self.url)

        text = str(response.data)
        self.assertNotIn("super-secret", text)
        self.assertNotIn("webhook-secret", text)
        self.assertNotIn("MAUTIC_PASSWORD", text)
        self.assertNotIn("MAUTIC_WEBHOOK_SECRET", text)

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_webhook_recent_event_and_supported_types_are_reported(self, client_cls):
        client_cls.return_value.health_check.return_value = True
        client_cls.return_value.get_marketing_bridge_capabilities.return_value = {"capabilities": []}
        client_cls.return_value.get_campaign_builder_capabilities.return_value = {
            "actions": [],
            "conditions": [],
            "decisions": [],
            "connectionRestrictions": {},
        }
        campaign = NewsletterCampaign.objects.create(name="Legacy", mautic_email_id="8")
        NewsletterCampaignTrackingEvent.objects.create(
            campaign=campaign,
            event_type=NewsletterCampaignTrackingEvent.EventType.OPENED,
            source="mautic",
            occurred_at=timezone.now(),
        )
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["webhook"]["last_processing_status"], "Received")
        self.assertEqual(response.data["webhook"]["registration"], "Not Verifiable")
        self.assertIn("mautic.email_on_open", response.data["webhook"]["supported_event_types"])

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_sync_status_counts_newsletter_queue_only(self, client_cls):
        self._mock_healthy_mautic(client_cls)
        category = NewsletterCategory.objects.create(name="Updates", slug="updates")
        self._create_sync_event(
            key="pending",
            user_id="1",
            category=category,
            status=NewsletterSyncEvent.Status.PENDING,
        )
        self._create_sync_event(
            key="failed",
            user_id="2",
            category=category,
            desired_subscribed=False,
            status=NewsletterSyncEvent.Status.FAILED,
            last_error="provider failed",
        )
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["sync"]["pending"], 1)
        self.assertEqual(response.data["sync"]["failed"], 1)
        self.assertTrue(response.data["sync"]["current_warning"])
        self.assertIn(
            "Newsletter sync has failed or retrying events.",
            response.data["diagnostics"]["warnings"],
        )
        self.assertTrue(response.data["background_processing"]["newsletter_sync_scheduled"])

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_sync_warning_ignores_historical_recovered_failures(self, client_cls):
        self._mock_healthy_mautic(client_cls)
        category = NewsletterCategory.objects.create(name="Recovered", slug="recovered")
        base_time = timezone.now() - timedelta(minutes=10)
        self._create_sync_event(
            key="failed-before-success",
            user_id="1",
            category=category,
            status=NewsletterSyncEvent.Status.FAILED,
            last_error="previous provider timeout",
            created_at=base_time,
        )
        self._create_sync_event(
            key="success-after-failure",
            user_id="1",
            category=category,
            status=NewsletterSyncEvent.Status.SUCCEEDED,
            attempt_count=2,
            completed_at=timezone.now(),
            created_at=base_time + timedelta(minutes=1),
        )
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["sync"]["failed"], 0)
        self.assertEqual(response.data["sync"]["retrying"], 0)
        self.assertFalse(response.data["sync"]["current_warning"])
        self.assertIsNone(response.data["sync"]["latest_failure_at"])
        self.assertEqual(response.data["sync"]["latest_failure"], "")
        self.assertNotIn(
            "Newsletter sync has failed or retrying events.",
            response.data["diagnostics"]["warnings"],
        )

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_sync_warning_is_current_for_retrying_events(self, client_cls):
        self._mock_healthy_mautic(client_cls)
        category = NewsletterCategory.objects.create(name="Retrying", slug="retrying")
        self._create_sync_event(
            key="retrying",
            user_id="1",
            category=category,
            status=NewsletterSyncEvent.Status.RETRYING,
            last_error="temporary provider timeout",
        )
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["sync"]["retrying"], 1)
        self.assertTrue(response.data["sync"]["current_warning"])
        self.assertIn(
            "Newsletter sync has failed or retrying events.",
            response.data["diagnostics"]["warnings"],
        )

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_failed_subscribe_followed_by_successful_unsubscribe_is_not_current(self, client_cls):
        self._mock_healthy_mautic(client_cls)
        category = NewsletterCategory.objects.create(name="State Change", slug="state-change")
        base_time = timezone.now() - timedelta(minutes=10)
        self._create_sync_event(
            key="subscribe-failed",
            user_id="1",
            category=category,
            desired_subscribed=True,
            status=NewsletterSyncEvent.Status.FAILED,
            last_error="subscribe failed",
            created_at=base_time,
        )
        self._create_sync_event(
            key="unsubscribe-succeeded",
            user_id="1",
            category=category,
            desired_subscribed=False,
            status=NewsletterSyncEvent.Status.SUCCEEDED,
            completed_at=timezone.now(),
            created_at=base_time + timedelta(minutes=1),
        )
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["sync"]["failed"], 0)
        self.assertFalse(response.data["sync"]["current_warning"])

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_success_for_different_target_does_not_resolve_failed_target(self, client_cls):
        self._mock_healthy_mautic(client_cls)
        category = NewsletterCategory.objects.create(name="Different Targets", slug="different-targets")
        base_time = timezone.now() - timedelta(minutes=10)
        self._create_sync_event(
            key="target-a-failed",
            user_id="1",
            category=category,
            status=NewsletterSyncEvent.Status.FAILED,
            last_error="target A failed",
            created_at=base_time,
        )
        self._create_sync_event(
            key="target-b-succeeded",
            user_id="2",
            category=category,
            status=NewsletterSyncEvent.Status.SUCCEEDED,
            completed_at=timezone.now(),
            created_at=base_time + timedelta(minutes=1),
        )
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["sync"]["failed"], 1)
        self.assertTrue(response.data["sync"]["current_warning"])
        self.assertEqual(response.data["sync"]["latest_failure"], "target A failed")

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_multiple_targets_count_only_each_latest_state(self, client_cls):
        self._mock_healthy_mautic(client_cls)
        category = NewsletterCategory.objects.create(name="Many", slug="many")
        other_category = NewsletterCategory.objects.create(name="Other Many", slug="other-many")
        base_time = timezone.now() - timedelta(minutes=10)
        self._create_sync_event(
            key="u1-old-failed",
            user_id="1",
            category=category,
            status=NewsletterSyncEvent.Status.FAILED,
            created_at=base_time,
        )
        self._create_sync_event(
            key="u1-new-success",
            user_id="1",
            category=category,
            status=NewsletterSyncEvent.Status.SUCCEEDED,
            completed_at=timezone.now(),
            created_at=base_time + timedelta(minutes=1),
        )
        self._create_sync_event(
            key="u2-processing",
            user_id="2",
            category=category,
            status=NewsletterSyncEvent.Status.PROCESSING,
            created_at=base_time + timedelta(minutes=2),
        )
        self._create_sync_event(
            key="u3-retrying",
            user_id="3",
            category=other_category,
            status=NewsletterSyncEvent.Status.RETRYING,
            last_error="still retrying",
            created_at=base_time + timedelta(minutes=3),
        )
        self._create_sync_event(
            key="u4-pending",
            user_id="4",
            category=other_category,
            status=NewsletterSyncEvent.Status.PENDING,
            created_at=base_time + timedelta(minutes=4),
        )
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["sync"]["failed"], 0)
        self.assertEqual(response.data["sync"]["retrying"], 1)
        self.assertEqual(response.data["sync"]["processing"], 1)
        self.assertEqual(response.data["sync"]["pending"], 1)
        self.assertTrue(response.data["sync"]["current_warning"])

    @patch("newsletter.mautic_diagnostics_services.MauticClient")
    def test_latest_state_tie_uses_highest_id(self, client_cls):
        self._mock_healthy_mautic(client_cls)
        category = NewsletterCategory.objects.create(name="Tie", slug="tie")
        same_time = timezone.now() - timedelta(minutes=5)
        self._create_sync_event(
            key="tie-success",
            user_id="1",
            category=category,
            status=NewsletterSyncEvent.Status.SUCCEEDED,
            completed_at=timezone.now(),
            created_at=same_time,
        )
        self._create_sync_event(
            key="tie-failed",
            user_id="1",
            category=category,
            status=NewsletterSyncEvent.Status.FAILED,
            last_error="tie failure wins by id",
            created_at=same_time,
        )
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["sync"]["failed"], 1)
        self.assertTrue(response.data["sync"]["current_warning"])
        self.assertEqual(response.data["sync"]["latest_failure"], "tie failure wins by id")
