from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from crm_integrations.models import CRMConnection, CRMObjectMapping, CRMSyncEvent
from crm_integrations.processor import process_sync_event, retry_delay_seconds
from crm_integrations.providers.base import (
    CRMUpsertResult,
    PermanentCRMError,
    TemporaryCRMError,
)


@override_settings(CRM_SYNC_ENABLED=True)
class CRMSyncProcessorTests(TestCase):
    def setUp(self):
        self.connection = CRMConnection.objects.create(
            provider=CRMConnection.Provider.SALESFORCE,
            name="Primary Salesforce",
            is_active=True,
        )
        self.user = get_user_model().objects.create_user(
            username="crm-user",
            email="CRM-USER@example.com",
            first_name=" Jane ",
            last_name=" Doe ",
        )

    def event(self, **overrides):
        values = {
            "connection": self.connection,
            "idempotency_key": f"processor-test-{CRMSyncEvent.objects.count()}",
            "event_type": "user.created",
            "object_type": "user",
            "object_id": str(self.user.pk),
            "payload": {"stale": "snapshot"},
        }
        values.update(overrides)
        return CRMSyncEvent.objects.create(**values)

    @patch("crm_integrations.processor.get_crm_provider")
    def test_success_upserts_latest_user_and_saves_mapping(self, provider_factory):
        provider = Mock()
        provider.upsert_contact.return_value = CRMUpsertResult(
            external_id="003000000000123AAA",
            external_object_type="Contact",
            created=True,
        )
        provider_factory.return_value = provider
        event = self.event()

        result = process_sync_event(event.pk)

        event.refresh_from_db()
        mapping = CRMObjectMapping.objects.get(
            connection=self.connection,
            local_object_type="user",
            local_object_id=str(self.user.pk),
        )
        self.assertEqual(result["status"], CRMSyncEvent.Status.SUCCEEDED)
        self.assertEqual(event.status, CRMSyncEvent.Status.SUCCEEDED)
        self.assertEqual(event.attempt_count, 1)
        self.assertEqual(event.payload["email"], "crm-user@example.com")
        self.assertEqual(mapping.external_id, "003000000000123AAA")
        self.assertIsNotNone(mapping.last_synced_at)
        sent_payload = provider.upsert_contact.call_args.args[0]
        self.assertEqual(sent_payload["first_name"], "Jane")

    @patch("crm_integrations.processor.get_crm_provider")
    def test_successful_event_is_not_processed_twice(self, provider_factory):
        provider = Mock()
        provider.upsert_contact.return_value = CRMUpsertResult(
            external_id="003000000000123AAA",
            external_object_type="Contact",
            created=False,
        )
        provider_factory.return_value = provider
        event = self.event()

        process_sync_event(event.pk)
        second = process_sync_event(event.pk)

        self.assertFalse(second["processed"])
        provider.upsert_contact.assert_called_once()

    @patch("crm_integrations.processor.get_crm_provider")
    @override_settings(CRM_SYNC_RETRY_BASE_SECONDS=10, CRM_SYNC_RETRY_MAX_SECONDS=60)
    def test_temporary_failure_is_scheduled_for_retry(self, provider_factory):
        provider_factory.return_value.upsert_contact.side_effect = TemporaryCRMError(
            "Salesforce rate limited request"
        )
        event = self.event()

        with self.assertRaises(TemporaryCRMError) as raised:
            process_sync_event(event.pk)

        event.refresh_from_db()
        self.assertEqual(event.status, CRMSyncEvent.Status.RETRYING)
        self.assertEqual(event.attempt_count, 1)
        self.assertEqual(raised.exception.retry_delay, 10)
        self.assertIsNotNone(event.next_retry_at)
        self.assertNotIn("client-secret", event.last_error)

    @patch("crm_integrations.processor.get_crm_provider")
    def test_permanent_failure_is_terminal(self, provider_factory):
        provider_factory.return_value.upsert_contact.side_effect = PermanentCRMError(
            "Invalid Salesforce field configuration"
        )
        event = self.event()

        result = process_sync_event(event.pk)

        event.refresh_from_db()
        self.assertEqual(result["status"], CRMSyncEvent.Status.FAILED)
        self.assertEqual(event.status, CRMSyncEvent.Status.FAILED)
        self.assertIsNotNone(event.completed_at)
        self.assertIsNone(event.next_retry_at)

    @patch("crm_integrations.processor.get_crm_provider")
    def test_inactive_connection_is_skipped_without_provider_call(self, provider_factory):
        self.connection.is_active = False
        self.connection.save(update_fields=["is_active"])
        event = self.event()

        result = process_sync_event(event.pk)

        event.refresh_from_db()
        self.assertEqual(result["status"], CRMSyncEvent.Status.SKIPPED)
        provider_factory.assert_not_called()

    @patch("crm_integrations.processor.get_crm_provider")
    def test_deleted_user_is_skipped_without_provider_call(self, provider_factory):
        event = self.event()
        self.user.delete()

        result = process_sync_event(event.pk)

        event.refresh_from_db()
        self.assertEqual(result["status"], CRMSyncEvent.Status.SKIPPED)
        self.assertIn("no longer exists", event.last_error)
        provider_factory.assert_not_called()

    @override_settings(CRM_SYNC_RETRY_BASE_SECONDS=10, CRM_SYNC_RETRY_MAX_SECONDS=25)
    def test_retry_delay_is_exponential_and_bounded(self):
        self.assertEqual(retry_delay_seconds(1), 10)
        self.assertEqual(retry_delay_seconds(2), 20)
        self.assertEqual(retry_delay_seconds(3), 25)
        self.assertEqual(retry_delay_seconds(10), 25)
