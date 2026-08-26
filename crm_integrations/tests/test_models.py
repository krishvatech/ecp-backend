from django.db import IntegrityError, transaction
from django.test import TestCase

from crm_integrations.models import CRMConnection, CRMObjectMapping, CRMSyncEvent


class CRMIntegrationModelTests(TestCase):
    def setUp(self):
        self.connection = CRMConnection.objects.create(
            provider=CRMConnection.Provider.SALESFORCE,
            name="Primary Salesforce",
        )

    def test_connection_is_inactive_by_default(self):
        self.assertFalse(self.connection.is_active)
        self.assertEqual(str(self.connection), "Primary Salesforce (Salesforce)")

    def test_local_object_can_only_have_one_mapping_per_connection(self):
        CRMObjectMapping.objects.create(
            connection=self.connection,
            local_object_type="user",
            local_object_id="123",
            external_object_type="Contact",
            external_id="003-first",
        )

        with self.assertRaises(IntegrityError), transaction.atomic():
            CRMObjectMapping.objects.create(
                connection=self.connection,
                local_object_type="user",
                local_object_id="123",
                external_object_type="Contact",
                external_id="003-second",
            )

    def test_sync_event_is_pending_and_idempotency_key_is_unique(self):
        event = CRMSyncEvent.objects.create(
            connection=self.connection,
            idempotency_key="salesforce:user.created:123:v1",
            event_type="user.created",
            object_type="user",
            object_id="123",
        )

        self.assertEqual(event.status, CRMSyncEvent.Status.PENDING)
        self.assertEqual(event.attempt_count, 0)
        self.assertIsNotNone(event.event_uuid)

        with self.assertRaises(IntegrityError), transaction.atomic():
            CRMSyncEvent.objects.create(
                connection=self.connection,
                idempotency_key=event.idempotency_key,
                event_type="user.created",
                object_type="user",
                object_id="123",
            )
