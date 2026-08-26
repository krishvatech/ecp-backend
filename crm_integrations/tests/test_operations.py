from datetime import timedelta
from io import StringIO
from unittest.mock import Mock, patch

from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from crm_integrations.models import CRMConnection, CRMSyncEvent
from crm_integrations.operations import (
    check_connection_health,
    dispatch_due_sync_events,
    due_sync_event_ids,
    requeue_sync_events,
)
from crm_integrations.providers.base import TemporaryCRMError


class CRMOperationalTests(TestCase):
    def setUp(self):
        self.connection = CRMConnection.objects.create(
            provider=CRMConnection.Provider.SALESFORCE,
            name="Primary Salesforce",
            is_active=True,
        )

    def event(self, status=CRMSyncEvent.Status.PENDING, **overrides):
        values = {
            "connection": self.connection,
            "idempotency_key": f"operations-test-{CRMSyncEvent.objects.count()}",
            "event_type": "user.updated",
            "object_type": "user",
            "object_id": "123",
            "status": status,
        }
        values.update(overrides)
        return CRMSyncEvent.objects.create(**values)

    @patch("crm_integrations.operations.get_crm_provider")
    def test_successful_health_check_is_persisted(self, provider_factory):
        provider_factory.return_value.health_check.return_value = True

        result = check_connection_health(self.connection)

        self.connection.refresh_from_db()
        self.assertTrue(result["healthy"])
        self.assertTrue(self.connection.last_health_check_status)
        self.assertIsNotNone(self.connection.last_health_check_at)
        self.assertEqual(self.connection.last_error, "")

    @patch("crm_integrations.operations.get_crm_provider")
    def test_failed_health_check_is_sanitized_and_persisted(self, provider_factory):
        provider_factory.return_value.health_check.side_effect = TemporaryCRMError(
            "Salesforce API request failed (HTTP 503)"
        )

        result = check_connection_health(self.connection)

        self.connection.refresh_from_db()
        self.assertFalse(result["healthy"])
        self.assertFalse(self.connection.last_health_check_status)
        self.assertIn("HTTP 503", self.connection.last_error)

    @override_settings(CRM_SYNC_PROCESSING_TIMEOUT_SECONDS=60)
    def test_due_selection_includes_pending_due_retry_and_stale_processing(self):
        pending = self.event()
        due_retry = self.event(
            status=CRMSyncEvent.Status.RETRYING,
            next_retry_at=timezone.now() - timedelta(seconds=1),
        )
        stale = self.event(
            status=CRMSyncEvent.Status.PROCESSING,
            processing_started_at=timezone.now() - timedelta(minutes=2),
        )
        future = self.event(
            status=CRMSyncEvent.Status.RETRYING,
            next_retry_at=timezone.now() + timedelta(hours=1),
        )
        succeeded = self.event(status=CRMSyncEvent.Status.SUCCEEDED)

        selected = due_sync_event_ids()

        self.assertEqual(set(selected), {pending.pk, due_retry.pk, stale.pk})
        self.assertNotIn(future.pk, selected)
        self.assertNotIn(succeeded.pk, selected)

    @override_settings(CRM_SYNC_ENABLED=True)
    @patch("crm_integrations.operations.process_crm_sync_event.delay")
    def test_dispatch_due_events_is_best_effort(self, delay):
        first = self.event()
        second = self.event()
        delay.side_effect = [None, ConnectionError("broker unavailable")]

        result = dispatch_due_sync_events()

        self.assertEqual(result["selected"], 2)
        self.assertEqual(result["dispatched"], 1)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(
            [call.args[0] for call in delay.call_args_list],
            [first.pk, second.pk],
        )

    @override_settings(CRM_SYNC_ENABLED=False)
    @patch("crm_integrations.operations.process_crm_sync_event.delay")
    def test_dispatch_is_disabled_by_rollout_flag(self, delay):
        self.event()

        result = dispatch_due_sync_events()

        self.assertTrue(result["disabled"])
        delay.assert_not_called()

    @override_settings(CRM_SYNC_ENABLED=True)
    @patch("crm_integrations.operations.process_crm_sync_event.delay")
    def test_manual_requeue_resets_failure_and_dispatches(self, delay):
        failed = self.event(
            status=CRMSyncEvent.Status.FAILED,
            last_error="Permanent failure",
            completed_at=timezone.now(),
        )
        succeeded = self.event(status=CRMSyncEvent.Status.SUCCEEDED)

        result = requeue_sync_events(
            CRMSyncEvent.objects.filter(pk__in=[failed.pk, succeeded.pk])
        )

        failed.refresh_from_db()
        self.assertEqual(result["selected"], 1)
        self.assertEqual(failed.status, CRMSyncEvent.Status.PENDING)
        self.assertEqual(failed.last_error, "")
        self.assertIsNone(failed.completed_at)
        delay.assert_called_once_with(failed.pk)

    @override_settings(CRM_SYNC_ENABLED=False)
    @patch("crm_integrations.operations.process_crm_sync_event.delay")
    def test_manual_requeue_retains_pending_event_when_sync_is_disabled(self, delay):
        failed = self.event(status=CRMSyncEvent.Status.FAILED)

        result = requeue_sync_events(CRMSyncEvent.objects.filter(pk=failed.pk))

        failed.refresh_from_db()
        self.assertEqual(failed.status, CRMSyncEvent.Status.PENDING)
        self.assertEqual(result["dispatched"], 0)
        delay.assert_not_called()

    @override_settings(CRM_SYNC_ENABLED=False)
    def test_management_command_reports_disabled_state(self):
        output = StringIO()

        call_command("dispatch_crm_sync_events", stdout=output)

        self.assertIn("CRM synchronization is disabled", output.getvalue())
