from unittest.mock import patch

from celery.exceptions import MaxRetriesExceededError, Retry
from django.test import SimpleTestCase, override_settings

from crm_integrations.providers.base import TemporaryCRMError
from crm_integrations.tasks import process_crm_sync_event


class CRMSyncTaskTests(SimpleTestCase):
    @patch("crm_integrations.tasks.process_sync_event")
    def test_temporary_failure_requests_celery_retry(self, processor):
        error = TemporaryCRMError("Salesforce unavailable")
        error.retry_delay = 45
        processor.side_effect = error

        with patch.object(process_crm_sync_event, "retry", side_effect=Retry()) as retry:
            with self.assertRaises(Retry):
                process_crm_sync_event.run(123)

        retry.assert_called_once_with(exc=error, countdown=45, max_retries=5)

    @override_settings(CRM_SYNC_MAX_RETRIES=3)
    @patch("crm_integrations.tasks.mark_retry_exhausted")
    @patch("crm_integrations.tasks.process_sync_event")
    def test_exhausted_retry_marks_event_failed(self, processor, mark_exhausted):
        error = TemporaryCRMError("Salesforce unavailable")
        error.retry_delay = 60
        processor.side_effect = error

        with patch.object(
            process_crm_sync_event,
            "retry",
            side_effect=MaxRetriesExceededError(),
        ):
            result = process_crm_sync_event.run(456)

        mark_exhausted.assert_called_once_with(456)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "retry_limit_exhausted")
