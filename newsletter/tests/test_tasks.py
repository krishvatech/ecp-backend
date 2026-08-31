from unittest.mock import patch

from celery.exceptions import MaxRetriesExceededError, Retry
from django.test import SimpleTestCase, override_settings

from newsletter.mautic import TemporaryMauticError
from newsletter.tasks import (
    dispatch_due_newsletter_sync_events,
    process_newsletter_sync_event,
)


class NewsletterSyncTaskTests(SimpleTestCase):
    @patch(
        "newsletter.tasks.process_sync_event",
        side_effect=TemporaryMauticError("temporary outage"),
    )
    def test_temporary_failure_requests_celery_retry(self, _processor):
        with patch.object(
            process_newsletter_sync_event,
            "retry",
            side_effect=Retry(),
        ) as retry:
            with self.assertRaises(Retry):
                process_newsletter_sync_event.run(123)

        retry.assert_called_once()
        self.assertEqual(retry.call_args.kwargs["countdown"], 30)
        self.assertEqual(retry.call_args.kwargs["max_retries"], 5)

    @override_settings(MAUTIC_SYNC_MAX_RETRIES=7)
    @patch(
        "newsletter.tasks.process_sync_event",
        side_effect=TemporaryMauticError("temporary outage"),
    )
    def test_retry_uses_configured_max_retries(self, _processor):
        with patch.object(
            process_newsletter_sync_event,
            "retry",
            side_effect=Retry(),
        ) as retry:
            with self.assertRaises(Retry):
                process_newsletter_sync_event.run(124)

        self.assertEqual(retry.call_args.kwargs["max_retries"], 7)

    @patch("newsletter.tasks.mark_retry_exhausted")
    @patch(
        "newsletter.tasks.process_sync_event",
        side_effect=TemporaryMauticError("still unavailable"),
    )
    def test_exhausted_retry_marks_event_failed(
        self,
        _processor,
        mark_retry_exhausted,
    ):
        with patch.object(
            process_newsletter_sync_event,
            "retry",
            side_effect=MaxRetriesExceededError(),
        ):
            result = process_newsletter_sync_event.run(456)

        mark_retry_exhausted.assert_called_once_with(456)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "retry_limit_exhausted")

    @patch("newsletter.operations.dispatch_due_sync_events")
    def test_dispatch_task_delegates_to_operations(self, dispatch):
        dispatch.return_value = {
            "disabled": False,
            "selected": 2,
            "dispatched": 2,
            "failed": 0,
        }

        result = dispatch_due_newsletter_sync_events.run(batch_size=25)

        dispatch.assert_called_once_with(batch_size=25)
        self.assertEqual(result["dispatched"], 2)

    def test_task_names_are_stable(self):
        self.assertEqual(
            process_newsletter_sync_event.name,
            "newsletter.process_sync_event",
        )
        self.assertEqual(
            dispatch_due_newsletter_sync_events.name,
            "newsletter.dispatch_due_sync_events",
        )
