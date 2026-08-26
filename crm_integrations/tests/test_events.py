from types import SimpleNamespace

from django.test import TestCase

from crm_integrations.events import USER_CREATED, USER_UPDATED, create_user_sync_events
from crm_integrations.models import CRMConnection, CRMSyncEvent


class UserSyncEventTests(TestCase):
    def setUp(self):
        self.connection = CRMConnection.objects.create(
            provider=CRMConnection.Provider.SALESFORCE,
            name="Primary Salesforce",
            is_active=True,
        )
        self.user = SimpleNamespace(
            pk=123,
            first_name="John",
            last_name="Smith",
            email="john@example.com",
            is_active=True,
            profile=SimpleNamespace(
                company="ABC Capital",
                job_title="Partner",
                location_country="United Kingdom",
                location_country_code="GB",
                profile_status="active",
            ),
        )

    def test_creates_one_pending_event_for_each_active_connection(self):
        CRMConnection.objects.create(
            provider=CRMConnection.Provider.SALESFORCE,
            name="Disabled Salesforce",
            is_active=False,
        )

        events = create_user_sync_events(self.user, USER_CREATED)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].connection, self.connection)
        self.assertEqual(events[0].status, CRMSyncEvent.Status.PENDING)
        self.assertEqual(events[0].payload["ecp_user_id"], "123")

    def test_identical_state_is_idempotent(self):
        first = create_user_sync_events(self.user, USER_UPDATED)[0]
        second = create_user_sync_events(self.user, USER_UPDATED)[0]

        self.assertEqual(first.pk, second.pk)
        self.assertEqual(CRMSyncEvent.objects.count(), 1)

    def test_changed_state_creates_a_new_update_event(self):
        first = create_user_sync_events(self.user, USER_UPDATED)[0]
        self.user.profile.company = "XYZ Capital"
        second = create_user_sync_events(self.user, USER_UPDATED)[0]

        self.assertNotEqual(first.pk, second.pk)
        self.assertEqual(CRMSyncEvent.objects.count(), 2)

    def test_returning_to_a_completed_state_creates_a_new_event(self):
        first = create_user_sync_events(self.user, USER_UPDATED)[0]
        first.status = CRMSyncEvent.Status.SUCCEEDED
        first.save(update_fields=["status"])

        self.user.profile.company = "XYZ Capital"
        second = create_user_sync_events(self.user, USER_UPDATED)[0]
        second.status = CRMSyncEvent.Status.SUCCEEDED
        second.save(update_fields=["status"])

        self.user.profile.company = "ABC Capital"
        third = create_user_sync_events(self.user, USER_UPDATED)[0]

        self.assertNotEqual(first.pk, third.pk)
        self.assertEqual(third.status, CRMSyncEvent.Status.PENDING)
        self.assertEqual(CRMSyncEvent.objects.count(), 3)

    def test_rejects_unsupported_event_type(self):
        with self.assertRaisesMessage(ValueError, "Unsupported user CRM event type"):
            create_user_sync_events(self.user, "order.paid")
