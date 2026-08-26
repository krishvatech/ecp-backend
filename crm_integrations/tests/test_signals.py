from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings

from crm_integrations.events import USER_CREATED, USER_DEACTIVATED, USER_UPDATED
from crm_integrations.models import CRMConnection, CRMSyncEvent
from crm_integrations.signals import (
    schedule_profile_crm_event,
    should_sync_user,
)


@override_settings(CRM_SYNC_ENABLED=True)
class UserCRMSignalTests(TestCase):
    def setUp(self):
        self.connection = CRMConnection.objects.create(
            provider=CRMConnection.Provider.SALESFORCE,
            name="Primary Salesforce",
            is_active=True,
        )

    def create_user(self, **overrides):
        values = {
            "username": "crm-signal-user",
            "email": "signal@example.com",
            "first_name": "Jane",
            "last_name": "Doe",
        }
        values.update(overrides)
        with patch("crm_integrations.signals.process_crm_sync_event.delay") as delay:
            with self.captureOnCommitCallbacks(execute=True):
                user = get_user_model().objects.create_user(**values)
        return user, delay

    def test_user_creation_persists_and_dispatches_created_event(self):
        user, delay = self.create_user()

        event = CRMSyncEvent.objects.get(event_type=USER_CREATED, object_id=str(user.pk))
        delay.assert_called_once_with(event.pk)
        self.assertEqual(event.status, CRMSyncEvent.Status.PENDING)

    def test_relevant_user_update_dispatches_updated_event(self):
        user, _ = self.create_user()
        user.first_name = "Janet"

        with patch("crm_integrations.signals.process_crm_sync_event.delay") as delay:
            with self.captureOnCommitCallbacks(execute=True):
                user.save(update_fields=["first_name"])

        event = CRMSyncEvent.objects.get(event_type=USER_UPDATED, object_id=str(user.pk))
        delay.assert_called_once_with(event.pk)

    def test_irrelevant_user_update_does_not_create_event(self):
        user, _ = self.create_user()
        before = CRMSyncEvent.objects.count()

        with patch("crm_integrations.signals.process_crm_sync_event.delay") as delay:
            with self.captureOnCommitCallbacks(execute=True):
                user.last_login = None
                user.save(update_fields=["last_login"])

        self.assertEqual(CRMSyncEvent.objects.count(), before)
        delay.assert_not_called()

    def test_deactivated_user_creates_deactivation_event(self):
        user, _ = self.create_user()
        user.is_active = False

        with patch("crm_integrations.signals.process_crm_sync_event.delay") as delay:
            with self.captureOnCommitCallbacks(execute=True):
                user.save(update_fields=["is_active"])

        event = CRMSyncEvent.objects.get(
            event_type=USER_DEACTIVATED,
            object_id=str(user.pk),
        )
        delay.assert_called_once_with(event.pk)

    def test_broker_failure_does_not_escape_and_event_remains_pending(self):
        with patch(
            "crm_integrations.signals.process_crm_sync_event.delay",
            side_effect=ConnectionError("broker unavailable"),
        ):
            with self.captureOnCommitCallbacks(execute=True):
                user = get_user_model().objects.create_user(
                    username="broker-failure-user",
                    email="broker-failure@example.com",
                    first_name="Broker",
                    last_name="Failure",
                )

        event = CRMSyncEvent.objects.get(event_type=USER_CREATED, object_id=str(user.pk))
        self.assertEqual(event.status, CRMSyncEvent.Status.PENDING)

    def test_inactive_connection_creates_no_event(self):
        self.connection.is_active = False
        self.connection.save(update_fields=["is_active"])

        user, delay = self.create_user()

        self.assertFalse(CRMSyncEvent.objects.filter(object_id=str(user.pk)).exists())
        delay.assert_not_called()


class CRMUserEligibilityTests(SimpleTestCase):
    @override_settings(CRM_SYNC_ENABLED=False)
    def test_global_rollout_flag_disables_sync(self):
        user = SimpleNamespace(
            pk=1,
            username="member",
            email="member@example.com",
            is_staff=False,
            is_superuser=False,
        )
        self.assertFalse(should_sync_user(user))

    @override_settings(CRM_SYNC_ENABLED=True, CRM_SYNC_STAFF_USERS=False)
    def test_staff_loadtest_and_system_users_are_excluded(self):
        base = {
            "pk": 1,
            "username": "member",
            "email": "member@example.com",
            "is_staff": False,
            "is_superuser": False,
        }
        self.assertFalse(should_sync_user(SimpleNamespace(**{**base, "is_staff": True})))
        self.assertFalse(
            should_sync_user(
                SimpleNamespace(**{**base, "username": "loadtest-42"})
            )
        )
        self.assertFalse(
            should_sync_user(
                SimpleNamespace(**{**base, "email": "user@wordpress.local"})
            )
        )

    @override_settings(CRM_SYNC_ENABLED=True)
    @patch("crm_integrations.signals.schedule_user_sync")
    @patch("crm_integrations.signals.should_sync_user", return_value=True)
    def test_blocked_profile_status_schedules_deactivation(
        self,
        eligibility,
        schedule,
    ):
        instance = SimpleNamespace(
            user=Mock(),
            user_id=77,
            profile_status="suspended",
            _crm_changed_fields={"profile_status"},
        )

        schedule_profile_crm_event(
            sender=None,
            instance=instance,
            created=False,
            raw=False,
        )

        schedule.assert_called_once_with(77, USER_DEACTIVATED)
