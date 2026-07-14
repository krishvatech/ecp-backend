from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from community.models import Community
from events.models import Event, EventRegistration, NetworkingMeeting, NetworkingTable


class NetworkingTableSoftDeleteTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username="networking-owner",
            email="networking-owner@example.com",
            password="test-pass",
        )
        self.requester = User.objects.create_user(
            username="networking-requester",
            email="networking-requester@example.com",
            password="test-pass",
        )
        self.recipient = User.objects.create_user(
            username="networking-recipient",
            email="networking-recipient@example.com",
            password="test-pass",
        )
        self.community = Community.objects.create(
            name="Networking Soft Delete Community",
            created_by=self.owner,
        )
        self.event = Event.objects.create(
            community=self.community,
            title="Networking Soft Delete Event",
            description="Test event",
            created_by=self.owner,
        )
        self.requester_registration = EventRegistration.objects.create(
            event=self.event,
            user=self.requester,
        )
        self.recipient_registration = EventRegistration.objects.create(
            event=self.event,
            user=self.recipient,
        )
        self.table = NetworkingTable.objects.create(
            event=self.event,
            table_number=1,
            name="Networking Table A",
            location_note="Level 1",
        )
        self.client = APIClient()
        self.client.force_authenticate(self.owner)
        self.detail_url = (
            f"/api/events/{self.event.id}/networking-tables/{self.table.id}/"
        )
        self.list_url = f"/api/events/{self.event.id}/networking-tables/"

    def test_delete_deactivates_table_and_preserves_completed_meeting(self):
        now = timezone.now()
        meeting = NetworkingMeeting.objects.create(
            event=self.event,
            requester=self.requester_registration,
            recipient=self.recipient_registration,
            duration_minutes=10,
            start_time=now - timedelta(minutes=30),
            end_time=now - timedelta(minutes=20),
            table=self.table,
            status="accepted",
            accepted_at=now - timedelta(minutes=35),
        )

        response = self.client.delete(
            self.detail_url,
            {"reason": "No longer required"},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["code"], "networking_table_soft_deleted")

        self.table.refresh_from_db()
        meeting.refresh_from_db()
        self.assertFalse(self.table.is_active)
        self.assertEqual(self.table.deactivation_reason, "No longer required")
        self.assertEqual(self.table.deactivated_by_id, self.owner.id)
        self.assertIsNotNone(self.table.deactivated_at)
        self.assertEqual(meeting.table_id, self.table.id)

        list_response = self.client.get(self.list_url)
        self.assertEqual(list_response.status_code, 200)
        results = list_response.data.get("results", list_response.data)
        self.assertEqual(results, [])

    def test_delete_is_blocked_while_accepted_meeting_has_not_ended(self):
        now = timezone.now()
        meeting = NetworkingMeeting.objects.create(
            event=self.event,
            requester=self.requester_registration,
            recipient=self.recipient_registration,
            duration_minutes=10,
            start_time=now + timedelta(minutes=10),
            end_time=now + timedelta(minutes=20),
            table=self.table,
            status="accepted",
            accepted_at=now,
        )

        response = self.client.delete(self.detail_url, format="json")

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data["code"], "networking_table_in_use")
        self.assertTrue(response.data["is_in_use"])
        self.assertEqual(response.data["active_meeting_count"], 1)
        self.assertIsNotNone(response.data["available_after"])
        self.assertIn("already in use", response.data["detail"])
        self.assertIn("Try again when the table is free", response.data["detail"])
        self.table.refresh_from_db()
        meeting.refresh_from_db()
        self.assertTrue(self.table.is_active)
        self.assertEqual(meeting.table_id, self.table.id)


    def test_list_and_detail_expose_current_table_usage(self):
        now = timezone.now()
        meeting = NetworkingMeeting.objects.create(
            event=self.event,
            requester=self.requester_registration,
            recipient=self.recipient_registration,
            duration_minutes=10,
            start_time=now + timedelta(minutes=10),
            end_time=now + timedelta(minutes=20),
            table=self.table,
            status="accepted",
            accepted_at=now,
        )

        list_response = self.client.get(self.list_url)
        self.assertEqual(list_response.status_code, 200)
        results = list_response.data.get("results", list_response.data)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["is_in_use"])
        self.assertEqual(results[0]["active_meeting_count"], 1)
        self.assertIsNotNone(results[0]["available_after"])

        detail_response = self.client.get(self.detail_url)
        self.assertEqual(detail_response.status_code, 200)
        self.assertTrue(detail_response.data["is_in_use"])
        self.assertEqual(detail_response.data["active_meeting_count"], 1)

        meeting.status = "cancelled"
        meeting.save(update_fields=["status"])

        refreshed_response = self.client.get(self.detail_url)
        self.assertEqual(refreshed_response.status_code, 200)
        self.assertFalse(refreshed_response.data["is_in_use"])
        self.assertEqual(refreshed_response.data["active_meeting_count"], 0)
        self.assertIsNone(refreshed_response.data["available_after"])

    def test_non_owner_cannot_remove_table(self):
        self.client.force_authenticate(self.requester)
        response = self.client.delete(self.detail_url, format="json")
        self.assertEqual(response.status_code, 403)
        self.table.refresh_from_db()
        self.assertTrue(self.table.is_active)
