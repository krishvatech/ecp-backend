from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework.test import APIClient

from community.models import Community
from events.models import Event, EventRegistration, LoungeParticipant, LoungeTable


class LoungeTableSoftDeleteTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username="lounge-owner",
            email="lounge-owner@example.com",
            password="test-pass",
        )
        self.attendee = User.objects.create_user(
            username="lounge-attendee",
            email="lounge-attendee@example.com",
            password="test-pass",
        )
        self.community = Community.objects.create(
            name="Lounge Soft Delete Community",
            created_by=self.owner,
        )
        self.event = Event.objects.create(
            community=self.community,
            title="Lounge Soft Delete Event",
            description="Test event",
            created_by=self.owner,
        )
        self.table = LoungeTable.objects.create(
            event=self.event,
            name="Table A",
            category="BREAKOUT",
            max_seats=4,
            rtk_meeting_id="rtk-table-a",
        )
        self.registration = EventRegistration.objects.create(
            event=self.event,
            user=self.attendee,
            last_breakout_table=self.table,
        )
        LoungeParticipant.objects.create(
            table=self.table,
            user=self.attendee,
            seat_index=0,
        )
        self.client = APIClient()
        self.client.force_authenticate(self.owner)

    def test_delete_endpoint_deactivates_table_and_clears_transient_seats(self):
        response = self.client.post(
            f"/api/events/{self.event.id}/lounge-table-delete/",
            {"table_id": self.table.id, "reason": "Created by mistake"},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["code"], "lounge_table_soft_deleted")
        self.assertEqual(response.data["deletion_type"], "soft")

        table = LoungeTable.all_objects.get(id=self.table.id)
        self.assertFalse(table.is_active)
        self.assertEqual(table.deactivation_reason, "Created by mistake")
        self.assertEqual(table.deactivated_by_id, self.owner.id)
        self.assertEqual(table.rtk_meeting_id, "rtk-table-a")
        self.assertFalse(LoungeTable.objects.filter(id=table.id).exists())
        self.assertFalse(LoungeParticipant.objects.filter(table_id=table.id).exists())

        self.registration.refresh_from_db()
        self.assertIsNone(self.registration.last_breakout_table_id)

    def test_restore_returns_table_without_recreating_old_seats(self):
        self.table.soft_delete(user=self.owner, reason="Temporary removal")
        table = LoungeTable.all_objects.get(id=self.table.id)
        table.restore()

        table.refresh_from_db()
        self.assertTrue(table.is_active)
        self.assertIsNone(table.deactivated_at)
        self.assertIsNone(table.deactivated_by_id)
        self.assertEqual(table.deactivation_reason, "")
        self.assertTrue(LoungeTable.objects.filter(id=table.id).exists())
        self.assertFalse(LoungeParticipant.objects.filter(table_id=table.id).exists())
