from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from community.models import Community
from events.models import Event, EventSeries, SeriesRegistration


class EventSeriesSoftDeleteTests(APITestCase):
    def setUp(self):
        self.owner = User.objects.create_user("series-owner", password="pass")
        self.member = User.objects.create_user("series-member", password="pass")
        self.community = Community.objects.create(name="Series Test Community", owner=self.owner)
        self.community.members.add(self.member)
        self.client.force_authenticate(self.owner)

    def _series(self, title="Test Series"):
        series = EventSeries.objects.create(
            community=self.community,
            created_by=self.owner,
            title=title,
            status="draft",
        )
        SeriesRegistration.objects.create(series=series, user=self.owner)
        return series

    def test_unused_series_is_soft_deleted_and_retained(self):
        series = self._series("Unused Series")
        owner_registration = SeriesRegistration.objects.get(series=series, user=self.owner)

        response = self.client.delete(
            reverse("series-detail", args=[series.id]),
            {"reason": "Created by mistake"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["deletion_type"], "soft")
        self.assertEqual(response.data["code"], "series_soft_deleted")
        self.assertFalse(EventSeries.objects.filter(id=series.id).exists())

        retained = EventSeries.all_objects.get(id=series.id)
        self.assertTrue(retained.is_deleted)
        self.assertEqual(retained.status, "archived")
        self.assertEqual(retained.status_before_delete, "draft")
        self.assertEqual(retained.deletion_reason, "Created by mistake")
        self.assertTrue(SeriesRegistration.objects.filter(id=owner_registration.id).exists())

    def test_series_with_participant_history_is_soft_deleted(self):
        series = self._series("Registered Series")
        registration = SeriesRegistration.objects.create(
            series=series,
            user=self.member,
            status="cancelled",
        )

        response = self.client.delete(
            reverse("series-detail", args=[series.id]),
            {"reason": "Created with the wrong title"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["deletion_type"], "soft")
        self.assertFalse(EventSeries.objects.filter(id=series.id).exists())

        retained = EventSeries.all_objects.get(id=series.id)
        self.assertTrue(retained.is_deleted)
        self.assertEqual(retained.status, "archived")
        self.assertEqual(retained.status_before_delete, "draft")
        self.assertEqual(retained.deletion_reason, "Created with the wrong title")
        self.assertTrue(SeriesRegistration.objects.filter(id=registration.id).exists())

    def test_series_with_child_event_is_soft_deleted_without_detaching_event(self):
        series = self._series("Series With Event")
        event = Event.objects.create(
            community=self.community,
            created_by=self.owner,
            title="Child Event",
            start_time=timezone.now(),
            end_time=timezone.now(),
            series=series,
            series_order=1,
            series_session_label="Session 1",
        )

        response = self.client.delete(reverse("series-detail", args=[series.id]), {}, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["deletion_type"], "soft")
        event.refresh_from_db()
        self.assertEqual(event.series_id, series.id)
        self.assertEqual(event.series_order, 1)
        self.assertEqual(event.series_session_label, "Session 1")
        self.assertTrue(EventSeries.all_objects.get(id=series.id).is_deleted)

    def test_restore_recovers_previous_status(self):
        series = self._series("Restore Series")
        series.status = "published"
        series.save(update_fields=["status"])
        series.soft_delete(user=self.owner, reason="Temporary removal")

        retained = EventSeries.all_objects.get(id=series.id)
        retained.restore()

        restored = EventSeries.objects.get(id=series.id)
        self.assertFalse(restored.is_deleted)
        self.assertEqual(restored.status, "published")
        self.assertEqual(restored.deletion_reason, "")
