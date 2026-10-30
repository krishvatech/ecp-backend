from datetime import datetime, timezone
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter import calendar_views as views
from newsletter.mautic import TemporaryMauticError
from newsletter.mautic.client import MauticClient
from newsletter.models import NewsletterCampaign, NewsletterCategory
from newsletter.tests.marketing_actors import grant_marketing_access
from newsletter.tests.test_mautic_template_client import response

User = get_user_model()
S = NewsletterCampaign.Status


def at(day, hour=9):
    return datetime(2026, 11, day, hour, 0, tzinfo=timezone.utc)


class WindowTests(SimpleTestCase):
    def test_window(self):
        self.assertEqual([d.isoformat() for d in views.parse_window("2026-11-01", "2026-11-30")], ["2026-11-01", "2026-11-30"])
        for bad in (("2026-11-31", "2026-12-01"), ("x", "2026-12-01"), ("2026-12-01", "2026-11-01"), ("2026-01-01", "2026-06-01")):
            with self.subTest(bad=bad), self.assertRaises(views.CalendarError):
                views.parse_window(*bad)

    def test_client_reads_the_bridge_window(self):
        session = Mock()
        session.request.return_value = response(200, {"items": [], "truncated": False})
        MauticClient(session=session).get_marketing_calendar("2026-11-01", "2026-11-30")
        self.assertTrue(session.request.call_args.args[1].endswith("/api/ecp/calendar"))
        self.assertEqual(session.request.call_args.kwargs["params"], {"from": "2026-11-01", "to": "2026-11-30"})


class BroadcastItemTests(TestCase):
    def test_each_status_is_dated_by_its_own_moment(self):
        weekly = NewsletterCategory.objects.create(name="Weekly", slug="weekly-calendar")
        scheduled = NewsletterCampaign.objects.create(name="Scheduled", subject="S", status=S.SCHEDULED, scheduled_at=at(5))
        scheduled.audiences.add(weekly)
        NewsletterCampaign.objects.create(name="Sent", status=S.SENT, scheduled_at=at(1), sent_at=at(2, 10))
        NewsletterCampaign.objects.create(name="Sending", status=S.SENDING, scheduled_at=at(3), send_started_at=at(3, 11))
        NewsletterCampaign.objects.create(name="Failed", status=S.FAILED, scheduled_at=at(4))
        NewsletterCampaign.objects.create(name="Draft", status=S.DRAFT, scheduled_at=at(6))
        NewsletterCampaign.objects.create(name="Cancelled", status=S.CANCELLED, scheduled_at=at(6))
        NewsletterCampaign.objects.create(name="Outside", status=S.SCHEDULED, scheduled_at=datetime(2026, 12, 1, 0, 0, tzinfo=timezone.utc))
        # Sent in the window but scheduled before it: dated by the send.
        NewsletterCampaign.objects.create(name="Late", status=S.SENT, scheduled_at=datetime(2026, 10, 31, tzinfo=timezone.utc), sent_at=at(1, 8))

        items = views.broadcast_items(*views.parse_window("2026-11-01", "2026-11-30"))
        by_name = {item["title"]: item for item in items}
        self.assertEqual(set(by_name), {"Scheduled", "Sent", "Sending", "Failed", "Late"})
        self.assertEqual((by_name["Sent"]["kind"], by_name["Sent"]["at"]), ("broadcast_sent", "2026-11-02T10:00:00+00:00"))
        self.assertEqual(by_name["Sending"]["at"], "2026-11-03T11:00:00+00:00")
        self.assertEqual(by_name["Scheduled"]["lists"], ["Weekly"])
        self.assertEqual(by_name["Scheduled"]["resourceId"], str(scheduled.uuid))


class CalendarApiTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username="calendar-admin", email="ca@example.test", password="x")
        grant_marketing_access(self.admin)
        self.api = APIClient()
        self.api.force_authenticate(self.admin)
        self.url = reverse("newsletter-admin-calendar")
        NewsletterCampaign.objects.create(name="Weekly digest", status=S.SCHEDULED, scheduled_at=at(4))

    def test_broadcasts_and_mautic_dates_merged_in_time_order(self):
        mautic = {"truncated": False, "items": [
            {"kind": "campaign_step", "id": "campaign-7-3-2026-11-03", "at": "2026-11-03T09:00:00+00:00", "title": "Send welcome", "count": 42},
            {"kind": "report_email", "id": "report-4", "at": "2026-11-09T00:00:00+00:00", "title": "Weekly sends"},
            {"kind": "something_else", "id": "x", "at": "2026-11-01T00:00:00+00:00", "title": "Ignored"},
        ]}
        with patch.object(MauticClient, "get_marketing_calendar", return_value=mautic) as read:
            body = self.api.get(self.url, {"from": "2026-11-01", "to": "2026-11-30"}).json()
        read.assert_called_once_with("2026-11-01", "2026-11-30")
        self.assertEqual([item["kind"] for item in body["items"]], ["campaign_step", "broadcast_scheduled", "report_email"])
        self.assertEqual(body["warning"], "")

    def test_a_mautic_outage_still_shows_broadcasts_with_a_warning(self):
        with patch.object(MauticClient, "get_marketing_calendar", side_effect=TemporaryMauticError("down")):
            r = self.api.get(self.url, {"from": "2026-11-01", "to": "2026-11-30"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual([item["title"] for item in r.json()["items"]], ["Weekly digest"])
        self.assertIn("only Broadcasts are shown", r.json()["warning"])

    def test_bad_windows_and_non_marketing_users(self):
        self.assertEqual(self.api.get(self.url, {"from": "2026-11-01", "to": "2027-11-01"}).json()["code"], "invalid_window")
        normal = APIClient()
        normal.force_authenticate(User.objects.create_user(username="calendar-normal", email="cn@example.test", password="x"))
        self.assertIn(normal.get(self.url, {"from": "2026-11-01", "to": "2026-11-30"}).status_code, (401, 403))
