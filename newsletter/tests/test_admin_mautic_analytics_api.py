from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter.mautic import TemporaryMauticError
from newsletter.mautic_analytics_services import _count_new_contacts


User = get_user_model()


class NewsletterAdminMauticAnalyticsAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="mautic-analytics-staff",
            email="mautic-analytics-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="mautic-analytics-normal",
            email="mautic-analytics-normal@example.test",
            password="test-password",
        )
        self.overview_url = reverse("newsletter-admin-analytics-overview")
        self.campaigns_url = reverse("newsletter-admin-analytics-campaigns")
        self.emails_url = reverse("newsletter-admin-analytics-emails")
        self.contacts_url = reverse("newsletter-admin-analytics-contacts")
        self.segments_url = reverse("newsletter-admin-analytics-segments")

    def _authenticate(self, user=None):
        self.client.force_authenticate(user=user or self.staff)

    def test_auth_is_preserved(self):
        response = self.client.get(self.overview_url)
        self.assertIn(response.status_code, (401, 403))

        self._authenticate(self.normal_user)
        response = self.client.get(self.overview_url)
        self.assertEqual(response.status_code, 403)

    @patch("newsletter.mautic_analytics_services.MauticClient")
    def test_overview_normalizes_provider_metrics_and_date_range(self, client_cls):
        client = client_cls.return_value
        client.list_contacts.side_effect = [
            {"total": 50, "contacts": []},
            {"total": 7, "contacts": []},
        ]
        client.list_campaigns.return_value = {
            "total": 2,
            "campaigns": [
                {"id": 1, "name": "Published", "isPublished": True},
                {"id": 2, "name": "Draft", "isPublished": False},
            ],
        }
        client.list_emails.return_value = {
            "total": 1,
            "emails": [{"id": 8, "name": "Digest", "sentCount": 10, "readCount": 4}],
        }
        client.get_email_stats.return_value = {
            "data": [
                {"lead_id": 1, "is_read": True, "clicked": True},
                {"lead_id": 2, "is_read": False, "is_failed": True},
            ]
        }
        client.list_segments.return_value = {"total": 3, "lists": []}
        self._authenticate()

        response = self.client.get(
            self.overview_url,
            {"from": "2026-09-01", "to": "2026-09-12"},
        )

        self.assertEqual(response.status_code, 200)
        metrics = {row["key"]: row for row in response.data["metrics"]}
        self.assertEqual(metrics["total_contacts"]["value"], 50)
        self.assertEqual(metrics["new_contacts"]["value"], 7)
        self.assertEqual(metrics["published_campaigns"]["value"], 1)
        self.assertEqual(metrics["opens"]["value"], 1)
        self.assertEqual(metrics["clicks"]["value"], 1)
        self.assertEqual(metrics["bounces"]["value"], 1)
        self.assertEqual(metrics["new_contacts"]["scope"], "date_range")
        self.assertEqual(
            client.list_contacts.call_args_list[1].kwargs,
            {
                "start": 0,
                "limit": 1,
                "where[0][col]": "dateAdded",
                "where[0][expr]": "gte",
                "where[0][val]": "2026-09-01 00:00:00",
                "where[1][col]": "dateAdded",
                "where[1][expr]": "lte",
                "where[1][val]": "2026-09-12 23:59:59",
            },
        )

    def test_overview_rejects_invalid_date_range(self):
        self._authenticate()
        response = self.client.get(
            self.overview_url,
            {"from": "2026-09-12", "to": "2026-09-01"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("from must be", response.data["detail"])

    @patch("newsletter.mautic_analytics_services.MauticClient")
    def test_campaigns_list_paginates_and_normalizes(self, client_cls):
        client_cls.return_value.list_campaigns.return_value = {
            "total": 1,
            "campaigns": [
                {
                    "id": 12,
                    "name": "Native Journey",
                    "isPublished": 1,
                    "contactCount": "42",
                    "events": {"1": {"id": 1}, "2": {"id": 2}},
                    "dateModified": "2026-09-12T10:00:00+00:00",
                }
            ],
        }
        self._authenticate()

        response = self.client.get(self.campaigns_url, {"page": 2, "page_size": 10})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["results"][0]["id"], "12")
        self.assertEqual(response.data["results"][0]["status"], "published")
        self.assertEqual(response.data["results"][0]["contactCount"], 42)
        self.assertEqual(response.data["results"][0]["eventCount"], 2)
        client_cls.return_value.list_campaigns.assert_called_once_with(start=10, limit=10)

    @patch("newsletter.mautic_analytics_services.MauticClient")
    def test_campaigns_provider_failure_returns_502(self, client_cls):
        client_cls.return_value.list_campaigns.side_effect = TemporaryMauticError("down")
        self._authenticate()

        response = self.client.get(self.campaigns_url)

        self.assertEqual(response.status_code, 502)

    @patch("newsletter.mautic_analytics_services.MauticClient")
    def test_emails_normalizes_metrics_and_zero_denominator_rates(self, client_cls):
        client = client_cls.return_value
        client.list_emails.return_value = {
            "total": 2,
            "emails": [
                {"id": 5, "name": "Launch", "isPublished": True, "sentCount": 10},
                {"id": 6, "name": "Draft", "isPublished": False, "sentCount": 0},
            ],
        }
        client.get_email_stats.side_effect = [
            {"data": [{"is_read": True}, {"clicked": True}]},
            {"data": [{"is_read": True}]},
        ]
        self._authenticate()

        response = self.client.get(self.emails_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["results"][0]["opened"], 1)
        self.assertEqual(response.data["results"][0]["clicked"], 1)
        self.assertEqual(response.data["results"][0]["openRate"], 0.1)
        self.assertIsNone(response.data["results"][1]["openRate"])

    @patch("newsletter.mautic_analytics_services.get_admin_stage_analytics")
    @patch("newsletter.mautic_analytics_services.MauticClient")
    def test_contacts_keeps_dnc_separate_and_reuses_stage_distribution(self, client_cls, stage_analytics):
        client = client_cls.return_value
        client.list_contacts.side_effect = [
            {"total": 100, "contacts": []},
            {"total": 5, "contacts": []},
        ]
        stage_analytics.return_value = {"total_contacts": 100, "stages": [{"id": "1", "count": 3}]}
        self._authenticate()

        response = self.client.get(self.contacts_url, {"from": "2026-09-01"})

        self.assertEqual(response.status_code, 200)
        metrics = {row["key"]: row for row in response.data["metrics"]}
        self.assertFalse(metrics["dnc"]["available"])
        self.assertEqual(response.data["stage_distribution"]["stages"][0]["count"], 3)
        self.assertEqual(
            client.list_contacts.call_args_list[1].kwargs,
            {
                "start": 0,
                "limit": 1,
                "where[0][col]": "dateAdded",
                "where[0][expr]": "gte",
                "where[0][val]": "2026-09-01 00:00:00",
            },
        )

    @patch("newsletter.mautic_analytics_services.get_admin_stage_analytics")
    @patch("newsletter.mautic_analytics_services.MauticClient")
    def test_contacts_provider_failure_returns_502(self, client_cls, stage_analytics):
        client = client_cls.return_value
        client.list_contacts.side_effect = TemporaryMauticError("contacts down")
        stage_analytics.return_value = {"total_contacts": 0, "stages": []}
        self._authenticate()

        response = self.client.get(self.contacts_url, {"from": "2026-09-01", "to": "2026-09-12"})

        self.assertEqual(response.status_code, 502)

    @patch("newsletter.mautic_analytics_services.MauticClient")
    def test_segments_uses_existing_count_bridge(self, client_cls):
        client = client_cls.return_value
        client.list_segments.return_value = {
            "total": 1,
            "lists": [{"id": 9, "name": "Members", "isPublished": True, "filters": [{"field": "email"}]}],
        }
        client.get_segment_count_via_bridge.return_value = {"segmentId": 9, "total": 20, "active": 18}
        self._authenticate()

        response = self.client.get(self.segments_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["results"][0]["segmentType"], "dynamic")
        self.assertEqual(response.data["results"][0]["totalContacts"], 20)
        self.assertEqual(response.data["results"][0]["activeContacts"], 18)
        client.get_segment_count_via_bridge.assert_called_once_with(9)


class NewContactsDateRangeServiceTests(SimpleTestCase):
    def test_builds_inclusive_mautic_date_added_range_filters(self):
        class Client:
            def __init__(self):
                self.kwargs = None

            def list_contacts(self, **kwargs):
                self.kwargs = kwargs
                return {"total": 3}

        client = Client()
        count = _count_new_contacts(client, {"from": "2026-08-13", "to": "2026-09-12"})

        self.assertEqual(count, 3)
        self.assertEqual(
            client.kwargs,
            {
                "start": 0,
                "limit": 1,
                "where[0][col]": "dateAdded",
                "where[0][expr]": "gte",
                "where[0][val]": "2026-08-13 00:00:00",
                "where[1][col]": "dateAdded",
                "where[1][expr]": "lte",
                "where[1][val]": "2026-09-12 23:59:59",
            },
        )

    def test_returns_unavailable_without_date_range(self):
        class Client:
            def list_contacts(self, **kwargs):
                raise AssertionError("date-filtered Mautic request should not be made")

        self.assertIsNone(_count_new_contacts(Client(), {"from": None, "to": None}))
