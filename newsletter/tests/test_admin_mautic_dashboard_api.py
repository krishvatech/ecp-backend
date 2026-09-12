from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.mautic import TemporaryMauticError
from newsletter.models import NewsletterCampaign, NewsletterCampaignTrackingEvent


User = get_user_model()


@override_settings(
    MAUTIC_BASE_URL="https://mautic.example.test",
    MAUTIC_USERNAME="api-user",
    MAUTIC_PASSWORD="super-secret",
)
class NewsletterAdminMauticDashboardAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="dashboard-staff",
            email="dashboard-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="dashboard-normal",
            email="dashboard-normal@example.test",
            password="test-password",
        )
        self.url = reverse("newsletter-admin-dashboard")

    def _authenticate(self, user=None):
        self.client.force_authenticate(user=user or self.staff)

    def _mock_provider(self, client_cls):
        client = client_cls.return_value
        client.list_campaigns.return_value = {"total": 0, "campaigns": []}
        client.list_contacts.side_effect = [
            {"total": 0, "contacts": []},
            {"total": 0, "contacts": []},
        ]
        client.list_emails.return_value = {"total": 0, "emails": []}
        return client

    def test_auth_is_preserved(self):
        response = self.client.get(self.url)
        self.assertIn(response.status_code, (401, 403))

        self._authenticate(self.normal_user)
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 403)

    @patch("newsletter.mautic_dashboard_services.get_mautic_diagnostics")
    @patch("newsletter.mautic_dashboard_services.MauticClient")
    def test_staff_success_normalizes_dashboard_sections(self, client_cls, diagnostics):
        client = self._mock_provider(client_cls)
        client.list_campaigns.return_value = {
            "total": 2,
            "campaigns": [
                {"id": 1, "name": "Older", "isPublished": False, "dateModified": "2026-09-10T10:00:00+00:00"},
                {"id": 2, "name": "Newer", "isPublished": True, "dateModified": "2026-09-12T10:00:00+00:00"},
            ],
        }
        client.list_contacts.side_effect = [
            {
                "total": 2,
                "contacts": [
                    {"id": 7, "dateAdded": "2026-09-01T00:00:00+00:00"},
                    {"id": 9, "dateAdded": "2026-09-12T23:59:59+00:00"},
                ],
            },
            {
                "total": 2,
                "contacts": [
                    {
                        "id": 8,
                        "fields": {"core": {"email": {"value": "old@example.test"}, "firstname": {"value": "Old"}}},
                        "dateAdded": "2026-09-10T09:00:00+00:00",
                    },
                    {
                        "id": 9,
                        "fields": {"core": {"email": {"value": "new@example.test"}, "firstname": {"value": "New"}}},
                        "stage": {"name": "Member"},
                        "dateAdded": "2026-09-12T09:00:00+00:00",
                    },
                ],
            },
        ]
        client.list_emails.return_value = {
            "total": 2,
            "emails": [
                {
                    "id": 4,
                    "name": "Scheduled",
                    "subject": "Soon",
                    "emailType": "list",
                    "isPublished": True,
                    "publishUp": (timezone.now() + timedelta(days=1)).isoformat(),
                },
                {
                    "id": 5,
                    "name": "Draft",
                    "subject": "No schedule",
                    "emailType": "list",
                    "isPublished": False,
                },
            ],
        }
        diagnostics.return_value = {"diagnostics": {"warnings": []}}
        self._authenticate()

        response = self.client.get(self.url, {"from": "2026-09-01", "to": "2026-09-12"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["source"], "mautic")
        self.assertEqual(response.data["recent_campaigns"]["results"][0]["name"], "Newer")
        self.assertEqual(response.data["recent_contacts"]["results"][0]["email"], "new@example.test")
        self.assertEqual(response.data["contacts_created"]["from"], "2026-09-01")
        self.assertEqual(response.data["contacts_created"]["to"], "2026-09-12")
        self.assertEqual(response.data["contacts_created"]["series"][0], {"date": "2026-09-01", "count": 1})
        self.assertEqual(response.data["contacts_created"]["series"][-1], {"date": "2026-09-12", "count": 1})
        self.assertEqual(response.data["upcoming_emails"]["count"], 1)
        self.assertEqual(response.data["upcoming_emails"]["results"][0]["name"], "Scheduled")
        self.assertEqual(response.data["attention"]["warning_count"], 0)
        self.assertEqual(response.data["attention"]["status_label"], "healthy")
        self.assertEqual(
            client.list_contacts.call_args_list[0].kwargs,
            {
                "start": 0,
                "limit": 100,
                "orderBy": "date_added",
                "orderByDir": "asc",
                "where[0][col]": "dateAdded",
                "where[0][expr]": "gte",
                "where[0][val]": "2026-09-01 00:00:00",
                "where[1][col]": "dateAdded",
                "where[1][expr]": "lte",
                "where[1][val]": "2026-09-12 23:59:59",
            },
        )
        self.assertEqual(
            client.list_contacts.call_args_list[1].kwargs,
            {"start": 0, "limit": 5, "orderBy": "date_added", "orderByDir": "desc"},
        )

    @patch("newsletter.mautic_dashboard_services.get_mautic_diagnostics")
    @patch("newsletter.mautic_dashboard_services.MauticClient")
    def test_invalid_contacts_created_range_returns_400(self, client_cls, diagnostics):
        self._mock_provider(client_cls)
        diagnostics.return_value = {"diagnostics": {"warnings": []}}
        self._authenticate()

        response = self.client.get(self.url, {"from": "2026-09-12", "to": "2026-09-01"})

        self.assertEqual(response.status_code, 400)
        self.assertIn("from must be", response.data["detail"])

    @patch("newsletter.mautic_dashboard_services.get_mautic_diagnostics")
    @patch("newsletter.mautic_dashboard_services.MauticClient")
    def test_recent_campaigns_empty_state(self, client_cls, diagnostics):
        self._mock_provider(client_cls)
        diagnostics.return_value = {"diagnostics": {"warnings": []}}
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["recent_campaigns"]["status"], "ok")
        self.assertEqual(response.data["recent_campaigns"]["results"], [])

    @patch("newsletter.mautic_dashboard_services.get_mautic_diagnostics")
    @patch("newsletter.mautic_dashboard_services.MauticClient")
    def test_recent_campaigns_provider_failure_is_section_scoped(self, client_cls, diagnostics):
        client = self._mock_provider(client_cls)
        client.list_campaigns.side_effect = TemporaryMauticError("campaigns down")
        client.list_contacts.side_effect = [
            {"total": 0, "contacts": []},
            {"total": 1, "contacts": [{"id": 9, "email": "ok@example.test", "dateAdded": "2026-09-12T09:00:00+00:00"}]},
        ]
        diagnostics.return_value = {"diagnostics": {"warnings": []}}
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["recent_campaigns"]["status"], "unavailable")
        self.assertIn("campaigns down", response.data["recent_campaigns"]["detail"])
        self.assertEqual(response.data["recent_contacts"]["status"], "ok")
        self.assertEqual(response.data["recent_contacts"]["results"][0]["email"], "ok@example.test")

    @patch("newsletter.mautic_dashboard_services.get_mautic_diagnostics")
    @patch("newsletter.mautic_dashboard_services.MauticClient")
    def test_recent_contacts_provider_failure_is_section_scoped(self, client_cls, diagnostics):
        client = self._mock_provider(client_cls)
        client.list_contacts.side_effect = [
            {"total": 0, "contacts": []},
            TemporaryMauticError("contacts down"),
        ]
        diagnostics.return_value = {"diagnostics": {"warnings": []}}
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["recent_contacts"]["status"], "unavailable")
        self.assertIn("contacts down", response.data["recent_contacts"]["detail"])

    @patch("newsletter.mautic_dashboard_services.get_mautic_diagnostics")
    @patch("newsletter.mautic_dashboard_services.MauticClient")
    def test_attention_degraded_diagnostics_returns_warning_summary(self, client_cls, diagnostics):
        self._mock_provider(client_cls)
        diagnostics.return_value = {
            "diagnostics": {
                "warnings": [
                    "Mautic REST API: Unavailable.",
                    "Newsletter sync has failed or retrying events.",
                ]
            }
        }
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["attention"]["status_label"], "attention")
        self.assertEqual(response.data["attention"]["warning_count"], 2)

    @patch("newsletter.mautic_dashboard_services.get_mautic_diagnostics")
    @patch("newsletter.mautic_dashboard_services.MauticClient")
    def test_resolved_historical_sync_failure_does_not_generate_attention_warning(self, client_cls, diagnostics):
        self._mock_provider(client_cls)
        diagnostics.return_value = {
            "sync": {"failed": 0, "retrying": 0, "current_warning": False},
            "diagnostics": {"warnings": []},
        }
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["attention"]["warning_count"], 0)

    @patch("newsletter.mautic_dashboard_services.get_mautic_diagnostics")
    @patch("newsletter.mautic_dashboard_services.MauticClient")
    def test_upcoming_emails_empty_and_excludes_non_scheduled_drafts(self, client_cls, diagnostics):
        client = self._mock_provider(client_cls)
        client.list_emails.return_value = {
            "total": 2,
            "emails": [
                {"id": 1, "name": "Draft", "isPublished": False},
                {"id": 2, "name": "Past", "isPublished": True, "publishUp": "2020-01-01T00:00:00+00:00"},
            ],
        }
        diagnostics.return_value = {"diagnostics": {"warnings": []}}
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["upcoming_emails"]["status"], "ok")
        self.assertEqual(response.data["upcoming_emails"]["results"], [])

    @patch("newsletter.mautic_dashboard_services.get_mautic_diagnostics")
    @patch("newsletter.mautic_dashboard_services.MauticClient")
    def test_upcoming_emails_provider_failure_is_section_scoped(self, client_cls, diagnostics):
        client = self._mock_provider(client_cls)
        client.list_emails.side_effect = TemporaryMauticError("emails down")
        diagnostics.return_value = {"diagnostics": {"warnings": []}}
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["upcoming_emails"]["status"], "unavailable")
        self.assertIn("emails down", response.data["upcoming_emails"]["detail"])

    @patch("newsletter.mautic_dashboard_services.get_mautic_diagnostics")
    @patch("newsletter.mautic_dashboard_services.MauticClient")
    def test_recent_activity_uses_real_entity_and_tracking_sources(self, client_cls, diagnostics):
        client = self._mock_provider(client_cls)
        client.list_campaigns.return_value = {
            "total": 1,
            "campaigns": [{"id": 22, "name": "Journey", "isPublished": True, "dateModified": "2026-09-12T10:00:00+00:00"}],
        }
        client.list_contacts.side_effect = [
            {"total": 0, "contacts": []},
            {"total": 1, "contacts": [{"id": 33, "email": "contact@example.test", "dateAdded": "2026-09-12T11:00:00+00:00"}]},
        ]
        diagnostics.return_value = {"diagnostics": {"warnings": []}}
        campaign = NewsletterCampaign.objects.create(name="Legacy", mautic_email_id="22")
        NewsletterCampaignTrackingEvent.objects.create(
            campaign=campaign,
            event_type=NewsletterCampaignTrackingEvent.EventType.OPENED,
            source="mautic",
            occurred_at=timezone.now(),
            mautic_contact_id="33",
            recipient_email="contact@example.test",
        )
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        event_types = {row["event_type"] for row in response.data["recent_activity"]["results"]}
        self.assertIn("contact_created", event_types)
        self.assertIn("campaign_updated", event_types)
        self.assertIn("email_opened", event_types)

    @patch("newsletter.mautic_dashboard_services.get_mautic_diagnostics")
    @patch("newsletter.mautic_dashboard_services.MauticClient")
    def test_contacts_created_filters_and_buckets_by_date_added_only(self, client_cls, diagnostics):
        client = self._mock_provider(client_cls)
        client.list_contacts.side_effect = [
            {
                "total": 5,
                "contacts": [
                    {"id": 1, "dateAdded": "2026-09-09T23:59:59+00:00"},
                    {"id": 2, "dateAdded": "2026-09-10T00:00:00+00:00"},
                    {"id": 3, "dateAdded": "2026-09-11T10:30:00+00:00", "dateModified": "2026-09-20T00:00:00+00:00"},
                    {"id": 4, "dateAdded": "2026-09-12T23:59:59+00:00"},
                    {"id": 5, "dateAdded": "2026-09-13T00:00:00+00:00"},
                ],
            },
            {"total": 0, "contacts": []},
        ]
        diagnostics.return_value = {"diagnostics": {"warnings": []}}
        self._authenticate()

        response = self.client.get(self.url, {"from": "2026-09-10", "to": "2026-09-12"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["contacts_created"]["series"],
            [
                {"date": "2026-09-10", "count": 1},
                {"date": "2026-09-11", "count": 1},
                {"date": "2026-09-12", "count": 1},
            ],
        )

    @override_settings(TIME_ZONE="Asia/Kolkata")
    @patch("newsletter.mautic_dashboard_services.get_mautic_diagnostics")
    @patch("newsletter.mautic_dashboard_services.MauticClient")
    def test_contacts_created_uses_provider_timestamp_date_without_local_shift(self, client_cls, diagnostics):
        client = self._mock_provider(client_cls)
        client.list_contacts.side_effect = [
            {
                "total": 5,
                "contacts": [
                    {"id": 1, "dateAdded": "2026-09-09T23:59:59+00:00"},
                    {"id": 2, "dateAdded": "2026-09-10T00:00:00+00:00"},
                    {"id": 3, "dateAdded": "2026-09-12T23:59:59+00:00"},
                    {"id": 4, "dateAdded": "2026-09-12T23:30:00-04:00"},
                    {"id": 5, "dateAdded": "not-a-date"},
                ],
            },
            {"total": 0, "contacts": []},
        ]
        diagnostics.return_value = {"diagnostics": {"warnings": []}}
        self._authenticate()

        response = self.client.get(self.url, {"from": "2026-09-10", "to": "2026-09-12"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["contacts_created"]["series"],
            [
                {"date": "2026-09-10", "count": 1},
                {"date": "2026-09-11", "count": 0},
                {"date": "2026-09-12", "count": 2},
            ],
        )

    @patch("newsletter.mautic_dashboard_services.get_mautic_diagnostics")
    @patch("newsletter.mautic_dashboard_services.MauticClient")
    def test_contacts_created_provider_failure_is_section_scoped(self, client_cls, diagnostics):
        client = self._mock_provider(client_cls)
        client.list_contacts.side_effect = [
            TemporaryMauticError("contacts chart down"),
            {"total": 1, "contacts": [{"id": 9, "email": "ok@example.test", "dateAdded": "2026-09-12T09:00:00+00:00"}]},
        ]
        diagnostics.return_value = {"diagnostics": {"warnings": []}}
        self._authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["contacts_created"]["status"], "unavailable")
        self.assertIn("contacts chart down", response.data["contacts_created"]["detail"])
        self.assertEqual(response.data["recent_contacts"]["status"], "ok")
