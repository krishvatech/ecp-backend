from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from newsletter.mautic import TemporaryMauticError
from newsletter.models import (
    MauticContactMapping,
    NewsletterCategory,
    NewsletterSubscription,
)


User = get_user_model()


class NewsletterAdminContactsAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="contacts-staff",
            email="contacts-staff@example.test",
            password="test-password",
            is_staff=True,
        )
        self.normal_user = User.objects.create_user(
            username="contacts-normal",
            email="contacts-normal@example.test",
            password="test-password",
        )
        self.url = reverse("newsletter-admin-contact-list")
        self.detail_url = reverse(
            "newsletter-admin-contact-detail",
            args=["2"],
        )
        self.activity_url = reverse(
            "newsletter-admin-contact-activity",
            args=["2"],
        )
        self.engagement_url = reverse(
            "newsletter-admin-contact-engagement",
            args=["2"],
        )

    def _authenticate(self, user):
        self.client.force_authenticate(user=user)

    def test_guest_and_normal_user_are_denied(self):
        response = self.client.get(self.url)
        self.assertIn(response.status_code, (401, 403))

        self._authenticate(self.normal_user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_contact_detail_guest_and_normal_user_are_denied(self):
        response = self.client.get(self.detail_url)
        self.assertIn(response.status_code, (401, 403))

        self._authenticate(self.normal_user)
        response = self.client.get(self.detail_url)
        self.assertEqual(response.status_code, 403)

    @patch("newsletter.contact_services.MauticClient")
    def test_contact_detail_enriches_mapping_and_all_active_lists(self, client_cls):
        ravi = User.objects.create_user(
            username="ravi-detail",
            email="ravi-detail@example.test",
            first_name="Ravi",
            last_name="Avaiya",
        )
        mapping = MauticContactMapping.objects.create(
            user=ravi,
            mautic_contact_id="2",
            last_synced_at=timezone.now(),
        )
        events = NewsletterCategory.objects.get(slug="imaa-events")
        deal_alert = NewsletterCategory.objects.get(slug="imaa-deal-alert")
        NewsletterSubscription.objects.create(
            user=ravi,
            category=events,
            is_subscribed=True,
            subscribed_at=timezone.now(),
            source="user",
        )
        NewsletterSubscription.objects.create(
            user=ravi,
            category=deal_alert,
            is_subscribed=False,
            unsubscribed_at=timezone.now(),
            source="user",
        )
        client_cls.return_value.get_contact.return_value = {
            "id": 2,
            "points": 3,
            "lastActive": "2026-09-07T10:00:00+00:00",
            "fields": {
                "core": {
                    "firstname": {"value": "Ravi"},
                    "lastname": {"value": "Avaiya"},
                    "email": {"value": "ravi-detail@example.test"},
                    "phone": {"value": "+91-1111111111"},
                    "city": {"value": "Surat"},
                    "country": {"value": "India"},
                }
            },
        }
        self._authenticate(self.staff)

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["mautic_contact_id"], "2")
        self.assertEqual(response.data["name"], "Ravi Avaiya")
        self.assertEqual(response.data["email"], "ravi-detail@example.test")
        self.assertEqual(response.data["location"], "Surat, India")
        self.assertEqual(response.data["points"], 3)
        self.assertTrue(response.data["mapped_in_ecp"])
        self.assertEqual(response.data["ecp_user_id"], ravi.pk)
        self.assertEqual(response.data["last_synced_at"], mapping.last_synced_at)
        self.assertEqual(
            response.data["contact_info"]["phone"],
            "+91-1111111111",
        )

        lists = {item["slug"]: item for item in response.data["subscription_lists"]}
        self.assertTrue(lists["imaa-events"]["is_subscribed"])
        self.assertFalse(lists["imaa-deal-alert"]["is_subscribed"])

    @patch("newsletter.contact_services.MauticClient")
    def test_contact_detail_supports_mautic_only_contact(self, client_cls):
        client_cls.return_value.get_contact.return_value = {
            "id": 99,
            "points": 0,
            "fields": {
                "all": {
                    "firstname": "Provider",
                    "lastname": "Only",
                    "email": "provider-only@example.test",
                }
            },
        }
        self._authenticate(self.staff)

        response = self.client.get(
            reverse("newsletter-admin-contact-detail", args=["99"])
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["name"], "Provider Only")
        self.assertFalse(response.data["mapped_in_ecp"])
        self.assertIsNone(response.data["ecp_user_id"])
        self.assertEqual(response.data["subscription_lists"], [])

    @patch("newsletter.contact_services.MauticClient")
    def test_contact_detail_provider_404_returns_404(self, client_cls):
        from newsletter.mautic import PermanentMauticError

        client_cls.return_value.get_contact.side_effect = PermanentMauticError(
            "Mautic API request failed (HTTP 404)"
        )
        self._authenticate(self.staff)

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 404)

    @patch("newsletter.contact_services.MauticClient")
    def test_contact_detail_provider_failure_returns_502(self, client_cls):
        client_cls.return_value.get_contact.side_effect = TemporaryMauticError(
            "Mautic contact unavailable"
        )
        self._authenticate(self.staff)

        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, 502)
        self.assertIn("Mautic contact unavailable", response.data["detail"])

    @patch("newsletter.contact_services.MauticClient")
    def test_contact_activity_normalizes_real_mautic_label_shape(self, client_cls):
        client_cls.return_value.get_contact_activity.return_value = {
            "events": [
                {
                    "event": "email.read",
                    "eventType": "Email read",
                    "eventLabel": {
                        "label": "testsss",
                        "href": "http://mautic.local/email/view/test",
                        "isExternal": True,
                    },
                    "timestamp": "2026-09-07T12:00:00+00:00",
                },
                {
                    "event": "segment_membership",
                    "eventType": "Segment membership change",
                    "eventLabel": "Contact added to segment, IMAA Events",
                    "timestamp": "2026-09-01T12:00:00+00:00",
                },
            ],
            "total": 2,
            "page": 1,
            "limit": 25,
            "maxPages": 1.0,
        }
        self._authenticate(self.staff)

        response = self.client.get(self.activity_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 2)
        self.assertEqual(response.data["num_pages"], 1)
        self.assertEqual(response.data["results"][0]["label"], "testsss")
        self.assertEqual(
            response.data["results"][0]["href"],
            "http://mautic.local/email/view/test",
        )
        self.assertEqual(
            response.data["results"][1]["label"],
            "Contact added to segment, IMAA Events",
        )
        client_cls.return_value.get_contact_activity.assert_called_once_with(
            "2",
            page=1,
            limit=25,
        )

    @patch("newsletter.contact_services.MauticClient")
    def test_contact_engagement_aggregates_real_activity(self, client_cls):
        client_cls.return_value.get_contact_activity.return_value = {
            "events": [
                {
                    "event": "email.sent",
                    "timestamp": "2026-09-01T12:00:00+00:00",
                },
                {
                    "event": "email.read",
                    "timestamp": "2026-09-03T12:00:00+00:00",
                },
                {
                    "event": "segment_membership",
                    "timestamp": "2026-09-03T13:00:00+00:00",
                },
            ],
            "total": 3,
            "page": 1,
            "limit": 25,
            "maxPages": 1.0,
        }
        self._authenticate(self.staff)

        response = self.client.get(
            self.engagement_url,
            {"from": "2026-09-01", "to": "2026-09-03"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["event_count"], 3)
        self.assertFalse(response.data["truncated"])
        self.assertEqual(
            response.data["series"],
            [
                {"date": "2026-09-01", "events": 1, "engagements": 1},
                {"date": "2026-09-02", "events": 0, "engagements": 1},
                {"date": "2026-09-03", "events": 2, "engagements": 3},
            ],
        )

    def test_contact_engagement_rejects_invalid_range(self):
        self._authenticate(self.staff)

        response = self.client.get(
            self.engagement_url,
            {"from": "2026-09-04", "to": "2026-09-03"},
        )

        self.assertEqual(response.status_code, 400)

    def test_contact_activity_guest_and_normal_user_are_denied(self):
        response = self.client.get(self.activity_url)
        self.assertIn(response.status_code, (401, 403))

        self._authenticate(self.normal_user)
        response = self.client.get(self.activity_url)
        self.assertEqual(response.status_code, 403)

    @patch("newsletter.contact_services.MauticClient")
    def test_list_includes_all_provider_contacts_and_enriches_ecp_mapping(
        self,
        client_cls,
    ):
        ravi = User.objects.create_user(
            username="ravi-contact",
            email="ravi@example.test",
            first_name="Ravi",
            last_name="Avaiya",
        )
        mapping = MauticContactMapping.objects.create(
            user=ravi,
            mautic_contact_id="2",
            last_synced_at=timezone.now(),
        )
        category = NewsletterCategory.objects.get(slug="imaa-events")
        NewsletterSubscription.objects.create(
            user=ravi,
            category=category,
            is_subscribed=True,
            subscribed_at=timezone.now(),
        )

        client_cls.return_value.list_contacts.return_value = {
            "total": 2,
            "contacts": {
                "2": {
                    "id": 2,
                    "points": 4,
                    "lastActive": "2026-09-07T10:00:00+00:00",
                    "fields": {
                        "core": {
                            "firstname": {"value": "Ravi"},
                            "lastname": {"value": "Avaiya"},
                            "email": {"value": "ravi@example.test"},
                            "city": {"value": "Surat"},
                            "country": {"value": "India"},
                        }
                    },
                },
                "99": {
                    "id": 99,
                    "points": 0,
                    "fields": {
                        "all": {
                            "firstname": "Provider",
                            "lastname": "Only",
                            "email": "provider-only@example.test",
                        }
                    },
                },
            },
        }
        self._authenticate(self.staff)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 2)
        self.assertEqual(len(response.data["results"]), 2)

        mapped = next(
            item
            for item in response.data["results"]
            if item["mautic_contact_id"] == "2"
        )
        self.assertEqual(mapped["name"], "Ravi Avaiya")
        self.assertEqual(mapped["email"], "ravi@example.test")
        self.assertEqual(mapped["location"], "Surat, India")
        self.assertEqual(mapped["points"], 4)
        self.assertTrue(mapped["mapped_in_ecp"])
        self.assertEqual(mapped["ecp_user_id"], ravi.pk)
        self.assertEqual(mapped["last_synced_at"], mapping.last_synced_at)
        self.assertEqual(len(mapped["subscription_lists"]), 1)
        self.assertEqual(
            mapped["subscription_lists"][0]["slug"],
            "imaa-events",
        )

        provider_only = next(
            item
            for item in response.data["results"]
            if item["mautic_contact_id"] == "99"
        )
        self.assertEqual(provider_only["name"], "Provider Only")
        self.assertFalse(provider_only["mapped_in_ecp"])
        self.assertIsNone(provider_only["ecp_user_id"])
        self.assertEqual(provider_only["subscription_lists"], [])

    @patch("newsletter.contact_services.MauticClient")
    def test_search_and_pagination_are_forwarded_to_mautic(self, client_cls):
        client_cls.return_value.list_contacts.return_value = {
            "total": 5,
            "contacts": {},
        }
        self._authenticate(self.staff)

        response = self.client.get(
            self.url,
            {"page": 2, "page_size": 2, "search": "ravi"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 5)
        self.assertEqual(response.data["page"], 2)
        self.assertEqual(response.data["page_size"], 2)
        self.assertEqual(response.data["num_pages"], 3)
        client_cls.return_value.list_contacts.assert_called_once_with(
            start=2,
            limit=2,
            search="ravi",
        )

    @patch("newsletter.contact_services.MauticClient")
    def test_page_values_are_safely_normalized(self, client_cls):
        client_cls.return_value.list_contacts.return_value = {
            "total": 0,
            "contacts": {},
        }
        self._authenticate(self.staff)

        response = self.client.get(
            self.url,
            {"page": "bad", "page_size": 1000},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["page"], 1)
        self.assertEqual(response.data["page_size"], 100)
        client_cls.return_value.list_contacts.assert_called_once_with(
            start=0,
            limit=100,
        )

    @patch("newsletter.contact_services.MauticClient")
    def test_provider_failure_returns_502(self, client_cls):
        client_cls.return_value.list_contacts.side_effect = TemporaryMauticError(
            "Mautic contacts unavailable"
        )
        self._authenticate(self.staff)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 502)
        self.assertIn("Mautic contacts unavailable", response.data["detail"])

