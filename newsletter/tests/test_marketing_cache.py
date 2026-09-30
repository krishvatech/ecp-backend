from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from newsletter import marketing_cache
from newsletter.mautic import TemporaryMauticError
from newsletter.middleware import MarketingCacheInvalidationMiddleware
from newsletter.tests.marketing_actors import grant_marketing_access


User = get_user_model()

CACHE_ON = dict(
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "marketing-cache-tests",
        }
    },
    MARKETING_RESPONSE_CACHE_ENABLED=True,
)


def _stub_overview_client(client):
    client.list_contacts.return_value = {"total": 50, "contacts": []}
    client.list_campaigns.return_value = {"total": 0, "campaigns": []}
    client.list_emails.return_value = {
        "total": 2,
        "emails": [
            {"id": 8, "name": "Digest", "sentCount": 10},
            {"id": 9, "name": "Launch", "sentCount": 5},
        ],
    }
    client.get_email_stats.return_value = {"data": [{"lead_id": 1, "is_read": True}]}
    client.list_segments.return_value = {"total": 3, "lists": []}


def _stub_dashboard_client(client):
    client.list_contacts.return_value = {"total": 0, "contacts": []}
    client.list_campaigns.return_value = {"total": 0, "campaigns": []}
    client.list_emails.return_value = {"total": 0, "emails": []}


@override_settings(**CACHE_ON)
class MarketingCacheTestCase(TestCase):
    def setUp(self):
        super().setUp()
        cache.clear()
        marketing_cache.reset_failure_state()
        self.addCleanup(marketing_cache.reset_failure_state)
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username="marketing-cache-staff",
            email="marketing-cache-staff@example.test",
            password="test-password",
            is_staff=True,
            is_superuser=True,
        )
        grant_marketing_access(self.staff)
        self.client.force_authenticate(user=self.staff)


class MarketingAnalyticsCacheTests(MarketingCacheTestCase):
    def setUp(self):
        super().setUp()
        self.overview_url = reverse("newsletter-admin-analytics-overview")
        self.emails_url = reverse("newsletter-admin-analytics-emails")

    @patch("newsletter.mautic_analytics_services.MauticClient")
    def test_repeat_request_is_served_from_cache(self, client_cls):
        _stub_overview_client(client_cls.return_value)

        first = self.client.get(self.overview_url)
        second = self.client.get(self.overview_url)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(first["X-Marketing-Cache"], "MISS")
        self.assertEqual(second["X-Marketing-Cache"], "HIT")
        self.assertEqual(second.data, first.data)
        self.assertEqual(client_cls.return_value.list_emails.call_count, 1)

    @patch("newsletter.mautic_analytics_services.MauticClient")
    def test_query_params_get_separate_entries(self, client_cls):
        _stub_overview_client(client_cls.return_value)

        self.client.get(self.overview_url, {"from": "2026-09-01", "to": "2026-09-10"})
        other = self.client.get(self.overview_url, {"from": "2026-09-02", "to": "2026-09-10"})
        same = self.client.get(self.overview_url, {"to": "2026-09-10", "from": "2026-09-01"})

        self.assertEqual(other["X-Marketing-Cache"], "MISS")
        self.assertEqual(same["X-Marketing-Cache"], "HIT")

    @patch("newsletter.mautic_analytics_services.MauticClient")
    def test_refresh_rebuilds_from_mautic(self, client_cls):
        _stub_overview_client(client_cls.return_value)
        self.client.get(self.overview_url)

        refreshed = self.client.get(self.overview_url, {"refresh": "1"})
        after = self.client.get(self.overview_url)

        self.assertEqual(refreshed["X-Marketing-Cache"], "MISS")
        self.assertEqual(after["X-Marketing-Cache"], "HIT")
        self.assertEqual(client_cls.return_value.list_emails.call_count, 2)
        # Refresh also drops cached per-email stats.
        self.assertEqual(client_cls.return_value.get_email_stats.call_count, 4)

    @patch("newsletter.mautic_analytics_services.MauticClient")
    def test_provider_error_is_not_cached(self, client_cls):
        client = client_cls.return_value
        _stub_overview_client(client)
        client.list_contacts.side_effect = [TemporaryMauticError("down"), {"total": 50, "contacts": []}]

        failed = self.client.get(self.overview_url)
        recovered = self.client.get(self.overview_url)

        self.assertGreaterEqual(failed.status_code, 500)
        self.assertEqual(recovered.status_code, 200)
        self.assertEqual(recovered["X-Marketing-Cache"], "MISS")

    @patch("newsletter.mautic_analytics_services.MauticClient")
    def test_email_stats_are_shared_between_pages(self, client_cls):
        _stub_overview_client(client_cls.return_value)

        self.client.get(self.overview_url)
        emails = self.client.get(self.emails_url)

        self.assertEqual(emails.status_code, 200)
        self.assertEqual(emails["X-Marketing-Cache"], "MISS")
        self.assertEqual(client_cls.return_value.get_email_stats.call_count, 2)
        self.assertEqual(emails.data["results"][0]["opened"], 1)

    @patch("newsletter.admin_views.MauticClient")
    @patch("newsletter.mautic_analytics_services.MauticClient")
    def test_marketing_write_invalidates(self, client_cls, stage_client_cls):
        _stub_overview_client(client_cls.return_value)
        self.client.get(self.overview_url)

        # Rejected by validation before touching Mautic, but a write attempt
        # all the same.
        write = self.client.post(reverse("newsletter-admin-stage-list"), {}, format="json")
        after = self.client.get(self.overview_url)

        self.assertEqual(write.status_code, 400)
        stage_client_cls.assert_not_called()
        self.assertEqual(after["X-Marketing-Cache"], "MISS")

    @patch("newsletter.admin_views.MauticClient")
    @patch("newsletter.mautic_analytics_services.MauticClient")
    def test_denied_write_does_not_invalidate(self, client_cls, _stage_client_cls):
        _stub_overview_client(client_cls.return_value)
        self.client.get(self.overview_url)
        outsider = User.objects.create_user(username="marketing-cache-outsider", password="test-password")

        denied = APIClient()
        denied.force_authenticate(user=outsider)
        response = denied.post(reverse("newsletter-admin-stage-list"), {}, format="json")
        after = self.client.get(self.overview_url)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(after["X-Marketing-Cache"], "HIT")

    @patch("newsletter.mautic_analytics_services.MauticClient")
    def test_redis_failure_falls_back_to_mautic(self, client_cls):
        _stub_overview_client(client_cls.return_value)

        # Only this module's handle fails: DRF throttles share the default cache.
        with patch("newsletter.marketing_cache.cache") as broken_cache:
            broken_cache.get.side_effect = ConnectionError("redis down")
            first = self.client.get(self.overview_url)
            second = self.client.get(self.overview_url)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second["X-Marketing-Cache"], "MISS")
        # The cooldown stops the second request from touching Redis at all.
        self.assertEqual(broken_cache.get.call_count, 1)

    @override_settings(MARKETING_RESPONSE_CACHE_ENABLED=False)
    @patch("newsletter.mautic_analytics_services.MauticClient")
    def test_kill_switch_disables_caching(self, client_cls):
        _stub_overview_client(client_cls.return_value)

        self.client.get(self.overview_url)
        second = self.client.get(self.overview_url)

        self.assertEqual(second["X-Marketing-Cache"], "MISS")
        self.assertEqual(client_cls.return_value.list_emails.call_count, 2)


class MarketingDashboardCacheTests(MarketingCacheTestCase):
    def setUp(self):
        super().setUp()
        self.url = reverse("newsletter-admin-dashboard")

    @patch("newsletter.mautic_dashboard_services.get_mautic_diagnostics")
    @patch("newsletter.mautic_dashboard_services.MauticClient")
    def test_complete_dashboard_is_cached(self, client_cls, diagnostics):
        _stub_dashboard_client(client_cls.return_value)
        diagnostics.return_value = {"diagnostics": {"warnings": []}}

        self.client.get(self.url)
        second = self.client.get(self.url)

        self.assertEqual(second["X-Marketing-Cache"], "HIT")
        self.assertEqual(diagnostics.call_count, 1)

    @patch("newsletter.mautic_dashboard_services.get_mautic_diagnostics")
    @patch("newsletter.mautic_dashboard_services.MauticClient")
    def test_partial_dashboard_is_not_cached(self, client_cls, diagnostics):
        _stub_dashboard_client(client_cls.return_value)
        client_cls.return_value.list_campaigns.side_effect = TemporaryMauticError("down")
        diagnostics.return_value = {"diagnostics": {"warnings": []}}

        first = self.client.get(self.url)
        second = self.client.get(self.url)

        self.assertEqual(first.data["recent_campaigns"]["status"], "unavailable")
        self.assertEqual(second["X-Marketing-Cache"], "MISS")
        self.assertEqual(diagnostics.call_count, 2)


class MarketingStageAnalyticsCacheTests(MarketingCacheTestCase):
    @patch("newsletter.contact_services.MauticClient")
    def test_stage_analytics_is_cached(self, client_cls):
        client = client_cls.return_value
        client.list_contacts.return_value = {"total": 4, "contacts": []}
        client.list_stages.return_value = {"total": 1, "stages": [{"id": 1, "name": "Lead"}]}
        url = reverse("newsletter-admin-stage-analytics")

        self.client.get(url)
        second = self.client.get(url)

        self.assertEqual(second["X-Marketing-Cache"], "HIT")
        self.assertEqual(client.list_stages.call_count, 1)


@override_settings(**CACHE_ON)
class MarketingCacheInvalidationMiddlewareTests(TestCase):
    def setUp(self):
        cache.clear()
        marketing_cache.reset_failure_state()
        self.factory = RequestFactory()

    def _run(self, method, path, status_code):
        before = marketing_cache.current_version()
        middleware = MarketingCacheInvalidationMiddleware(lambda request: HttpResponse(status=status_code))
        middleware(getattr(self.factory, method)(path))
        return marketing_cache.current_version() != before

    def test_marketing_writes_invalidate_even_when_they_fail(self):
        self.assertTrue(self._run("post", "/api/newsletter/admin/contacts/", 201))
        self.assertTrue(self._run("delete", "/api/newsletter/admin/stages/3/", 204))
        self.assertTrue(self._run("patch", "/api/newsletter/admin/contacts/bulk-stage/", 502))

    def test_reads_refusals_and_other_paths_do_not_invalidate(self):
        self.assertFalse(self._run("get", "/api/newsletter/admin/contacts/", 200))
        self.assertFalse(self._run("post", "/api/newsletter/admin/contacts/", 403))
        self.assertFalse(self._run("post", "/api/newsletter/preferences/", 200))
        self.assertFalse(self._run("post", "/api/blogs/", 201))
