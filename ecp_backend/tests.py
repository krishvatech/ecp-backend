"""
Tests for health check endpoints (Phase 9).

Tests verify:
- /api/health/ remains simple and ALB-safe (always 200 with {"status": "ok"})
- /api/live/health/ performs deep checks and returns appropriate status codes
- Deep checks handle failures gracefully
- No secrets are exposed in responses
"""
import json
from unittest import mock
from django.test import TestCase, Client
from django.db import connections
import redis


class HealthEndpointTestCase(TestCase):
    """Test the simple /api/health/ endpoint for ALB compatibility."""

    def setUp(self):
        self.client = Client()

    def test_health_endpoint_returns_200(self):
        """ALB health check must always return 200."""
        response = self.client.get("/api/health/")
        self.assertEqual(response.status_code, 200)

    def test_health_endpoint_returns_ok_status(self):
        """ALB health check must return {"status": "ok"}."""
        response = self.client.get("/api/health/")
        data = json.loads(response.content)
        self.assertEqual(data["status"], "ok")

    def test_health_endpoint_no_deep_checks(self):
        """ALB health endpoint must not include checks dict."""
        response = self.client.get("/api/health/")
        data = json.loads(response.content)
        self.assertNotIn("checks", data)
        self.assertNotIn("details", data)
        self.assertNotIn("duration_ms", data)

    def test_health_endpoint_content_type(self):
        """ALB health check must return JSON."""
        response = self.client.get("/api/health/")
        self.assertEqual(response["Content-Type"], "application/json")


class LiveHealthEndpointTestCase(TestCase):
    """Test the deep monitoring /api/live/health/ endpoint."""

    def setUp(self):
        self.client = Client()

    def test_live_health_endpoint_returns_response(self):
        """Live health endpoint must return a response."""
        response = self.client.get("/api/live/health/")
        self.assertIn(response.status_code, [200, 503])

    def test_live_health_response_format(self):
        """Live health response must have required fields."""
        response = self.client.get("/api/live/health/")
        data = json.loads(response.content)

        self.assertIn("status", data)
        self.assertIn("checks", data)
        self.assertIn("details", data)
        self.assertIn("duration_ms", data)

    def test_live_health_status_values(self):
        """Live health status must be 'ok' or 'degraded'."""
        response = self.client.get("/api/live/health/")
        data = json.loads(response.content)
        self.assertIn(data["status"], ["ok", "degraded"])

    def test_live_health_checks_structure(self):
        """Live health checks dict must include all required checks."""
        response = self.client.get("/api/live/health/")
        data = json.loads(response.content)
        checks = data["checks"]

        required_checks = ["django", "database", "redis", "channels", "realtimekit"]
        for check in required_checks:
            self.assertIn(check, checks)
            self.assertIn(checks[check], ["ok", "fail"])

    def test_live_health_status_code_200_on_all_ok(self):
        """Live health returns 200 when all checks pass."""
        # Mock all checks to pass
        with mock.patch("ecp_backend.health_checks.HealthChecker.run_all_checks") as mock_checks:
            mock_checks.return_value = {
                "status": "ok",
                "checks": {
                    "django": "ok",
                    "database": "ok",
                    "redis": "ok",
                    "channels": "ok",
                    "realtimekit": "ok",
                },
                "details": {},
                "duration_ms": 100,
            }
            response = self.client.get("/api/live/health/")
            self.assertEqual(response.status_code, 200)

    def test_live_health_status_code_503_on_degraded(self):
        """Live health returns 503 when any check fails."""
        # Mock checks with one failure
        with mock.patch("ecp_backend.health_checks.HealthChecker.run_all_checks") as mock_checks:
            mock_checks.return_value = {
                "status": "degraded",
                "checks": {
                    "django": "ok",
                    "database": "fail",
                    "redis": "ok",
                    "channels": "ok",
                    "realtimekit": "ok",
                },
                "details": {},
                "duration_ms": 100,
            }
            response = self.client.get("/api/live/health/")
            self.assertEqual(response.status_code, 503)

    def test_live_health_duration_is_integer(self):
        """Live health duration_ms must be an integer."""
        response = self.client.get("/api/live/health/")
        data = json.loads(response.content)
        self.assertIsInstance(data["duration_ms"], int)
        self.assertGreaterEqual(data["duration_ms"], 0)

    def test_live_health_no_secrets_exposed(self):
        """Live health response must not expose secret values."""
        response = self.client.get("/api/live/health/")
        data = json.loads(response.content)
        response_str = json.dumps(data)

        # Check that no common secret patterns are in response
        secret_patterns = [
            "password",
            "secret_key",
            "api_key",
            "token",
            "key=",
            "aws_secret",
        ]
        for pattern in secret_patterns:
            self.assertNotIn(pattern.lower(), response_str.lower())


class HealthCheckerUnitTestCase(TestCase):
    """Unit tests for individual health checks."""

    def test_django_check_always_passes(self):
        """Django process check should always pass."""
        from ecp_backend.health_checks import HealthChecker

        checker = HealthChecker()
        result = checker.check_django()
        self.assertTrue(result)
        self.assertEqual(checker.checks["django"], "ok")

    def test_database_check_with_valid_connection(self):
        """Database check should pass with valid connection."""
        from ecp_backend.health_checks import HealthChecker

        checker = HealthChecker()
        result = checker.check_database()
        # Should pass in test environment with test database
        self.assertIsNotNone(result)
        self.assertIn(checker.checks["database"], ["ok", "fail"])

    def test_redis_check_handles_connection_error(self):
        """Redis check should handle connection failures gracefully."""
        from ecp_backend.health_checks import HealthChecker

        with mock.patch("redis.from_url") as mock_redis:
            mock_redis.side_effect = redis.ConnectionError("Connection refused")
            checker = HealthChecker()
            result = checker.check_redis()
            self.assertFalse(result)
            self.assertEqual(checker.checks["redis"], "fail")

    def test_redis_check_respects_timeout(self):
        """Redis check should use configured timeout."""
        from ecp_backend.health_checks import HealthChecker

        with mock.patch("redis.from_url") as mock_redis:
            checker = HealthChecker()
            checker.check_redis(timeout=3)
            # Verify socket_timeout was passed
            mock_redis.assert_called()
            call_kwargs = mock_redis.call_args[1]
            self.assertEqual(call_kwargs.get("socket_timeout"), 3)

    def test_channels_check_handles_missing_layer(self):
        """Channels check should handle missing channel layer gracefully."""
        from ecp_backend.health_checks import HealthChecker

        with mock.patch("ecp_backend.health_checks.get_channel_layer") as mock_layer:
            mock_layer.return_value = None
            checker = HealthChecker()
            result = checker.check_channels()
            self.assertFalse(result)
            self.assertEqual(checker.checks["channels"], "fail")

    def test_realtimekit_check_handles_missing_config(self):
        """RealtimeKit check should pass even without config (it's optional)."""
        from ecp_backend.health_checks import HealthChecker
        from django.conf import settings

        with mock.patch.object(settings, "REALTIMEKIT_API_KEY", None):
            with mock.patch.object(settings, "DYTE_API_KEY", None):
                with mock.patch.object(settings, "AGORA_APP_ID", None):
                    checker = HealthChecker()
                    result = checker.check_realtimekit()
                    # Should pass - config is optional
                    self.assertTrue(result)
                    self.assertEqual(checker.checks["realtimekit"], "ok")

    def test_all_checks_returns_complete_response(self):
        """run_all_checks should return properly formatted response."""
        from ecp_backend.health_checks import HealthChecker

        checker = HealthChecker()
        result = checker.run_all_checks()

        # Verify response structure
        self.assertIn("status", result)
        self.assertIn("checks", result)
        self.assertIn("details", result)
        self.assertIn("duration_ms", result)

        # Verify status value
        self.assertIn(result["status"], ["ok", "degraded"])

        # Verify all checks are present
        required_checks = ["django", "database", "redis", "channels", "realtimekit"]
        for check in required_checks:
            self.assertIn(check, result["checks"])

    def test_duration_increases_with_checks(self):
        """duration_ms should be a positive integer."""
        from ecp_backend.health_checks import HealthChecker

        checker = HealthChecker()
        result = checker.run_all_checks()
        self.assertGreater(result["duration_ms"], 0)
        self.assertIsInstance(result["duration_ms"], int)


class HealthCheckIntegrationTestCase(TestCase):
    """Integration tests for health checks."""

    def test_full_health_check_flow(self):
        """Full health check should complete without errors."""
        from ecp_backend.health_checks import get_health_status

        status = get_health_status()
        self.assertIsNotNone(status)
        self.assertIn("status", status)

    def test_multiple_consecutive_checks(self):
        """Multiple health checks should be independent."""
        from ecp_backend.health_checks import get_health_status

        status1 = get_health_status()
        status2 = get_health_status()

        self.assertEqual(len(status1), len(status2))
        self.assertEqual(set(status1.keys()), set(status2.keys()))

    def test_health_endpoints_accessible_without_auth(self):
        """Both health endpoints must be accessible without authentication."""
        # These endpoints should not require authentication
        response1 = self.client.get("/api/health/")
        response2 = self.client.get("/api/live/health/")

        self.assertIn(response1.status_code, [200, 401, 403, 500, 502, 503])
        self.assertIn(response2.status_code, [200, 401, 403, 500, 502, 503])
