import uuid
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient, APIRequestFactory

from users.cache_utils import user_cache_version
from users.cognito_auth import CognitoJWTAuthentication
from users.models import CognitoIdentity, UserProfile
from users.serializers import UserSerializer
from users.tests.test_disposable_email import (
    CLIENT_ID, LOCMEM_CACHE, POOL_ID, REGION, _PRIVATE_KEY, make_id_token,
)

ME_URL = "/api/users/me/"


@override_settings(
    CACHES=LOCMEM_CACHE,
    COGNITO_REGION=REGION,
    COGNITO_USER_POOL_ID=POOL_ID,
    COGNITO_APP_CLIENT_ID=CLIENT_ID,
    SALEOR_ENABLED=True,
)
class CognitoRequestWritesTestBase(TestCase):
    def setUp(self):
        cache.clear()
        for target, kwargs in (
            ("boto3.client", {}),
            ("users.cognito_auth._get_public_key", {"return_value": _PRIVATE_KEY.public_key()}),
            ("users.cognito_auth._fetch_imaa_wordpress_user_profile", {"return_value": None}),
            ("users.cognito_auth._enable_federated_user_password", {"return_value": True}),
        ):
            patcher = mock.patch(target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

        saleor_patch = mock.patch("users.tasks.sync_user_to_saleor_async.delay")
        self.saleor_delay = saleor_patch.start()
        self.addCleanup(saleor_patch.stop)

        self.sub = str(uuid.uuid4())
        self.user = User.objects.create_user(
            username=f"member-{self.sub[:8]}",
            email=f"{self.sub[:8]}@example.com",
            password="x-Unused-123",
            first_name="Alex",
            last_name="Sample",
        )
        # ensure_profile runs in transaction.on_commit, which never fires inside TestCase.
        self.profile, _ = UserProfile.objects.get_or_create(user=self.user)
        # A full name and recent activity leave authentication and
        # LastActivityMiddleware with no profile changes of their own to save.
        UserProfile.objects.filter(pk=self.profile.pk).update(
            full_name="Alex Sample",
            last_activity_at=timezone.now(),
        )
        CognitoIdentity.objects.create(
            user=self.user, cognito_sub=self.sub, email=self.user.email, provider="cognito"
        )
        self.token = make_id_token(self.sub, self.user.email)

    def set_last_login(self, age):
        User.objects.filter(pk=self.user.pk).update(last_login=timezone.now() - age)
        self.user.refresh_from_db()
        return self.user.last_login

    def authenticate(self):
        request = APIRequestFactory().get(ME_URL, HTTP_AUTHORIZATION=f"Bearer {self.token}")
        # Outside a test transaction these callbacks run straight away.
        with self.captureOnCommitCallbacks(execute=True):
            return CognitoJWTAuthentication().authenticate(request)


class LastLoginWriteTests(CognitoRequestWritesTestBase):
    def test_first_request_writes_last_login(self):
        self.assertIsNone(self.user.last_login)

        self.authenticate()

        self.user.refresh_from_db()
        self.assertIsNotNone(self.user.last_login)

    def test_recent_last_login_is_not_written_again(self):
        recent = self.set_last_login(timedelta(minutes=4))

        with CaptureQueriesContext(connection) as queries:
            self.authenticate()

        self.user.refresh_from_db()
        self.assertEqual(self.user.last_login, recent)
        writes = [q["sql"] for q in queries if q["sql"].startswith('UPDATE "auth_user"')]
        self.assertEqual(writes, [])

    def test_old_last_login_is_refreshed(self):
        old = self.set_last_login(timedelta(minutes=6))

        self.authenticate()

        self.user.refresh_from_db()
        self.assertGreater(self.user.last_login, old)
        self.assertLess(timezone.now() - self.user.last_login, timedelta(minutes=1))

    def test_recent_last_login_keeps_the_user_cache_version(self):
        self.set_last_login(timedelta(minutes=1))
        cache.set(f"user:{self.user.id}:detail-version", 111, None)

        self.authenticate()

        self.assertEqual(user_cache_version(self.user.id), 111)


class UsersMeCacheTests(CognitoRequestWritesTestBase):
    def setUp(self):
        super().setUp()
        self.client = APIClient()
        self.set_last_login(timedelta(minutes=1))

    def get_me(self):
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.get(ME_URL, HTTP_AUTHORIZATION=f"Bearer {self.token}")
        self.assertEqual(response.status_code, 200, response.content)
        return response

    def test_repeat_request_is_served_from_cache(self):
        with mock.patch("users.views.UserSerializer", wraps=UserSerializer) as serializer:
            first = self.get_me()
            second = self.get_me()

        self.assertEqual(second.data, first.data)
        self.assertEqual(serializer.call_count, 1)

    def test_profile_save_shows_up_on_the_next_request(self):
        self.get_me()

        profile = UserProfile.objects.get(pk=self.profile.pk)
        profile.full_name = "Jordan Example"
        with self.captureOnCommitCallbacks(execute=True):
            profile.save(update_fields=["full_name"])

        self.assertEqual(self.get_me().data["profile"]["full_name"], "Jordan Example")


class SaleorQueueTests(CognitoRequestWritesTestBase):
    def link_to_saleor(self):
        UserProfile.objects.filter(pk=self.profile.pk).update(saleor_customer_id="saleor-customer-1")

    def test_unlinked_user_is_queued_once_per_retry_window(self):
        self.authenticate()
        self.authenticate()

        self.saleor_delay.assert_called_once_with(self.user.id)

    def test_unlinked_user_is_queued_again_after_the_retry_window(self):
        self.authenticate()
        cache.delete(f"user:{self.user.id}:saleor-sync-queued")

        self.authenticate()

        self.assertEqual(self.saleor_delay.call_count, 2)

    def test_linked_user_is_not_queued(self):
        self.link_to_saleor()

        self.authenticate()

        self.saleor_delay.assert_not_called()

    def test_queueing_stops_once_the_task_links_the_user(self):
        self.authenticate()
        self.link_to_saleor()
        cache.delete(f"user:{self.user.id}:saleor-sync-queued")

        self.authenticate()

        self.saleor_delay.assert_called_once_with(self.user.id)

    @override_settings(SALEOR_ENABLED=False)
    def test_nothing_is_queued_when_saleor_is_disabled(self):
        self.authenticate()

        self.saleor_delay.assert_not_called()

    def test_broker_failure_does_not_block_authentication(self):
        self.saleor_delay.side_effect = RuntimeError("broker down")

        with self.assertLogs("users.cognito_auth", level="WARNING"):
            user, _ = self.authenticate()

        self.assertEqual(user.pk, self.user.pk)

    def test_cache_failure_does_not_block_authentication(self):
        with mock.patch("users.cognito_auth.cache.add", side_effect=ConnectionError("redis down")):
            with self.assertLogs("users.cognito_auth", level="WARNING"):
                user, _ = self.authenticate()

        self.assertEqual(user.pk, self.user.pk)
