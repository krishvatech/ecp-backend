import uuid
from unittest import mock
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from rest_framework.test import APIClient, APIRequestFactory

from users.cognito_auth import CognitoJWTAuthentication
from users.models import CognitoIdentity, UserProfile
from users.tests.test_disposable_email import (
    CLIENT_ID, LOCMEM_CACHE, POOL_ID, REGION, _PRIVATE_KEY, make_id_token,
)


@override_settings(COGNITO_REGION="", COGNITO_USER_POOL_ID="", SALEOR_ENABLED=False)
class StaffUserNameSyncTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(
            username="admin",
            email="admin@example.com",
            password="password",
        )
        self.user = User.objects.create_user(
            username="member",
            email="member@example.com",
            password="password",
            first_name="Alex",
            last_name="Sample",
        )
        self.profile, _ = UserProfile.objects.get_or_create(user=self.user)
        self.profile.middle_name = "Quinn"
        self.profile.full_name = "Alex Sample"
        self.profile.save()
        CognitoIdentity.objects.create(
            user=self.user,
            cognito_sub="sub-member-1",
            email=self.user.email,
            email_verified=True,
            provider="cognito",
        )
        self.client = APIClient()
        self.client.force_authenticate(self.admin)

    def _patch(self, data):
        return self.client.patch(f"/api/auth/admin/users/{self.user.id}/", data, format="json")

    @patch("users.views.update_cognito_user_names", return_value=True)
    def test_rename_updates_full_name_and_cognito(self, update_names):
        response = self._patch({"first_name": "Jordan", "last_name": "Example"})

        self.assertEqual(response.status_code, 200, response.content)
        self.user.refresh_from_db()
        self.profile.refresh_from_db()
        self.assertEqual((self.user.first_name, self.user.last_name), ("Jordan", "Example"))
        self.assertEqual(self.profile.full_name, "Jordan Quinn Example")
        update_names.assert_called_once()
        usernames, first, last = update_names.call_args.args
        self.assertEqual(usernames[0], "sub-member-1")
        self.assertEqual((first, last), ("Jordan", "Example"))

    @patch("users.views.update_cognito_user_names", return_value=True)
    def test_non_name_edit_leaves_full_name_and_cognito_alone(self, update_names):
        self.profile.full_name = "Custom Display Name"
        self.profile.save(update_fields=["full_name"])

        response = self._patch({"first_name": "Alex", "last_name": "Sample", "is_active": True})

        self.assertEqual(response.status_code, 200, response.content)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.full_name, "Custom Display Name")
        update_names.assert_not_called()

    @patch("users.views.update_cognito_user_names", return_value=False)
    def test_cognito_failure_does_not_block_db_rename(self, update_names):
        response = self._patch({"first_name": "Jordan"})

        self.assertEqual(response.status_code, 200, response.content)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.full_name, "Jordan Quinn Sample")
        update_names.assert_called_once()


class BootstrapNameOverwriteTests(TestCase):
    URL = "/api/auth/cognito/bootstrap/"

    def setUp(self):
        self.user = User.objects.create_user(
            username="social-member",
            email="social-member@example.com",
            password="password",
            first_name="Jordan",
            last_name="Example",
        )
        self.profile, _ = UserProfile.objects.get_or_create(user=self.user)
        self.profile.full_name = "Jordan Example"
        self.profile.company = "Acme Ltd"
        self.profile.job_title = "Analyst"
        self.profile.save()
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_social_login_bootstrap_keeps_admin_name_and_company(self):
        # Shape of CognitoOAuthCallback.jsx: provider name, no company/job title.
        response = self.client.post(
            self.URL,
            {"email": "social-member@example.com", "firstName": "Alex", "lastName": "Sample"},
            format="json",
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.user.refresh_from_db()
        self.profile.refresh_from_db()
        self.assertEqual((self.user.first_name, self.user.last_name), ("Jordan", "Example"))
        self.assertEqual(self.profile.full_name, "Jordan Example")
        self.assertEqual((self.profile.company, self.profile.job_title), ("Acme Ltd", "Analyst"))

    def test_bootstrap_fills_empty_names(self):
        self.user.first_name = ""
        self.user.last_name = ""
        self.user.save()
        self.profile.full_name = ""
        self.profile.save()

        response = self.client.post(
            self.URL,
            {"email": "social-member@example.com", "firstName": "Alex", "lastName": "Sample"},
            format="json",
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.user.refresh_from_db()
        self.profile.refresh_from_db()
        self.assertEqual((self.user.first_name, self.user.last_name), ("Alex", "Sample"))
        self.assertEqual(self.profile.full_name, "Alex Sample")


@override_settings(
    CACHES=LOCMEM_CACHE,
    COGNITO_REGION=REGION,
    COGNITO_USER_POOL_ID=POOL_ID,
    COGNITO_APP_CLIENT_ID=CLIENT_ID,
)
class CognitoLoginNameOverwriteTests(TestCase):
    def setUp(self):
        for target, kwargs in (
            ("boto3.client", {}),
            ("users.tasks.sync_user_to_saleor_async.delay", {}),
            ("users.cognito_auth._get_public_key", {"return_value": _PRIVATE_KEY.public_key()}),
            ("users.cognito_auth._fetch_imaa_wordpress_user_profile", {"return_value": None}),
            ("users.cognito_auth._enable_federated_user_password", {"return_value": True}),
        ):
            patcher = mock.patch(target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

    def authenticate(self, token):
        request = APIRequestFactory().get("/api/auth/users/me/", HTTP_AUTHORIZATION=f"Bearer {token}")
        return CognitoJWTAuthentication().authenticate(request)

    def test_google_login_does_not_revert_admin_rename(self):
        sub = str(uuid.uuid4())
        user, _ = self.authenticate(make_id_token(
            sub, "google-member@example.com", username="Google_1234567890",
            given_name="Alex", family_name="Sample",
        ))
        self.assertEqual((user.first_name, user.last_name), ("Alex", "Sample"))

        # Admin rename, then the next Google login still carries the old name.
        user.first_name, user.last_name = "Jordan", "Example"
        user.save()
        authed, _ = self.authenticate(make_id_token(
            sub, "google-member@example.com", username="Google_1234567890",
            given_name="Alex", family_name="Sample",
        ))

        authed.refresh_from_db()
        self.assertEqual((authed.first_name, authed.last_name), ("Jordan", "Example"))
