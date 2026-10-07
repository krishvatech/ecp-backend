from unittest.mock import Mock, patch

from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from users.views import _cognito_secret_hash

IMAA_CLIENT_ID = "imaa-app-client"
FALLBACK_CLIENT_ID = "fallback-client"
SALEOR_CLIENT_ID = "saleor-shared-client"
FEDERATED_USERNAME = "Google_1234567890"
GENERIC_DETAIL = "If that email exists, we've sent a reset code."

FORGOT_URL = "/api/auth/password/forgot-cognito/"
RESET_URL = "/api/auth/password/reset-cognito/"


def _mock_cognito(users=None, forgot_resp=None):
    client = Mock()
    client.list_users.return_value = {"Users": users if users is not None else [{"Username": FEDERATED_USERNAME}]}
    client.forgot_password.return_value = forgot_resp if forgot_resp is not None else {}
    client.confirm_forgot_password.return_value = {}
    return client


@override_settings(
    COGNITO_REGION="eu-central-1",
    COGNITO_USER_POOL_ID="eu-central-1_pool",
    COGNITO_APP_CLIENT_ID=IMAA_CLIENT_ID,
    COGNITO_CLIENT_ID=IMAA_CLIENT_ID,
    COGNITO_APP_CLIENT_SECRET="",
    COGNITO_SALEOR_CLIENT_ID=SALEOR_CLIENT_ID,
)
class ForgotCognitoPasswordTests(TestCase):
    def setUp(self):
        self.api = APIClient()

    def _post(self, client, email="member@example.com"):
        with patch("users.views._cognito_client", return_value=client):
            return self.api.post(FORGOT_URL, {"email": email}, format="json")

    def test_existing_user_uses_app_client_forgot_password(self):
        client = _mock_cognito()

        res = self._post(client)

        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["detail"], GENERIC_DETAIL)
        client.list_users.assert_called_once_with(
            UserPoolId="eu-central-1_pool", Filter='email = "member@example.com"', Limit=2
        )
        client.forgot_password.assert_called_once_with(ClientId=IMAA_CLIENT_ID, Username=FEDERATED_USERNAME)
        client.admin_reset_user_password.assert_not_called()

    @override_settings(COGNITO_APP_CLIENT_ID="", COGNITO_CLIENT_ID=FALLBACK_CLIENT_ID)
    def test_falls_back_to_cognito_client_id(self):
        client = _mock_cognito()

        res = self._post(client)

        self.assertEqual(res.status_code, 200)
        client.forgot_password.assert_called_once_with(ClientId=FALLBACK_CLIENT_ID, Username=FEDERATED_USERNAME)

    @override_settings(COGNITO_APP_CLIENT_SECRET="app-client-secret")
    def test_secret_hash_included_when_secret_configured(self):
        client = _mock_cognito()

        res = self._post(client)

        self.assertEqual(res.status_code, 200)
        expected_hash = _cognito_secret_hash(FEDERATED_USERNAME)
        self.assertTrue(expected_hash)
        client.forgot_password.assert_called_once_with(
            ClientId=IMAA_CLIENT_ID, Username=FEDERATED_USERNAME, SecretHash=expected_hash
        )

    def test_secret_hash_omitted_without_secret(self):
        client = _mock_cognito()

        self._post(client)

        kwargs = client.forgot_password.call_args.kwargs
        self.assertNotIn("SecretHash", kwargs)

    def test_unknown_email_returns_generic_response_without_reset(self):
        client = _mock_cognito(users=[])

        res = self._post(client, email="nobody@example.com")

        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"detail": GENERIC_DETAIL, "delivery": {"medium": "EMAIL_OR_SMS"}})
        client.forgot_password.assert_not_called()
        client.admin_reset_user_password.assert_not_called()

    def test_cognito_failure_returns_generic_response(self):
        client = _mock_cognito()
        client.forgot_password.side_effect = Exception("LimitExceededException: internal secret detail")

        res = self._post(client)

        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"detail": GENERIC_DETAIL, "delivery": {"medium": "EMAIL_OR_SMS"}})
        self.assertNotIn("LimitExceeded", res.content.decode())
        self.assertNotIn("internal secret detail", res.content.decode())

    def test_delivery_medium_returned_without_destination(self):
        client = _mock_cognito(
            forgot_resp={
                "CodeDeliveryDetails": {
                    "Destination": "m***@e***.com",
                    "DeliveryMedium": "EMAIL",
                    "AttributeName": "email",
                }
            }
        )

        res = self._post(client)

        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["delivery"], {"medium": "EMAIL"})
        self.assertNotIn("m***@e***.com", res.content.decode())

    def test_never_uses_saleor_client_id(self):
        client = _mock_cognito()

        self._post(client)

        self.assertNotEqual(client.forgot_password.call_args.kwargs["ClientId"], SALEOR_CLIENT_ID)

    @override_settings(COGNITO_APP_CLIENT_ID="", COGNITO_CLIENT_ID="")
    def test_missing_app_client_does_not_fall_back_to_saleor(self):
        client = _mock_cognito()

        res = self._post(client)

        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["detail"], GENERIC_DETAIL)
        client.forgot_password.assert_not_called()
        client.admin_reset_user_password.assert_not_called()

    def test_duplicate_users_logs_warning_and_uses_first(self):
        client = _mock_cognito(users=[{"Username": FEDERATED_USERNAME}, {"Username": "other-user"}])

        with self.assertLogs("users.views", level="WARNING") as logs:
            self._post(client)

        self.assertTrue(any("Multiple Cognito users matched" in line for line in logs.output))
        client.forgot_password.assert_called_once_with(ClientId=IMAA_CLIENT_ID, Username=FEDERATED_USERNAME)


@override_settings(
    COGNITO_REGION="eu-central-1",
    COGNITO_USER_POOL_ID="eu-central-1_pool",
    COGNITO_APP_CLIENT_ID=IMAA_CLIENT_ID,
    COGNITO_CLIENT_ID=IMAA_CLIENT_ID,
    COGNITO_APP_CLIENT_SECRET="",
    COGNITO_SALEOR_CLIENT_ID=SALEOR_CLIENT_ID,
)
class ResetCognitoPasswordRegressionTests(TestCase):
    def setUp(self):
        self.api = APIClient()

    def test_confirm_forgot_password_uses_app_client(self):
        client = _mock_cognito()
        body = {
            "email": "member@example.com",
            "code": "123456",
            "new_password": "NewPassword123!",
            "confirm_new_password": "NewPassword123!",
        }

        with patch("users.views._cognito_client", return_value=client):
            res = self.api.post(RESET_URL, body, format="json")

        self.assertEqual(res.status_code, 200)
        client.confirm_forgot_password.assert_called_once_with(
            ClientId=IMAA_CLIENT_ID,
            Username=FEDERATED_USERNAME,
            ConfirmationCode="123456",
            Password="NewPassword123!",
        )
