from unittest.mock import Mock

import requests
from django.test import SimpleTestCase, override_settings

from crm_integrations.providers.base import PermanentCRMError, TemporaryCRMError
from crm_integrations.providers import get_crm_provider
from crm_integrations.providers.salesforce import SalesforceProvider


class FakeResponse:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self._data = {} if data is None else data

    def json(self):
        return self._data


SALESFORCE_TEST_SETTINGS = {
    "SALESFORCE_LOGIN_URL": "https://login.example.test",
    "SALESFORCE_CLIENT_ID": "client-id",
    "SALESFORCE_CLIENT_SECRET": "client-secret",
    "SALESFORCE_API_VERSION": "v61.0",
    "SALESFORCE_REQUEST_TIMEOUT": 5,
    "SALESFORCE_CONTACT_EXTERNAL_ID_FIELD": "IMAA_Connect_User_ID__c",
    "SALESFORCE_CONTACT_COMPANY_FIELD": "Company__c",
    "SALESFORCE_CONTACT_COUNTRY_CODE_FIELD": "Country_Code__c",
    "SALESFORCE_CONTACT_PROFILE_STATUS_FIELD": "Profile_Status__c",
    "SALESFORCE_CONTACT_ACTIVE_FIELD": "IMAA_Active__c",
}


def contact_payload(**overrides):
    payload = {
        "ecp_user_id": "123",
        "first_name": "Jane",
        "last_name": "Doe",
        "email": "jane@example.com",
        "company": "Acme Capital",
        "job_title": "Director",
        "country": "Switzerland",
        "country_code": "CH",
        "is_active": True,
        "profile_status": "active",
    }
    payload.update(overrides)
    return payload


@override_settings(**SALESFORCE_TEST_SETTINGS)
class SalesforceProviderTests(SimpleTestCase):
    def test_provider_factory_selects_salesforce(self):
        connection = Mock(provider="salesforce")

        provider = get_crm_provider(connection, session=Mock())

        self.assertIsInstance(provider, SalesforceProvider)
        self.assertIs(provider.connection, connection)

    def test_authenticates_and_upserts_contact_with_external_id(self):
        session = Mock()
        session.request.side_effect = [
            FakeResponse(
                data={
                    "access_token": "access-token",
                    "instance_url": "https://instance.example.test",
                    "expires_in": 600,
                }
            ),
            FakeResponse(
                data=[
                    {
                        "id": "003000000000123AAA",
                        "success": True,
                        "created": True,
                        "errors": [],
                    }
                ]
            ),
        ]

        result = SalesforceProvider(session=session).upsert_contact(contact_payload())

        self.assertEqual(result.external_id, "003000000000123AAA")
        self.assertEqual(result.external_object_type, "Contact")
        self.assertTrue(result.created)
        auth_call, upsert_call = session.request.call_args_list
        self.assertEqual(auth_call.args[:2], ("POST", "https://login.example.test/services/oauth2/token"))
        self.assertNotIn("client-secret", str(upsert_call))
        self.assertEqual(upsert_call.args[0], "PATCH")
        self.assertTrue(
            upsert_call.args[1].endswith(
                "/services/data/v61.0/composite/sobjects/Contact/IMAA_Connect_User_ID__c"
            )
        )
        record = upsert_call.kwargs["json"]["records"][0]
        self.assertEqual(record["IMAA_Connect_User_ID__c"], "123")
        self.assertEqual(record["Company__c"], "Acme Capital")
        self.assertEqual(record["Country_Code__c"], "CH")
        self.assertEqual(record["IMAA_Active__c"], True)

    def test_health_check_refreshes_token_once_after_unauthorized(self):
        session = Mock()
        session.request.side_effect = [
            FakeResponse(data={"access_token": "old", "instance_url": "https://instance.example.test"}),
            FakeResponse(status_code=401, data=[{"errorCode": "INVALID_SESSION_ID"}]),
            FakeResponse(data={"access_token": "new", "instance_url": "https://instance.example.test"}),
            FakeResponse(data={"DailyApiRequests": {}}),
        ]

        self.assertTrue(SalesforceProvider(session=session).health_check())
        self.assertEqual(session.request.call_count, 4)
        final_headers = session.request.call_args.kwargs["headers"]
        self.assertEqual(final_headers["Authorization"], "Bearer new")

    def test_rate_limit_is_a_temporary_error(self):
        session = Mock()
        session.request.side_effect = [
            FakeResponse(data={"access_token": "token", "instance_url": "https://instance.example.test"}),
            FakeResponse(status_code=429, data=[{"errorCode": "REQUEST_LIMIT_EXCEEDED"}]),
        ]

        with self.assertRaises(TemporaryCRMError):
            SalesforceProvider(session=session).health_check()

    def test_validation_response_is_a_permanent_error(self):
        session = Mock()
        session.request.side_effect = [
            FakeResponse(data={"access_token": "token", "instance_url": "https://instance.example.test"}),
            FakeResponse(status_code=400, data=[{"errorCode": "INVALID_FIELD", "message": "Bad field"}]),
        ]

        with self.assertRaises(PermanentCRMError):
            SalesforceProvider(session=session).health_check()

    def test_timeout_is_a_temporary_error(self):
        session = Mock()
        session.request.side_effect = requests.Timeout("secret transport detail")

        with self.assertRaisesMessage(TemporaryCRMError, "authentication request failed"):
            SalesforceProvider(session=session).health_check()

    def test_missing_required_contact_data_is_rejected_before_upsert(self):
        provider = SalesforceProvider(session=Mock())

        with self.assertRaisesMessage(PermanentCRMError, "Last name is required"):
            provider.upsert_contact(contact_payload(last_name=""))

    @override_settings(SALESFORCE_CLIENT_SECRET="")
    def test_missing_credentials_are_rejected_without_network_call(self):
        session = Mock()

        with self.assertRaisesMessage(PermanentCRMError, "credentials are not configured"):
            SalesforceProvider(session=session)

        session.request.assert_not_called()

    @override_settings(SALESFORCE_CONTACT_ACTIVE_FIELD="", SALESFORCE_CONTACT_PROFILE_STATUS_FIELD="")
    def test_deactivation_requires_a_configured_status_field(self):
        provider = SalesforceProvider(session=Mock())

        with self.assertRaisesMessage(PermanentCRMError, "deactivation field is not configured"):
            provider.deactivate_contact("003000000000123AAA", contact_payload())
