"""Salesforce OAuth and Contact adapter."""

import re
import time
from typing import Any

import requests
from django.conf import settings

from .base import (
    CRMContactPayload,
    CRMProvider,
    CRMUpsertResult,
    PermanentCRMError,
    TemporaryCRMError,
)


_FIELD_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_API_VERSION = re.compile(r"^v\d+\.\d+$")
_TEMPORARY_STATUS_CODES = {401, 408, 425, 429}


class SalesforceProvider(CRMProvider):
    def __init__(self, connection=None, session=None):
        self.connection = connection
        self.session = session or requests.Session()
        self.login_url = settings.SALESFORCE_LOGIN_URL.rstrip("/")
        self.client_id = settings.SALESFORCE_CLIENT_ID
        self.client_secret = settings.SALESFORCE_CLIENT_SECRET
        self.api_version = settings.SALESFORCE_API_VERSION
        self.timeout = settings.SALESFORCE_REQUEST_TIMEOUT
        self.external_id_field = settings.SALESFORCE_CONTACT_EXTERNAL_ID_FIELD
        self.company_field = settings.SALESFORCE_CONTACT_COMPANY_FIELD
        self.country_code_field = settings.SALESFORCE_CONTACT_COUNTRY_CODE_FIELD
        self.profile_status_field = settings.SALESFORCE_CONTACT_PROFILE_STATUS_FIELD
        self.active_field = settings.SALESFORCE_CONTACT_ACTIVE_FIELD
        self._access_token = ""
        self._instance_url = ""
        self._token_expires_at = 0.0
        self._validate_configuration()

    def _validate_configuration(self):
        if not self.client_id or not self.client_secret:
            raise PermanentCRMError("Salesforce OAuth credentials are not configured")
        if not _API_VERSION.fullmatch(self.api_version):
            raise PermanentCRMError("Invalid Salesforce API version")
        for field_name in (
            self.external_id_field,
            self.company_field,
            self.country_code_field,
            self.profile_status_field,
            self.active_field,
        ):
            if field_name and not _FIELD_NAME.fullmatch(field_name):
                raise PermanentCRMError("Invalid Salesforce field configuration")

    def _authenticate(self, force=False):
        if (
            not force
            and self._access_token
            and self._instance_url
            and time.monotonic() < self._token_expires_at
        ):
            return

        try:
            response = self.session.request(
                "POST",
                f"{self.login_url}/services/oauth2/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
                timeout=self.timeout,
            )
        except (requests.Timeout, requests.ConnectionError) as exc:
            raise TemporaryCRMError("Salesforce authentication request failed") from exc
        except requests.RequestException as exc:
            raise TemporaryCRMError("Salesforce authentication transport failed") from exc

        self._raise_for_response(response, "Salesforce authentication failed")
        try:
            data = response.json()
            self._access_token = data["access_token"]
            self._instance_url = data["instance_url"].rstrip("/")
        except (ValueError, KeyError, TypeError) as exc:
            raise TemporaryCRMError("Salesforce authentication returned an invalid response") from exc

        expires_in = data.get("expires_in", 900)
        try:
            expires_in = max(60, int(expires_in))
        except (TypeError, ValueError):
            expires_in = 900
        self._token_expires_at = time.monotonic() + expires_in - 30

    @staticmethod
    def _safe_error_detail(response) -> str:
        try:
            data = response.json()
        except (ValueError, TypeError):
            return ""

        if isinstance(data, list) and data:
            data = data[0]
        if not isinstance(data, dict):
            return ""
        code = str(data.get("errorCode") or data.get("error") or "")[:80]
        message = str(data.get("message") or data.get("error_description") or "")[:240]
        return ": ".join(part for part in (code, message) if part)

    def _raise_for_response(self, response, context: str):
        if 200 <= response.status_code < 300:
            return
        detail = self._safe_error_detail(response)
        message = f"{context} (HTTP {response.status_code})"
        if detail:
            message = f"{message}: {detail}"
        if response.status_code in _TEMPORARY_STATUS_CODES or response.status_code >= 500:
            raise TemporaryCRMError(message)
        raise PermanentCRMError(message)

    def _api_request(self, method: str, path: str, **kwargs):
        self._authenticate()
        for attempt in range(2):
            try:
                response = self.session.request(
                    method,
                    f"{self._instance_url}/services/data/{self.api_version}{path}",
                    headers={
                        "Authorization": f"Bearer {self._access_token}",
                        "Content-Type": "application/json",
                    },
                    timeout=self.timeout,
                    **kwargs,
                )
            except (requests.Timeout, requests.ConnectionError) as exc:
                raise TemporaryCRMError("Salesforce API request failed") from exc
            except requests.RequestException as exc:
                raise TemporaryCRMError("Salesforce API transport failed") from exc

            if response.status_code == 401 and attempt == 0:
                self._authenticate(force=True)
                continue
            self._raise_for_response(response, "Salesforce API request failed")
            return response
        raise TemporaryCRMError("Salesforce authentication was rejected")

    def health_check(self) -> bool:
        self._api_request("GET", "/limits")
        return True

    def _contact_record(self, payload: CRMContactPayload) -> dict[str, Any]:
        if not payload["ecp_user_id"]:
            raise PermanentCRMError("ECP user ID is required for Salesforce upsert")
        if not payload["last_name"]:
            raise PermanentCRMError("Last name is required for Salesforce Contact")
        if not payload["email"]:
            raise PermanentCRMError("Email is required for Salesforce Contact")

        record: dict[str, Any] = {
            "attributes": {"type": "Contact"},
            self.external_id_field: payload["ecp_user_id"],
            "FirstName": payload["first_name"],
            "LastName": payload["last_name"],
            "Email": payload["email"],
            "Title": payload["job_title"],
            "MailingCountry": payload["country"],
        }
        optional_fields = (
            (self.company_field, payload["company"]),
            (self.country_code_field, payload["country_code"]),
            (self.profile_status_field, payload["profile_status"]),
            (self.active_field, payload["is_active"]),
        )
        for field_name, value in optional_fields:
            if field_name:
                record[field_name] = value
        return record

    def upsert_contact(self, payload: CRMContactPayload) -> CRMUpsertResult:
        response = self._api_request(
            "PATCH",
            f"/composite/sobjects/Contact/{self.external_id_field}",
            json={"allOrNone": True, "records": [self._contact_record(payload)]},
        )
        try:
            result = response.json()[0]
        except (ValueError, TypeError, IndexError) as exc:
            raise TemporaryCRMError("Salesforce upsert returned an invalid response") from exc
        if not result.get("success") or not result.get("id"):
            errors = result.get("errors") or []
            detail = ""
            if errors and isinstance(errors[0], dict):
                detail = str(errors[0].get("statusCode") or errors[0].get("message") or "")[:240]
            message = "Salesforce Contact upsert was rejected"
            if detail:
                message = f"{message}: {detail}"
            raise PermanentCRMError(message)
        return CRMUpsertResult(
            external_id=str(result["id"]),
            external_object_type="Contact",
            created=result.get("created"),
        )

    def deactivate_contact(
        self,
        external_id: str,
        payload: CRMContactPayload,
    ) -> CRMUpsertResult:
        if not self.active_field and not self.profile_status_field:
            raise PermanentCRMError(
                "Salesforce contact deactivation field is not configured"
            )
        inactive_payload = dict(payload)
        inactive_payload["is_active"] = False
        return self.upsert_contact(inactive_payload)  # type: ignore[arg-type]
