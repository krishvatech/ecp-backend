"""Small, testable Mautic REST API client.

This module performs only provider HTTP operations. It intentionally contains
no preference persistence, Celery dispatch, or synchronization orchestration.
Those responsibilities are added in later newsletter integration phases.
"""

from __future__ import annotations

import json
from datetime import timezone as dt_timezone
from typing import Any

import requests
from django.conf import settings
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import NewConnectionError

from .exceptions import (
    MauticBridgeRejectedError,
    MauticIdentityConfigurationError,
    MauticRequestNotSentError,
    PermanentMauticError,
    TemporaryMauticError,
)
from .operations import (
    REPORT_CREATE,
    REPORT_DELETE,
    REPORT_UPDATE,
    EMAIL_CREATE,
    EMAIL_DELETE,
    EMAIL_UPDATE,
    CAMPAIGN_CONTACT_ADD,
    CAMPAIGN_CONTACT_REMOVE,
    CONTACT_MERGE,
    EMAIL_TRANSLATION_CREATE,
    EMAIL_VARIANT_CREATE,
    EMAIL_VARIANT_UPDATE,
    CAMPAIGN_CREATE,
    CAMPAIGN_DELETE,
    CAMPAIGN_EVENT_DELETE,
    CAMPAIGN_UPDATE,
    COMPANY_CONTACT_ADD,
    COMPANY_CONTACT_REMOVE,
    COMPANY_CREATE,
    COMPANY_DELETE,
    COMPANY_UPDATE,
    CONTACT_CREATE,
    CONTACT_DNC_ADD,
    CONTACT_DELETE,
    CONTACT_DNC_REMOVE,
    CONTACT_IMPORT_CREATE,
    CONTACT_NOTE_CREATE,
    CONTACT_TAG_ADD,
    CONTACT_TAG_REMOVE,
    CONTACT_UPDATE,
    FIELD_CREATE,
    FIELD_DELETE,
    FIELD_UPDATE,
    FORM_ACTION_CREATE,
    FORM_ACTION_REORDER,
    FORM_ACTION_UPDATE,
    FORM_CREATE,
    FORM_DELETE,
    FORM_FIELD_CREATE,
    FORM_FIELD_REORDER,
    FORM_FIELD_UPDATE,
    FORM_PUBLISH,
    FORM_UNPUBLISH,
    FORM_UPDATE,
    NEWSLETTER_TEST_SEND,
    PAGE_CREATE,
    PAGE_DELETE,
    PAGE_DUPLICATE,
    PAGE_TRANSLATION_CREATE,
    PAGE_UPDATE,
    PAGE_VARIANT_CREATE,
    PAGE_VARIANT_UPDATE,
    PAGE_VARIANT_WINNER,
    POINT_ACTION_CREATE,
    POINT_ACTION_DELETE,
    POINT_ACTION_UPDATE,
    POINT_CONTACT_ADJUST,
    POINT_CONTACT_GROUP_ADJUST,
    POINT_GROUP_CREATE,
    POINT_GROUP_DELETE,
    POINT_GROUP_UPDATE,
    POINT_TRIGGER_CREATE,
    POINT_TRIGGER_DELETE,
    POINT_TRIGGER_EVENT_CREATE,
    POINT_TRIGGER_EVENT_DELETE,
    POINT_TRIGGER_EVENT_UPDATE,
    POINT_TRIGGER_UPDATE,
    SEGMENT_CONTACT_ADD,
    SEGMENT_CONTACT_REMOVE,
    SEGMENT_CREATE,
    SEGMENT_DELETE,
    SEGMENT_UPDATE,
    STAGE_CONTACT_ADD,
    STAGE_CONTACT_REMOVE,
    STAGE_CREATE,
    STAGE_DELETE,
    STAGE_UPDATE,
    TAG_CREATE,
    TAG_DELETE,
    TAG_UPDATE,
    TEMPLATE_CREATE,
    TEMPLATE_DELETE,
    TEMPLATE_DUPLICATE,
    TEMPLATE_TRANSLATION_CREATE,
    TEMPLATE_VARIANT_CREATE,
    TEMPLATE_VARIANT_UPDATE,
    TEMPLATE_VARIANT_WINNER,
    TEMPLATE_UPDATE,
)


_TEMPORARY_STATUS_CODES = {408, 425, 429}

# Headers consumed only by the ECP bridge endpoints in the Mautic plugin.
ECP_IDENTITY_ASSERTION_HEADER = "X-ECP-Identity-Assertion"
ECP_CORRELATION_HEADER = "X-ECP-Correlation-Id"


def _request_reached_mautic(exc: Exception) -> bool:
    """False only when the connection itself was never made.

    A connect timeout, a refused connection or a DNS failure means Mautic never
    received the request. Anything else — a read timeout, or a connection that
    dropped mid-response — may have been processed, so it must be treated as
    possibly delivered.
    """
    if isinstance(exc, requests.ConnectTimeout):
        return False
    if isinstance(exc, requests.ConnectionError) and not isinstance(exc, requests.Timeout):
        reason = exc.args[0] if exc.args else None
        reason = getattr(reason, "reason", reason)
        if isinstance(reason, NewConnectionError):
            return False
    return True


class MauticClient:
    def __init__(
        self,
        session=None,
        execution_identity=None,
        assertion_provider=None,
        correlation_id=None,
    ):
        self.session = session or requests.Session()
        # Metadata only (see newsletter.mautic.identity). Authentication always
        # uses the configured service account.
        self.execution_identity = execution_identity
        # Set only in ASSERTED_USER mode: a callable returning a fresh signed
        # ECP identity assertion. It is sent to the ECP bridge endpoints only,
        # in addition to (never instead of) the service credentials.
        self._assertion_provider = assertion_provider
        # Correlates one ECP request with the Mautic-side audit entry. Not a
        # credential, and sent to the bridge endpoints only.
        self.correlation_id = correlation_id
        self.base_url = str(getattr(settings, "MAUTIC_BASE_URL", "") or "").strip().rstrip("/")
        self.username = str(getattr(settings, "MAUTIC_USERNAME", "") or "").strip()
        self.password = str(getattr(settings, "MAUTIC_PASSWORD", "") or "")
        self.timeout = float(getattr(settings, "MAUTIC_REQUEST_TIMEOUT", 15))
        self._validate_configuration()

    def _validate_configuration(self) -> None:
        if not self.base_url:
            raise PermanentMauticError("Mautic base URL is not configured")
        if not self.base_url.startswith(("http://", "https://")):
            raise PermanentMauticError("Invalid Mautic base URL")
        if not self.username or not self.password:
            raise PermanentMauticError("Mautic API credentials are not configured")
        if self.timeout <= 0:
            raise PermanentMauticError("Invalid Mautic request timeout")

    @staticmethod
    def _safe_error_detail(response) -> str:
        try:
            data = response.json()
        except (ValueError, TypeError):
            return ""

        if not isinstance(data, dict):
            return ""

        errors = data.get("errors")
        if isinstance(errors, list) and errors:
            first = errors[0]
            if isinstance(first, dict):
                message = first.get("message") or first.get("code") or ""
                return str(message)[:240]
            return str(first)[:240]

        message = data.get("error") or data.get("message") or ""
        return str(message)[:240]

    def _raise_for_response(self, response, context: str) -> None:
        if 200 <= response.status_code < 300:
            return

        detail = self._safe_error_detail(response)
        message = f"{context} (HTTP {response.status_code})"
        if detail:
            message = f"{message}: {detail}"

        if (
            response.status_code in _TEMPORARY_STATUS_CODES
            or response.status_code >= 500
        ):
            raise TemporaryMauticError(message)
        raise PermanentMauticError(message)

    def _request(self, method: str, path: str, *, timeout=None, **kwargs):
        url = f"{self.base_url}/api/{path.lstrip('/')}"
        try:
            response = self.session.request(
                method,
                url,
                auth=HTTPBasicAuth(self.username, self.password),
                timeout=timeout or self.timeout,
                **kwargs,
            )
        except (requests.Timeout, requests.ConnectionError) as exc:
            if not _request_reached_mautic(exc):
                raise MauticRequestNotSentError("Mautic API request failed") from exc
            raise TemporaryMauticError("Mautic API request failed") from exc
        except requests.RequestException as exc:
            raise TemporaryMauticError("Mautic API transport failed") from exc

        self._raise_for_response(response, "Mautic API request failed")
        return response

    def _bridge_request(self, method: str, path: str, *, operation: str, **kwargs):
        """Call an ECP bridge endpoint with the service credentials plus a
        single-use identity assertion naming the acting human user.

        The assertion is bound to ``operation``, so the bridge accepts it only
        on the route that performs it.
        """
        headers = dict(kwargs.pop("headers", None) or {})
        headers[ECP_IDENTITY_ASSERTION_HEADER] = self._assertion_provider(operation)
        if self.correlation_id:
            headers[ECP_CORRELATION_HEADER] = str(self.correlation_id)

        try:
            return self._request(method, path, headers=headers, **kwargs)
        except PermanentMauticError as exc:
            message = str(exc)
            if any(f"HTTP {code}" in message for code in (401, 403)):
                # The bridge verified the service account but refused the human
                # identity or its Mautic permissions.
                raise MauticBridgeRejectedError(message) from exc
            raise

    def _uses_asserted_user(self) -> bool:
        return self._assertion_provider is not None

    @property
    def last_assertion_jti(self) -> str:
        """Identifier of the most recent assertion this client sent, if any.

        Empty unless the provider tracks it, so a stubbed provider stays a
        plain ``() -> str`` callable.
        """
        return str(getattr(self._assertion_provider, "last_jti", "") or "")

    @staticmethod
    def _json_object(response, context: str) -> dict[str, Any]:
        try:
            data = response.json()
        except (ValueError, TypeError) as exc:
            raise TemporaryMauticError(f"{context} returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise TemporaryMauticError(f"{context} returned an invalid response")
        return data

    def health_check(self) -> bool:
        self._request("GET", "contacts", params={"limit": 1})
        return True

    def get_contact(self, contact_id, *, timeout=None) -> dict[str, Any]:
        normalized = str(contact_id or "").strip()
        if not normalized:
            raise PermanentMauticError("Mautic contact id is required")
        response = self._request("GET", f"contacts/{normalized}", timeout=timeout)
        data = self._json_object(response, "Mautic contact detail")
        contact = data.get("contact")
        if not isinstance(contact, dict):
            raise TemporaryMauticError("Mautic contact detail returned an invalid response")
        return contact

    def get_user(self, user_id) -> dict[str, Any]:
        normalized = str(user_id or "").strip()
        if not normalized or not normalized.isdigit() or int(normalized) < 1:
            raise PermanentMauticError("Mautic user ID is required")
        response = self._request("GET", f"users/{normalized}")
        data = self._json_object(response, "Mautic user lookup")
        user = data.get("user")
        if not isinstance(user, dict) or not user.get("id"):
            raise TemporaryMauticError("Mautic user lookup returned an invalid response")
        return user

    @staticmethod
    def _items(collection) -> list[dict[str, Any]]:
        """Mautic returns a keyed object for collections, a list when empty."""
        if isinstance(collection, dict):
            return [item for item in collection.values() if isinstance(item, dict)]
        if isinstance(collection, list):
            return [item for item in collection if isinstance(item, dict)]
        return []

    def find_users_by_email(self, email: str) -> list[dict[str, Any]]:
        """Provider-side discovery only.

        Email is used to *detect* an existing Mautic human so provisioning can
        refuse to guess; it never becomes the stored mapping key. Mautic's
        search is not an exact match, so results are filtered here.
        """
        normalized = str(email or "").strip().lower()
        if not normalized:
            raise PermanentMauticError("Mautic user email is required")
        response = self._request(
            "GET",
            "users",
            params={"search": normalized, "limit": 50},
        )
        data = self._json_object(response, "Mautic user search")
        return [
            user
            for user in self._items(data.get("users"))
            if str(user.get("email") or "").strip().lower() == normalized
        ]

    def find_user_by_username(self, username: str) -> dict[str, Any] | None:
        normalized = str(username or "").strip().lower()
        if not normalized:
            raise PermanentMauticError("Mautic username is required")
        response = self._request(
            "GET",
            "users",
            params={"search": normalized, "limit": 50},
        )
        data = self._json_object(response, "Mautic user search")
        for user in self._items(data.get("users")):
            if str(user.get("username") or "").strip().lower() == normalized:
                return user
        return None

    def get_role_by_name(self, role_name: str) -> dict[str, Any] | None:
        normalized = str(role_name or "").strip()
        if not normalized:
            raise PermanentMauticError("Mautic role name is required")
        response = self._request(
            "GET",
            "roles",
            params={"search": normalized, "limit": 100},
        )
        data = self._json_object(response, "Mautic role lookup")
        for role in self._items(data.get("roles")):
            if str(role.get("name") or "").strip().casefold() == normalized.casefold():
                return role
        return None

    def get_role(self, role_id) -> dict[str, Any]:
        normalized = str(role_id or "").strip()
        if not normalized or not normalized.isdigit() or int(normalized) < 1:
            raise PermanentMauticError("Mautic role ID is required")
        response = self._request("GET", f"roles/{normalized}")
        data = self._json_object(response, "Mautic role lookup")
        role = data.get("role")
        if not isinstance(role, dict) or not role.get("id"):
            raise TemporaryMauticError("Mautic role lookup returned an invalid response")
        return role

    def set_user_published(self, user_id, published: bool) -> dict[str, Any]:
        """Enable or disable a Mautic human.

        Used to disable a provisioned user that ECP could not finish mapping, so
        no unmapped privileged Mautic account is left enabled.
        """
        normalized = str(user_id or "").strip()
        if not normalized or not normalized.isdigit() or int(normalized) < 1:
            raise PermanentMauticError("Mautic user ID is required")
        response = self._request(
            "PATCH",
            f"users/{normalized}/edit",
            json={"isPublished": 1 if published else 0},
        )
        data = self._json_object(response, "Mautic user update")
        user = data.get("user")
        if not isinstance(user, dict) or not user.get("id"):
            raise TemporaryMauticError("Mautic user update returned an invalid response")
        return user

    def create_user(
        self,
        *,
        username: str,
        email: str,
        first_name: str,
        last_name: str,
        role_id: int,
        password: str,
    ) -> dict[str, Any]:
        """Create a Mautic human via the native user API.

        This is a SYSTEM/administrative provisioning call: it runs on the
        service account because the identity being created cannot yet assert
        itself. ``password`` is a generated provider-side credential that is
        never returned, displayed, stored or logged by ECP.
        """
        if not str(username or "").strip():
            raise PermanentMauticError("Mautic username is required")
        if not str(email or "").strip():
            raise PermanentMauticError("Mautic user email is required")
        try:
            normalized_role = int(role_id)
        except (TypeError, ValueError):
            raise PermanentMauticError("Mautic role ID is required") from None
        if normalized_role < 1:
            raise PermanentMauticError("Mautic role ID is required")
        if not password:
            raise PermanentMauticError("A generated Mautic password is required")

        response = self._request(
            "POST",
            "users/new",
            json={
                "username": str(username).strip(),
                "email": str(email).strip(),
                "firstName": str(first_name or "").strip(),
                "lastName": str(last_name or "").strip(),
                "role": normalized_role,
                "isPublished": 1,
                "plainPassword": {"password": password, "confirm": password},
            },
        )
        data = self._json_object(response, "Mautic user creation")
        user = data.get("user")
        if not isinstance(user, dict) or not user.get("id"):
            raise TemporaryMauticError("Mautic user creation returned an invalid response")
        return user

    def get_contact_activity(self, contact_id, **params) -> dict[str, Any]:
        normalized = str(contact_id or "").strip()
        if not normalized:
            raise PermanentMauticError("Mautic contact id is required")
        response = self._request(
            "GET",
            f"contacts/{normalized}/activity",
            params=params or None,
        )
        data = self._json_object(response, "Mautic contact activity")
        if not isinstance(data.get("events"), (dict, list)):
            raise TemporaryMauticError("Mautic contact activity returned invalid events")
        return data

    def list_contacts(self, **params) -> dict[str, Any]:
        response = self._request("GET", "contacts", params=params or None)
        data = self._json_object(response, "Mautic contact list")
        if "contacts" not in data:
            raise TemporaryMauticError(
                "Mautic contact list returned an invalid response"
            )
        contacts = data["contacts"]
        if not isinstance(contacts, (dict, list)):
            raise TemporaryMauticError("Mautic contact list returned invalid contacts")
        return data

    def find_contact_by_email(self, email: str) -> dict[str, Any] | None:
        normalized = str(email or "").strip().lower()
        if not normalized:
            raise PermanentMauticError("Email is required to find a Mautic contact")

        response = self._request(
            "GET",
            "contacts",
            params={"search": f"email:{normalized}", "limit": 20},
        )
        data = self._json_object(response, "Mautic contact search")
        contacts = data.get("contacts") or {}

        if isinstance(contacts, dict):
            candidates = contacts.values()
        elif isinstance(contacts, list):
            candidates = contacts
        else:
            raise TemporaryMauticError("Mautic contact search returned invalid contacts")

        for contact in candidates:
            if not isinstance(contact, dict):
                continue
            fields = contact.get("fields")
            if isinstance(fields, dict):
                core = fields.get("core")
                if isinstance(core, dict):
                    email_field = core.get("email")
                    if isinstance(email_field, dict):
                        candidate_email = email_field.get("value")
                    else:
                        candidate_email = email_field
                    if str(candidate_email or "").strip().lower() == normalized:
                        return contact

            if str(contact.get("email") or "").strip().lower() == normalized:
                return contact

        return None

    def create_contact(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not str(payload.get("email") or "").strip():
            raise PermanentMauticError("Email is required to create a Mautic contact")

        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                "ecp/bridge/contacts/new",
                operation=CONTACT_CREATE,
                data=payload,
            )
        else:
            response = self._request("POST", "contacts/new", data=payload)
        data = self._json_object(response, "Mautic contact creation")
        contact = data.get("contact")
        if not isinstance(contact, dict) or not contact.get("id"):
            raise TemporaryMauticError(
                "Mautic contact creation returned an invalid response"
            )
        return contact

    def create_disposable_contact(self, email: str) -> tuple[dict[str, Any], bool]:
        """Create a throwaway contact and report whether this call inserted it.

        Mautic's ``contacts/new`` is an upsert: when a contact with the same
        email already exists it updates and returns that contact with HTTP 200;
        only a contact this request inserted comes back with HTTP 201. Racing
        creates each insert their own row (201, distinct IDs) or fail with 422.
        So ``created`` is True only for 201 — the one answer that proves this
        exact contact is safe to delete afterwards.
        """
        normalized = str(email or "").strip()
        if not normalized:
            raise PermanentMauticError("Email is required to create a Mautic contact")

        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                "ecp/bridge/contacts/new",
                operation=CONTACT_CREATE,
                data={"email": normalized},
            )
        else:
            response = self._request("POST", "contacts/new", data={"email": normalized})
        data = self._json_object(response, "Mautic contact creation")
        contact = data.get("contact")
        if not isinstance(contact, dict) or not contact.get("id"):
            raise TemporaryMauticError(
                "Mautic contact creation returned an invalid response"
            )
        return contact, response.status_code == 201

    def update_contact(
        self,
        contact_id: int | str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        contact_id = str(contact_id or "").strip()
        if not contact_id:
            raise PermanentMauticError("Mautic contact ID is required")

        if self._uses_asserted_user():
            response = self._bridge_request(
                "PATCH",
                f"ecp/bridge/contacts/{contact_id}/edit",
                operation=CONTACT_UPDATE,
                data=payload,
            )
        else:
            response = self._request(
                "PATCH",
                f"contacts/{contact_id}/edit",
                data=payload,
            )
        data = self._json_object(response, "Mautic contact update")
        contact = data.get("contact")
        if not isinstance(contact, dict) or not contact.get("id"):
            raise TemporaryMauticError(
                "Mautic contact update returned an invalid response"
            )
        return contact

    def delete_contact(self, contact_id: int | str) -> None:
        contact_id = str(contact_id or "").strip()
        if not contact_id:
            raise PermanentMauticError("Mautic contact ID is required")
        self._request("DELETE", f"contacts/{contact_id}/delete")

    def create_contact_import(
        self,
        *,
        file_name: str,
        content: bytes,
        config: dict[str, Any],
    ) -> tuple[dict[str, Any], bool]:
        """Queue a native Mautic contact import through the ECP bridge.

        Asserted-user only: Mautic records the human as the import's creator
        and ``mautic:import`` later processes every row with that user's own
        permissions, so there is no service-account path. Returns
        ``(import, duplicate)``; ``duplicate`` is True when the bridge already
        held an import for the same idempotency key and queued nothing new.
        """
        if not self._uses_asserted_user():
            raise PermanentMauticError(
                "Contact imports require per-user Mautic execution"
            )
        response = self._bridge_request(
            "POST",
            "ecp/bridge/contacts/imports/new",
            operation=CONTACT_IMPORT_CREATE,
            data={"config": json.dumps(config)},
            files={"file": (file_name, content, "text/csv")},
        )
        data = self._json_object(response, "Mautic contact import creation")
        contact_import = data.get("import")
        if not isinstance(contact_import, dict) or not contact_import.get("id"):
            raise TemporaryMauticError(
                "Mautic contact import creation returned an invalid response"
            )
        return contact_import, bool(data.get("duplicate"))

    def list_contact_imports(
        self,
        *,
        created_by: int | None = None,
        limit: int = 25,
        start: int = 0,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit, "start": start}
        if created_by:
            params["created_by"] = int(created_by)
        response = self._request("GET", "ecp/contacts/imports", params=params)
        data = self._json_object(response, "Mautic contact import list")
        if not isinstance(data.get("imports"), list):
            raise TemporaryMauticError("Mautic contact import list returned an invalid response")
        return data

    def get_contact_import(self, import_id: int | str) -> dict[str, Any]:
        import_id = str(import_id or "").strip()
        if not import_id.isdigit():
            raise PermanentMauticError("Mautic import ID is required")
        response = self._request("GET", f"ecp/contacts/imports/{import_id}")
        data = self._json_object(response, "Mautic contact import")
        contact_import = data.get("import")
        if not isinstance(contact_import, dict) or not contact_import.get("id"):
            raise TemporaryMauticError("Mautic contact import returned an invalid response")
        return contact_import

    def list_contact_import_errors(
        self,
        import_id: int | str,
        *,
        limit: int = 25,
        start: int = 0,
    ) -> dict[str, Any]:
        import_id = str(import_id or "").strip()
        if not import_id.isdigit():
            raise PermanentMauticError("Mautic import ID is required")
        response = self._request(
            "GET",
            f"ecp/contacts/imports/{import_id}/errors",
            params={"limit": limit, "start": start},
        )
        data = self._json_object(response, "Mautic contact import errors")
        if not isinstance(data.get("errors"), list):
            raise TemporaryMauticError("Mautic contact import errors returned an invalid response")
        return data

    def delete_contacts_batch(self, contact_ids: list[int]) -> dict[str, Any]:
        """Delete up to 100 contacts with Mautic's native batch delete.

        With an asserted user this goes through the ECP bridge, so Mautic
        applies that user's own delete permission to every contact. The
        response is advisory: callers confirm the outcome by looking the IDs
        up again, which also makes a retried batch harmless.
        """
        ids = ",".join(str(int(contact_id)) for contact_id in contact_ids)
        if not ids:
            raise PermanentMauticError("At least one Mautic contact ID is required")
        if self._uses_asserted_user():
            response = self._bridge_request(
                "DELETE",
                "ecp/bridge/contacts/batch/delete",
                operation=CONTACT_DELETE,
                params={"ids": ids},
            )
        else:
            response = self._request("DELETE", "contacts/batch/delete", params={"ids": ids})
        try:
            data = response.json()
        except (ValueError, TypeError):
            data = {}
        return data if isinstance(data, dict) else {}

    def lookup_contacts_by_id(self, contact_ids: list[int]) -> dict[str, dict[str, Any]]:
        """Current email, Do Not Contact records and campaign count per contact
        (read-only bridge). Unknown IDs are absent from the result."""
        response = self._request(
            "POST",
            "ecp/contacts/id-lookup",
            json={"ids": [int(contact_id) for contact_id in contact_ids]},
        )
        data = self._json_object(response, "Mautic contact lookup")
        contacts = data.get("contacts")
        if isinstance(contacts, list) and not contacts:
            contacts = {}
        if not isinstance(contacts, dict):
            raise TemporaryMauticError("Mautic contact lookup returned an invalid response")
        return {str(key): value for key, value in contacts.items() if isinstance(value, dict)}

    def lookup_contact_emails(self, emails: list[str]) -> dict[str, dict[str, Any]]:
        """Which emails already belong to a Mautic contact (read-only bridge).

        Returns ``{email: {"contact_ids": [...], "dnc_email": bool,
        "dnc_reason": str | None}}`` keyed by lower-cased email.
        """
        response = self._request(
            "POST",
            "ecp/contacts/email-lookup",
            json={"emails": list(emails)},
        )
        data = self._json_object(response, "Mautic contact email lookup")
        matches = data.get("matches")
        if isinstance(matches, list) and not matches:
            matches = {}
        if not isinstance(matches, dict):
            raise TemporaryMauticError("Mautic contact email lookup returned an invalid response")
        return matches

    def list_contact_fields(self, **params) -> dict[str, Any]:
        response = self._request(
            "GET",
            "contacts/list/fields",
            params=params or None,
        )
        data = self._json_object(response, "Mautic contact field metadata")
        if not isinstance(data, (dict,)):
            raise TemporaryMauticError(
                "Mautic contact field metadata returned an invalid response"
            )
        return data

    def list_categories(self, **params) -> dict[str, Any]:
        response = self._request("GET", "categories", params=params or None)
        data = self._json_object(response, "Mautic category list")
        categories = data.get("categories")
        if not isinstance(categories, (dict, list)):
            raise TemporaryMauticError(
                "Mautic category list returned invalid categories"
            )
        return data

    def list_themes(self, **params) -> dict[str, Any]:
        response = self._request("GET", "themes", params=params or None)
        data = self._json_object(response, "Mautic theme list")
        themes = data.get("themes")
        if not isinstance(themes, (dict, list)):
            raise TemporaryMauticError("Mautic theme list returned invalid themes")
        return data

    @staticmethod
    def _normalize_field_object(field_object) -> str:
        """Map an ECP field object name onto a Mautic ``/api/fields/{object}`` path segment."""
        normalized = str(field_object or "contact").strip().lower()
        if normalized == "lead":
            normalized = "contact"
        if normalized not in {"contact", "company"}:
            raise PermanentMauticError(
                "Mautic field object must be either 'contact' or 'company'"
            )
        return normalized

    @staticmethod
    def _field_from_response(
        response,
        context: str,
        *,
        require_id: bool = True,
    ) -> dict[str, Any]:
        data = MauticClient._json_object(response, context)
        field = data.get("field")
        if not isinstance(field, dict) or (require_id and not field.get("id")):
            raise TemporaryMauticError(f"{context} returned an invalid response")
        return field

    def list_fields(self, field_object: str = "contact", **params) -> dict[str, Any]:
        field_object = self._normalize_field_object(field_object)
        response = self._request(
            "GET",
            f"fields/{field_object}",
            params=params or None,
        )
        data = self._json_object(response, "Mautic field list")
        fields = data.get("fields")
        if not isinstance(fields, (dict, list)):
            raise TemporaryMauticError("Mautic field list returned an invalid response")
        return data

    def get_field(self, field_object: str, field_id: int | str) -> dict[str, Any]:
        field_object = self._normalize_field_object(field_object)
        field_id = str(field_id or "").strip()
        if not field_id:
            raise PermanentMauticError("Mautic field ID is required")
        response = self._request("GET", f"fields/{field_object}/{field_id}")
        return self._field_from_response(response, "Mautic field lookup")

    def create_field(
        self,
        field_object: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        field_object = self._normalize_field_object(field_object)
        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                f"ecp/bridge/fields/{field_object}/new",
                operation=FIELD_CREATE,
                data=payload,
            )
        else:
            response = self._request("POST", f"fields/{field_object}/new", data=payload)
        return self._field_from_response(response, "Mautic field creation")

    def update_field(
        self,
        field_object: str,
        field_id: int | str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        field_object = self._normalize_field_object(field_object)
        field_id = str(field_id or "").strip()
        if not field_id:
            raise PermanentMauticError("Mautic field ID is required")
        if self._uses_asserted_user():
            response = self._bridge_request(
                "PATCH",
                f"ecp/bridge/fields/{field_object}/{field_id}/edit",
                operation=FIELD_UPDATE,
                data=payload,
            )
        else:
            response = self._request(
                "PATCH",
                f"fields/{field_object}/{field_id}/edit",
                data=payload,
            )
        return self._field_from_response(response, "Mautic field update")

    def delete_field(self, field_object: str, field_id: int | str) -> dict[str, Any]:
        field_object = self._normalize_field_object(field_object)
        field_id = str(field_id or "").strip()
        if not field_id:
            raise PermanentMauticError("Mautic field ID is required")
        if self._uses_asserted_user():
            response = self._bridge_request(
                "DELETE",
                f"ecp/bridge/fields/{field_object}/{field_id}/delete",
                operation=FIELD_DELETE,
            )
        else:
            response = self._request("DELETE", f"fields/{field_object}/{field_id}/delete")
        return self._field_from_response(
            response,
            "Mautic field deletion",
            require_id=False,
        )

    def list_tags(self, **params) -> dict[str, Any]:
        response = self._request("GET", "tags", params=params or None)
        data = self._json_object(response, "Mautic tag list")
        tags = data.get("tags")
        if not isinstance(tags, (dict, list)):
            raise TemporaryMauticError("Mautic tag list returned invalid tags")
        return data

    @staticmethod
    def _tag_from_response(
        response,
        context: str,
        *,
        require_id: bool = True,
    ) -> dict[str, Any]:
        data = MauticClient._json_object(response, context)
        tag = data.get("tag")
        if not isinstance(tag, dict) or (require_id and not tag.get("id")):
            raise TemporaryMauticError(f"{context} returned an invalid response")
        return tag

    def get_tag(self, tag_id: int | str) -> dict[str, Any]:
        tag_id = str(tag_id or "").strip()
        if not tag_id:
            raise PermanentMauticError("Mautic tag ID is required")
        response = self._request("GET", f"tags/{tag_id}")
        return self._tag_from_response(response, "Mautic tag lookup")

    def create_tag(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                "ecp/bridge/tags/new",
                operation=TAG_CREATE,
                data=payload,
            )
        else:
            response = self._request("POST", "tags/new", data=payload)
        return self._tag_from_response(response, "Mautic tag creation")

    def update_tag(self, tag_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        tag_id = str(tag_id or "").strip()
        if not tag_id:
            raise PermanentMauticError("Mautic tag ID is required")
        if self._uses_asserted_user():
            response = self._bridge_request(
                "PATCH",
                f"ecp/bridge/tags/{tag_id}/edit",
                operation=TAG_UPDATE,
                data=payload,
            )
        else:
            response = self._request("PATCH", f"tags/{tag_id}/edit", data=payload)
        return self._tag_from_response(response, "Mautic tag update")

    def delete_tag(self, tag_id: int | str) -> dict[str, Any]:
        tag_id = str(tag_id or "").strip()
        if not tag_id:
            raise PermanentMauticError("Mautic tag ID is required")
        if self._uses_asserted_user():
            response = self._bridge_request(
                "DELETE",
                f"ecp/bridge/tags/{tag_id}/delete",
                operation=TAG_DELETE,
            )
        else:
            response = self._request("DELETE", f"tags/{tag_id}/delete")
        return self._tag_from_response(
            response,
            "Mautic tag deletion",
            require_id=False,
        )

    def list_contact_notes(self, contact_id: int | str, **params) -> dict[str, Any]:
        contact_id = str(contact_id or "").strip()
        if not contact_id:
            raise PermanentMauticError("Mautic contact ID is required")
        response = self._request(
            "GET",
            f"contacts/{contact_id}/notes",
            params=params or None,
        )
        data = self._json_object(response, "Mautic contact notes")
        notes = data.get("notes")
        if not isinstance(notes, (dict, list)):
            raise TemporaryMauticError("Mautic contact notes returned invalid notes")
        return data

    def create_note(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                "ecp/bridge/notes/new",
                operation=CONTACT_NOTE_CREATE,
                data=payload,
            )
        else:
            response = self._request("POST", "notes/new", data=payload)
        data = self._json_object(response, "Mautic note creation")
        note = data.get("note")
        if not isinstance(note, dict) or not note.get("id"):
            raise TemporaryMauticError("Mautic note creation returned an invalid response")
        return note

    def add_contact_dnc(
        self,
        contact_id: int | str,
        channel: str = "email",
        *,
        reason: int | str = 3,
        comments: str = "",
    ) -> dict[str, Any]:
        contact_id = str(contact_id or "").strip()
        channel = str(channel or "email").strip()
        if not contact_id or not channel:
            raise PermanentMauticError("Mautic contact ID and DNC channel are required")
        body = {"reason": reason, "comments": comments}
        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                f"ecp/bridge/contacts/{contact_id}/dnc/{channel}/add",
                operation=CONTACT_DNC_ADD,
                data=body,
            )
        else:
            response = self._request(
                "POST",
                f"contacts/{contact_id}/dnc/{channel}/add",
                data=body,
            )
        data = self._json_object(response, "Mautic contact DNC add")
        contact = data.get("contact")
        if not isinstance(contact, dict):
            raise TemporaryMauticError("Mautic contact DNC add returned an invalid response")
        return contact

    def remove_contact_dnc(
        self,
        contact_id: int | str,
        channel: str = "email",
    ) -> dict[str, Any]:
        contact_id = str(contact_id or "").strip()
        channel = str(channel or "email").strip()
        if not contact_id or not channel:
            raise PermanentMauticError("Mautic contact ID and DNC channel are required")
        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                f"ecp/bridge/contacts/{contact_id}/dnc/{channel}/remove",
                operation=CONTACT_DNC_REMOVE,
            )
        else:
            response = self._request("POST", f"contacts/{contact_id}/dnc/{channel}/remove")
        data = self._json_object(response, "Mautic contact DNC remove")
        contact = data.get("contact")
        if not isinstance(contact, dict):
            raise TemporaryMauticError(
                "Mautic contact DNC remove returned an invalid response"
            )
        return data

    def list_contact_companies(self, contact_id: int | str) -> dict[str, Any]:
        contact_id = str(contact_id or "").strip()
        if not contact_id:
            raise PermanentMauticError("Mautic contact ID is required")
        response = self._request("GET", f"contacts/{contact_id}/companies")
        data = self._json_object(response, "Mautic contact companies")
        companies = data.get("companies")
        if not isinstance(companies, (dict, list)):
            raise TemporaryMauticError(
                "Mautic contact companies returned invalid companies"
            )
        return data

    def list_companies(self, **params) -> dict[str, Any]:
        response = self._request("GET", "companies", params=params or None)
        data = self._json_object(response, "Mautic company list")
        companies = data.get("companies")
        if not isinstance(companies, (dict, list)):
            raise TemporaryMauticError("Mautic company list returned invalid companies")
        return data

    @staticmethod
    def _company_from_response(
        response,
        context: str,
        *,
        require_id: bool = True,
    ) -> dict[str, Any]:
        data = MauticClient._json_object(response, context)
        company = data.get("company")
        if not isinstance(company, dict) or (require_id and not company.get("id")):
            raise TemporaryMauticError(f"{context} returned an invalid response")
        return company

    def get_company(self, company_id: int | str) -> dict[str, Any]:
        company_id = str(company_id or "").strip()
        if not company_id:
            raise PermanentMauticError("Mautic company ID is required")
        response = self._request("GET", f"companies/{company_id}")
        return self._company_from_response(response, "Mautic company lookup")

    def create_company(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                "ecp/bridge/companies/new",
                operation=COMPANY_CREATE,
                data=payload,
            )
            return self._company_from_response(response, "Mautic company creation")
        response = self._request("POST", "companies/new", data=payload)
        return self._company_from_response(response, "Mautic company creation")

    def update_company(
        self,
        company_id: int | str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        company_id = str(company_id or "").strip()
        if not company_id:
            raise PermanentMauticError("Mautic company ID is required")
        if self._uses_asserted_user():
            response = self._bridge_request(
                "PATCH",
                f"ecp/bridge/companies/{company_id}/edit",
                operation=COMPANY_UPDATE,
                data=payload,
            )
            return self._company_from_response(response, "Mautic company update")
        response = self._request(
            "PATCH",
            f"companies/{company_id}/edit",
            data=payload,
        )
        return self._company_from_response(response, "Mautic company update")

    def delete_company(self, company_id: int | str) -> dict[str, Any]:
        company_id = str(company_id or "").strip()
        if not company_id:
            raise PermanentMauticError("Mautic company ID is required")
        if self._uses_asserted_user():
            response = self._bridge_request(
                "DELETE",
                f"ecp/bridge/companies/{company_id}/delete",
                operation=COMPANY_DELETE,
            )
            return self._company_from_response(
                response,
                "Mautic company deletion",
                require_id=False,
            )
        response = self._request("DELETE", f"companies/{company_id}/delete")
        return self._company_from_response(
            response,
            "Mautic company deletion",
            require_id=False,
        )

    def add_contact_to_company(
        self,
        company_id: int | str,
        contact_id: int | str,
    ) -> None:
        company_id = str(company_id or "").strip()
        contact_id = str(contact_id or "").strip()
        if not company_id or not contact_id:
            raise PermanentMauticError("Mautic company ID and contact ID are required")
        if self._uses_asserted_user():
            self._bridge_request(
                "POST",
                f"ecp/bridge/companies/{company_id}/contact/{contact_id}/add",
                operation=COMPANY_CONTACT_ADD,
            )
            return
        self._request("POST", f"companies/{company_id}/contact/{contact_id}/add")

    def remove_contact_from_company(
        self,
        company_id: int | str,
        contact_id: int | str,
    ) -> None:
        company_id = str(company_id or "").strip()
        contact_id = str(contact_id or "").strip()
        if not company_id or not contact_id:
            raise PermanentMauticError("Mautic company ID and contact ID are required")
        if self._uses_asserted_user():
            self._bridge_request(
                "POST",
                f"ecp/bridge/companies/{company_id}/contact/{contact_id}/remove",
                operation=COMPANY_CONTACT_REMOVE,
            )
            return
        self._request("POST", f"companies/{company_id}/contact/{contact_id}/remove")

    @staticmethod
    def _point_from_response(
        response,
        context: str,
        *,
        require_id: bool = True,
    ) -> dict[str, Any]:
        data = MauticClient._json_object(response, context)
        point = data.get("point")
        if not isinstance(point, dict) or (require_id and not point.get("id")):
            raise TemporaryMauticError(
                f"{context} returned an invalid response"
            )
        return point

    def list_point_actions(self, **params) -> dict[str, Any]:
        response = self._request("GET", "points", params=params or None)
        data = self._json_object(response, "Mautic point action list")
        points = data.get("points")
        if not isinstance(points, (dict, list)):
            raise TemporaryMauticError(
                "Mautic point action list returned an invalid response"
            )
        return data

    def list_point_action_types(self) -> dict[str, str]:
        response = self._request("GET", "points/actions/types")
        data = self._json_object(response, "Mautic point action type list")
        action_types = data.get("pointActionTypes")
        if not isinstance(action_types, dict):
            raise TemporaryMauticError(
                "Mautic point action type list returned an invalid response"
            )
        return {
            str(action_type): str(label)
            for action_type, label in action_types.items()
        }

    def get_point_action(self, point_id: int | str) -> dict[str, Any]:
        point_id = str(point_id or "").strip()
        if not point_id:
            raise PermanentMauticError("Mautic point action ID is required")

        response = self._request("GET", f"points/{point_id}")
        return self._point_from_response(
            response,
            "Mautic point action lookup",
        )

    @staticmethod
    def _point_action_property_fields(
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            str(key): value
            for key, value in payload.items()
            if str(key).startswith("properties[")
        }

    @staticmethod
    def _point_action_property_alias(field_name: str) -> str:
        prefix = "properties["
        if not str(field_name).startswith(prefix):
            return ""
        remainder = str(field_name)[len(prefix):]
        alias, separator, _ = remainder.partition("]")
        return alias if separator else ""

    @staticmethod
    def _point_property_matches(actual, expected) -> bool:
        if isinstance(expected, (list, tuple)):
            actual_values = actual if isinstance(actual, (list, tuple)) else [actual]
            return [str(value) for value in actual_values] == [
                str(value) for value in expected
            ]
        return str(actual) == str(expected)

    def create_point_action(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                "ecp/bridge/points/new",
                operation=POINT_ACTION_CREATE,
                data=payload,
            )
            return self._point_from_response(
                response,
                "Mautic point action creation",
            )

        property_fields = self._point_action_property_fields(payload)
        if not property_fields:
            response = self._request("POST", "points/new", data=payload)
            return self._point_from_response(
                response,
                "Mautic point action creation",
            )

        # Mautic 7.1.3 only builds the type-specific properties form once the
        # Point entity already has its action type. Create the base entity
        # first, then PATCH the dynamic properties after an ID exists.
        base_payload = {
            key: value
            for key, value in payload.items()
            if key not in property_fields
        }
        response = self._request("POST", "points/new", data=base_payload)
        created = self._point_from_response(
            response,
            "Mautic point action creation",
        )
        point_id = created["id"]

        patch_payload = dict(property_fields)
        point_type = str(created.get("type") or base_payload.get("type") or "").strip()
        if point_type:
            patch_payload["type"] = point_type

        try:
            self.update_point_action(point_id, patch_payload)
            fetched = self.get_point_action(point_id)
            properties = fetched.get("properties")
            if not isinstance(properties, dict):
                raise TemporaryMauticError(
                    "Mautic point action properties were not persisted"
                )

            for field_name, expected in property_fields.items():
                alias = self._point_action_property_alias(field_name)
                if not alias or alias not in properties:
                    raise TemporaryMauticError(
                        "Mautic point action properties were not persisted"
                    )
                if not self._point_property_matches(properties.get(alias), expected):
                    raise TemporaryMauticError(
                        "Mautic point action properties were not persisted"
                    )
            return fetched
        except (PermanentMauticError, TemporaryMauticError):
            # Do not leave a partially configured Point Action in Mautic if
            # the required second-step property persistence fails.
            try:
                self.delete_point_action(point_id)
            except (PermanentMauticError, TemporaryMauticError):
                pass
            raise

    def update_point_action(
        self,
        point_id: int | str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        point_id = str(point_id or "").strip()
        if not point_id:
            raise PermanentMauticError("Mautic point action ID is required")

        if self._uses_asserted_user():
            response = self._bridge_request(
                "PATCH",
                f"ecp/bridge/points/{point_id}/edit",
                operation=POINT_ACTION_UPDATE,
                data=payload,
            )
            return self._point_from_response(
                response,
                "Mautic point action update",
            )

        response = self._request(
            "PATCH",
            f"points/{point_id}/edit",
            data=payload,
        )
        return self._point_from_response(
            response,
            "Mautic point action update",
        )

    def delete_point_action(
        self,
        point_id: int | str,
    ) -> dict[str, Any]:
        point_id = str(point_id or "").strip()
        if not point_id:
            raise PermanentMauticError("Mautic point action ID is required")

        if self._uses_asserted_user():
            response = self._bridge_request(
                "DELETE",
                f"ecp/bridge/points/{point_id}/delete",
                operation=POINT_ACTION_DELETE,
            )
            return self._point_from_response(
                response,
                "Mautic point action deletion",
                require_id=False,
            )

        response = self._request("DELETE", f"points/{point_id}/delete")
        return self._point_from_response(
            response,
            "Mautic point action deletion",
            require_id=False,
        )

    @staticmethod
    def _point_group_from_response(
        response,
        context: str,
        *,
        require_id: bool = True,
    ) -> dict[str, Any]:
        data = MauticClient._json_object(response, context)
        group = data.get("pointGroup")
        if not isinstance(group, dict) or (
            require_id and not group.get("id")
        ):
            raise TemporaryMauticError(
                f"{context} returned an invalid response"
            )
        return group

    def list_point_groups(self, **params) -> dict[str, Any]:
        response = self._request(
            "GET",
            "points/groups",
            params=params or None,
        )
        data = self._json_object(response, "Mautic point group list")
        groups = data.get("pointGroups")
        if not isinstance(groups, (dict, list)):
            raise TemporaryMauticError(
                "Mautic point group list returned an invalid response"
            )
        return data

    def get_point_group(
        self,
        group_id: int | str,
    ) -> dict[str, Any]:
        group_id = str(group_id or "").strip()
        if not group_id:
            raise PermanentMauticError(
                "Mautic point group ID is required"
            )

        response = self._request(
            "GET",
            f"points/groups/{group_id}",
        )
        return self._point_group_from_response(
            response,
            "Mautic point group lookup",
        )

    def create_point_group(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                "ecp/bridge/points/groups/new",
                operation=POINT_GROUP_CREATE,
                data=payload,
            )
            return self._point_group_from_response(
                response,
                "Mautic point group creation",
            )

        response = self._request(
            "POST",
            "points/groups/new",
            data=payload,
        )
        return self._point_group_from_response(
            response,
            "Mautic point group creation",
        )

    def update_point_group(
        self,
        group_id: int | str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        group_id = str(group_id or "").strip()
        if not group_id:
            raise PermanentMauticError(
                "Mautic point group ID is required"
            )

        if self._uses_asserted_user():
            response = self._bridge_request(
                "PATCH",
                f"ecp/bridge/points/groups/{group_id}/edit",
                operation=POINT_GROUP_UPDATE,
                data=payload,
            )
            return self._point_group_from_response(
                response,
                "Mautic point group update",
            )

        response = self._request(
            "PATCH",
            f"points/groups/{group_id}/edit",
            data=payload,
        )
        return self._point_group_from_response(
            response,
            "Mautic point group update",
        )

    def delete_point_group(
        self,
        group_id: int | str,
    ) -> dict[str, Any]:
        group_id = str(group_id or "").strip()
        if not group_id:
            raise PermanentMauticError(
                "Mautic point group ID is required"
            )

        if self._uses_asserted_user():
            response = self._bridge_request(
                "DELETE",
                f"ecp/bridge/points/groups/{group_id}/delete",
                operation=POINT_GROUP_DELETE,
            )
            return self._point_group_from_response(
                response,
                "Mautic point group deletion",
                require_id=False,
            )

        # Mautic 7.1.3 cascades Point Group deletion to linked Point Actions,
        # Point Triggers, and contact group-score rows. Higher-level callers
        # must perform dependency checks before invoking this low-level delete.
        response = self._request(
            "DELETE",
            f"points/groups/{group_id}/delete",
        )
        return self._point_group_from_response(
            response,
            "Mautic point group deletion",
            require_id=False,
        )

    @staticmethod
    def _point_group_score_from_response(
        response,
        context: str,
    ) -> dict[str, Any]:
        data = MauticClient._json_object(response, context)
        group_score = data.get("groupScore")
        if not isinstance(group_score, dict) or "score" not in group_score:
            raise TemporaryMauticError(
                f"{context} returned an invalid response"
            )
        group = group_score.get("group")
        if not isinstance(group, dict) or not group.get("id"):
            raise TemporaryMauticError(
                f"{context} returned an invalid response"
            )
        return group_score

    def list_contact_point_groups(
        self,
        contact_id: int | str,
    ) -> dict[str, Any]:
        contact_id = str(contact_id or "").strip()
        if not contact_id:
            raise PermanentMauticError(
                "Mautic contact ID is required"
            )

        response = self._request(
            "GET",
            f"contacts/{contact_id}/points/groups",
        )
        data = self._json_object(
            response,
            "Mautic contact point group list",
        )
        group_scores = data.get("groupScores")
        if not isinstance(group_scores, (dict, list)):
            raise TemporaryMauticError(
                "Mautic contact point group list returned an invalid response"
            )
        return data

    def get_contact_point_group(
        self,
        contact_id: int | str,
        group_id: int | str,
    ) -> dict[str, Any]:
        contact_id = str(contact_id or "").strip()
        group_id = str(group_id or "").strip()
        if not contact_id or not group_id:
            raise PermanentMauticError(
                "Mautic contact ID and point group ID are required"
            )

        response = self._request(
            "GET",
            f"contacts/{contact_id}/points/groups/{group_id}",
        )
        return self._point_group_score_from_response(
            response,
            "Mautic contact point group lookup",
        )

    def adjust_contact_group_points(
        self,
        contact_id: int | str,
        group_id: int | str,
        operator: str,
        amount: int,
        *,
        event_name: str = "",
        action_name: str = "",
    ) -> dict[str, Any]:
        contact_id = str(contact_id or "").strip()
        group_id = str(group_id or "").strip()
        normalized_operator = str(operator or "").strip().lower()
        if not contact_id or not group_id:
            raise PermanentMauticError(
                "Mautic contact ID and point group ID are required"
            )
        if normalized_operator not in {"plus", "minus"}:
            raise PermanentMauticError(
                "Mautic point group operator must be 'plus' or 'minus'"
            )
        if isinstance(amount, bool):
            raise PermanentMauticError(
                "Mautic point group adjustment amount must be a positive integer"
            )
        try:
            normalized_amount = int(amount)
        except (TypeError, ValueError) as exc:
            raise PermanentMauticError(
                "Mautic point group adjustment amount must be a positive integer"
            ) from exc
        if normalized_amount <= 0:
            raise PermanentMauticError(
                "Mautic point group adjustment amount must be a positive integer"
            )

        payload = {}
        normalized_event_name = str(event_name or "").strip()
        normalized_action_name = str(action_name or "").strip()
        if normalized_event_name:
            payload["eventName"] = normalized_event_name
        if normalized_action_name:
            payload["actionName"] = normalized_action_name

        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                (
                    f"ecp/bridge/contacts/{contact_id}/points/groups/{group_id}/"
                    f"{normalized_operator}/{normalized_amount}"
                ),
                operation=POINT_CONTACT_GROUP_ADJUST,
                data=payload or None,
            )
            return self._point_group_score_from_response(
                response,
                "Mautic contact point group adjustment",
            )

        response = self._request(
            "POST",
            (
                f"contacts/{contact_id}/points/groups/{group_id}/"
                f"{normalized_operator}/{normalized_amount}"
            ),
            data=payload or None,
        )
        return self._point_group_score_from_response(
            response,
            "Mautic contact point group adjustment",
        )

    def adjust_contact_points(
        self,
        contact_id: int | str,
        operator: str,
        amount: int,
        *,
        event_name: str = "",
        action_name: str = "",
    ) -> dict[str, Any]:
        contact_id = str(contact_id or "").strip()
        normalized_operator = str(operator or "").strip().lower()
        if not contact_id:
            raise PermanentMauticError("Mautic contact ID is required")
        if normalized_operator not in {"plus", "minus"}:
            raise PermanentMauticError(
                "Mautic point operator must be 'plus' or 'minus'"
            )
        if isinstance(amount, bool):
            raise PermanentMauticError(
                "Mautic point adjustment amount must be a positive integer"
            )
        try:
            normalized_amount = int(amount)
        except (TypeError, ValueError) as exc:
            raise PermanentMauticError(
                "Mautic point adjustment amount must be a positive integer"
            ) from exc
        if normalized_amount <= 0:
            raise PermanentMauticError(
                "Mautic point adjustment amount must be a positive integer"
            )

        payload = {}
        normalized_event_name = str(event_name or "").strip()
        normalized_action_name = str(action_name or "").strip()
        if normalized_event_name:
            payload["eventName"] = normalized_event_name
        if normalized_action_name:
            payload["actionName"] = normalized_action_name

        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                (
                    f"ecp/bridge/contacts/{contact_id}/points/"
                    f"{normalized_operator}/{normalized_amount}"
                ),
                operation=POINT_CONTACT_ADJUST,
                data=payload or None,
            )
            data = self._json_object(response, "Mautic contact point adjustment")
            if not data.get("success"):
                raise TemporaryMauticError(
                    "Mautic contact point adjustment returned an unsuccessful response"
                )
            return data

        response = self._request(
            "POST",
            (
                f"contacts/{contact_id}/points/"
                f"{normalized_operator}/{normalized_amount}"
            ),
            data=payload or None,
        )
        data = self._json_object(response, "Mautic contact point adjustment")
        if not data.get("success"):
            raise TemporaryMauticError(
                "Mautic contact point adjustment returned an unsuccessful response"
            )
        return data

    @staticmethod
    def _point_trigger_from_response(
        response,
        context: str,
        *,
        require_id: bool = True,
    ) -> dict[str, Any]:
        data = MauticClient._json_object(response, context)
        trigger = data.get("trigger")
        if not isinstance(trigger, dict) or (
            require_id and not trigger.get("id")
        ):
            raise TemporaryMauticError(
                f"{context} returned an invalid response"
            )
        return trigger

    def list_point_triggers(self, **params) -> dict[str, Any]:
        response = self._request(
            "GET",
            "points/triggers",
            params=params or None,
        )
        data = self._json_object(response, "Mautic point trigger list")
        triggers = data.get("triggers")
        if not isinstance(triggers, (dict, list)):
            raise TemporaryMauticError(
                "Mautic point trigger list returned an invalid response"
            )
        return data

    def list_point_trigger_event_types(self) -> dict[str, str]:
        response = self._request(
            "GET",
            "points/triggers/events/types",
        )
        data = self._json_object(
            response,
            "Mautic point trigger event type list",
        )
        event_types = data.get("eventTypes")
        if not isinstance(event_types, dict):
            raise TemporaryMauticError(
                "Mautic point trigger event type list returned an invalid response"
            )
        return {
            str(event_type): str(label)
            for event_type, label in event_types.items()
        }

    def get_point_trigger(
        self,
        trigger_id: int | str,
    ) -> dict[str, Any]:
        trigger_id = str(trigger_id or "").strip()
        if not trigger_id:
            raise PermanentMauticError(
                "Mautic point trigger ID is required"
            )

        response = self._request(
            "GET",
            f"points/triggers/{trigger_id}",
        )
        return self._point_trigger_from_response(
            response,
            "Mautic point trigger lookup",
        )

    def create_point_trigger(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                "ecp/bridge/points/triggers/new",
                operation=POINT_TRIGGER_CREATE,
                data=payload,
            )
            return self._point_trigger_from_response(
                response,
                "Mautic point trigger creation",
            )

        response = self._request(
            "POST",
            "points/triggers/new",
            data=payload,
        )
        return self._point_trigger_from_response(
            response,
            "Mautic point trigger creation",
        )

    def update_point_trigger(
        self,
        trigger_id: int | str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        trigger_id = str(trigger_id or "").strip()
        if not trigger_id:
            raise PermanentMauticError(
                "Mautic point trigger ID is required"
            )

        if self._uses_asserted_user():
            response = self._bridge_request(
                "PATCH",
                f"ecp/bridge/points/triggers/{trigger_id}/edit",
                operation=POINT_TRIGGER_UPDATE,
                data=payload,
            )
            return self._point_trigger_from_response(
                response,
                "Mautic point trigger update",
            )

        response = self._request(
            "PATCH",
            f"points/triggers/{trigger_id}/edit",
            data=payload,
        )
        return self._point_trigger_from_response(
            response,
            "Mautic point trigger update",
        )

    def delete_point_trigger(
        self,
        trigger_id: int | str,
    ) -> dict[str, Any]:
        trigger_id = str(trigger_id or "").strip()
        if not trigger_id:
            raise PermanentMauticError(
                "Mautic point trigger ID is required"
            )

        if self._uses_asserted_user():
            response = self._bridge_request(
                "DELETE",
                f"ecp/bridge/points/triggers/{trigger_id}/delete",
                operation=POINT_TRIGGER_DELETE,
            )
            return self._point_trigger_from_response(
                response,
                "Mautic point trigger deletion",
                require_id=False,
            )

        response = self._request(
            "DELETE",
            f"points/triggers/{trigger_id}/delete",
        )
        return self._point_trigger_from_response(
            response,
            "Mautic point trigger deletion",
            require_id=False,
        )

    @staticmethod
    def _point_trigger_event_from_response(
        response,
        context: str,
    ) -> dict[str, Any]:
        event = MauticClient._json_object(response, context)
        if not event.get("id"):
            raise TemporaryMauticError(
                f"{context} returned an invalid response"
            )
        return event

    def create_point_trigger_event(
        self,
        trigger_id: int | str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        trigger_id = str(trigger_id or "").strip()
        if not trigger_id:
            raise PermanentMauticError(
                "Mautic point trigger ID is required"
            )
        if not isinstance(payload, dict) or not payload:
            raise PermanentMauticError(
                "Mautic point trigger event creation payload is required"
            )

        event_payload = dict(payload)
        event_payload["trigger"] = f"/api/v2/triggers/{trigger_id}"

        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                f"ecp/bridge/points/triggers/{trigger_id}/events",
                operation=POINT_TRIGGER_EVENT_CREATE,
                json=event_payload,
                headers={
                    "Content-Type": "application/ld+json",
                },
            )
            return self._point_trigger_event_from_response(
                response,
                "Mautic point trigger event creation",
            )

        response = self._request(
            "POST",
            "v2/trigger_events",
            json=event_payload,
            headers={
                "Content-Type": "application/ld+json",
            },
        )
        return self._point_trigger_event_from_response(
            response,
            "Mautic point trigger event creation",
        )

    def get_point_trigger_event(
        self,
        event_id: int | str,
    ) -> dict[str, Any]:
        event_id = str(event_id or "").strip()
        if not event_id:
            raise PermanentMauticError(
                "Mautic point trigger event ID is required"
            )

        response = self._request(
            "GET",
            f"v2/trigger_events/{event_id}",
        )
        return self._point_trigger_event_from_response(
            response,
            "Mautic point trigger event lookup",
        )

    def update_point_trigger_event(
        self,
        event_id: int | str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        event_id = str(event_id or "").strip()
        if not event_id:
            raise PermanentMauticError(
                "Mautic point trigger event ID is required"
            )
        if not isinstance(payload, dict) or not payload:
            raise PermanentMauticError(
                "Mautic point trigger event update payload is required"
            )

        if self._uses_asserted_user():
            response = self._bridge_request(
                "PATCH",
                f"ecp/bridge/points/triggers/events/{event_id}",
                operation=POINT_TRIGGER_EVENT_UPDATE,
                json=payload,
                headers={
                    "Content-Type": "application/merge-patch+json",
                },
            )
            return self._point_trigger_event_from_response(
                response,
                "Mautic point trigger event update",
            )

        response = self._request(
            "PATCH",
            f"v2/trigger_events/{event_id}",
            json=payload,
            headers={
                "Content-Type": "application/merge-patch+json",
            },
        )
        return self._point_trigger_event_from_response(
            response,
            "Mautic point trigger event update",
        )

    def delete_point_trigger_event(
        self,
        event_id: int | str,
    ) -> None:
        event_id = str(event_id or "").strip()
        if not event_id:
            raise PermanentMauticError(
                "Mautic point trigger event ID is required"
            )

        # The legacy
        # /api/points/triggers/{triggerId}/events/delete endpoint returns an
        # in-memory Trigger with the event removed but does not persist that
        # deletion on Mautic 7.1.3. Use the direct API Platform resource,
        # which performs the real entity deletion.
        if self._uses_asserted_user():
            self._bridge_request(
                "DELETE",
                f"ecp/bridge/points/triggers/events/{event_id}",
                operation=POINT_TRIGGER_EVENT_DELETE,
            )
            return

        self._request(
            "DELETE",
            f"v2/trigger_events/{event_id}",
        )

    @staticmethod
    def _email_form_data(payload: dict[str, Any]) -> list[tuple[str, Any]]:
        """Encode Mautic email form collections using Symfony array notation."""
        form_data = []
        for key, value in payload.items():
            if isinstance(value, (list, tuple)):
                form_data.extend((f"{key}[]", item) for item in value)
            elif isinstance(value, bool):
                form_data.append((key, "1" if value else "0"))
            else:
                form_data.append((key, value))
        return form_data

    @staticmethod
    def _email_from_response(
        response,
        context: str,
        *,
        require_id: bool = True,
    ) -> dict[str, Any]:
        data = MauticClient._json_object(response, context)
        email = data.get("email")
        if not isinstance(email, dict) or (require_id and not email.get("id")):
            raise TemporaryMauticError(
                f"{context} returned an invalid response"
            )
        return email

    def get_email(self, email_id: int | str) -> dict[str, Any]:
        email_id = str(email_id or "").strip()
        if not email_id:
            raise PermanentMauticError("Mautic email ID is required")

        response = self._request("GET", f"emails/{email_id}")
        return self._email_from_response(response, "Mautic email lookup")

    def get_email_stats(self, email_id: int | str) -> dict[str, Any]:
        email_id = str(email_id or "").strip()
        if not email_id:
            raise PermanentMauticError("Mautic email ID is required")

        response = self._request(
            "GET",
            "stats/email_stats",
            params={
                "where[0][col]": "email_id",
                "where[0][expr]": "eq",
                "where[0][val]": email_id,
            },
        )
        data = self._json_object(response, "Mautic email statistics lookup")
        if "data" not in data and "stats" not in data and "total" not in data:
            raise TemporaryMauticError(
                "Mautic email statistics lookup returned an invalid response"
            )
        return data

    def _email_stats_query(
        self,
        email_id: int | str,
        *,
        filters: dict[str, Any] | None = None,
        order: tuple[str, str] | None = None,
        limit: int = 1,
    ) -> dict[str, Any]:
        email_id = str(email_id or "").strip()
        if not email_id:
            raise PermanentMauticError("Mautic email ID is required")

        params = {
            "where[0][col]": "email_id",
            "where[0][expr]": "eq",
            "where[0][val]": email_id,
            "limit": int(limit),
        }
        for index, (column, value) in enumerate((filters or {}).items(), start=1):
            params[f"where[{index}][col]"] = column
            params[f"where[{index}][expr]"] = "eq"
            params[f"where[{index}][val]"] = value
        if order:
            params["order[0][col]"], params["order[0][dir]"] = order

        response = self._request("GET", "stats/email_stats", params=params)
        data = self._json_object(response, "Mautic email statistics lookup")
        if "total" not in data:
            raise TemporaryMauticError(
                "Mautic email statistics lookup returned an invalid response"
            )
        return data

    def count_email_stats(self, email_id: int | str, **filters) -> int:
        """Count email_stats rows for one email, optionally filtered by column.

        Reads the provider's ``total`` rather than counting returned rows, so
        the result stays exact past the stats API's page size.
        """
        data = self._email_stats_query(email_id, filters=filters, limit=1)
        try:
            return int(data["total"])
        except (TypeError, ValueError) as exc:
            raise TemporaryMauticError(
                "Mautic email statistics lookup returned an invalid total"
            ) from exc

    @staticmethod
    def _stats_where_params(filters) -> dict[str, Any]:
        """``[(column, expr, value)]`` as Mautic stats ``where`` params.

        ``value`` is ignored for column-only expressions (``isNotNull``); ``in``
        takes a comma-separated string, as Mautic's CsvHelper parses it.
        """
        params: dict[str, Any] = {}
        for index, (column, expr, value) in enumerate(filters or []):
            params[f"where[{index}][col]"] = column
            params[f"where[{index}][expr]"] = expr
            if value is not None:
                params[f"where[{index}][val]"] = value
        return params

    def list_stat_rows(
        self,
        table: str,
        filters=None,
        *,
        start: int = 0,
        limit: int = 100,
        order: tuple[str, str] | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """One page of a Mautic stats table and the provider's exact total."""
        params = self._stats_where_params(filters)
        params["start"] = int(start)
        params["limit"] = int(limit)
        if order:
            params["order[0][col]"], params["order[0][dir]"] = order
        response = self._request("GET", f"stats/{table}", params=params)
        data = self._json_object(response, f"Mautic {table} statistics lookup")
        try:
            total = int(data["total"])
        except (KeyError, TypeError, ValueError) as exc:
            raise TemporaryMauticError(
                f"Mautic {table} statistics lookup returned an invalid response"
            ) from exc
        rows = data.get("stats")
        if isinstance(rows, dict):
            rows = list(rows.values())
        if not isinstance(rows, list):
            rows = []
        return [row for row in rows if isinstance(row, dict)], total

    def count_stat_rows(self, table: str, filters=None) -> int:
        """Exact row count of a filtered Mautic stats table (one request)."""
        _, total = self.list_stat_rows(table, filters, limit=1)
        return total

    def get_latest_email_send(self, email_id: int | str) -> dict[str, Any] | None:
        """Most recent successful send row for one email, or None."""
        data = self._email_stats_query(
            email_id,
            filters={"is_failed": 0},
            order=("date_sent", "DESC"),
            limit=1,
        )
        rows = data.get("stats")
        if isinstance(rows, dict):
            rows = list(rows.values())
        if not isinstance(rows, list):
            return None
        return next((row for row in rows if isinstance(row, dict)), None)

    def list_emails(self, **params) -> dict[str, Any]:
        response = self._request("GET", "emails", params=params or None)
        data = self._json_object(response, "Mautic email list")
        self._email_collection_items(data, "Mautic email list")
        return data

    def create_email(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                "ecp/bridge/emails/new",
                operation=EMAIL_CREATE,
                data=self._email_form_data(payload),
            )
        else:
            response = self._request(
                "POST",
                "emails/new",
                data=self._email_form_data(payload),
            )
        return self._email_from_response(response, "Mautic email creation")

    def update_email(
        self,
        email_id: int | str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        email_id = str(email_id or "").strip()
        if not email_id:
            raise PermanentMauticError("Mautic email ID is required")

        if self._uses_asserted_user():
            response = self._bridge_request(
                "PATCH",
                f"ecp/bridge/emails/{email_id}/edit",
                operation=EMAIL_UPDATE,
                data=self._email_form_data(payload),
            )
        else:
            response = self._request(
                "PATCH",
                f"emails/{email_id}/edit",
                data=self._email_form_data(payload),
            )
        return self._email_from_response(response, "Mautic email update")

    def delete_email(self, email_id: int | str) -> dict[str, Any]:
        email_id = str(email_id or "").strip()
        if not email_id:
            raise PermanentMauticError("Mautic email ID is required")

        if self._uses_asserted_user():
            response = self._bridge_request(
                "DELETE",
                f"ecp/bridge/emails/{email_id}/delete",
                operation=EMAIL_DELETE,
            )
        else:
            response = self._request("DELETE", f"emails/{email_id}/delete")
        return self._email_from_response(
            response,
            "Mautic email deletion",
            require_id=False,
        )

    @staticmethod
    def _email_collection_items(
        data: dict[str, Any],
        context: str,
    ) -> list[dict[str, Any]]:
        emails = data.get("emails")
        if isinstance(emails, dict):
            rows = list(emails.values())
        elif isinstance(emails, list):
            rows = list(emails)
        else:
            raise TemporaryMauticError(
                f"{context} returned an invalid response"
            )

        if any(not isinstance(row, dict) for row in rows):
            raise TemporaryMauticError(
                f"{context} returned invalid emails"
            )
        return rows

    @staticmethod
    def _require_template_email(
        email: dict[str, Any],
        context: str,
    ) -> dict[str, Any]:
        if str(email.get("emailType") or "").strip() != "template":
            raise PermanentMauticError(
                f"{context} is not a Mautic template email"
            )
        return email

    def list_email_templates(self, **params) -> dict[str, Any]:
        """List only reusable Mautic template emails.

        Mautic 7.1.3 ignores the legacy ``email_type`` list filter, so this
        method walks the provider result set and filters by ``emailType`` in
        ECP before applying template pagination.
        """
        query = dict(params or {})
        raw_start = query.pop("start", 0)
        raw_limit = query.pop("limit", 30)
        query.pop("email_type", None)
        query.pop("emailType", None)

        try:
            start = int(raw_start)
            limit = int(raw_limit)
        except (TypeError, ValueError) as exc:
            raise PermanentMauticError(
                "Mautic template pagination is invalid"
            ) from exc

        if isinstance(raw_start, bool) or isinstance(raw_limit, bool):
            raise PermanentMauticError(
                "Mautic template pagination is invalid"
            )
        if start < 0 or limit <= 0:
            raise PermanentMauticError(
                "Mautic template pagination is invalid"
            )

        templates: list[dict[str, Any]] = []
        provider_start = 0
        provider_limit = 100

        while True:
            response = self._request(
                "GET",
                "emails",
                params={
                    **query,
                    "start": provider_start,
                    "limit": provider_limit,
                },
            )
            data = self._json_object(
                response,
                "Mautic email template list",
            )
            rows = self._email_collection_items(
                data,
                "Mautic email template list",
            )
            # Mautic's list leaves out A/B variants but not translations;
            # both are reached through their main template.
            templates.extend(
                row
                for row in rows
                if str(row.get("emailType") or "").strip() == "template"
                and not row.get("translationParent")
                and not row.get("variantParent")
            )

            provider_start += len(rows)
            try:
                provider_total = int(data.get("total"))
            except (TypeError, ValueError):
                provider_total = None

            if not rows:
                break
            if provider_total is not None and provider_start >= provider_total:
                break
            if provider_total is None and len(rows) < provider_limit:
                break

        return {
            "total": len(templates),
            "start": start,
            "limit": limit,
            "emails": templates[start:start + limit],
        }

    def get_email_template(
        self,
        email_id: int | str,
    ) -> dict[str, Any]:
        return self._require_template_email(
            self.get_email(email_id),
            "Mautic email",
        )

    def create_email_template(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(payload, dict) or not payload:
            raise PermanentMauticError(
                "Mautic email template creation payload is required"
            )

        template_payload = dict(payload)
        requested_type = str(
            template_payload.get("emailType") or ""
        ).strip()
        if requested_type and requested_type != "template":
            raise PermanentMauticError(
                "Mautic email template type must be template"
            )
        template_payload["emailType"] = "template"

        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                "ecp/bridge/templates/new",
                operation=TEMPLATE_CREATE,
                data=self._email_form_data(template_payload),
            )
            return self._require_template_email(
                self._email_from_response(response, "Mautic email template creation"),
                "Created Mautic email",
            )

        return self._require_template_email(
            self.create_email(template_payload),
            "Created Mautic email",
        )

    def update_email_template(
        self,
        email_id: int | str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(payload, dict) or not payload:
            raise PermanentMauticError(
                "Mautic email template update payload is required"
            )

        email_id = str(email_id or "").strip()
        if not email_id:
            raise PermanentMauticError("Mautic email ID is required")

        template_payload = dict(payload)
        requested_type = str(
            template_payload.get("emailType") or ""
        ).strip()
        if requested_type and requested_type != "template":
            raise PermanentMauticError(
                "Mautic email template type must be template"
            )
        template_payload["emailType"] = "template"

        if self._uses_asserted_user():
            response = self._bridge_request(
                "PATCH",
                f"ecp/bridge/templates/{email_id}/edit",
                operation=TEMPLATE_UPDATE,
                data=self._email_form_data(template_payload),
            )
            return self._require_template_email(
                self._email_from_response(response, "Mautic email template update"),
                "Updated Mautic email",
            )

        self.get_email_template(email_id)
        return self._require_template_email(
            self.update_email(email_id, template_payload),
            "Updated Mautic email",
        )

    def delete_email_template(
        self,
        email_id: int | str,
    ) -> dict[str, Any]:
        email_id = str(email_id or "").strip()
        if not email_id:
            raise PermanentMauticError("Mautic email ID is required")
        if self._uses_asserted_user():
            response = self._bridge_request(
                "DELETE",
                f"ecp/bridge/templates/{email_id}/delete",
                operation=TEMPLATE_DELETE,
            )
            return self._email_from_response(
                response,
                "Mautic email template deletion",
                require_id=False,
            )
        self.get_email_template(email_id)
        return self.delete_email(email_id)

    def _template_family_request(self, method: str, path: str, *, operation: str, context: str, data=None) -> dict[str, Any]:
        if not self._uses_asserted_user():
            raise MauticIdentityConfigurationError(f"{context} requires per-user Mautic identity")
        kwargs = {"data": self._email_form_data(data)} if data else {}
        return self._json_object(self._bridge_request(method, path, operation=operation, **kwargs), context)

    def create_template_variant(self, template_id, *, weight: int, winner_criteria: str, name: str | None = None) -> dict[str, Any]:
        """Add an unpublished A/B variant (a copy of the main template's content)."""
        template = self._numeric_id(template_id, "template")
        data = {"weight": int(weight), "winnerCriteria": winner_criteria, **({"name": name} if name else {})}
        response = self._template_family_request(
            "POST", f"ecp/bridge/templates/{template}/variants/new", operation=TEMPLATE_VARIANT_CREATE,
            context="Mautic template variant creation", data=data,
        )
        return self._require_template_email(self._email_payload(response, "Mautic template variant creation"), "Created Mautic email")

    def update_template_variant(self, template_id, *, weight: int | None = None, winner_criteria: str | None = None) -> dict[str, Any]:
        """Change a variant's weight and/or the whole test's winner criteria."""
        template = self._numeric_id(template_id, "template")
        data: dict[str, Any] = {}
        if weight is not None:
            data["weight"] = int(weight)
        if winner_criteria is not None:
            data["winnerCriteria"] = winner_criteria
        if not data:
            raise PermanentMauticError("Mautic template variant update payload is required")
        return self._template_family_request(
            "PATCH", f"ecp/bridge/templates/{template}/variant/edit", operation=TEMPLATE_VARIANT_UPDATE,
            context="Mautic template variant update", data=data,
        )

    def make_template_variant_winner(self, template_id) -> dict[str, Any]:
        """End the test: variants switched off, the winner's content copied onto the main template."""
        template = self._numeric_id(template_id, "template")
        return self._template_family_request(
            "POST", f"ecp/bridge/templates/{template}/winner", operation=TEMPLATE_VARIANT_WINNER,
            context="Mautic template variant winner",
        )

    def create_template_translation(self, template_id, *, language: str, name: str | None = None) -> dict[str, Any]:
        """Add an unpublished translation (a copy of the main template in another language)."""
        template = self._numeric_id(template_id, "template")
        data = {"language": language, **({"name": name} if name else {})}
        response = self._template_family_request(
            "POST", f"ecp/bridge/templates/{template}/translations/new", operation=TEMPLATE_TRANSLATION_CREATE,
            context="Mautic template translation creation", data=data,
        )
        return self._require_template_email(self._email_payload(response, "Mautic template translation creation"), "Created Mautic email")

    def get_template_abtest(self, template_id, *, timeout=None) -> dict[str, Any]:
        template = self._numeric_id(template_id, "template")
        response = self._request("GET", f"ecp/bridge/templates/{template}/abtest", timeout=timeout)
        test = self._json_object(response, "Mautic template A/B test").get("abTest")
        if not isinstance(test, dict) or not isinstance(test.get("versions"), list):
            raise TemporaryMauticError("Mautic template A/B test returned an invalid response")
        return test

    def create_broadcast_variant(self, email_id, *, weight: int, winner_criteria: str, name: str | None = None) -> dict[str, Any]:
        """Add an A/B variant to a broadcast's email: a copy, sent only inside its send."""
        email = self._numeric_id(email_id, "email")
        data = {"weight": int(weight), "winnerCriteria": winner_criteria, **({"name": name} if name else {})}
        response = self._template_family_request(
            "POST", f"ecp/bridge/emails/{email}/variants/new", operation=EMAIL_VARIANT_CREATE,
            context="Mautic broadcast variant creation", data=data,
        )
        return self._email_payload(response, "Mautic broadcast variant creation")

    def update_broadcast_variant(self, email_id, *, weight: int | None = None, winner_criteria: str | None = None) -> dict[str, Any]:
        email = self._numeric_id(email_id, "email")
        data: dict[str, Any] = {}
        if weight is not None:
            data["weight"] = int(weight)
        if winner_criteria is not None:
            data["winnerCriteria"] = winner_criteria
        if not data:
            raise PermanentMauticError("Mautic broadcast variant update payload is required")
        return self._template_family_request(
            "PATCH", f"ecp/bridge/emails/{email}/variant/edit", operation=EMAIL_VARIANT_UPDATE,
            context="Mautic broadcast variant update", data=data,
        )

    def create_broadcast_translation(self, email_id, *, language: str, name: str | None = None) -> dict[str, Any]:
        email = self._numeric_id(email_id, "email")
        data = {"language": language, **({"name": name} if name else {})}
        response = self._template_family_request(
            "POST", f"ecp/bridge/emails/{email}/translations/new", operation=EMAIL_TRANSLATION_CREATE,
            context="Mautic broadcast translation creation", data=data,
        )
        return self._email_payload(response, "Mautic broadcast translation creation")

    def get_broadcast_abtest(self, email_id, *, timeout=None) -> dict[str, Any]:
        email = self._numeric_id(email_id, "email")
        response = self._request("GET", f"ecp/bridge/emails/{email}/abtest", timeout=timeout)
        test = self._json_object(response, "Mautic broadcast A/B test").get("abTest")
        if not isinstance(test, dict) or not isinstance(test.get("versions"), list):
            raise TemporaryMauticError("Mautic broadcast A/B test returned an invalid response")
        return test

    def get_email_family_ids(self, email_id) -> list[str]:
        """The email's variants and translations (not the email itself)."""
        email = self.get_email(email_id)
        ids = []
        for key in ("variantChildren", "translationChildren"):
            rows = email.get(key)
            rows = rows.values() if isinstance(rows, dict) else rows if isinstance(rows, list) else []
            ids.extend(str(row["id"]) for row in rows if isinstance(row, dict) and row.get("id") is not None)
        return ids

    @staticmethod
    def _email_payload(data: dict[str, Any], context: str) -> dict[str, Any]:
        email = data.get("email")
        if not isinstance(email, dict) or email.get("id") is None:
            raise TemporaryMauticError(f"{context} returned an invalid response")
        return email

    def duplicate_email_template(
        self,
        email_id: int | str,
        *,
        name: str | None = None,
    ) -> dict[str, Any]:
        email_id = str(email_id or "").strip()
        if not email_id:
            raise PermanentMauticError("Mautic email ID is required")
        if self._uses_asserted_user():
            payload = {}
            if name is not None:
                payload["name"] = name
            response = self._bridge_request(
                "POST",
                f"ecp/bridge/templates/{email_id}/duplicate",
                operation=TEMPLATE_DUPLICATE,
                data=payload,
            )
            return self._require_template_email(
                self._email_from_response(response, "Mautic email template duplicate"),
                "Duplicated Mautic email",
            )

        source = self.get_email_template(email_id)
        clone_fields = (
            "subject",
            "preheaderText",
            "fromName",
            "fromAddress",
            "plainText",
            "customHtml",
            "template",
            "language",
            "publicPreview",
        )
        payload = {
            key: source[key]
            for key in clone_fields
            if key in source and source.get(key) is not None
        }
        payload["name"] = name or f"{str(source.get('name') or '').strip()} Copy".strip()
        payload["isPublished"] = False

        category = source.get("category")
        if isinstance(category, dict) and category.get("id"):
            payload["category"] = category["id"]
        elif category:
            payload["category"] = category

        return self.create_email_template(payload)

    @staticmethod
    def _campaign_form_data(
        payload: dict[str, Any],
    ) -> list[tuple[str, Any]]:
        """Encode nested Mautic Campaign payloads using Symfony bracket keys."""
        if not isinstance(payload, dict) or not payload:
            raise PermanentMauticError(
                "Mautic campaign payload is required"
            )

        form_data: list[tuple[str, Any]] = []

        def walk(prefix: str, value: Any) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    child_key = f"{prefix}[{key}]" if prefix else str(key)
                    walk(child_key, child)
                return
            if isinstance(value, (list, tuple)):
                for index, child in enumerate(value):
                    walk(f"{prefix}[{index}]", child)
                return
            if value is None:
                form_data.append((prefix, ""))
                return
            if isinstance(value, bool):
                form_data.append((prefix, "1" if value else "0"))
                return
            form_data.append((prefix, value))

        walk("", payload)
        return [(key, value) for key, value in form_data if key]

    @staticmethod
    def _campaign_from_response(
        response,
        context: str,
        *,
        require_id: bool = True,
    ) -> dict[str, Any]:
        data = MauticClient._json_object(response, context)
        campaign = data.get("campaign")
        if not isinstance(campaign, dict) or (
            require_id and not campaign.get("id")
        ):
            raise TemporaryMauticError(
                f"{context} returned an invalid response"
            )
        return campaign

    def list_campaigns(self, **params) -> dict[str, Any]:
        response = self._request(
            "GET",
            "campaigns",
            params=params or None,
        )
        data = self._json_object(response, "Mautic campaign list")
        campaigns = data.get("campaigns")
        if not isinstance(campaigns, (dict, list)):
            raise TemporaryMauticError(
                "Mautic campaign list returned invalid campaigns"
            )
        return data

    def get_contact_segment_ids(self, contact_id) -> set[str]:
        contact = self._numeric_id(contact_id, "contact")
        data = self._json_object(self._request("GET", f"contacts/{contact}/segments"), "Mautic contact segments")
        rows = data.get("lists")
        rows = rows.values() if isinstance(rows, dict) else rows if isinstance(rows, list) else []
        return {str(row.get("id")) for row in rows if isinstance(row, dict) and row.get("id") is not None}

    def get_contact_campaigns(self, contact_id) -> list[dict[str, Any]]:
        """Every Campaign the contact is in, published or not (ECP plugin).

        The native contacts/{id}/campaigns lists published Campaigns only,
        while Mautic keeps membership of unpublished ones as well."""
        contact = self._numeric_id(contact_id, "contact")
        data = self._json_object(
            self._request("GET", f"ecp/contacts/{contact}/campaign-memberships"), "Mautic contact campaigns"
        )
        rows = data.get("campaigns")
        if not isinstance(rows, list):
            raise TemporaryMauticError("Mautic contact campaigns returned an invalid response")
        return [row for row in rows if isinstance(row, dict) and row.get("id") is not None]

    def get_contact_campaign_ids(self, contact_id) -> set[str]:
        return {str(row["id"]) for row in self.get_contact_campaigns(contact_id)}

    def _campaign_contact_bridge(self, action: str, campaign_id, contact_id, operation: str) -> None:
        # Manual Campaign membership is attributed to a human Mautic user or
        # not changed at all: there is deliberately no service-account fallback.
        if not self._uses_asserted_user():
            raise MauticIdentityConfigurationError(
                "Mautic Campaign membership changes require per-user Mautic identity"
            )
        campaign = self._numeric_id(campaign_id, "campaign")
        contact = self._numeric_id(contact_id, "contact")
        self._bridge_request("POST", f"ecp/bridge/campaigns/{campaign}/contact/{contact}/{action}", operation=operation)

    def add_contact_to_campaign(self, campaign_id, contact_id) -> None:
        self._campaign_contact_bridge("add", campaign_id, contact_id, CAMPAIGN_CONTACT_ADD)

    def remove_contact_from_campaign(self, campaign_id, contact_id) -> None:
        self._campaign_contact_bridge("remove", campaign_id, contact_id, CAMPAIGN_CONTACT_REMOVE)

    def merge_contacts(self, contact_id, other_contact_id) -> dict[str, Any]:
        """Merge ``other_contact_id`` into ``contact_id`` (the Mautic UI's Merge button).

        Mautic deletes the other contact afterwards. Asserted user only: there is
        no REST endpoint for a manual merge and no service-account fallback."""
        if not self._uses_asserted_user():
            raise MauticIdentityConfigurationError("Mautic contact merges require per-user Mautic identity")
        contact = self._numeric_id(contact_id, "contact")
        other = self._numeric_id(other_contact_id, "contact")
        response = self._bridge_request("POST", f"ecp/bridge/contacts/{contact}/merge/{other}", operation=CONTACT_MERGE)
        return self._json_object(response, "Mautic contact merge")

    # Reports -------------------------------------------------------------------
    # Reads are the bridge's metadata/definition/data endpoints (service user);
    # writes are forwarded by the bridge to the native v1 report API as the
    # asserted user, so Mautic's own form validates every column and filter.

    def list_report_sources(self) -> list[dict[str, Any]]:
        data = self._json_object(self._request("GET", "ecp/reports/sources"), "Mautic report sources")
        rows = data.get("sources")
        if not isinstance(rows, list):
            raise TemporaryMauticError("Mautic report sources returned an invalid response")
        return [row for row in rows if isinstance(row, dict) and row.get("source")]

    def get_report_source(self, source: str) -> dict[str, Any]:
        normalized = str(source or "").strip()
        if not normalized or not all(ch.isalnum() or ch in "._" for ch in normalized):
            raise PermanentMauticError("Mautic report source is invalid")
        data = self._json_object(self._request("GET", f"ecp/reports/sources/{normalized}"), "Mautic report source")
        if not isinstance(data.get("columns"), list):
            raise TemporaryMauticError("Mautic report source returned an invalid response")
        return data

    def list_reports(self) -> list[dict[str, Any]]:
        data = self._json_object(self._request("GET", "ecp/reports"), "Mautic report list")
        rows = data.get("reports")
        if not isinstance(rows, list):
            raise TemporaryMauticError("Mautic report list returned an invalid response")
        return [row for row in rows if isinstance(row, dict) and row.get("id") is not None]

    def get_report(self, report_id) -> dict[str, Any]:
        report = self._numeric_id(report_id, "report")
        return self._report_from(self._request("GET", f"ecp/reports/{report}"), "Mautic report lookup")

    def get_report_data(self, report_id, *, timeout=None, **params) -> dict[str, Any]:
        report = self._numeric_id(report_id, "report")
        data = self._json_object(
            self._request("GET", f"ecp/reports/{report}/data", params=params or None, timeout=timeout),
            "Mautic report data",
        )
        if not isinstance(data.get("rows"), list) or not isinstance(data.get("columns"), list):
            raise TemporaryMauticError("Mautic report data returned an invalid response")
        return data

    def _require_asserted_reports(self) -> None:
        # Saved reports are attributed to a human Mautic user or not changed at
        # all: there is deliberately no service-account fallback.
        if not self._uses_asserted_user():
            raise MauticIdentityConfigurationError("Mautic report changes require per-user Mautic identity")

    def create_report(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_asserted_reports()
        response = self._bridge_request("POST", "ecp/bridge/reports/new", operation=REPORT_CREATE, json=payload)
        return self._report_from(response, "Mautic report creation")

    def update_report(self, report_id, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_asserted_reports()
        report = self._numeric_id(report_id, "report")
        response = self._bridge_request("PATCH", f"ecp/bridge/reports/{report}/edit", operation=REPORT_UPDATE, json=payload)
        return self._report_from(response, "Mautic report update")

    def delete_report(self, report_id) -> None:
        self._require_asserted_reports()
        report = self._numeric_id(report_id, "report")
        self._bridge_request("DELETE", f"ecp/bridge/reports/{report}/delete", operation=REPORT_DELETE)

    def _report_from(self, response, context: str) -> dict[str, Any]:
        report = self._json_object(response, context).get("report")
        if not isinstance(report, dict) or report.get("id") is None:
            raise TemporaryMauticError(f"{context} returned an invalid response")
        return report

    def list_users(self, **params) -> dict[str, Any]:
        data = self._json_object(self._request("GET", "users", params=params or None), "Mautic user list")
        if not isinstance(data.get("users"), (dict, list)):
            raise TemporaryMauticError("Mautic user list returned an invalid response")
        return data

    def get_campaign(self, campaign_id: int | str) -> dict[str, Any]:
        campaign_id = str(campaign_id or "").strip()
        if not campaign_id:
            raise PermanentMauticError("Mautic campaign ID is required")
        response = self._request("GET", f"campaigns/{campaign_id}")
        return self._campaign_from_response(response, "Mautic campaign lookup")

    def create_campaign(self, payload: dict[str, Any]) -> dict[str, Any]:
        data = self._campaign_form_data(payload)
        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                "ecp/bridge/campaigns/new",
                operation=CAMPAIGN_CREATE,
                data=data,
            )
        else:
            response = self._request("POST", "campaigns/new", data=data)
        return self._campaign_from_response(response, "Mautic campaign creation")

    def update_campaign(
        self,
        campaign_id: int | str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        campaign_id = str(campaign_id or "").strip()
        if not campaign_id:
            raise PermanentMauticError("Mautic campaign ID is required")
        data = self._campaign_form_data(payload)
        if self._uses_asserted_user():
            response = self._bridge_request(
                "PATCH",
                f"ecp/bridge/campaigns/{campaign_id}/edit",
                operation=CAMPAIGN_UPDATE,
                data=data,
            )
        else:
            response = self._request(
                "PATCH",
                f"campaigns/{campaign_id}/edit",
                data=data,
            )
        return self._campaign_from_response(response, "Mautic campaign update")

    def delete_campaign(self, campaign_id: int | str) -> dict[str, Any]:
        campaign_id = str(campaign_id or "").strip()
        if not campaign_id:
            raise PermanentMauticError("Mautic campaign ID is required")
        if self._uses_asserted_user():
            response = self._bridge_request(
                "DELETE",
                f"ecp/bridge/campaigns/{campaign_id}/delete",
                operation=CAMPAIGN_DELETE,
            )
        else:
            response = self._request(
                "DELETE",
                f"campaigns/{campaign_id}/delete",
            )
        return self._campaign_from_response(
            response,
            "Mautic campaign deletion",
            require_id=False,
        )

    @staticmethod
    def _stage_from_response(
        response,
        context: str,
        *,
        require_id: bool = True,
    ) -> dict[str, Any]:
        data = MauticClient._json_object(response, context)
        stage = data.get("stage")
        if not isinstance(stage, dict) or (require_id and not stage.get("id")):
            raise TemporaryMauticError(f"{context} returned an invalid response")
        return stage

    def list_stages(self, **params) -> dict[str, Any]:
        response = self._request("GET", "stages", params=params or None)
        data = self._json_object(response, "Mautic stage list")
        stages = data.get("stages")
        if not isinstance(stages, (dict, list)):
            raise TemporaryMauticError(
                "Mautic stage list returned an invalid response"
            )
        return data

    def get_stage(self, stage_id: int | str) -> dict[str, Any]:
        stage_id = str(stage_id or "").strip()
        if not stage_id:
            raise PermanentMauticError("Mautic stage ID is required")

        response = self._request("GET", f"stages/{stage_id}")
        return self._stage_from_response(response, "Mautic stage lookup")

    def create_stage(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                "ecp/bridge/stages/new",
                operation=STAGE_CREATE,
                data=payload,
            )
            return self._stage_from_response(response, "Mautic stage creation")
        response = self._request("POST", "stages/new", data=payload)
        return self._stage_from_response(response, "Mautic stage creation")

    def update_stage(
        self,
        stage_id: int | str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        stage_id = str(stage_id or "").strip()
        if not stage_id:
            raise PermanentMauticError("Mautic stage ID is required")

        if self._uses_asserted_user():
            response = self._bridge_request(
                "PATCH",
                f"ecp/bridge/stages/{stage_id}/edit",
                operation=STAGE_UPDATE,
                data=payload,
            )
            return self._stage_from_response(response, "Mautic stage update")
        response = self._request(
            "PATCH",
            f"stages/{stage_id}/edit",
            data=payload,
        )
        return self._stage_from_response(response, "Mautic stage update")

    def delete_stage(self, stage_id: int | str) -> dict[str, Any]:
        stage_id = str(stage_id or "").strip()
        if not stage_id:
            raise PermanentMauticError("Mautic stage ID is required")

        if self._uses_asserted_user():
            response = self._bridge_request(
                "DELETE",
                f"ecp/bridge/stages/{stage_id}/delete",
                operation=STAGE_DELETE,
            )
        else:
            response = self._request("DELETE", f"stages/{stage_id}/delete")
        return self._stage_from_response(
            response,
            "Mautic stage deletion",
            require_id=False,
        )

    def add_contact_to_stage(
        self,
        stage_id: int | str,
        contact_id: int | str,
    ) -> None:
        stage_id = str(stage_id or "").strip()
        contact_id = str(contact_id or "").strip()
        if not stage_id or not contact_id:
            raise PermanentMauticError(
                "Mautic stage ID and contact ID are required"
            )
        if self._uses_asserted_user():
            self._bridge_request(
                "POST",
                f"ecp/bridge/stages/{stage_id}/contact/{contact_id}/add",
                operation=STAGE_CONTACT_ADD,
            )
            return
        self._request(
            "POST",
            f"stages/{stage_id}/contact/{contact_id}/add",
        )

    def remove_contact_from_stage(
        self,
        stage_id: int | str,
        contact_id: int | str,
    ) -> None:
        stage_id = str(stage_id or "").strip()
        contact_id = str(contact_id or "").strip()
        if not stage_id or not contact_id:
            raise PermanentMauticError(
                "Mautic stage ID and contact ID are required"
            )
        if self._uses_asserted_user():
            self._bridge_request(
                "POST",
                f"ecp/bridge/stages/{stage_id}/contact/{contact_id}/remove",
                operation=STAGE_CONTACT_REMOVE,
            )
            return
        self._request(
            "POST",
            f"stages/{stage_id}/contact/{contact_id}/remove",
        )
    @staticmethod
    def _segment_from_response(
        response,
        context: str,
        *,
        require_id: bool = True,
    ) -> dict[str, Any]:
        data = MauticClient._json_object(response, context)
        # Key presence, not truthiness: a delete can legitimately answer with an
        # empty entity, which an `or` chain would skip straight past.
        segment = data["list"] if "list" in data else data.get("segment")
        if not isinstance(segment, dict) or (require_id and not segment.get("id")):
            raise TemporaryMauticError(f"{context} returned an invalid response")
        return segment

    def list_segments(self, **params) -> dict[str, Any]:
        response = self._request("GET", "segments", params=params or None)
        data = self._json_object(response, "Mautic segment list")
        if "lists" in data:
            segments = data["lists"]
        elif "segments" in data:
            segments = data["segments"]
        else:
            raise TemporaryMauticError(
                "Mautic segment list returned an invalid response"
            )
        if not isinstance(segments, (dict, list)):
            raise TemporaryMauticError("Mautic segment list returned an invalid response")
        return data

    def list_forms(self, **params) -> dict[str, Any]:
        response = self._request("GET", "forms", params=params or None)
        data = self._json_object(response, "Mautic form list")
        forms = data.get("forms")
        if not isinstance(forms, (dict, list)):
            raise TemporaryMauticError("Mautic form list returned an invalid response")
        return data

    @staticmethod
    def _form_from_response(response, context: str) -> dict[str, Any]:
        form = MauticClient._json_object(response, context).get("form")
        if not isinstance(form, dict) or not form.get("id"):
            raise TemporaryMauticError(f"{context} returned an invalid response")
        return form

    def get_form(self, form_id) -> dict[str, Any]:
        normalized = str(form_id or "").strip()
        if not normalized.isdigit():
            raise PermanentMauticError("Mautic form id must be numeric")
        response = self._request("GET", f"forms/{normalized}")
        return self._form_from_response(response, "Mautic form detail")

    def _form_bridge_request(self, method: str, path: str, *, operation: str, context: str, **kwargs):
        # Form writes are attributed to a human Mautic user or not made at
        # all: there is deliberately no service-account fallback.
        if not self._uses_asserted_user():
            raise MauticIdentityConfigurationError(
                "Mautic Form changes require per-user Mautic identity"
            )
        response = self._bridge_request(method, path, operation=operation, **kwargs)
        return self._form_from_response(response, context)

    def create_form(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Create an unpublished Form from basic settings only (the bridge
        refuses fields, actions and publication)."""
        if not isinstance(payload, dict) or not payload.get("name"):
            raise PermanentMauticError("Mautic form name is required")
        return self._form_bridge_request(
            "POST",
            "ecp/bridge/forms/new",
            operation=FORM_CREATE,
            context="Mautic form creation",
            data=self._email_form_data(payload),
        )

    def update_form(self, form_id, payload: dict[str, Any]) -> dict[str, Any]:
        """Partially update a Form's basic settings (native PATCH semantics:
        fields and actions are never sent, so they are left untouched)."""
        normalized = str(form_id or "").strip()
        if not normalized.isdigit():
            raise PermanentMauticError("Mautic form id must be numeric")
        if not isinstance(payload, dict) or not payload:
            raise PermanentMauticError("Mautic form update payload is required")
        return self._form_bridge_request(
            "PATCH",
            f"ecp/bridge/forms/{normalized}/edit",
            operation=FORM_UPDATE,
            context="Mautic form update",
            data=self._email_form_data(payload),
        )

    @staticmethod
    def _numeric_id(value, label: str) -> str:
        normalized = str(value or "").strip()
        if not normalized.isdigit():
            raise PermanentMauticError(f"Mautic {label} id must be numeric")
        return normalized

    def create_form_field(self, form_id, field: dict[str, Any], position: int | None = None) -> dict[str, Any]:
        """Add one field. The bridge re-sends every existing field so their
        order and settings stay as they are."""
        form = self._numeric_id(form_id, "form")
        body: dict[str, Any] = {"field": field}
        if position is not None:
            body["position"] = int(position)
        return self._form_bridge_request(
            "POST", f"ecp/bridge/forms/{form}/fields/new",
            operation=FORM_FIELD_CREATE, context="Mautic form field creation", json=body,
        )

    def update_form_field(self, form_id, field_id, changes: dict[str, Any]) -> dict[str, Any]:
        form = self._numeric_id(form_id, "form")
        field = self._numeric_id(field_id, "form field")
        return self._form_bridge_request(
            "PATCH", f"ecp/bridge/forms/{form}/fields/{field}/edit",
            operation=FORM_FIELD_UPDATE, context="Mautic form field update", json={"field": changes},
        )

    def reorder_form_fields(self, form_id, order: list) -> dict[str, Any]:
        form = self._numeric_id(form_id, "form")
        return self._form_bridge_request(
            "POST", f"ecp/bridge/forms/{form}/fields/reorder",
            operation=FORM_FIELD_REORDER, context="Mautic form field reorder",
            json={"order": [int(self._numeric_id(item, "form field")) for item in order]},
        )

    def create_form_action(self, form_id, action: dict[str, Any], position: int | None = None) -> dict[str, Any]:
        """Add one submit action; the bridge re-sends every existing action."""
        form = self._numeric_id(form_id, "form")
        body: dict[str, Any] = {"action": action}
        if position is not None:
            body["position"] = int(position)
        return self._form_bridge_request(
            "POST", f"ecp/bridge/forms/{form}/actions/new",
            operation=FORM_ACTION_CREATE, context="Mautic form action creation", json=body,
        )

    def update_form_action(self, form_id, action_id, changes: dict[str, Any]) -> dict[str, Any]:
        form = self._numeric_id(form_id, "form")
        action = self._numeric_id(action_id, "form action")
        return self._form_bridge_request(
            "PATCH", f"ecp/bridge/forms/{form}/actions/{action}/edit",
            operation=FORM_ACTION_UPDATE, context="Mautic form action update", json={"action": changes},
        )

    def reorder_form_actions(self, form_id, order: list) -> dict[str, Any]:
        form = self._numeric_id(form_id, "form")
        return self._form_bridge_request(
            "POST", f"ecp/bridge/forms/{form}/actions/reorder",
            operation=FORM_ACTION_REORDER, context="Mautic form action reorder",
            json={"order": [int(self._numeric_id(item, "form action")) for item in order]},
        )

    def get_form_usage(self, form_id, *, timeout=None) -> dict[str, Any]:
        """Read-only: Campaigns and point actions that reference the Form, and
        its stored submission count (no contact data)."""
        form = self._numeric_id(form_id, "form")
        response = self._request("GET", f"ecp/bridge/forms/{form}/usage", timeout=timeout)
        usage = self._json_object(response, "Mautic form usage").get("usage")
        if not isinstance(usage, dict):
            raise TemporaryMauticError("Mautic form usage returned an invalid response")
        return usage

    def list_form_submissions(self, form_id, *, start: int = 0, limit: int = 25, timeout=None) -> dict[str, Any]:
        form = self._numeric_id(form_id, "form")
        response = self._request(
            "GET", f"forms/{form}/submissions",
            params={"start": int(start), "limit": int(limit), "orderBy": "s.id", "orderByDir": "DESC"},
            timeout=timeout,
        )
        data = self._json_object(response, "Mautic form submissions")
        if not isinstance(data.get("submissions"), (list, dict)):
            raise TemporaryMauticError("Mautic form submissions returned an invalid response")
        return data

    def get_form_submission(self, form_id, submission_id, *, timeout=None) -> dict[str, Any]:
        form = self._numeric_id(form_id, "form")
        submission = self._numeric_id(submission_id, "form submission")
        response = self._request("GET", f"forms/{form}/submissions/{submission}", timeout=timeout)
        data = self._json_object(response, "Mautic form submission").get("submission")
        if not isinstance(data, dict) or not data.get("id"):
            raise TemporaryMauticError("Mautic form submission returned an invalid response")
        return data

    def set_form_published(self, form_id, published: bool) -> dict[str, Any]:
        normalized = str(form_id or "").strip()
        if not normalized.isdigit():
            raise PermanentMauticError("Mautic form id must be numeric")
        action = "publish" if published else "unpublish"
        return self._form_bridge_request(
            "POST",
            f"ecp/bridge/forms/{normalized}/{action}",
            operation=FORM_PUBLISH if published else FORM_UNPUBLISH,
            context=f"Mautic form {action}",
        )

    def delete_form(self, form_id) -> dict[str, Any]:
        """Delete a Form as the acting admin. Mautic's own delete permissions
        (own/other, against Created by) decide; the bridge refuses a Form a
        Campaign uses. Mautic keeps the Form's stored submissions."""
        form = self._numeric_id(form_id, "form")
        if not self._uses_asserted_user():
            raise MauticIdentityConfigurationError(
                "Mautic Form changes require per-user Mautic identity"
            )
        response = self._bridge_request("DELETE", f"ecp/bridge/forms/{form}/delete", operation=FORM_DELETE)
        # The native delete returns the removed Form without its id.
        deleted = self._json_object(response, "Mautic form deletion").get("form")
        if not isinstance(deleted, dict):
            raise TemporaryMauticError("Mautic form deletion returned an invalid response")
        return deleted

    # Landing pages ------------------------------------------------------------

    def list_pages(self, **params) -> dict[str, Any]:
        response = self._request("GET", "pages", params=params or None)
        data = self._json_object(response, "Mautic page list")
        if not isinstance(data.get("pages"), (dict, list)):
            raise TemporaryMauticError("Mautic page list returned an invalid response")
        return data

    @staticmethod
    def _page_from_response(response, context: str, *, require_id: bool = True) -> dict[str, Any]:
        page = MauticClient._json_object(response, context).get("page")
        if not isinstance(page, dict) or (require_id and not page.get("id")):
            raise TemporaryMauticError(f"{context} returned an invalid response")
        return page

    def get_page(self, page_id) -> dict[str, Any]:
        page = self._numeric_id(page_id, "page")
        response = self._request("GET", f"pages/{page}")
        return self._page_from_response(response, "Mautic page detail")

    def _page_bridge_request(self, method: str, path: str, *, operation: str, context: str, **kwargs):
        # Page writes are attributed to a human Mautic user or not made at
        # all: there is deliberately no service-account fallback.
        if not self._uses_asserted_user():
            raise MauticIdentityConfigurationError(
                "Mautic landing page changes require per-user Mautic identity"
            )
        response = self._bridge_request(method, path, operation=operation, **kwargs)
        return self._page_from_response(response, context, require_id=method != "DELETE")

    def create_page(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Create an unpublished landing page (the bridge refuses scripts and
        preference-center pages)."""
        if not isinstance(payload, dict) or not payload.get("title"):
            raise PermanentMauticError("Mautic page title is required")
        return self._page_bridge_request(
            "POST",
            "ecp/bridge/pages/new",
            operation=PAGE_CREATE,
            context="Mautic page creation",
            data=self._email_form_data(payload),
        )

    def update_page(self, page_id, payload: dict[str, Any]) -> dict[str, Any]:
        """Partially update a landing page (native PATCH semantics)."""
        page = self._numeric_id(page_id, "page")
        if not isinstance(payload, dict) or not payload:
            raise PermanentMauticError("Mautic page update payload is required")
        return self._page_bridge_request(
            "PATCH",
            f"ecp/bridge/pages/{page}/edit",
            operation=PAGE_UPDATE,
            context="Mautic page update",
            data=self._email_form_data(payload),
        )

    def duplicate_page(self, page_id, *, title: str | None = None) -> dict[str, Any]:
        page = self._numeric_id(page_id, "page")
        return self._page_bridge_request(
            "POST",
            f"ecp/bridge/pages/{page}/duplicate",
            operation=PAGE_DUPLICATE,
            context="Mautic page duplicate",
            data={"title": title} if title else {},
        )

    def delete_page(self, page_id) -> dict[str, Any]:
        """Delete as the acting admin. Mautic's own delete permissions decide;
        the bridge refuses a page that Campaigns or preference-center Emails
        name, or that has variants or translations."""
        page = self._numeric_id(page_id, "page")
        # The native delete returns the removed page without its id.
        return self._page_bridge_request(
            "DELETE",
            f"ecp/bridge/pages/{page}/delete",
            operation=PAGE_DELETE,
            context="Mautic page deletion",
        )

    def create_page_variant(self, page_id, *, weight: int, winner_criteria: str, title: str | None = None) -> dict[str, Any]:
        """Add an unpublished A/B variant (a copy of the main page's content)."""
        page = self._numeric_id(page_id, "page")
        data = {"weight": int(weight), "winnerCriteria": winner_criteria}
        if title:
            data["title"] = title
        return self._page_bridge_request(
            "POST", f"ecp/bridge/pages/{page}/variants/new", operation=PAGE_VARIANT_CREATE, context="Mautic page variant creation", data=data
        )

    def update_page_variant(self, page_id, *, weight: int | None = None, winner_criteria: str | None = None) -> dict[str, Any]:
        """Change a variant's weight and/or the whole test's winner criteria."""
        page = self._numeric_id(page_id, "page")
        data: dict[str, Any] = {}
        if weight is not None:
            data["weight"] = int(weight)
        if winner_criteria is not None:
            data["winnerCriteria"] = winner_criteria
        if not data:
            raise PermanentMauticError("Mautic page variant update payload is required")
        return self._page_bridge_request(
            "PATCH", f"ecp/bridge/pages/{page}/variant/edit", operation=PAGE_VARIANT_UPDATE, context="Mautic page variant update", data=data
        )

    def make_page_variant_winner(self, page_id) -> dict[str, Any]:
        """Make a variant the main page (Mautic's own conversion)."""
        page = self._numeric_id(page_id, "page")
        return self._page_bridge_request(
            "POST", f"ecp/bridge/pages/{page}/winner", operation=PAGE_VARIANT_WINNER, context="Mautic page variant winner"
        )

    def create_page_translation(self, page_id, *, language: str, title: str | None = None) -> dict[str, Any]:
        """Add an unpublished translation (a copy of the main page in another language)."""
        page = self._numeric_id(page_id, "page")
        data = {"language": language}
        if title:
            data["title"] = title
        return self._page_bridge_request(
            "POST", f"ecp/bridge/pages/{page}/translations/new", operation=PAGE_TRANSLATION_CREATE,
            context="Mautic page translation creation", data=data,
        )

    def get_page_abtest(self, page_id, *, timeout=None) -> dict[str, Any]:
        page = self._numeric_id(page_id, "page")
        response = self._request("GET", f"ecp/bridge/pages/{page}/abtest", timeout=timeout)
        test = self._json_object(response, "Mautic page A/B test").get("abTest")
        if not isinstance(test, dict) or not isinstance(test.get("versions"), list):
            raise TemporaryMauticError("Mautic page A/B test returned an invalid response")
        return test

    def get_page_usage(self, page_id, *, timeout=None) -> dict[str, Any]:
        page = self._numeric_id(page_id, "page")
        response = self._request("GET", f"ecp/bridge/pages/{page}/usage", timeout=timeout)
        usage = self._json_object(response, "Mautic page usage").get("usage")
        if not isinstance(usage, dict):
            raise TemporaryMauticError("Mautic page usage returned an invalid response")
        return usage

    def get_campaign_builder_capabilities(self) -> dict[str, Any]:
        response = self._request("GET", "ecp/campaign-builder/capabilities")
        data = self._json_object(
            response,
            "Mautic campaign builder capabilities",
        )
        for field in ("actions", "conditions", "decisions"):
            if not isinstance(data.get(field), list):
                raise TemporaryMauticError(
                    "Mautic campaign builder capabilities returned "
                    f"invalid {field}"
                )
        connection_restrictions = data.get("connectionRestrictions", {})
        if not isinstance(connection_restrictions, dict):
            raise TemporaryMauticError(
                "Mautic campaign builder capabilities returned invalid "
                "connectionRestrictions"
            )
        return data

    def get_campaign_builder_event_field_choices(
        self,
        *,
        event_type: str,
        key: str,
        field: str,
        search: str = "",
        start: int = 0,
        limit: int = 50,
        values: list[str] | None = None,
    ) -> dict[str, Any]:
        """Resolve one campaign event field's choices from the provider on demand.

        Large provider choice lists are no longer inlined into the capabilities
        response, and only the event's own Symfony form can resolve them, so the
        campaign builder bridge serves a filtered, paged slice of that same form.
        """
        event_type = str(event_type or "").strip()
        key = str(key or "").strip()
        field = str(field or "").strip()
        if not event_type or not key or not field:
            raise PermanentMauticError(
                "Mautic campaign event field choices require an event type, key and field"
            )

        params: list[tuple[str, Any]] = [
            ("eventType", event_type),
            ("key", key),
            ("field", field),
        ]
        for value in values or []:
            params.append(("values[]", str(value)))
        if not values:
            if search:
                params.append(("search", search))
            params.append(("start", max(0, int(start))))
            params.append(("limit", max(1, int(limit))))

        response = self._request(
            "GET",
            "ecp/campaign-builder/choices",
            params=params,
        )
        data = self._json_object(response, "Mautic campaign event field choices")
        if not isinstance(data.get("choices"), list):
            raise TemporaryMauticError(
                "Mautic campaign event field choices returned invalid choices"
            )
        return data

    def get_campaign_event_states(self, campaign_id: int | str) -> dict[str, Any]:
        """Read which of a campaign's events Mautic still considers active.

        Mautic deletes campaign events by stamping them `deleted`, and the official
        campaign endpoint serializes the raw events association: soft-deleted events
        are still returned and the `deleted` field is not exposed at all, so active
        and deleted events are indistinguishable over official REST.
        """
        campaign_id = str(campaign_id or "").strip()
        if not campaign_id:
            raise PermanentMauticError("Mautic campaign ID is required")

        response = self._request(
            "GET",
            f"ecp/campaign-builder/campaigns/{campaign_id}/events",
        )
        data = self._json_object(response, "Mautic campaign event states")
        if not isinstance(data.get("activeEventIds"), list):
            raise TemporaryMauticError(
                "Mautic campaign event states returned invalid activeEventIds"
            )
        return data

    def get_consent_step(
        self, campaign_id: int, event_id: int, merged_ids: list[int]
    ) -> dict[str, Any] | None:
        """One Campaign step as the bridge plugin reads it now, for consent
        decisions: the Campaign's Form sources, its active events, the step's
        Email category and how Mautic resolves each merged contact id.

        ``None`` when the plugin predates this endpoint (Mautic answers 404 for
        the route; the endpoint itself reports a missing Campaign as
        ``{"campaign": null}``), so callers can read the same facts the long way.
        """
        try:
            response = self._request(
                "POST",
                f"ecp/consent/campaigns/{int(campaign_id)}/events/{int(event_id)}",
                json={"merged_ids": [int(m) for m in merged_ids]},
            )
        except PermanentMauticError as exc:
            if "HTTP 404" in str(exc):
                return None
            raise
        data = self._json_object(response, "Mautic consent step")
        campaign, events, email, merged = (data.get(key) for key in ("campaign", "events", "email", "merged"))
        valid_id = lambda value: isinstance(value, int) and not isinstance(value, bool) and value > 0  # noqa: E731
        if (
            not (campaign is None or (isinstance(campaign, dict) and isinstance(campaign.get("forms"), list)))
            or not isinstance(events, list)
            or not all(isinstance(event, dict) and valid_id(event.get("id")) for event in events)
            or not (email is None or isinstance(email, dict))
            or not isinstance(merged, dict)
            # Every merge claim asked about is answered, with a contact id or null.
            or set(merged) != {str(int(m)) for m in merged_ids}
            or not all(value is None or valid_id(value) for value in merged.values())
        ):
            raise TemporaryMauticError("Mautic consent step returned an invalid response")
        return data

    def delete_campaign_event(
        self,
        campaign_id: int | str,
        event_id: int | str,
    ) -> dict[str, Any]:
        """Delete one campaign workflow event through the campaign builder bridge.

        Official REST exposes campaign events read-only, and omitting an event from
        a campaign update does not remove it, so deletion goes through the bridge
        that drives Mautic's own campaign event deletion.
        """
        campaign_id = str(campaign_id or "").strip()
        event_id = str(event_id or "").strip()
        if not campaign_id or not event_id:
            raise PermanentMauticError(
                "Mautic campaign ID and event ID are required"
            )

        if self._uses_asserted_user():
            response = self._bridge_request(
                "DELETE",
                f"ecp/campaign-builder/campaigns/{campaign_id}/events/{event_id}",
                operation=CAMPAIGN_EVENT_DELETE,
            )
        else:
            response = self._request(
                "DELETE",
                f"ecp/campaign-builder/campaigns/{campaign_id}/events/{event_id}",
            )
        return self._json_object(response, "Mautic campaign event deletion")

    def get_segment_filter_metadata(self, search: str = "") -> dict[str, Any]:
        """Read the metadata Mautic's own segment builder uses for a filter row.

        Official REST publishes contact and company fields and accepts filters on
        write, but nothing exposes which operators a field accepts, which value
        control it needs, or the behavioural filters that are not contact fields at
        all. That comes from ListModel::getChoiceFields() via the bridge.
        """
        params = {"search": search} if search else None
        response = self._request(
            "GET",
            "ecp/segments/filter-metadata",
            params=params,
        )
        data = self._json_object(response, "Mautic segment filter metadata")
        if not isinstance(data.get("fields"), list) or not isinstance(
            data.get("operators"), list
        ):
            raise TemporaryMauticError(
                "Mautic segment filter metadata returned an invalid response"
            )
        return data

    def get_marketing_bridge_capabilities(self) -> dict[str, Any]:
        response = self._request("GET", "ecp/capabilities")
        data = self._json_object(response, "Mautic marketing bridge capabilities")
        capabilities = data.get("capabilities")
        if not isinstance(capabilities, list):
            raise TemporaryMauticError(
                "Mautic marketing bridge capabilities returned invalid capabilities"
            )
        return data

    def get_background_health(self, timeout=None) -> dict[str, Any]:
        """Read-only cron run records and messenger backlog from the ECP bridge.

        ``timeout`` lets diagnostics use a shorter budget than ordinary calls.
        """
        response = self._request("GET", "ecp/background-health", timeout=timeout)
        data = self._json_object(response, "Mautic background health")
        if not isinstance(data.get("cron"), dict) or not isinstance(data.get("messenger"), dict):
            raise TemporaryMauticError("Mautic background health returned an invalid report")
        return data

    def list_webhooks(self, *, timeout=None) -> list[dict[str, Any]]:
        """Native Mautic webhooks (``GET /api/hooks``), read-only."""
        response = self._request("GET", "hooks", params={"limit": 200}, timeout=timeout)
        data = self._json_object(response, "Mautic webhook list")
        hooks = data.get("hooks")
        if isinstance(hooks, dict):
            hooks = list(hooks.values())
        if not isinstance(hooks, list):
            raise TemporaryMauticError("Mautic webhook list returned an invalid response")
        return [hook for hook in hooks if isinstance(hook, dict)]

    def get_email_send_evidence(
        self, email_id: int | str, *, since=None, due_before=None, timeout=None
    ) -> dict[str, Any]:
        """Read-only send evidence for one segment email from the ECP bridge:
        stats (split at ``since``), Mautic's own pending count for members
        who joined its segments before ``due_before`` (default ``since``), and
        queued messages."""
        email_id = str(email_id or "").strip()
        if not email_id:
            raise PermanentMauticError("Mautic email ID is required")
        params = {}
        for name, moment in (("since", since), ("due_before", due_before)):
            if moment is not None:
                params[name] = moment.astimezone(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        response = self._request(
            "GET", f"ecp/emails/{email_id}/send-evidence", params=params or None, timeout=timeout
        )
        data = self._json_object(response, "Mautic email send evidence")
        if not isinstance(data.get("email"), dict) or not isinstance(data.get("stats"), dict):
            raise TemporaryMauticError("Mautic email send evidence returned an invalid report")
        return data

    def get_field_type_capabilities(self) -> dict[str, Any]:
        """Read the supported custom-field type registry from the ECP bridge plugin.

        Official Mautic REST exposes existing field definitions but not the registry of
        field types Mautic will accept for a new field, so this comes from the bridge.
        """
        response = self._request("GET", "ecp/fields/types")
        data = self._json_object(response, "Mautic field type capabilities")
        types = data.get("types")
        if not isinstance(types, list):
            raise TemporaryMauticError(
                "Mautic field type capabilities returned invalid types"
            )
        return data

    def get_field_type_choices(self, field_type: str) -> dict[str, Any]:
        """Read a Mautic reference option list (country/region/timezone/locale).

        These lists live in Mautic's bundled reference data rather than in a field's
        properties, so they are served by the ECP bridge plugin.
        """
        field_type = str(field_type or "").strip().lower()
        if field_type not in {"country", "region", "timezone", "locale"}:
            raise PermanentMauticError(
                "Mautic reference choices are only available for "
                "country, region, timezone, and locale fields"
            )
        response = self._request("GET", f"ecp/fields/choices/{field_type}")
        data = self._json_object(response, "Mautic field choices")
        if not isinstance(data.get("choices"), list):
            raise TemporaryMauticError("Mautic field choices returned invalid choices")
        return data

    def get_segment(self, segment_id: int | str) -> dict[str, Any]:
        segment_id = str(segment_id or "").strip()
        if not segment_id:
            raise PermanentMauticError("Mautic segment ID is required")

        response = self._request("GET", f"segments/{segment_id}")
        return self._segment_from_response(response, "Mautic segment lookup")

    def list_segment_contacts_via_bridge(
        self,
        segment_id: int | str,
        **params,
    ) -> dict[str, Any]:
        segment_id = str(segment_id or "").strip()
        if not segment_id:
            raise PermanentMauticError("Mautic segment ID is required")

        response = self._request(
            "GET",
            f"ecp/segments/{segment_id}/contacts",
            params=params or None,
        )
        data = self._json_object(response, "Mautic segment contacts bridge")
        contacts = data.get("contacts")
        if not isinstance(contacts, (dict, list)):
            raise TemporaryMauticError(
                "Mautic segment contacts bridge returned invalid contacts"
            )
        return data

    def get_segment_count_via_bridge(self, segment_id: int | str) -> dict[str, Any]:
        segment_id = str(segment_id or "").strip()
        if not segment_id:
            raise PermanentMauticError("Mautic segment ID is required")

        response = self._request("GET", f"ecp/segments/{segment_id}/count")
        data = self._json_object(response, "Mautic segment count bridge")
        if "total" not in data and "active" not in data:
            raise TemporaryMauticError(
                "Mautic segment count bridge returned an invalid response"
            )
        return data

    @staticmethod
    def _segment_form_data(payload: dict[str, Any]) -> list[tuple[str, Any]]:
        """Encode a segment payload the way Symfony reads it.

        A segment's filters are a list of objects, and plain form encoding flattens
        those into unusable values — Mautic answers "filters: The collection is
        invalid". The bracket encoding is the same one campaigns use.
        """
        if not isinstance(payload, dict) or not payload:
            raise PermanentMauticError("Mautic segment payload is required")

        return MauticClient._campaign_form_data(payload)

    def create_segment(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                "ecp/bridge/segments/new",
                operation=SEGMENT_CREATE,
                data=self._segment_form_data(payload),
            )
        else:
            response = self._request(
                "POST",
                "segments/new",
                data=self._segment_form_data(payload),
            )
        return self._segment_from_response(response, "Mautic segment creation")

    def update_segment(
        self,
        segment_id: int | str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        segment_id = str(segment_id or "").strip()
        if not segment_id:
            raise PermanentMauticError("Mautic segment ID is required")

        if self._uses_asserted_user():
            response = self._bridge_request(
                "PATCH",
                f"ecp/bridge/segments/{segment_id}/edit",
                operation=SEGMENT_UPDATE,
                data=self._segment_form_data(payload),
            )
        else:
            response = self._request(
                "PATCH",
                f"segments/{segment_id}/edit",
                data=self._segment_form_data(payload),
            )
        return self._segment_from_response(response, "Mautic segment update")

    def delete_segment(self, segment_id: int | str) -> dict[str, Any]:
        segment_id = str(segment_id or "").strip()
        if not segment_id:
            raise PermanentMauticError("Mautic segment ID is required")

        # Mautic answers a delete with HTTP 200 and the serialized entity whose id
        # Doctrine has already nulled, so an id is not part of the success
        # contract here — as with every other entity's delete in this client.
        if self._uses_asserted_user():
            response = self._bridge_request(
                "DELETE",
                f"ecp/bridge/segments/{segment_id}/delete",
                operation=SEGMENT_DELETE,
            )
        else:
            response = self._request("DELETE", f"segments/{segment_id}/delete")
        return self._segment_from_response(
            response,
            "Mautic segment deletion",
            require_id=False,
        )

    def send_email_to_contact(
        self,
        email_id: int | str,
        contact_id: int | str,
    ) -> dict[str, Any]:
        email_id = str(email_id or "").strip()
        contact_id = str(contact_id or "").strip()
        if not email_id or not contact_id:
            raise PermanentMauticError(
                "Mautic email ID and contact ID are required"
            )

        if self._uses_asserted_user():
            response = self._bridge_request(
                "POST",
                f"ecp/bridge/emails/{email_id}/contact/{contact_id}/send",
                operation=NEWSLETTER_TEST_SEND,
            )
        else:
            response = self._request(
                "POST",
                f"emails/{email_id}/contact/{contact_id}/send",
            )
        data = self._json_object(response, "Mautic single-contact email send")
        if not data.get("success"):
            raise TemporaryMauticError(
                "Mautic single-contact email send returned an unsuccessful response"
            )
        return data

    def send_email_to_segments(
        self,
        email_id: int | str,
        segment_ids: list[int | str] | tuple[int | str, ...],
    ) -> dict[str, Any]:
        email_id = str(email_id or "").strip()
        normalized_segment_ids = [
            str(segment_id or "").strip()
            for segment_id in (segment_ids or [])
            if str(segment_id or "").strip()
        ]
        if not email_id:
            raise PermanentMauticError("Mautic email ID is required")
        if not normalized_segment_ids:
            raise PermanentMauticError(
                "At least one Mautic segment ID is required"
            )

        # Mautic 7 passes request "lists" values directly into
        # EmailModel::sendEmailToLists(), which expects List entities and calls
        # getId() on each item. Supplying raw segment IDs therefore causes a
        # provider-side 500. The email is already synchronized with its target
        # segments before broadcast, so omit "lists" and let Mautic resolve the
        # attached List entities from the Email itself.
        response = self._request(
            "POST",
            f"emails/{email_id}/send",
        )
        data = self._json_object(response, "Mautic segment email send")
        if not data.get("success"):
            raise TemporaryMauticError(
                "Mautic segment email send returned an unsuccessful response"
            )
        return data

    def add_contact_to_segment(
        self,
        segment_id: int | str,
        contact_id: int | str,
    ) -> None:
        segment_id = str(segment_id or "").strip()
        contact_id = str(contact_id or "").strip()
        if not segment_id or not contact_id:
            raise PermanentMauticError(
                "Mautic segment ID and contact ID are required"
            )
        if self._uses_asserted_user():
            self._bridge_request(
                "POST",
                f"ecp/bridge/segments/{segment_id}/contact/{contact_id}/add",
                operation=SEGMENT_CONTACT_ADD,
            )
        else:
            self._request(
                "POST",
                f"segments/{segment_id}/contact/{contact_id}/add",
            )

    def remove_contact_from_segment(
        self,
        segment_id: int | str,
        contact_id: int | str,
    ) -> None:
        segment_id = str(segment_id or "").strip()
        contact_id = str(contact_id or "").strip()
        if not segment_id or not contact_id:
            raise PermanentMauticError(
                "Mautic segment ID and contact ID are required"
            )
        if self._uses_asserted_user():
            self._bridge_request(
                "POST",
                f"ecp/bridge/segments/{segment_id}/contact/{contact_id}/remove",
                operation=SEGMENT_CONTACT_REMOVE,
            )
        else:
            self._request(
                "POST",
                f"segments/{segment_id}/contact/{contact_id}/remove",
            )

    def add_contact_tag(self, contact_id: int | str, tag: str, current_tags: list[str]) -> dict[str, Any]:
        contact_id = str(contact_id or "").strip()
        if not contact_id:
            raise PermanentMauticError("Mautic contact ID is required")
        if self._uses_asserted_user():
            response = self._bridge_request(
                "PATCH",
                f"ecp/bridge/contacts/{contact_id}/tags/add",
                operation=CONTACT_TAG_ADD,
                data={"tags": current_tags},
            )
            data = self._json_object(response, "Mautic contact tag add")
            contact = data.get("contact")
            if not isinstance(contact, dict) or not contact.get("id"):
                raise TemporaryMauticError(
                    "Mautic contact tag add returned an invalid response"
                )
            return contact
        return self.update_contact(contact_id, {"tags": current_tags})

    def remove_contact_tag(self, contact_id: int | str, tag: str, current_tags: list[str]) -> dict[str, Any]:
        contact_id = str(contact_id or "").strip()
        if not contact_id:
            raise PermanentMauticError("Mautic contact ID is required")
        if self._uses_asserted_user():
            response = self._bridge_request(
                "PATCH",
                f"ecp/bridge/contacts/{contact_id}/tags/remove",
                operation=CONTACT_TAG_REMOVE,
                data={"tag": tag, "tags": current_tags},
            )
            data = self._json_object(response, "Mautic contact tag remove")
            contact = data.get("contact")
            if not isinstance(contact, dict) or not contact.get("id"):
                raise TemporaryMauticError(
                    "Mautic contact tag remove returned an invalid response"
                )
            return contact
        return self.update_contact(contact_id, {"tags": current_tags})
