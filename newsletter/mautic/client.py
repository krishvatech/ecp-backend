"""Small, testable Mautic REST API client.

This module performs only provider HTTP operations. It intentionally contains
no preference persistence, Celery dispatch, or synchronization orchestration.
Those responsibilities are added in later newsletter integration phases.
"""

from __future__ import annotations

from typing import Any

import requests
from django.conf import settings
from requests.auth import HTTPBasicAuth

from .exceptions import PermanentMauticError, TemporaryMauticError


_TEMPORARY_STATUS_CODES = {408, 425, 429}


class MauticClient:
    def __init__(self, session=None):
        self.session = session or requests.Session()
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

    def _request(self, method: str, path: str, **kwargs):
        url = f"{self.base_url}/api/{path.lstrip('/')}"
        try:
            response = self.session.request(
                method,
                url,
                auth=HTTPBasicAuth(self.username, self.password),
                timeout=self.timeout,
                **kwargs,
            )
        except (requests.Timeout, requests.ConnectionError) as exc:
            raise TemporaryMauticError("Mautic API request failed") from exc
        except requests.RequestException as exc:
            raise TemporaryMauticError("Mautic API transport failed") from exc

        self._raise_for_response(response, "Mautic API request failed")
        return response

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

        response = self._request("POST", "contacts/new", data=payload)
        data = self._json_object(response, "Mautic contact creation")
        contact = data.get("contact")
        if not isinstance(contact, dict) or not contact.get("id"):
            raise TemporaryMauticError(
                "Mautic contact creation returned an invalid response"
            )
        return contact

    def update_contact(
        self,
        contact_id: int | str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        contact_id = str(contact_id or "").strip()
        if not contact_id:
            raise PermanentMauticError("Mautic contact ID is required")

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

    def create_email(self, payload: dict[str, Any]) -> dict[str, Any]:
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

        response = self._request("DELETE", f"emails/{email_id}/delete")
        return self._email_from_response(
            response,
            "Mautic email deletion",
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
        self._request(
            "POST",
            f"segments/{segment_id}/contact/{contact_id}/remove",
        )
