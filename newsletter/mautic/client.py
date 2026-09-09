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

    def get_contact(self, contact_id) -> dict[str, Any]:
        normalized = str(contact_id or "").strip()
        if not normalized:
            raise PermanentMauticError("Mautic contact id is required")
        response = self._request("GET", f"contacts/{normalized}")
        data = self._json_object(response, "Mautic contact detail")
        contact = data.get("contact")
        if not isinstance(contact, dict):
            raise TemporaryMauticError("Mautic contact detail returned an invalid response")
        return contact

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
            templates.extend(
                row
                for row in rows
                if str(row.get("emailType") or "").strip() == "template"
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

        self.get_email_template(email_id)

        template_payload = dict(payload)
        requested_type = str(
            template_payload.get("emailType") or ""
        ).strip()
        if requested_type and requested_type != "template":
            raise PermanentMauticError(
                "Mautic email template type must be template"
            )
        template_payload["emailType"] = "template"

        return self._require_template_email(
            self.update_email(email_id, template_payload),
            "Updated Mautic email",
        )

    def delete_email_template(
        self,
        email_id: int | str,
    ) -> dict[str, Any]:
        self.get_email_template(email_id)
        return self.delete_email(email_id)

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
        self._request(
            "POST",
            f"stages/{stage_id}/contact/{contact_id}/remove",
        )
    @staticmethod
    def _segment_from_response(response, context: str) -> dict[str, Any]:
        data = MauticClient._json_object(response, context)
        segment = data.get("list") or data.get("segment")
        if not isinstance(segment, dict) or not segment.get("id"):
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

    def get_segment(self, segment_id: int | str) -> dict[str, Any]:
        segment_id = str(segment_id or "").strip()
        if not segment_id:
            raise PermanentMauticError("Mautic segment ID is required")

        response = self._request("GET", f"segments/{segment_id}")
        return self._segment_from_response(response, "Mautic segment lookup")

    def create_segment(self, payload: dict[str, Any]) -> dict[str, Any]:
        response = self._request("POST", "segments/new", data=payload)
        return self._segment_from_response(response, "Mautic segment creation")

    def update_segment(
        self,
        segment_id: int | str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        segment_id = str(segment_id or "").strip()
        if not segment_id:
            raise PermanentMauticError("Mautic segment ID is required")

        response = self._request("PATCH", f"segments/{segment_id}/edit", data=payload)
        return self._segment_from_response(response, "Mautic segment update")

    def delete_segment(self, segment_id: int | str) -> dict[str, Any]:
        segment_id = str(segment_id or "").strip()
        if not segment_id:
            raise PermanentMauticError("Mautic segment ID is required")

        response = self._request("DELETE", f"segments/{segment_id}/delete")
        return self._segment_from_response(response, "Mautic segment deletion")

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
