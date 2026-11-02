"""Send one published template email to one contact from the Marketing Hub.

Mautic's own send-to-contact API sends as transactional with Do Not Contact
ignored, so ECP refuses a contact with any email Do Not Contact (unsubscribed,
bounced, manual) here, and the bridge checks again right before the send. Only
published templates are sent, exactly as saved, as the acting admin, audited.
"""

from __future__ import annotations

import logging

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .contact_bulk_services import _has_email_dnc
from .marketing_permissions import HasMarketingHubAccess
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .mautic.exceptions import MauticRequestNotSentError
from .mautic.operations import EMAIL_CONTACT_SEND
from .mautic_identity_execution import run_interactive_mutation

logger = logging.getLogger(__name__)


def _error(message: str, code: str, http_status: int) -> Response:
    return Response({"detail": message, "code": code}, status=http_status)


def _provider_message(exc) -> str:
    message = str(exc)
    return message.split(": ", 1)[1] if ": " in message else message


class NewsletterAdminContactSendEmailView(APIView):
    """POST {"emailId"}: send that published template to this contact."""

    permission_classes = [HasMarketingHubAccess]

    def post(self, request, mautic_contact_id):
        contact_id = str(mautic_contact_id or "").strip()
        email_id = str((request.data or {}).get("emailId") or "").strip() if hasattr(request.data, "get") else ""
        if not contact_id.isdigit() or not email_id.isdigit():
            return _error("Choose a template to send.", "invalid_send_request", status.HTTP_400_BAD_REQUEST)
        client = MauticClient()
        try:
            contact = client.get_contact(contact_id)
            template = client.get_email(email_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            if isinstance(exc, PermanentMauticError) and "HTTP 404" in str(exc):
                return _error("The contact or the template was not found in Mautic.", "not_found", status.HTTP_404_NOT_FOUND)
            return _error("Mautic could not be reached; nothing was sent.", "mautic_error", status.HTTP_502_BAD_GATEWAY)

        fields = contact.get("fields") if isinstance(contact.get("fields"), dict) else {}
        address = str((fields.get("all") or {}).get("email") or contact.get("email") or "").strip()
        if not address:
            return _error("This contact has no email address.", "contact_no_email", status.HTTP_409_CONFLICT)
        if _has_email_dnc(contact):
            return _error("This contact is marked Do Not Contact for email, so nothing can be sent.", "contact_dnc", status.HTTP_409_CONFLICT)
        if str(template.get("emailType") or "") != "template":
            return _error("Only templates can be sent to a single contact.", "not_a_template", status.HTTP_409_CONFLICT)
        if template.get("isPublished") in (False, 0, "0", None):
            return _error("Publish the template before sending it.", "template_unpublished", status.HTTP_409_CONFLICT)

        try:
            _, error_response = run_interactive_mutation(
                request,
                action=EMAIL_CONTACT_SEND,
                resource="contact_email",
                resource_id=f"{contact_id}:{email_id}",
                mutate=lambda asserted: asserted.send_template_to_contact(email_id, contact_id),
                client_factory=MauticClient,
                audit_and_reraise=(TemporaryMauticError, PermanentMauticError),
                detail=f"template {email_id}",
            )
        except MauticRequestNotSentError:
            return _error("Mautic could not be reached; nothing was sent.", "mautic_unavailable", status.HTTP_503_SERVICE_UNAVAILABLE)
        except PermanentMauticError as exc:
            if "HTTP 409" in str(exc) or "HTTP 400" in str(exc):
                return _error(_provider_message(exc), "send_refused", status.HTTP_409_CONFLICT)
            return _error("Mautic refused the send.", "mautic_error", status.HTTP_502_BAD_GATEWAY)
        except TemporaryMauticError:
            logger.warning("Send of template %s to contact %s is unconfirmed", email_id, contact_id, exc_info=True)
            return _error("Mautic did not confirm the send. Check the contact's activity before sending again.",
                          "send_unconfirmed", status.HTTP_502_BAD_GATEWAY)
        if error_response is not None:
            return error_response
        return Response({"sent": True, "emailId": email_id, "contactId": contact_id, "to": address,
                         "templateName": str(template.get("name") or "")})
