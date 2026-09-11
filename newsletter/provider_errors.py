"""Shared normalization of Mautic provider failures for marketing admin endpoints.

Follows the mapping the existing newsletter admin views already use:

* missing provider resource -> 404
* provider validation / conflict -> 400
* anything else (auth, transport, 5xx) -> 502 with a safe message

Raw provider stack traces are never forwarded; only the client's own sanitized message
(``MauticClient._safe_error_detail``) reaches the frontend.
"""

from __future__ import annotations

from django.http import Http404
from rest_framework import status
from rest_framework.response import Response

from .mautic import PermanentMauticError


def provider_error_response(exc, *, context: str = "Mautic operation failed."):
    message = str(exc)
    if isinstance(exc, PermanentMauticError):
        if "HTTP 404" in message:
            raise Http404
        if any(f"HTTP {code}" in message for code in (400, 409, 422)):
            return Response(
                {"detail": message},
                status=status.HTTP_400_BAD_REQUEST,
            )
    return Response(
        {"detail": message or context},
        status=status.HTTP_502_BAD_GATEWAY,
    )
