"""
Standalone Q&A export view.

Kept as a plain APIView (not a ViewSet action) to avoid any ViewSet
dispatch complexity and make debugging straightforward.

GET /api/interactions/questions/export/?event_id=<id>&format=csv|pdf
"""
import logging

from django.http import Http404
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status as http_status

logger = logging.getLogger(__name__)


class QnAExportView(APIView):
    permission_classes = [IsAuthenticated]

    @staticmethod
    def _is_guest_user(user) -> bool:
        return bool(getattr(user, "is_guest", False))

    def get(self, request):
        from events.models import Event
        from .exporters import (
            build_export_rows,
            generate_csv_response,
            generate_pdf_response,
        )

        # ── 1. validate query params ──────────────────────────────────────────
        event_id = request.query_params.get("event_id", "").strip()
        fmt = request.query_params.get("export_format", "").strip().lower()

        # Fallback: also accept ?format= but only if export_format not given
        # (avoids collision with DRF's built-in ?format= content-negotiation param)
        if not fmt:
            fmt = request.query_params.get("format", "").strip().lower()

        logger.debug("QnAExportView.get called: event_id=%r fmt=%r user=%r",
                     event_id, fmt, request.user)

        if not event_id:
            raise ValidationError({"event_id": "This parameter is required."})
        if fmt not in ("csv", "pdf"):
            raise ValidationError({"export_format": "Must be 'csv' or 'pdf'."})

        # ── 2. load event ─────────────────────────────────────────────────────
        try:
            event = Event.objects.get(pk=event_id)
        except Event.DoesNotExist:
            raise Http404(f"Event {event_id} not found.")
        except (ValueError, TypeError):
            raise ValidationError({"event_id": "Must be a valid integer."})

        # ── 3. permission check ───────────────────────────────────────────────
        user = request.user
        is_host = (not self._is_guest_user(user)) and (user == event.created_by)
        is_staff = (not self._is_guest_user(user)) and user.is_staff

        if not (is_host or is_staff):
            raise PermissionDenied(
                "Only the event host or platform staff can export Q&A data."
            )

        # ── 4. event must be ended ────────────────────────────────────────────
        if event.status != "ended":
            return Response(
                {"detail": "Q&A export is only available after the event has ended."},
                status=http_status.HTTP_403_FORBIDDEN,
            )

        # ── 5. build rows and return file ─────────────────────────────────────
        rows = build_export_rows(event)

        if fmt == "csv":
            return generate_csv_response(rows, event)

        exported_by = (
            (getattr(user, "get_full_name", lambda: "")() or "").strip()
            or getattr(user, "username", "")
            or getattr(user, "email", "")
            or f"User {user.pk}"
        )
        return generate_pdf_response(rows, event, exported_by=exported_by)
