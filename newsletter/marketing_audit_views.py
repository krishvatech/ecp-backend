"""Read-only Marketing Audit & Activity API."""

from __future__ import annotations

from datetime import datetime, time

from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.utils.dateparse import parse_date, parse_datetime
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .marketing_permissions import CanManageMarketingAccess
from .models import MauticIdentityAuditLog


MAX_PAGE_SIZE = 100


DOMAIN_DEFINITIONS = {
    "campaigns": ("Campaigns", ("campaign.",)),
    "segments": ("Segments", ("segment.",)),
    "contacts": ("Contacts", ("contact.",)),
    "companies": ("Companies", ("company.",)),
    "templates": ("Templates", ("template.",)),
    "broadcasts": ("Email Broadcasts", ("email.",)),
    "stages": ("Stages", ("stage.",)),
    "points": ("Points", ("point.",)),
    "tags": ("Tags", ("tag.",)),
    "fields": ("Fields", ("field.",)),
    "delivery": ("Delivery", ("newsletter.",)),
    "access": ("Access", ("connection.",)),
}


def domain_for_action(action: str) -> str:
    action = str(action or "")
    for label, prefixes in DOMAIN_DEFINITIONS.values():
        if any(action.startswith(prefix) for prefix in prefixes):
            return label
    return "Other"


def _parse_positive_int(value, *, field_name):
    if value in (None, ""):
        return None, None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None, f"{field_name} must be a positive integer."
    if parsed <= 0:
        return None, f"{field_name} must be a positive integer."
    return parsed, None


def _parse_page_params(request):
    page, _ = _parse_positive_int(request.query_params.get("page", "1"), field_name="page")
    page_size, _ = _parse_positive_int(
        request.query_params.get("page_size", "25"),
        field_name="page_size",
    )
    return page or 1, min(page_size or 25, MAX_PAGE_SIZE)


def _parse_datetime_filter(value, *, end_of_day=False):
    raw = str(value or "").strip()
    if not raw:
        return None, None

    parsed = parse_datetime(raw)
    if parsed is None:
        parsed_date = parse_date(raw)
        if parsed_date is None:
            return None, "Use ISO date or datetime format."
        parsed = datetime.combine(
            parsed_date,
            time.max if end_of_day else time.min,
        )

    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.get_current_timezone())
    return parsed, None


def _valid_values(enum_cls):
    return {choice.value for choice in enum_cls}


def _domain_action_q(domain_key):
    _, prefixes = DOMAIN_DEFINITIONS[domain_key]
    query = Q()
    for prefix in prefixes:
        query |= Q(action__startswith=prefix)
    return query


def _actor_payload(entry):
    user = entry.ecp_user
    if user is None:
        return {
            "id": entry.ecp_user_id,
            "username": entry.ecp_user_label or "",
            "email": "",
            "label": entry.ecp_user_label or "Deleted/Unavailable user",
            "is_deleted": True,
        }

    full_name = " ".join(
        part
        for part in [
            str(getattr(user, "first_name", "") or "").strip(),
            str(getattr(user, "last_name", "") or "").strip(),
        ]
        if part
    )
    label = full_name or user.get_username() or getattr(user, "email", "") or f"ECP #{user.pk}"
    return {
        "id": user.pk,
        "username": user.get_username(),
        "email": getattr(user, "email", "") or "",
        "label": label,
        "is_deleted": False,
    }


def serialize_audit_entry(entry):
    return {
        "id": entry.id,
        "created_at": entry.created_at,
        "action": entry.action,
        "domain": domain_for_action(entry.action),
        "status": entry.status,
        "auth_mode": entry.auth_mode,
        "resource": entry.resource,
        "resource_id": entry.resource_id,
        "ecp_user": _actor_payload(entry),
        "mautic_user": {
            "id": entry.mautic_user_id,
            "username": "",
        }
        if entry.mautic_user_id
        else None,
        "correlation_id": entry.correlation_id or "",
        "assertion_jti": entry.assertion_jti or "",
        "error_code": entry.error_code or "",
        "error_detail": entry.detail or "",
    }


class NewsletterAdminMarketingAuditView(APIView):
    """Operational audit list for Marketing administrators."""

    permission_classes = [CanManageMarketingAccess]

    def get(self, request):
        queryset = MauticIdentityAuditLog.objects.select_related("ecp_user").all()
        errors = {}

        date_from, error = _parse_datetime_filter(request.query_params.get("date_from"))
        if error:
            errors["date_from"] = error
        elif date_from is not None:
            queryset = queryset.filter(created_at__gte=date_from)

        date_to, error = _parse_datetime_filter(
            request.query_params.get("date_to"),
            end_of_day=True,
        )
        if error:
            errors["date_to"] = error
        elif date_to is not None:
            queryset = queryset.filter(created_at__lte=date_to)

        for param, field in [("ecp_user_id", "ecp_user_id"), ("mautic_user_id", "mautic_user_id")]:
            value, error = _parse_positive_int(
                request.query_params.get(param),
                field_name=param,
            )
            if error:
                errors[param] = error
            elif value is not None:
                queryset = queryset.filter(**{field: value})

        action = str(request.query_params.get("action", "") or "").strip()
        valid_actions = _valid_values(MauticIdentityAuditLog.Action)
        if action:
            if action not in valid_actions:
                errors["action"] = "Unsupported action."
            else:
                queryset = queryset.filter(action=action)

        audit_status = str(request.query_params.get("status", "") or "").strip()
        valid_statuses = _valid_values(MauticIdentityAuditLog.Status)
        if audit_status:
            if audit_status not in valid_statuses:
                errors["status"] = "Unsupported status."
            else:
                queryset = queryset.filter(status=audit_status)

        auth_mode = str(request.query_params.get("auth_mode", "") or "").strip()
        if auth_mode:
            if auth_mode not in {"asserted_user", "service_account"}:
                errors["auth_mode"] = "Unsupported auth_mode."
            else:
                queryset = queryset.filter(auth_mode=auth_mode)

        domain = str(request.query_params.get("domain", "") or "").strip().lower()
        if domain:
            if domain not in DOMAIN_DEFINITIONS:
                errors["domain"] = "Unsupported domain."
            else:
                queryset = queryset.filter(_domain_action_q(domain))

        search = str(request.query_params.get("search", "") or "").strip()
        if search:
            search_q = (
                Q(ecp_user_label__icontains=search)
                | Q(ecp_user__username__icontains=search)
                | Q(ecp_user__email__icontains=search)
                | Q(correlation_id__icontains=search)
                | Q(assertion_jti__icontains=search)
            )
            try:
                numeric = int(search)
            except ValueError:
                numeric = None
            if numeric is not None and numeric > 0:
                search_q |= Q(ecp_user_id=numeric) | Q(mautic_user_id=numeric)
            queryset = queryset.filter(search_q)

        if errors:
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)

        status_counts = {
            row["status"]: row["count"]
            for row in queryset.values("status").annotate(count=Count("id"))
        }
        mode_counts = {
            row["auth_mode"]: row["count"]
            for row in queryset.values("auth_mode").annotate(count=Count("id"))
        }
        summary = {
            "actions": queryset.count(),
            "succeeded": status_counts.get(MauticIdentityAuditLog.Status.SUCCEEDED, 0),
            "denied": status_counts.get(MauticIdentityAuditLog.Status.DENIED, 0),
            "failed": status_counts.get(MauticIdentityAuditLog.Status.FAILED, 0),
            "asserted_user": mode_counts.get("asserted_user", 0),
            "service_account": mode_counts.get("service_account", 0),
        }

        page, page_size = _parse_page_params(request)
        paginator = Paginator(queryset, page_size)
        rows = paginator.get_page(page)

        return Response(
            {
                "count": paginator.count,
                "page": rows.number,
                "page_size": page_size,
                "num_pages": paginator.num_pages,
                "summary": summary,
                "filters": {
                    "actions": sorted(valid_actions),
                    "statuses": sorted(valid_statuses),
                    "auth_modes": ["asserted_user", "service_account"],
                    "domains": [
                        {"value": key, "label": label}
                        for key, (label, _) in DOMAIN_DEFINITIONS.items()
                    ],
                },
                "results": [serialize_audit_entry(entry) for entry in rows],
            },
            status=status.HTTP_200_OK,
        )
