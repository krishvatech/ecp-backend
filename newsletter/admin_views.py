from django.http import Http404
from django.conf import settings
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q
from django.utils.text import slugify
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
import logging
import math
import re

from moderation.permissions import IsStaffOrSuperuser

from .admin_serializers import (
    NewsletterAudienceAdminSerializer,
    NewsletterAdminCategorySerializer,
    NewsletterCategoryPublicSerializer,
    NewsletterCampaignScheduleSerializer,
    NewsletterCampaignSerializer,
    NewsletterCampaignTestEmailSerializer,
)
from .analytics_services import get_campaign_analytics
from .category_analytics import (
    build_category_contact_timeline,
    resolve_contact_timeline_range,
)
from .contact_services import (
    bulk_update_admin_contact_stage,
    clear_admin_contact_stage,
    add_admin_contact_dnc,
    create_admin_contact,
    create_admin_contact_note,
    get_admin_contact,
    get_admin_contact_engagement,
    list_admin_contact_companies,
    list_admin_contact_field_metadata,
    list_admin_contact_notes,
    get_admin_stage_analytics,
    list_admin_contact_activity,
    list_admin_contacts,
    list_admin_tags,
    move_admin_contact_to_stage,
    remove_admin_contact_dnc,
    set_admin_contact_tag,
    update_admin_contact,
)
from .campaign_services import (
    CampaignNotEditable,
    CampaignScheduleNotAllowed,
    cancel_scheduled_campaign,
    create_campaign,
    delete_draft_campaign,
    get_campaign,
    list_campaigns,
    request_campaign_send,
    schedule_campaign,
    send_campaign_test_email,
    sync_campaign_draft_to_mautic,
    update_campaign,
)
from .models import (
    MauticContactMapping,
    NewsletterAudience,
    NewsletterCampaign,
    NewsletterCategory,
    NewsletterSubscription,
    NewsletterSyncEvent,
)
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError
from .sync_events import create_newsletter_sync_event

logger = logging.getLogger(__name__)


def _get_campaign_or_404(uuid):
    try:
        return get_campaign(uuid)
    except (NewsletterCampaign.DoesNotExist, ValueError):
        raise Http404


def _get_audience_or_404(uuid):
    try:
        return NewsletterAudience.objects.get(uuid=uuid)
    except (NewsletterAudience.DoesNotExist, ValueError):
        raise Http404


def _mautic_enabled():
    return bool(getattr(settings, "MAUTIC_SYNC_ENABLED", False))


def _segment_filters(segment):
    filters = segment.get("filters")
    if filters in (None, "", [], {}):
        return []
    if isinstance(filters, dict):
        return [item for item in filters.values() if item]
    return filters


def _segment_is_static(segment):
    return not bool(_segment_filters(segment))


def _normalize_provider_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    normalized = str(value or "").strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off", ""}:
        return False
    return bool(value)


def _parse_provider_bool(value, *, field_name):
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    normalized = str(value or "").strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{field_name} must be a boolean.")


def _segment_payload_for_category(category, *, include_alias=False):
    payload = {
        "name": category.name,
        "description": category.description,
        "isPublished": bool(category.is_active),
        "isPreferenceCenter": False,
        "filters": [],
    }
    if include_alias:
        payload["alias"] = category.slug
    return payload


def _segments_from_response(data):
    segments = data.get("lists") or data.get("segments") or {}
    if isinstance(segments, dict):
        return [segment for segment in segments.values() if isinstance(segment, dict)]
    if isinstance(segments, list):
        return [segment for segment in segments if isinstance(segment, dict)]
    return []


def _find_segment_by_exact_alias(client, alias):
    data = client.list_segments(search=f"alias:{alias}", limit=20)
    for segment in _segments_from_response(data):
        if str(segment.get("alias") or "").strip() == alias:
            return segment
    return None


def _mapped_category_for_segment(segment_id, *, exclude_category=None):
    qs = NewsletterCategory.objects.filter(mautic_segment_id=str(segment_id))
    if exclude_category is not None:
        qs = qs.exclude(pk=exclude_category.pk)
    return qs.first()


def _reserved_subscription_list_for_alias(alias):
    normalized = str(alias or "").strip()
    if not normalized:
        return None
    return NewsletterCategory.objects.filter(slug=normalized).first()


def _ensure_native_segment_is_not_managed(segment_id):
    mapped = _mapped_category_for_segment(segment_id)
    if mapped is not None:
        return Response(
            {
                "detail": (
                    "This Mautic segment is managed by the ECP Subscription "
                    f"List '{mapped.name}'. Edit it from Subscription Lists."
                )
            },
            status=status.HTTP_409_CONFLICT,
        )
    return None


def _mapped_categories_by_segment_id():
    return {
        str(category.mautic_segment_id): category
        for category in NewsletterCategory.objects.exclude(mautic_segment_id="")
    }


def _segment_count(segment, *field_names):
    for field_name in field_names:
        value = segment.get(field_name)
        if value in (None, ""):
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            return value
    return None


def _normalize_mautic_segment(segment, mapped_categories=None):
    mapped_categories = mapped_categories or _mapped_categories_by_segment_id()
    raw_segment_id = segment.get("id")
    segment_id = str(raw_segment_id) if raw_segment_id is not None else ""
    filters = _segment_filters(segment)
    mapped_category = mapped_categories.get(segment_id)
    managed = mapped_category is not None

    normalized = {
        "id": segment_id,
        "name": segment.get("name") or "",
        "alias": segment.get("alias") or "",
        "description": segment.get("description") or "",
        "isPublished": _normalize_provider_bool(
            segment.get("isPublished", segment.get("is_published", False))
        ),
        "is_static": not bool(filters),
        "is_dynamic": bool(filters),
        "filters": filters,
        "filter_count": len(filters) if isinstance(filters, list) else None,
        "contact_count": _segment_count(
            segment,
            "contactCount",
            "leadCount",
            "memberCount",
            "contactsCount",
            "membersCount",
        ),
        "dateAdded": segment.get("dateAdded") or segment.get("date_added"),
        "dateModified": segment.get("dateModified") or segment.get("date_modified"),
        "createdByUser": segment.get("createdByUser"),
        "modifiedByUser": segment.get("modifiedByUser"),
        "managed_by_subscription_list": managed,
        "subscription_list_slug": mapped_category.slug if mapped_category else None,
        "subscription_list_name": mapped_category.name if mapped_category else None,
        "mapped_in_ecp": managed,
    }
    return normalized


_SEGMENT_ALIAS_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def _parse_native_segment_payload(data, *, partial=False):
    allowed_fields = {"name", "alias", "description", "isPublished"}
    unsupported = sorted(set(data.keys()) - allowed_fields)
    if unsupported:
        raise ValueError(
            "Unsupported native Mautic Segment field(s): " + ", ".join(unsupported)
        )

    payload = {}
    if not partial or "name" in data:
        name = str(data.get("name") or "").strip()
        if not name:
            raise ValueError("Native Mautic Segment name is required.")
        if len(name) > 190:
            raise ValueError("Native Mautic Segment name cannot exceed 190 characters.")
        payload["name"] = name

    if "alias" in data:
        alias = str(data.get("alias") or "").strip()
        if alias:
            if len(alias) > 190:
                raise ValueError("Native Mautic Segment alias cannot exceed 190 characters.")
            if not _SEGMENT_ALIAS_PATTERN.match(alias):
                raise ValueError(
                    "Native Mautic Segment alias may contain only letters, numbers, underscores, and hyphens."
                )
            if _reserved_subscription_list_for_alias(alias) is not None:
                raise ValueError("This alias is reserved by an ECP Subscription List.")
        payload["alias"] = alias

    if "description" in data:
        payload["description"] = str(data.get("description") or "")

    if "isPublished" in data:
        payload["isPublished"] = _parse_provider_bool(
            data.get("isPublished"),
            field_name="Native Mautic Segment isPublished",
        )
    elif not partial:
        payload["isPublished"] = False

    if not partial:
        payload["filters"] = []
    elif not payload:
        raise ValueError("At least one native Mautic Segment field is required.")

    return payload


def _native_segment_provider_error_response(exc):
    message = str(exc)
    if isinstance(exc, PermanentMauticError):
        if "HTTP 404" in message:
            raise Http404
        if any(f"HTTP {code}" in message for code in (400, 409, 422)):
            return Response({"detail": message}, status=status.HTTP_400_BAD_REQUEST)
    return _provider_error_response(exc)


def _contacts_from_segment_response(data):
    contacts = data.get("contacts", data.get("leads", {}))
    if isinstance(contacts, dict):
        return [contact for contact in contacts.values() if isinstance(contact, dict)]
    if isinstance(contacts, list):
        return [contact for contact in contacts if isinstance(contact, dict)]
    return []


def _contact_value(contact, alias):
    value = contact.get(alias)
    if isinstance(value, dict):
        value = value.get("value")
    if value not in (None, ""):
        return value
    fields = contact.get("fields")
    if not isinstance(fields, dict):
        return None
    for group_name in ("all", "core"):
        group = fields.get(group_name)
        if not isinstance(group, dict):
            continue
        value = group.get(alias)
        if isinstance(value, dict):
            value = value.get("value")
        if value not in (None, ""):
            return value
    return None


def _normalize_segment_contact(contact):
    contact_id = contact.get("id")
    firstname = str(_contact_value(contact, "firstname") or "").strip()
    lastname = str(_contact_value(contact, "lastname") or "").strip()
    email = str(_contact_value(contact, "email") or "").strip()
    company = _contact_value(contact, "company")
    stage = contact.get("stage")
    points = contact.get("points")
    return {
        "id": str(contact_id) if contact_id is not None else "",
        "firstname": firstname,
        "lastname": lastname,
        "name": " ".join(part for part in (firstname, lastname) if part) or email,
        "email": email,
        "company": str(company or "").strip(),
        "stage": stage if isinstance(stage, dict) else None,
        "points": points,
        "dateAdded": contact.get("dateAdded") or contact.get("date_added"),
        "dateModified": contact.get("dateModified") or contact.get("date_modified"),
    }


def _parse_positive_id(value, *, field_name):
    normalized = str(value or "").strip()
    if not normalized or not normalized.isdigit() or int(normalized) <= 0:
        raise ValueError(f"{field_name} must be a positive integer.")
    return str(int(normalized))


def _segment_membership_protection_response(segment):
    mapped = _mapped_category_for_segment(segment.get("id"))
    if mapped is not None:
        return Response(
            {
                "detail": (
                    "This segment is managed by Subscription Lists. Membership "
                    "is controlled by newsletter consent synchronization."
                )
            },
            status=status.HTTP_409_CONFLICT,
        )
    if not _segment_is_static(segment):
        return Response(
            {
                "detail": (
                    "Manual membership is available only for static native "
                    "Mautic segments."
                )
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
    return None


def _queue_category_reconciliation(category):
    event_ids = []
    subscriptions = NewsletterSubscription.objects.filter(category=category).select_related(
        "category"
    )
    for subscription in subscriptions.iterator():
        event = create_newsletter_sync_event(subscription)
        event_ids.append(event.pk)

    def dispatch_events():
        from .tasks import process_newsletter_sync_event

        for event_id in event_ids:
            try:
                process_newsletter_sync_event.delay(event_id)
            except Exception:
                logger.exception(
                    "Could not dispatch newsletter reconciliation event_id=%s",
                    event_id,
                )

    if event_ids:
        transaction.on_commit(dispatch_events)
    return len(event_ids)


def _provider_error_response(exc):
    return Response(
        {"detail": str(exc) or "Mautic segment operation failed."},
        status=status.HTTP_502_BAD_GATEWAY,
    )


def _compensate_created_segment(client, segment_id):
    try:
        client.update_segment(segment_id, {"isPublished": False})
    except Exception:
        logger.exception(
            "Could not compensate newly-created Mautic segment_id=%s",
            segment_id,
        )


def _is_missing_segment_error(exc):
    return "HTTP 404" in str(exc)


def _ensure_category_segment(category):
    client = MauticClient()
    segment_id = str(category.mautic_segment_id or "").strip()
    if segment_id:
        try:
            segment = client.get_segment(segment_id)
        except PermanentMauticError as exc:
            if not _is_missing_segment_error(exc):
                raise
            segment = None
        if segment is not None:
            if not _segment_is_static(segment):
                raise PermanentMauticError("Mapped Mautic segment is dynamic.")
            client.update_segment(segment_id, _segment_payload_for_category(category))
            return segment_id, False

    existing = _find_segment_by_exact_alias(client, category.slug)
    if existing is not None:
        if not _segment_is_static(existing):
            raise PermanentMauticError(
                "A dynamic Mautic segment already uses this newsletter slug."
            )
        segment_id = str(existing["id"])
        mapped = _mapped_category_for_segment(segment_id, exclude_category=category)
        if mapped is not None:
            raise PermanentMauticError(
                "Mautic segment is already mapped to another newsletter category."
            )
        client.update_segment(segment_id, _segment_payload_for_category(category))
        category.mautic_segment_id = segment_id
        category.save(update_fields=["mautic_segment_id", "updated_at"])
        return segment_id, True

    segment = client.create_segment(
        _segment_payload_for_category(category, include_alias=True)
    )
    category.mautic_segment_id = str(segment["id"])
    try:
        category.save(update_fields=["mautic_segment_id", "updated_at"])
    except Exception:
        _compensate_created_segment(client, category.mautic_segment_id)
        raise
    return category.mautic_segment_id, True


class NewsletterAdminAudienceListCreateView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        audiences = NewsletterAudience.objects.filter(is_active=True).order_by(
            "-created_at",
            "-id",
        )
        serializer = NewsletterAudienceAdminSerializer(audiences, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = NewsletterAudienceAdminSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        audience = serializer.save(created_by=request.user)
        response = NewsletterAudienceAdminSerializer(audience)
        return Response(response.data, status=status.HTTP_201_CREATED)


class NewsletterAdminAudienceDetailView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, uuid):
        serializer = NewsletterAudienceAdminSerializer(_get_audience_or_404(uuid))
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, uuid):
        audience = _get_audience_or_404(uuid)
        serializer = NewsletterAudienceAdminSerializer(
            audience,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        audience = serializer.save()
        response = NewsletterAudienceAdminSerializer(audience)
        return Response(response.data, status=status.HTTP_200_OK)

    def delete(self, request, uuid):
        audience = _get_audience_or_404(uuid)
        audience.status = NewsletterAudience.Status.ARCHIVED
        audience.is_active = False
        audience.save(update_fields=["status", "is_active", "updated_at"])
        serializer = NewsletterAudienceAdminSerializer(audience)
        return Response(serializer.data, status=status.HTTP_200_OK)


class NewsletterAdminCampaignListCreateView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        serializer = NewsletterCampaignSerializer(list_campaigns(), many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = NewsletterCampaignSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        campaign = create_campaign(serializer.validated_data, user=request.user)
        response = NewsletterCampaignSerializer(campaign)
        return Response(response.data, status=status.HTTP_201_CREATED)


class NewsletterAdminCampaignDetailView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, uuid):
        serializer = NewsletterCampaignSerializer(_get_campaign_or_404(uuid))
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, uuid):
        campaign = _get_campaign_or_404(uuid)
        serializer = NewsletterCampaignSerializer(
            campaign,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        try:
            campaign = update_campaign(
                campaign,
                serializer.validated_data,
                user=request.user,
            )
        except CampaignNotEditable as exc:
            return Response({"detail": exc.detail}, status=status.HTTP_400_BAD_REQUEST)
        response = NewsletterCampaignSerializer(campaign)
        return Response(response.data, status=status.HTTP_200_OK)

    def delete(self, request, uuid):
        campaign = _get_campaign_or_404(uuid)
        try:
            delete_draft_campaign(campaign)
        except CampaignNotEditable as exc:
            return Response({"detail": exc.detail}, status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminCampaignPreviewView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, uuid):
        campaign = _get_campaign_or_404(uuid)
        return Response(
            {
                "name": campaign.name,
                "subject": campaign.subject,
                "preview_text": campaign.preview_text,
                "from_name": campaign.from_name,
                "from_email": campaign.from_email,
                "html_content": campaign.html_content,
                "plain_text": campaign.plain_text,
                "status": campaign.status,
            },
            status=status.HTTP_200_OK,
        )


class NewsletterAdminCampaignAnalyticsView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, uuid):
        return Response(
            get_campaign_analytics(_get_campaign_or_404(uuid)),
            status=status.HTTP_200_OK,
        )


class NewsletterAdminCampaignTestEmailView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def post(self, request, uuid):
        serializer = NewsletterCampaignTestEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        result = send_campaign_test_email(
            _get_campaign_or_404(uuid),
            serializer.validated_data["email"],
            actor=request.user,
        )
        return Response(
            {
                "success": True,
                "recipient_email": result["recipient_email"],
            },
            status=status.HTTP_200_OK,
        )


class NewsletterAdminCampaignSyncView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def post(self, request, uuid):
        campaign = sync_campaign_draft_to_mautic(
            _get_campaign_or_404(uuid),
            actor=request.user,
        )
        serializer = NewsletterCampaignSerializer(campaign)
        return Response(serializer.data, status=status.HTTP_200_OK)


class NewsletterAdminCampaignSendView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def post(self, request, uuid):
        event = request_campaign_send(
            _get_campaign_or_404(uuid),
            user=request.user,
        )
        return Response(
            {
                "accepted": True,
                "status": event.status,
            },
            status=status.HTTP_202_ACCEPTED,
        )


class NewsletterAdminCampaignScheduleView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def post(self, request, uuid):
        serializer = NewsletterCampaignScheduleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            campaign = schedule_campaign(
                _get_campaign_or_404(uuid),
                scheduled_at=serializer.validated_data["scheduled_at"],
                user=request.user,
            )
        except CampaignScheduleNotAllowed as exc:
            return Response({"detail": exc.detail}, status=status.HTTP_400_BAD_REQUEST)

        response = NewsletterCampaignSerializer(campaign)
        return Response(response.data, status=status.HTTP_200_OK)


class NewsletterAdminCampaignCancelView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def post(self, request, uuid):
        try:
            campaign = cancel_scheduled_campaign(
                _get_campaign_or_404(uuid),
                user=request.user,
            )
        except CampaignScheduleNotAllowed as exc:
            return Response({"detail": exc.detail}, status=status.HTTP_400_BAD_REQUEST)

        response = NewsletterCampaignSerializer(campaign)
        return Response(response.data, status=status.HTTP_200_OK)


class NewsletterAdminContactListView(APIView):
    """List the full Mautic contact directory with ECP enrichment."""

    permission_classes = [IsStaffOrSuperuser]
    default_page_size = 25
    max_page_size = 100

    def get(self, request):
        try:
            page = max(1, int(request.query_params.get("page", 1)))
        except (TypeError, ValueError):
            page = 1
        try:
            page_size = int(
                request.query_params.get("page_size", self.default_page_size)
            )
        except (TypeError, ValueError):
            page_size = self.default_page_size
        page_size = max(1, min(page_size, self.max_page_size))
        search = str(request.query_params.get("search", "") or "").strip()
        stage_id = str(request.query_params.get("stage_id", "") or "").strip()

        try:
            data = list_admin_contacts(
                page=page,
                page_size=page_size,
                search=search,
                stage_id=stage_id,
            )
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(data, status=status.HTTP_200_OK)

    def post(self, request):
        try:
            data = create_admin_contact(request.data)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _contact_stage_provider_error_response(exc)

        return Response(data, status=status.HTTP_201_CREATED)


class NewsletterAdminContactBulkStageView(APIView):
    """Move or clear a selected batch of Mautic contacts."""

    permission_classes = [IsStaffOrSuperuser]

    def post(self, request):
        allowed_fields = {"action", "contact_ids", "stage_id"}
        unsupported = sorted(set(request.data.keys()) - allowed_fields)
        if unsupported:
            return Response(
                {
                    "detail": (
                        "Unsupported bulk stage field(s): "
                        + ", ".join(unsupported)
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        action = str(request.data.get("action") or "move").strip().lower()
        if action not in {"move", "clear"}:
            return Response(
                {"detail": "action must be either 'move' or 'clear'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            data = bulk_update_admin_contact_stage(
                request.data.get("contact_ids"),
                stage_id=request.data.get("stage_id"),
                clear=action == "clear",
            )
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _contact_stage_provider_error_response(exc)

        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminContactDetailView(APIView):
    """Return one Mautic contact with ECP mapping and consent state."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, mautic_contact_id):
        try:
            data = get_admin_contact(mautic_contact_id)
        except PermanentMauticError as exc:
            if "HTTP 404" in str(exc):
                raise Http404
            return _provider_error_response(exc)
        except TemporaryMauticError as exc:
            return _provider_error_response(exc)

        return Response(data, status=status.HTTP_200_OK)

    def patch(self, request, mautic_contact_id):
        try:
            data = update_admin_contact(mautic_contact_id, request.data)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except PermanentMauticError as exc:
            if "HTTP 404" in str(exc):
                raise Http404
            return _contact_stage_provider_error_response(exc)
        except TemporaryMauticError as exc:
            return _provider_error_response(exc)

        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminContactFieldMetadataView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        try:
            data = list_admin_contact_field_metadata()
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminTagListView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        try:
            data = list_admin_tags(
                search=request.query_params.get("search", ""),
                limit=request.query_params.get("limit", 100),
            )
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminContactTagsView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def post(self, request, mautic_contact_id):
        try:
            data = set_admin_contact_tag(
                mautic_contact_id,
                request.data.get("tag"),
                remove=False,
            )
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _contact_stage_provider_error_response(exc)

        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminContactTagDetailView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def delete(self, request, mautic_contact_id, tag):
        try:
            data = set_admin_contact_tag(mautic_contact_id, tag, remove=True)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _contact_stage_provider_error_response(exc)

        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminContactNotesView(APIView):
    permission_classes = [IsStaffOrSuperuser]
    default_page_size = 25
    max_page_size = 100

    def get(self, request, mautic_contact_id):
        try:
            page = max(1, int(request.query_params.get("page", 1)))
            page_size = max(
                1,
                min(
                    int(request.query_params.get("page_size", self.default_page_size)),
                    self.max_page_size,
                ),
            )
            data = list_admin_contact_notes(
                mautic_contact_id,
                page=page,
                page_size=page_size,
                search=request.query_params.get("search", ""),
            )
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except PermanentMauticError as exc:
            if "HTTP 404" in str(exc):
                raise Http404
            return _provider_error_response(exc)
        except TemporaryMauticError as exc:
            return _provider_error_response(exc)

        return Response(data, status=status.HTTP_200_OK)

    def post(self, request, mautic_contact_id):
        try:
            data = create_admin_contact_note(mautic_contact_id, request.data)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except PermanentMauticError as exc:
            if "HTTP 404" in str(exc):
                raise Http404
            return _contact_stage_provider_error_response(exc)
        except TemporaryMauticError as exc:
            return _provider_error_response(exc)

        return Response(data, status=status.HTTP_201_CREATED)


class NewsletterAdminContactDncView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def post(self, request, mautic_contact_id):
        try:
            data = add_admin_contact_dnc(mautic_contact_id, request.data)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _contact_stage_provider_error_response(exc)

        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminContactDncDetailView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def delete(self, request, mautic_contact_id, channel):
        try:
            data = remove_admin_contact_dnc(mautic_contact_id, channel)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _contact_stage_provider_error_response(exc)

        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminContactCompaniesView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, mautic_contact_id):
        try:
            data = list_admin_contact_companies(mautic_contact_id)
        except PermanentMauticError as exc:
            if "HTTP 404" in str(exc):
                raise Http404
            return _provider_error_response(exc)
        except TemporaryMauticError as exc:
            return _provider_error_response(exc)

        return Response(data, status=status.HTTP_200_OK)


def _contact_stage_provider_error_response(exc):
    message = str(exc)
    if isinstance(exc, PermanentMauticError):
        if "HTTP 404" in message:
            raise Http404
        if any(
            f"HTTP {code}" in message
            for code in (400, 409, 422)
        ):
            return Response(
                {"detail": message},
                status=status.HTTP_400_BAD_REQUEST,
            )
    return _provider_error_response(exc)


class NewsletterAdminContactStageView(APIView):
    """Move or clear one contact's Mautic lifecycle stage."""

    permission_classes = [IsStaffOrSuperuser]

    def post(self, request, mautic_contact_id):
        unsupported = sorted(set(request.data.keys()) - {"stage_id"})
        if unsupported:
            return Response(
                {
                    "detail": (
                        "Unsupported contact stage field(s): "
                        + ", ".join(unsupported)
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        stage_id = str(request.data.get("stage_id") or "").strip()
        if not stage_id:
            return Response(
                {"detail": "stage_id is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            current_stage = move_admin_contact_to_stage(
                mautic_contact_id,
                stage_id,
            )
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _contact_stage_provider_error_response(exc)

        return Response(
            {
                "mautic_contact_id": str(mautic_contact_id),
                "current_stage": current_stage,
            },
            status=status.HTTP_200_OK,
        )

    def delete(self, request, mautic_contact_id):
        try:
            clear_admin_contact_stage(mautic_contact_id)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _contact_stage_provider_error_response(exc)

        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminContactActivityView(APIView):
    """Return paginated real Mautic activity for one contact."""

    permission_classes = [IsStaffOrSuperuser]
    default_page_size = 25
    max_page_size = 100

    def get(self, request, mautic_contact_id):
        try:
            page = max(1, int(request.query_params.get("page", 1)))
        except (TypeError, ValueError):
            page = 1
        try:
            page_size = int(
                request.query_params.get("page_size", self.default_page_size)
            )
        except (TypeError, ValueError):
            page_size = self.default_page_size
        page_size = max(1, min(page_size, self.max_page_size))

        try:
            data = list_admin_contact_activity(
                mautic_contact_id,
                page=page,
                page_size=page_size,
            )
        except PermanentMauticError as exc:
            if "HTTP 404" in str(exc):
                raise Http404
            return _provider_error_response(exc)
        except TemporaryMauticError as exc:
            return _provider_error_response(exc)

        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminContactEngagementView(APIView):
    """Return a date-ranged cumulative engagement series from Mautic activity."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, mautic_contact_id):
        try:
            data = get_admin_contact_engagement(
                mautic_contact_id,
                from_value=request.query_params.get("from"),
                to_value=request.query_params.get("to"),
            )
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except PermanentMauticError as exc:
            if "HTTP 404" in str(exc):
                raise Http404
            return _provider_error_response(exc)
        except TemporaryMauticError as exc:
            return _provider_error_response(exc)

        return Response(data, status=status.HTTP_200_OK)


def _stages_from_response(data):
    stages = data.get("stages") or []
    if isinstance(stages, dict):
        return [stage for stage in stages.values() if isinstance(stage, dict)]
    if isinstance(stages, list):
        return [stage for stage in stages if isinstance(stage, dict)]
    return []


def _normalize_stage(stage):
    stage_id = stage.get("id")
    weight = stage.get("weight")
    try:
        weight = int(weight) if weight is not None and weight != "" else None
    except (TypeError, ValueError):
        weight = None

    category = stage.get("category")
    return {
        "id": str(stage_id) if stage_id is not None else None,
        "name": str(stage.get("name") or ""),
        "description": str(stage.get("description") or ""),
        "weight": weight,
        "isPublished": _normalize_provider_bool(
            stage.get("isPublished", stage.get("is_published", False))
        ),
        "category": category if isinstance(category, dict) else None,
        "dateAdded": stage.get("dateAdded"),
        "dateModified": stage.get("dateModified"),
        "publishUp": stage.get("publishUp"),
        "publishDown": stage.get("publishDown"),
    }


def _parse_stage_request_payload(data, *, partial=False):
    allowed_fields = {"name", "description", "weight", "isPublished"}
    unsupported = sorted(set(data.keys()) - allowed_fields)
    if unsupported:
        raise ValueError(
            "Unsupported stage field(s): " + ", ".join(unsupported)
        )

    payload = {}

    if not partial or "name" in data:
        name = str(data.get("name") or "").strip()
        if not name:
            raise ValueError("Stage name is required.")
        payload["name"] = name

    if "description" in data:
        payload["description"] = str(data.get("description") or "").strip()

    if "weight" in data:
        value = data.get("weight")
        if isinstance(value, bool):
            raise ValueError("Stage weight must be an integer.")
        try:
            payload["weight"] = int(str(value).strip())
        except (TypeError, ValueError):
            raise ValueError("Stage weight must be an integer.")

    if "isPublished" in data:
        value = data.get("isPublished")
        if isinstance(value, bool):
            payload["isPublished"] = value
        elif isinstance(value, int) and value in {0, 1}:
            payload["isPublished"] = bool(value)
        else:
            normalized = str(value or "").strip().lower()
            if normalized in {"1", "true", "yes", "on"}:
                payload["isPublished"] = True
            elif normalized in {"0", "false", "no", "off"}:
                payload["isPublished"] = False
            else:
                raise ValueError("Stage isPublished must be a boolean.")

    if partial and not payload:
        raise ValueError("At least one stage field is required.")

    return payload


def _stage_provider_error_response(exc):
    if isinstance(exc, PermanentMauticError) and "HTTP 404" in str(exc):
        raise Http404
    return _provider_error_response(exc)


class NewsletterAdminStageAnalyticsView(APIView):
    """Return current Mautic contact distribution by lifecycle stage."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        try:
            data = get_admin_stage_analytics()
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminStageListCreateView(APIView):
    """List and create Mautic lifecycle stages."""

    permission_classes = [IsStaffOrSuperuser]
    default_page_size = 25
    max_page_size = 100

    def get(self, request):
        try:
            page = max(1, int(request.query_params.get("page", 1)))
        except (TypeError, ValueError):
            page = 1
        try:
            page_size = int(
                request.query_params.get("page_size", self.default_page_size)
            )
        except (TypeError, ValueError):
            page_size = self.default_page_size
        page_size = max(1, min(page_size, self.max_page_size))
        search = str(request.query_params.get("search", "") or "").strip()

        params = {
            "start": (page - 1) * page_size,
            "limit": page_size,
        }
        if search:
            params["search"] = search

        try:
            data = MauticClient().list_stages(**params)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        stages = _stages_from_response(data)
        try:
            total = max(0, int(data.get("total", len(stages))))
        except (TypeError, ValueError):
            total = len(stages)

        return Response(
            {
                "count": total,
                "page": page,
                "page_size": page_size,
                "num_pages": (
                    (total + page_size - 1) // page_size if total else 0
                ),
                "results": [_normalize_stage(stage) for stage in stages],
            },
            status=status.HTTP_200_OK,
        )

    def post(self, request):
        try:
            payload = _parse_stage_request_payload(request.data)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            stage = MauticClient().create_stage(payload)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_stage(stage),
            status=status.HTTP_201_CREATED,
        )


class NewsletterAdminStageDetailView(APIView):
    """Read, update, or delete one Mautic lifecycle stage."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, stage_id):
        try:
            stage = MauticClient().get_stage(stage_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _stage_provider_error_response(exc)

        return Response(_normalize_stage(stage), status=status.HTTP_200_OK)

    def patch(self, request, stage_id):
        try:
            payload = _parse_stage_request_payload(request.data, partial=True)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            stage = MauticClient().update_stage(stage_id, payload)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _stage_provider_error_response(exc)

        return Response(_normalize_stage(stage), status=status.HTTP_200_OK)

    def delete(self, request, stage_id):
        try:
            MauticClient().delete_stage(stage_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _stage_provider_error_response(exc)

        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminCategoryListView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        include_mautic = str(
            request.query_params.get("include_mautic", "")
        ).strip().lower() in {"1", "true", "yes", "on"}
        serializer_class = (
            NewsletterAdminCategorySerializer
            if include_mautic
            else NewsletterCategoryPublicSerializer
        )
        serializer = serializer_class(
            NewsletterCategory.objects.all().order_by("name"),
            many=True,
        )
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = NewsletterAdminCategorySerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        name = serializer.validated_data.get('name', '').strip()
        if not name:
            return Response(
                {'name': 'Category name is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        slug = slugify(name)

        # Ensure unique slug
        base_slug = slug
        counter = 1
        while NewsletterCategory.objects.filter(slug=slug).exists():
            slug = f"{base_slug}-{counter}"
            counter += 1

        try:
            with transaction.atomic():
                category = NewsletterCategory.objects.create(
                    name=name,
                    slug=slug,
                    description=serializer.validated_data.get('description', ''),
                    is_active=True,
                    mautic_segment_id='',
                )
                if _mautic_enabled():
                    _ensure_category_segment(category)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(
            NewsletterAdminCategorySerializer(category).data,
            status=status.HTTP_201_CREATED,
        )


class NewsletterAdminCategoryContactsView(APIView):
    """List the current ECP subscribers for one newsletter subscription list.

    ECP PostgreSQL remains the source of truth. This endpoint intentionally
    does not call Mautic; provider IDs/status are read from the existing local
    mapping and durable sync-event records.
    """

    permission_classes = [IsStaffOrSuperuser]
    default_page_size = 25
    max_page_size = 100

    def get(self, request, slug):
        try:
            category = NewsletterCategory.objects.get(slug=slug)
        except NewsletterCategory.DoesNotExist:
            raise Http404

        subscriptions = (
            NewsletterSubscription.objects.filter(
                category=category,
                is_subscribed=True,
            )
            .select_related("user")
            .order_by("-subscribed_at", "-updated_at", "id")
        )

        search = str(request.query_params.get("search", "") or "").strip()
        if search:
            subscriptions = subscriptions.filter(
                Q(user__email__icontains=search)
                | Q(user__first_name__icontains=search)
                | Q(user__last_name__icontains=search)
                | Q(user__username__icontains=search)
            )

        try:
            page_size = int(
                request.query_params.get("page_size", self.default_page_size)
            )
        except (TypeError, ValueError):
            page_size = self.default_page_size
        page_size = max(1, min(page_size, self.max_page_size))

        paginator = Paginator(subscriptions, page_size)
        page_obj = paginator.get_page(request.query_params.get("page", 1))
        page_subscriptions = list(page_obj.object_list)

        user_ids = [subscription.user_id for subscription in page_subscriptions]
        mappings = {
            mapping.user_id: mapping
            for mapping in MauticContactMapping.objects.filter(user_id__in=user_ids)
        }

        user_id_strings = [str(user_id) for user_id in user_ids]
        latest_events = {}
        for event in NewsletterSyncEvent.objects.filter(
            category=category,
            user_id__in=user_id_strings,
        ).order_by("user_id", "-created_at", "-id"):
            latest_events.setdefault(event.user_id, event)

        results = []
        for subscription in page_subscriptions:
            user = subscription.user
            mapping = mappings.get(subscription.user_id)
            latest_event = latest_events.get(str(subscription.user_id))
            full_name = " ".join(
                part
                for part in (
                    str(getattr(user, "first_name", "") or "").strip(),
                    str(getattr(user, "last_name", "") or "").strip(),
                )
                if part
            )
            if latest_event is not None:
                sync_status = latest_event.status
                sync_error = latest_event.last_error
            elif mapping is not None and mapping.last_synced_at is not None:
                sync_status = "succeeded"
                sync_error = ""
            elif mapping is not None:
                sync_status = "mapped"
                sync_error = ""
            else:
                sync_status = "not_synced"
                sync_error = ""

            results.append(
                {
                    "user_id": subscription.user_id,
                    "name": full_name or user.email or getattr(user, "username", ""),
                    "email": user.email,
                    "subscribed": True,
                    "subscribed_at": subscription.subscribed_at,
                    "source": subscription.source,
                    "mautic_contact_id": (
                        mapping.mautic_contact_id if mapping is not None else None
                    ),
                    "last_synced_at": (
                        mapping.last_synced_at if mapping is not None else None
                    ),
                    "sync_status": sync_status,
                    "sync_error": sync_error,
                }
            )

        return Response(
            {
                "category": {
                    "slug": category.slug,
                    "name": category.name,
                    "description": category.description,
                    "is_active": category.is_active,
                    "mautic_segment_id": category.mautic_segment_id or None,
                },
                "count": paginator.count,
                "page": page_obj.number,
                "page_size": page_size,
                "num_pages": paginator.num_pages,
                "results": results,
            },
            status=status.HTTP_200_OK,
        )


class NewsletterAdminCategoryContactAnalyticsView(APIView):
    """Return an ECP-owned Added / Removed / Total contact timeline."""

    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, slug):
        try:
            category = NewsletterCategory.objects.get(slug=slug)
        except NewsletterCategory.DoesNotExist:
            raise Http404

        try:
            start_date, end_date = resolve_contact_timeline_range(
                from_value=request.query_params.get("from"),
                to_value=request.query_params.get("to"),
            )
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        data = build_category_contact_timeline(
            category,
            start_date=start_date,
            end_date=end_date,
        )
        data["category"] = {
            "slug": category.slug,
            "name": category.name,
            "mautic_segment_id": category.mautic_segment_id or None,
        }
        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminCategoryDetailView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def patch(self, request, slug):
        try:
            category = NewsletterCategory.objects.get(slug=slug)
        except NewsletterCategory.DoesNotExist:
            raise Http404

        serializer = NewsletterAdminCategorySerializer(
            category, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)

        try:
            with transaction.atomic():
                category = serializer.save()
                if _mautic_enabled() and str(category.mautic_segment_id or "").strip():
                    client = MauticClient()
                    segment = client.get_segment(category.mautic_segment_id)
                    if not _segment_is_static(segment):
                        raise PermanentMauticError("Mapped Mautic segment is dynamic.")
                    client.update_segment(
                        category.mautic_segment_id,
                        _segment_payload_for_category(category),
                    )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        return Response(NewsletterAdminCategorySerializer(category).data)

    def delete(self, request, slug):
        try:
            category = NewsletterCategory.objects.get(slug=slug)
        except NewsletterCategory.DoesNotExist:
            raise Http404

        try:
            with transaction.atomic():
                category.is_active = False
                category.save(update_fields=["is_active", "updated_at"])
                if _mautic_enabled() and str(category.mautic_segment_id or "").strip():
                    MauticClient().update_segment(
                        category.mautic_segment_id,
                        {"isPublished": False},
                    )
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)
        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminCategoryLinkMauticSegmentView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def post(self, request, slug):
        """Link a Mautic segment to a newsletter category."""
        try:
            category = NewsletterCategory.objects.get(slug=slug)
        except NewsletterCategory.DoesNotExist:
            raise Http404

        segment_id = request.data.get('mautic_segment_id', '').strip()
        if not segment_id:
            return Response(
                {'error': 'mautic_segment_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            client = MauticClient()
            segment = client.get_segment(segment_id)
            if not _segment_is_static(segment):
                return Response(
                    {'error': 'Dynamic Mautic segments cannot be linked to newsletter subscription lists.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            mapped = _mapped_category_for_segment(segment_id, exclude_category=category)
            if mapped is not None:
                return Response(
                    {'error': f'Mautic segment is already mapped to newsletter category {mapped.slug}.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            with transaction.atomic():
                mapping_changed = str(category.mautic_segment_id or "").strip() != segment_id
                category.mautic_segment_id = segment_id
                category.save(update_fields=['mautic_segment_id', 'updated_at'])
                queued = _queue_category_reconciliation(category) if mapping_changed else 0
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        data = NewsletterAdminCategorySerializer(category).data
        data["reconciliation_queued"] = queued
        return Response(data, status=status.HTTP_200_OK)


class NewsletterAdminMauticSegmentListView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        try:
            segments = _segments_from_response(MauticClient().list_segments(limit=200))
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        mapped_categories = _mapped_categories_by_segment_id()
        return Response(
            [
                _normalize_mautic_segment(segment, mapped_categories)
                for segment in segments
            ],
            status=status.HTTP_200_OK,
        )

    def post(self, request):
        try:
            payload = _parse_native_segment_payload(request.data)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            segment = MauticClient().create_segment(payload)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _native_segment_provider_error_response(exc)

        return Response(
            _normalize_mautic_segment(segment),
            status=status.HTTP_201_CREATED,
        )


class NewsletterAdminMauticSegmentDetailView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request, segment_id):
        try:
            segment = MauticClient().get_segment(segment_id)
        except PermanentMauticError as exc:
            if "HTTP 404" in str(exc):
                raise Http404
            return _provider_error_response(exc)
        except TemporaryMauticError as exc:
            return _provider_error_response(exc)

        return Response(
            _normalize_mautic_segment(segment),
            status=status.HTTP_200_OK,
        )

    def patch(self, request, segment_id):
        protected_response = _ensure_native_segment_is_not_managed(segment_id)
        if protected_response is not None:
            return protected_response

        try:
            payload = _parse_native_segment_payload(request.data, partial=True)
        except ValueError as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            segment = MauticClient().update_segment(segment_id, payload)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _native_segment_provider_error_response(exc)

        return Response(
            _normalize_mautic_segment(segment),
            status=status.HTTP_200_OK,
        )

    def delete(self, request, segment_id):
        mapped = _mapped_category_for_segment(segment_id)
        if mapped is not None:
            return Response(
                {
                    "detail": (
                        "This Mautic segment is managed by Subscription List "
                        f"'{mapped.name}' and cannot be deleted here."
                    )
                },
                status=status.HTTP_409_CONFLICT,
            )

        try:
            MauticClient().delete_segment(segment_id)
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _native_segment_provider_error_response(exc)

        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminMauticSegmentContactsView(APIView):
    permission_classes = [IsStaffOrSuperuser]
    default_page_size = 25
    max_page_size = 100

    def get(self, request, segment_id):
        try:
            page = max(1, int(request.query_params.get("page", 1)))
        except (TypeError, ValueError):
            page = 1
        try:
            page_size = int(
                request.query_params.get("page_size", self.default_page_size)
            )
        except (TypeError, ValueError):
            page_size = self.default_page_size
        page_size = max(1, min(page_size, self.max_page_size))
        search = str(request.query_params.get("search", "") or "").strip()
        params = {
            "start": (page - 1) * page_size,
            "limit": page_size,
        }
        if search:
            params["search"] = search

        try:
            client = MauticClient()
            data = client.list_segment_contacts_via_bridge(segment_id, **params)
        except PermanentMauticError as exc:
            if "HTTP 404" in str(exc):
                raise Http404
            return _native_segment_provider_error_response(exc)
        except TemporaryMauticError as exc:
            return _native_segment_provider_error_response(exc)

        contacts = _contacts_from_segment_response(data)
        try:
            count = max(0, int(data.get("total", len(contacts))))
        except (TypeError, ValueError):
            count = len(contacts)

        return Response(
            {
                "segment": _normalize_mautic_segment(data.get("segment") or {}),
                "count": count,
                "page": page,
                "page_size": page_size,
                "num_pages": math.ceil(count / page_size) if count else 0,
                "results": [
                    _normalize_segment_contact(contact)
                    for contact in contacts
                ],
            },
            status=status.HTTP_200_OK,
        )

    def post(self, request, segment_id):
        try:
            contact_id = _parse_positive_id(
                request.data.get("contact_id"),
                field_name="contact_id",
            )
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        try:
            client = MauticClient()
            segment = client.get_segment(segment_id)
            protected_response = _segment_membership_protection_response(segment)
            if protected_response is not None:
                return protected_response
            client.get_contact(contact_id)
            client.add_contact_to_segment(segment_id, contact_id)
        except PermanentMauticError as exc:
            if "HTTP 404" in str(exc):
                raise Http404
            return _native_segment_provider_error_response(exc)
        except TemporaryMauticError as exc:
            return _native_segment_provider_error_response(exc)

        return Response(
            {
                "segment_id": str(segment_id),
                "contact_id": contact_id,
                "added": True,
            },
            status=status.HTTP_200_OK,
        )


class NewsletterAdminMauticSegmentContactDetailView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def delete(self, request, segment_id, contact_id):
        try:
            normalized_contact_id = _parse_positive_id(
                contact_id,
                field_name="contact_id",
            )
            client = MauticClient()
            segment = client.get_segment(segment_id)
            protected_response = _segment_membership_protection_response(segment)
            if protected_response is not None:
                return protected_response
            client.remove_contact_from_segment(segment_id, normalized_contact_id)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except PermanentMauticError as exc:
            if "HTTP 404" in str(exc):
                raise Http404
            return _native_segment_provider_error_response(exc)
        except TemporaryMauticError as exc:
            return _native_segment_provider_error_response(exc)

        return Response(status=status.HTTP_204_NO_CONTENT)


class NewsletterAdminCategorySyncMauticView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def post(self, request, slug):
        try:
            category = NewsletterCategory.objects.get(slug=slug)
        except NewsletterCategory.DoesNotExist:
            raise Http404

        if not _mautic_enabled():
            return Response(
                {"detail": "Mautic newsletter synchronization is disabled."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            with transaction.atomic():
                previous_segment_id = str(category.mautic_segment_id or "").strip()
                segment_id, mapping_changed = _ensure_category_segment(category)
                mapped = _mapped_category_for_segment(segment_id, exclude_category=category)
                if mapped is not None:
                    raise PermanentMauticError(
                        "Mautic segment is already mapped to another newsletter category."
                    )
                queued = _queue_category_reconciliation(category) if mapping_changed or previous_segment_id != segment_id else 0
        except (TemporaryMauticError, PermanentMauticError) as exc:
            return _provider_error_response(exc)

        data = NewsletterAdminCategorySerializer(category).data
        data["reconciliation_queued"] = queued
        return Response(data, status=status.HTTP_200_OK)
