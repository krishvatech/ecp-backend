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

        mapped_ids = set(
            NewsletterCategory.objects.exclude(mautic_segment_id="")
            .values_list("mautic_segment_id", flat=True)
        )
        return Response(
            [
                {
                    "id": str(segment.get("id")),
                    "name": segment.get("name") or "",
                    "alias": segment.get("alias") or "",
                    "description": segment.get("description") or "",
                    "isPublished": _normalize_provider_bool(
                        segment.get("isPublished", segment.get("is_published", False))
                    ),
                    "is_static": _segment_is_static(segment),
                    "is_dynamic": not _segment_is_static(segment),
                    "mapped_in_ecp": str(segment.get("id")) in mapped_ids,
                }
                for segment in segments
            ],
            status=status.HTTP_200_OK,
        )


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
