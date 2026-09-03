from django.http import Http404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
import logging

from moderation.permissions import IsStaffOrSuperuser

from .admin_serializers import (
    NewsletterAudienceAdminSerializer,
    NewsletterAdminCategorySerializer,
    NewsletterCampaignScheduleSerializer,
    NewsletterCampaignSerializer,
    NewsletterCampaignTestEmailSerializer,
)
from .analytics_services import get_campaign_analytics
from .campaign_services import (
    CampaignNotEditable,
    CampaignScheduleNotAllowed,
    cancel_scheduled_campaign,
    create_campaign,
    delete_draft_campaign,
    get_campaign,
    list_active_categories,
    list_campaigns,
    request_campaign_send,
    schedule_campaign,
    send_campaign_test_email,
    sync_campaign_draft_to_mautic,
    update_campaign,
)
from .models import NewsletterAudience, NewsletterCampaign, NewsletterCategory
from .mautic import MauticClient, PermanentMauticError, TemporaryMauticError

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
        serializer = NewsletterAdminCategorySerializer(
            list_active_categories(),
            many=True,
        )
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = NewsletterAdminCategorySerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # Auto-generate slug from name
        from django.utils.text import slugify
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

        category = NewsletterCategory.objects.create(
            name=name,
            slug=slug,
            description=serializer.validated_data.get('description', ''),
            is_active=True,
            mautic_segment_id='',
        )

        logger.info(f"Created category {slug}. Mautic segment needs to be linked manually via /link-mautic-segment/ endpoint.")

        return Response(
            NewsletterAdminCategorySerializer(category).data,
            status=status.HTTP_201_CREATED,
        )


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

        # Note: Mautic segment updates are not supported in this version of Mautic's API
        # Segments are read-only and must be edited directly in Mautic UI
        category = serializer.save()

        if 'name' in request.data or 'description' in request.data:
            if category.mautic_segment_id:
                logger.info(
                    f"Category {slug} updated. "
                    f"Note: To update the Mautic segment '{category.mautic_segment_id}', "
                    f"please edit it directly in Mautic UI (Contacts → Segments)"
                )

        return Response(NewsletterAdminCategorySerializer(category).data)

    def delete(self, request, slug):
        try:
            category = NewsletterCategory.objects.get(slug=slug)
        except NewsletterCategory.DoesNotExist:
            raise Http404

        category.is_active = False
        category.save()
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

        # Optional: validate segment exists in Mautic
        try:
            from .mautic import MauticClient
            client = MauticClient()
            # Try to fetch the segment to verify it exists
            client._request('GET', f'segments/{segment_id}')
        except Exception as e:
            return Response(
                {'error': f'Mautic segment validation failed: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Link the segment
        category.mautic_segment_id = segment_id
        category.save(update_fields=['mautic_segment_id', 'updated_at'])

        return Response(
            NewsletterAdminCategorySerializer(category).data,
            status=status.HTTP_200_OK
        )
