from django.http import Http404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from moderation.permissions import IsStaffOrSuperuser

from .admin_serializers import (
    NewsletterAdminCategorySerializer,
    NewsletterCampaignSerializer,
)
from .campaign_services import (
    CampaignNotEditable,
    create_campaign,
    delete_draft_campaign,
    get_campaign,
    list_active_categories,
    list_campaigns,
    sync_campaign_to_mautic,
    update_campaign,
)
from .models import NewsletterCampaign


def _get_campaign_or_404(uuid):
    try:
        return get_campaign(uuid)
    except (NewsletterCampaign.DoesNotExist, ValueError):
        raise Http404


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


class NewsletterAdminCampaignSyncView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def post(self, request, uuid):
        campaign = sync_campaign_to_mautic(
            _get_campaign_or_404(uuid),
            actor=request.user,
        )
        serializer = NewsletterCampaignSerializer(campaign)
        return Response(serializer.data, status=status.HTTP_200_OK)


class NewsletterAdminCategoryListView(APIView):
    permission_classes = [IsStaffOrSuperuser]

    def get(self, request):
        serializer = NewsletterAdminCategorySerializer(
            list_active_categories(),
            many=True,
        )
        return Response(serializer.data, status=status.HTTP_200_OK)
