from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import (
    ReportViewSet, ModerationQueueView, ModerationActionView,
    ProfileReportViewSet, ProfileModerationQueueView, ProfileModerationActionView
)

router = DefaultRouter()
router.register(r"reports", ReportViewSet, basename="moderation-reports")

urlpatterns = [
    path("queue/", ModerationQueueView.as_view(), name="moderation-queue"),
    path("actions/", ModerationActionView.as_view(), name="moderation-actions"),

    # Profile Moderation
    path("reports/profile/", ProfileReportViewSet.as_view({'post': 'create'}), name="profile-report-create"),
    path("profiles/queue/", ProfileModerationQueueView.as_view(), name="profile-moderation-queue"),
    path("profiles/action/", ProfileModerationActionView.as_view(), name="profile-moderation-action"),
]

urlpatterns += router.urls
