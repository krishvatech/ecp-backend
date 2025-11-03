from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import EventViewSet, EventRegistrationViewSet, EventRecordingViewSet, RecordingWebhookView

router = DefaultRouter()
router.register(r"events", EventViewSet, basename="event")
router.register(r"event-registrations", EventRegistrationViewSet, basename="eventregistration")
router.register(r"event-recordings", EventRecordingViewSet, basename="eventrecording")  # NEW

urlpatterns = router.urls + [
    path("events/recording/webhook/", RecordingWebhookView.as_view(), name="recording-webhook"),  # NEW
]