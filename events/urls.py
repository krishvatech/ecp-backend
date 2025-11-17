from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import EventViewSet, EventRegistrationViewSet,RecordingWebhookView

router = DefaultRouter()
router.register(r"events", EventViewSet, basename="event")
router.register(r"event-registrations", EventRegistrationViewSet, basename="eventregistration")


urlpatterns = router.urls + [
    path("events/recording/webhook/", RecordingWebhookView.as_view(), name="dyte-recording-webhook"),  # NEW
]