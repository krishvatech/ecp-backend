from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import EventViewSet, EventRegistrationViewSet, RecordingWebhookView
from .webhooks import realtime_webhook

router = DefaultRouter()
router.register(r"events", EventViewSet, basename="event")
router.register(r"event-registrations", EventRegistrationViewSet, basename="eventregistration")


urlpatterns = router.urls + [
    path("events/recording/webhook/", RecordingWebhookView.as_view(), name="dyte-recording-webhook"),  # NEW
    path("realtime/webhook/", realtime_webhook, name="realtime-webhook"),
    path(
        "realtimekit/webhooks/chat-synced/",
        realtime_webhook,
        name="realtimekit-chat-webhook",
    ),
]