from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import EventViewSet, EventRegistrationViewSet, RecordingWebhookView, EventSessionViewSet
from .speed_networking_views import SpeedNetworkingSessionViewSet, SpeedNetworkingQueueViewSet
from .webhooks import realtime_webhook

router = DefaultRouter()
router.register(r"events", EventViewSet, basename="event")
router.register(r"event-registrations", EventRegistrationViewSet, basename="eventregistration")


urlpatterns = router.urls + [
    path("events/recording/webhook/", RecordingWebhookView.as_view(), name="dyte-recording-webhook"),
    path("realtime/webhook/", realtime_webhook, name="realtime-webhook"),
    path(
        "realtimekit/webhooks/chat-synced/",
        realtime_webhook,
        name="realtimekit-chat-webhook",
    ),

    # --- Speed Networking Sessions ---
    path(
        "events/<int:event_id>/speed-networking/",
        SpeedNetworkingSessionViewSet.as_view({'get': 'list', 'post': 'create'}),
        name='speed-networking-list'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/",
        SpeedNetworkingSessionViewSet.as_view({'get': 'retrieve', 'patch': 'partial_update'}),
        name='speed-networking-detail'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/start/",
        SpeedNetworkingSessionViewSet.as_view({'post': 'start'}),
        name='speed-networking-start'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/stop/",
        SpeedNetworkingSessionViewSet.as_view({'post': 'stop'}),
        name='speed-networking-stop'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/stats/",
        SpeedNetworkingSessionViewSet.as_view({'get': 'stats'}),
        name='speed-networking-stats'
    ),

    # --- Speed Networking Queue ---
    path(
        "events/<int:event_id>/speed-networking/<int:session_id>/join/",
        SpeedNetworkingQueueViewSet.as_view({'post': 'join'}),
        name='speed-networking-join'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:session_id>/leave/",
        SpeedNetworkingQueueViewSet.as_view({'post': 'leave'}),
        name='speed-networking-leave'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:session_id>/my-match/",
        SpeedNetworkingQueueViewSet.as_view({'get': 'my_match'}),
        name='speed-networking-my-match'
    ),
    path(
        "events/<int:event_id>/speed-networking/matches/<int:match_id>/next/",
        SpeedNetworkingQueueViewSet.as_view({'post': 'next_match'}),
        name='speed-networking-next-match'
    ),

    # --- Event Sessions ---
    path(
        "events/<int:event_id>/sessions/",
        EventSessionViewSet.as_view({'get': 'list', 'post': 'create'}),
        name='event-session-list'
    ),
    path(
        "events/<int:event_id>/sessions/<int:pk>/",
        EventSessionViewSet.as_view({'get': 'retrieve', 'patch': 'partial_update', 'delete': 'destroy'}),
        name='event-session-detail'
    ),
    path(
        "events/<int:event_id>/sessions/<int:pk>/start-live/",
        EventSessionViewSet.as_view({'post': 'start_live'}),
        name='event-session-start-live'
    ),
    path(
        "events/<int:event_id>/sessions/<int:pk>/end-live/",
        EventSessionViewSet.as_view({'post': 'end_live'}),
        name='event-session-end-live'
    ),
    path(
        "events/<int:event_id>/sessions/<int:pk>/join/",
        EventSessionViewSet.as_view({'post': 'join_session'}),
        name='event-session-join'
    ),
    path(
        "events/<int:event_id>/sessions/<int:pk>/attendances/",
        EventSessionViewSet.as_view({'get': 'list_attendances'}),
        name='event-session-attendances'
    ),
]