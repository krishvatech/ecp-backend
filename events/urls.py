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
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/queue/",
        SpeedNetworkingSessionViewSet.as_view({'get': 'queue'}),
        name='speed-networking-queue'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/remove-from-queue/<int:user_id>/",
        SpeedNetworkingSessionViewSet.as_view({'post': 'remove_from_queue'}),
        name='speed-networking-remove-from-queue'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/create_rule/",
        SpeedNetworkingSessionViewSet.as_view({'post': 'create_rule'}),
        name='speed-networking-create-rule'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/rules/",
        SpeedNetworkingSessionViewSet.as_view({'get': 'rules'}),
        name='speed-networking-rules'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/set_matching_strategy/",
        SpeedNetworkingSessionViewSet.as_view({'post': 'set_matching_strategy'}),
        name='speed-networking-set-matching-strategy'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/update_criteria/",
        SpeedNetworkingSessionViewSet.as_view({'patch': 'update_criteria'}),
        name='speed-networking-update-criteria'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/test_match_score/",
        SpeedNetworkingSessionViewSet.as_view({'post': 'test_match_score'}),
        name='speed-networking-test-match-score'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/match_preview/",
        SpeedNetworkingSessionViewSet.as_view({'get': 'match_preview'}),
        name='speed-networking-match-preview'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/recalculate_matches/",
        SpeedNetworkingSessionViewSet.as_view({'post': 'recalculate_matches'}),
        name='speed-networking-recalculate-matches'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/suggest_weights/",
        SpeedNetworkingSessionViewSet.as_view({'get': 'suggest_weights'}),
        name='speed-networking-suggest-weights'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/match_quality/",
        SpeedNetworkingSessionViewSet.as_view({'get': 'match_quality'}),
        name='speed-networking-match-quality'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/start_config_comparison/",
        SpeedNetworkingSessionViewSet.as_view({'post': 'start_config_comparison'}),
        name='speed-networking-start-config-comparison'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/get_comparison_results/",
        SpeedNetworkingSessionViewSet.as_view({'get': 'get_comparison_results'}),
        name='speed-networking-get-comparison-results'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/finalize_comparison/",
        SpeedNetworkingSessionViewSet.as_view({'post': 'finalize_comparison'}),
        name='speed-networking-finalize-comparison'
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
    path(
        "events/<int:event_id>/speed-networking/<int:session_id>/user-matches/",
        SpeedNetworkingQueueViewSet.as_view({'get': 'user_matches'}),
        name='speed-networking-user-matches'
    ),

    # --- Event Sessions ---
    path(
        "events/<int:event_id>/sessions/",
        EventSessionViewSet.as_view({'get': 'list', 'post': 'create'}),
        name='event-session-list'
    ),
    path(
        "events/<int:event_id>/sessions/<int:pk>/",
        EventSessionViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}),
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