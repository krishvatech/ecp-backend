from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import (
    EventViewSet,
    PublicEventDetailView,
    EventRegistrationViewSet,
    RecordingWebhookView,
    EventSessionViewSet,
    VirtualSpeakerViewSet,
    SaleorChannelListView,
    SaleorChannelSyncView,
    SaleorChannelCreateView,
    SaleorChannelUpdateView,
    SaleorChannelDeleteView,
    SaleorChannelOptionsView,
    SaleorWarehouseListView,
    SaleorWarehouseSyncView,
    SaleorWarehouseCreateView,
    SaleorWarehouseUpdateView,
    SaleorWarehouseDeleteView,
    SaleorWarehouseOptionsView,
    SaleorShippingZoneListView,
    SaleorShippingZoneSyncView,
    SaleorShippingZoneCreateView,
    SaleorShippingZoneUpdateView,
    SaleorShippingZoneDeleteView,
    SaleorShippingZoneOptionsView,
    SaleorProductTypeListView,
    SaleorProductTypeSyncView,
    SaleorProductTypeCreateView,
    SaleorProductTypeUpdateView,
    SaleorProductTypeDeleteView,
    SaleorProductTypeOptionsView,
    SaleorStaffUserListView,
    SaleorStaffUserSyncView,
    SaleorStaffUserActiveView,
    SaleorStaffUserPermissionGroupsView,
    SaleorPermissionGroupListView,
    SaleorPermissionGroupSyncView,
    SaleorPermissionGroupCreateView,
    SaleorPermissionGroupUpdateView,
    SaleorPermissionGroupDeleteView,
)
from .guest_views import (
    GuestJoinView,
    GuestVerifyOTPView,
    ResendGuestOTPView,
    GuestRegisterView,
    GuestRegisterLinkView,
    GuestProfileUpdateView,
    GuestProfileDetailView,
)
from .speed_networking_views import SpeedNetworkingSessionViewSet, SpeedNetworkingQueueViewSet
from .webhooks import realtime_webhook
from .wordpress_event_webhook import WordPressEventWebhookView
from .saleor_webhooks import SaleorProductWebhookView

router = DefaultRouter()
router.register(r"events", EventViewSet, basename="event")
router.register(r"event-registrations", EventRegistrationViewSet, basename="eventregistration")
router.register(r"virtual-speakers", VirtualSpeakerViewSet, basename="virtual-speaker")


urlpatterns = [
    # WordPress Events Calendar sync webhook
    path("events/wordpress/webhook/", WordPressEventWebhookView.as_view(), name="wp-event-webhook"),

    # Saleor Product sync webhook
    path("webhooks/saleor/product/", SaleorProductWebhookView.as_view(), name="saleor-product-webhook"),

    # Public event landing page endpoint
    path("events/public/<str:slug>/", PublicEventDetailView.as_view(), name="event-public-detail"),

    # Guest attendee endpoints
    path("events/<int:pk>/guest-join/", GuestJoinView.as_view(), name="guest-join"),
    path("events/<int:pk>/guest-verify-otp/", GuestVerifyOTPView.as_view(), name="guest-verify-otp"),
    path("events/<int:pk>/guest-resend-otp/", ResendGuestOTPView.as_view(), name="guest-resend-otp"),
    path("events/<int:pk>/guest-profile/", GuestProfileUpdateView.as_view(), name="guest-profile-update"),
    path("events/<int:event_id>/guests/<int:guest_id>/profile/", GuestProfileDetailView.as_view(), name="guest-profile-detail"),
    path("auth/guest-register/", GuestRegisterView.as_view(), name="guest-register"),
    path("auth/guest-register/link/", GuestRegisterLinkView.as_view(), name="guest-register-link"),
] + router.urls + [
    path("events/recording/webhook/", RecordingWebhookView.as_view(), name="rtk-recording-webhook"),
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
        "events/<int:event_id>/speed-networking/<int:pk>/extend-duration/",
        SpeedNetworkingSessionViewSet.as_view({'post': 'extend_duration'}),
        name='speed-networking-extend-duration'
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
        "events/<int:event_id>/speed-networking/<int:pk>/interest-tags/",
        SpeedNetworkingSessionViewSet.as_view({'get': 'interest_tags', 'post': 'interest_tags'}),
        name='speed-networking-interest-tags'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/interest-tags/<int:tag_id>/",
        SpeedNetworkingSessionViewSet.as_view({'delete': 'delete_interest_tag'}),
        name='speed-networking-delete-interest-tag'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/start_config_comparison/",
        SpeedNetworkingQueueViewSet.as_view({'post': 'start_config_comparison'}),
        name='speed-networking-start-config-comparison'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/get_comparison_results/",
        SpeedNetworkingQueueViewSet.as_view({'get': 'get_comparison_results'}),
        name='speed-networking-get-comparison-results'
    ),
    path(
        "events/<int:event_id>/speed-networking/<int:pk>/finalize_comparison/",
        SpeedNetworkingQueueViewSet.as_view({'post': 'finalize_comparison'}),
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
        "events/<int:event_id>/speed-networking/<int:session_id>/navigation-state/",
        SpeedNetworkingQueueViewSet.as_view({'get': 'navigation_state'}),
        name='speed-networking-navigation-state'
    ),
    path(
        "events/<int:event_id>/speed-networking/matches/<int:match_id>/next/",
        SpeedNetworkingQueueViewSet.as_view({'post': 'next_match'}),
        name='speed-networking-next-match'
    ),
    path(
        "events/<int:event_id>/speed-networking/matches/<int:match_id>/request-extension/",
        SpeedNetworkingQueueViewSet.as_view({'post': 'request_extension'}),
        name='speed-networking-request-extension'
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

    # Saleor Manager endpoints
    path("events/saleor/channels/", SaleorChannelListView.as_view(), name="saleor-channel-list"),
    path("events/saleor/channels/sync/", SaleorChannelSyncView.as_view(), name="saleor-channel-sync"),
    path("events/saleor/channels/create/", SaleorChannelCreateView.as_view(), name="saleor-channel-create"),
    path("events/saleor/channels/<int:pk>/", SaleorChannelUpdateView.as_view(), name="saleor-channel-update"),
    path("events/saleor/channels/<int:pk>/delete/", SaleorChannelDeleteView.as_view(), name="saleor-channel-delete"),
    path("events/saleor/channel-options/", SaleorChannelOptionsView.as_view(), name="saleor-channel-options"),

    path("events/saleor/warehouses/", SaleorWarehouseListView.as_view(), name="saleor-warehouse-list"),
    path("events/saleor/warehouses/sync/", SaleorWarehouseSyncView.as_view(), name="saleor-warehouse-sync"),
    path("events/saleor/warehouses/create/", SaleorWarehouseCreateView.as_view(), name="saleor-warehouse-create"),
    path("events/saleor/warehouses/<int:pk>/", SaleorWarehouseUpdateView.as_view(), name="saleor-warehouse-update"),
    path("events/saleor/warehouses/<int:pk>/delete/", SaleorWarehouseDeleteView.as_view(), name="saleor-warehouse-delete"),
    path("events/saleor/warehouse-options/", SaleorWarehouseOptionsView.as_view(), name="saleor-warehouse-options"),

    path("events/saleor/shipping-zones/", SaleorShippingZoneListView.as_view(), name="saleor-shipping-zone-list"),
    path("events/saleor/shipping-zones/sync/", SaleorShippingZoneSyncView.as_view(), name="saleor-shipping-zone-sync"),
    path("events/saleor/shipping-zones/create/", SaleorShippingZoneCreateView.as_view(), name="saleor-shipping-zone-create"),
    path("events/saleor/shipping-zones/<int:pk>/", SaleorShippingZoneUpdateView.as_view(), name="saleor-shipping-zone-update"),
    path("events/saleor/shipping-zones/<int:pk>/delete/", SaleorShippingZoneDeleteView.as_view(), name="saleor-shipping-zone-delete"),
    path("events/saleor/shipping-zone-options/", SaleorShippingZoneOptionsView.as_view(), name="saleor-shipping-zone-options"),

    path("events/saleor/product-types/", SaleorProductTypeListView.as_view(), name="saleor-product-type-list"),
    path("events/saleor/product-types/sync/", SaleorProductTypeSyncView.as_view(), name="saleor-product-type-sync"),
    path("events/saleor/product-types/create/", SaleorProductTypeCreateView.as_view(), name="saleor-product-type-create"),
    path("events/saleor/product-types/<int:pk>/", SaleorProductTypeUpdateView.as_view(), name="saleor-product-type-update"),
    path("events/saleor/product-types/<int:pk>/delete/", SaleorProductTypeDeleteView.as_view(), name="saleor-product-type-delete"),
    path("events/saleor/product-type-options/", SaleorProductTypeOptionsView.as_view(), name="saleor-product-type-options"),

    path("events/saleor/staff-users/", SaleorStaffUserListView.as_view(), name="saleor-staff-user-list"),
    path("events/saleor/staff-users/sync/", SaleorStaffUserSyncView.as_view(), name="saleor-staff-user-sync"),
    path("events/saleor/staff-users/<int:pk>/active/", SaleorStaffUserActiveView.as_view(), name="saleor-staff-user-active"),
    path("events/saleor/staff-users/<int:pk>/permission-groups/", SaleorStaffUserPermissionGroupsView.as_view(), name="saleor-staff-user-permission-groups"),

    path("events/saleor/permission-groups/", SaleorPermissionGroupListView.as_view(), name="saleor-permission-group-list"),
    path("events/saleor/permission-groups/sync/", SaleorPermissionGroupSyncView.as_view(), name="saleor-permission-group-sync"),
    path("events/saleor/permission-groups/create/", SaleorPermissionGroupCreateView.as_view(), name="saleor-permission-group-create"),
    path("events/saleor/permission-groups/<int:pk>/", SaleorPermissionGroupUpdateView.as_view(), name="saleor-permission-group-update"),
    path("events/saleor/permission-groups/<int:pk>/delete/", SaleorPermissionGroupDeleteView.as_view(), name="saleor-permission-group-delete"),
]
