from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import (
    EventViewSet,
    PublicEventDetailView,
    EventRegistrationViewSet,
    EventBadgeLabelViewSet,
    RecordingWebhookView,
    EventSessionViewSet,
    SessionBreakViewSet,
    VirtualSpeakerViewSet,
    SeriesViewSet,
    PostAcceptanceFormAssignmentViewSet,
    PostAcceptanceFormAssignmentAdminViewSet,
    EventApplicationTrackViewSet,
    EventRoleViewSet,
    FormFieldViewSet,
    TrackPricingTierViewSet,
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
    EventScheduleView,
    SessionBookmarkToggleView,
)
from .admin_promotional_profiles import (
    PromotionalProfileAdminViewSet,
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
from .networking_views import (
    EventNetworkingSettingsView,
    NetworkingTableViewSet,
    NetworkingMeetingAvailabilityView,
    NetworkingMeetingListCreateView,
    NetworkingMeetingMyView,
    NetworkingMeetingAcceptView,
    NetworkingMeetingDeclineView,
    NetworkingMeetingSuggestView,
    NetworkingMeetingCancelView,
    NetworkingMeetingRescheduleView,
    NetworkingMeetingMarkSeenView,
)
from .views_participant_directory import ParticipantDirectoryViewSet
from .webhooks import realtime_webhook
from .wordpress_event_webhook import WordPressEventWebhookView
from .saleor_webhooks import SaleorProductWebhookView

router = DefaultRouter()
router.register(r"events", EventViewSet, basename="event")
router.register(r"event-registrations", EventRegistrationViewSet, basename="eventregistration")
router.register(r"event-badge-labels", EventBadgeLabelViewSet, basename="eventbadgelabel")
router.register(r"series", SeriesViewSet, basename="series")
router.register(r"virtual-speakers", VirtualSpeakerViewSet, basename="virtual-speaker")
router.register(r"post-acceptance-form-assignments", PostAcceptanceFormAssignmentViewSet, basename="post-acceptance-form-assignment")


urlpatterns = [
    # WordPress Events Calendar sync webhook
    path("events/wordpress/webhook/", WordPressEventWebhookView.as_view(), name="wp-event-webhook"),

    # Saleor Product sync webhook
    path("webhooks/saleor/product/", SaleorProductWebhookView.as_view(), name="saleor-product-webhook"),

    # Public event landing page endpoint
    path("events/public/<str:slug>/", PublicEventDetailView.as_view(), name="event-public-detail"),

    # Participant Directory (public, no auth required for in-person events)
    path(
        "events/<int:event_id>/participants/directory/",
        ParticipantDirectoryViewSet.as_view({'get': 'directory'}),
        name='participant-directory'
    ),
    path(
        "events/<int:event_id>/participants/search/",
        ParticipantDirectoryViewSet.as_view({'get': 'search'}),
        name='participant-search'
    ),

    # Guest attendee endpoints
    path("events/<int:pk>/guest-join/", GuestJoinView.as_view(), name="guest-join"),
    path("events/<int:pk>/guest-verify-otp/", GuestVerifyOTPView.as_view(), name="guest-verify-otp"),
    path("events/<int:pk>/guest-resend-otp/", ResendGuestOTPView.as_view(), name="guest-resend-otp"),
    path("events/<int:pk>/guest-profile/", GuestProfileUpdateView.as_view(), name="guest-profile-update"),
    path("events/<int:event_id>/guests/<int:guest_id>/profile/", GuestProfileDetailView.as_view(), name="guest-profile-detail"),
    path("auth/guest-register/", GuestRegisterView.as_view(), name="guest-register"),
    path("auth/guest-register/link/", GuestRegisterLinkView.as_view(), name="guest-register-link"),
] + router.urls + [
    # Admin form assignments endpoints
    path(
        "events/<int:event_id>/post-acceptance-form-assignments-admin/",
        PostAcceptanceFormAssignmentAdminViewSet.as_view({
            'get': 'list',
            'post': 'send_reminders'
        }),
        name='admin-form-assignments-list'
    ),
    path(
        "events/<int:event_id>/post-acceptance-form-assignments-admin/send-reminders/",
        PostAcceptanceFormAssignmentAdminViewSet.as_view({'post': 'send_reminders'}),
        name='admin-form-assignments-send-reminders'
    ),
    path(
        "events/<int:event_id>/post-acceptance-form-assignments-admin/export/",
        PostAcceptanceFormAssignmentAdminViewSet.as_view({'post': 'export'}),
        name='admin-form-assignments-export'
    ),
    path(
        "events/<int:event_id>/post-acceptance-form-assignments-admin/export-promotional/",
        PostAcceptanceFormAssignmentAdminViewSet.as_view({'post': 'export_promotional'}),
        name='admin-form-assignments-export-promotional'
    ),
    path(
        "events/<int:event_id>/post-acceptance-form-assignments-admin/export-promotional-completed/",
        PostAcceptanceFormAssignmentAdminViewSet.as_view({'get': 'export_promotional_completed'}),
        name='admin-form-assignments-export-promotional-completed'
    ),
    path(
        "events/<int:event_id>/post-acceptance-form-assignments-admin/export-promotional-speakers/",
        PostAcceptanceFormAssignmentAdminViewSet.as_view({'get': 'export_speakers'}),
        name='admin-form-assignments-export-speakers'
    ),
    path(
        "events/<int:event_id>/post-acceptance-form-assignments-admin/export-promotional-sponsors/",
        PostAcceptanceFormAssignmentAdminViewSet.as_view({'get': 'export_sponsors'}),
        name='admin-form-assignments-export-sponsors'
    ),
    path(
        "events/<int:event_id>/post-acceptance-form-assignments-admin/export-promotional-startups/",
        PostAcceptanceFormAssignmentAdminViewSet.as_view({'get': 'export_startups'}),
        name='admin-form-assignments-export-startups'
    ),
    path(
        "events/<int:event_id>/post-acceptance-form-assignments-admin/export-promotional-investors/",
        PostAcceptanceFormAssignmentAdminViewSet.as_view({'get': 'export_investors'}),
        name='admin-form-assignments-export-investors'
    ),
    path(
        "events/<int:event_id>/post-acceptance-form-assignments-admin/summary/",
        PostAcceptanceFormAssignmentAdminViewSet.as_view({'get': 'summary'}),
        name='admin-form-assignments-summary'
    ),
    path(
        "events/<int:event_id>/post-acceptance-form-assignments-admin/<int:pk>/",
        PostAcceptanceFormAssignmentAdminViewSet.as_view({
            'get': 'retrieve'
        }),
        name='admin-form-assignments-detail'
    ),
    path(
        "events/<int:event_id>/post-acceptance-form-assignments-admin/<int:pk>/details/",
        PostAcceptanceFormAssignmentAdminViewSet.as_view({'get': 'details'}),
        name='admin-form-assignments-full-details'
    ),
    path(
        "events/<int:event_id>/post-acceptance-form-assignments-admin/<int:pk>/mark-complete/",
        PostAcceptanceFormAssignmentAdminViewSet.as_view({'post': 'mark_complete'}),
        name='admin-form-assignments-mark-complete'
    ),

    # Application Tracks Endpoints
    path(
        "events/<int:event_id>/application-tracks/",
        EventApplicationTrackViewSet.as_view({
            'get': 'list',
            'post': 'create'
        }),
        name='application-tracks-list'
    ),
    path(
        "events/<int:event_id>/application-tracks/<int:pk>/",
        EventApplicationTrackViewSet.as_view({
            'get': 'retrieve',
            'put': 'update',
            'patch': 'partial_update',
            'delete': 'destroy'
        }),
        name='application-tracks-detail'
    ),

    # Event Roles Endpoints
    path(
        "events/<int:event_id>/roles/",
        EventRoleViewSet.as_view({
            'get': 'list',
            'post': 'create'
        }),
        name='event-roles-list'
    ),
    path(
        "events/<int:event_id>/roles/<int:pk>/",
        EventRoleViewSet.as_view({
            'get': 'retrieve',
            'put': 'update',
            'patch': 'partial_update',
            'delete': 'destroy'
        }),
        name='event-roles-detail'
    ),

    # Form Fields Endpoints (nested under application tracks)
    path(
        "events/<int:event_id>/application-tracks/<int:track_id>/form-fields/",
        FormFieldViewSet.as_view({
            'get': 'list',
            'post': 'create'
        }),
        name='form-fields-list'
    ),
    path(
        "events/<int:event_id>/application-tracks/<int:track_id>/form-fields/<int:pk>/",
        FormFieldViewSet.as_view({
            'get': 'retrieve',
            'put': 'update',
            'patch': 'partial_update',
            'delete': 'destroy'
        }),
        name='form-fields-detail'
    ),

    # FIX 3: Pricing Tiers Endpoints (nested under application tracks)
    path(
        "events/<int:event_id>/application-tracks/<int:track_id>/pricing-tiers/",
        TrackPricingTierViewSet.as_view({
            'get': 'list',
            'post': 'create'
        }),
        name='pricing-tiers-list'
    ),
    path(
        "events/<int:event_id>/application-tracks/<int:track_id>/pricing-tiers/<int:pk>/",
        TrackPricingTierViewSet.as_view({
            'get': 'retrieve',
            'put': 'update',
            'patch': 'partial_update',
            'delete': 'destroy'
        }),
        name='pricing-tiers-detail'
    ),

    # Promotional Profile Admin Endpoints
    path(
        "events/<int:event_id>/promotional-profiles-admin/",
        PromotionalProfileAdminViewSet.as_view({'get': 'list'}),
        name='promotional-profiles-admin-list'
    ),
    path(
        "events/<int:event_id>/promotional-profiles-admin/summary/",
        PromotionalProfileAdminViewSet.as_view({'get': 'summary'}),
        name='promotional-profiles-admin-summary'
    ),
    path(
        "events/<int:event_id>/promotional-profiles-admin/reminders/",
        PromotionalProfileAdminViewSet.as_view({'post': 'bulk_send_reminders'}),
        name='promotional-profiles-admin-reminders'
    ),
    path(
        "events/<int:event_id>/promotional-profiles-admin/mark-complete/",
        PromotionalProfileAdminViewSet.as_view({'post': 'bulk_mark_complete'}),
        name='promotional-profiles-admin-mark-complete'
    ),
    path(
        "events/<int:event_id>/promotional-profiles-admin/export-csv/",
        PromotionalProfileAdminViewSet.as_view({'get': 'export_csv'}),
        name='promotional-profiles-admin-export-csv'
    ),
    path(
        "events/<int:event_id>/promotional-profiles-admin/export-by-role/",
        PromotionalProfileAdminViewSet.as_view({'get': 'export_by_role'}),
        name='promotional-profiles-admin-export-by-role'
    ),
    path(
        "events/<int:event_id>/promotional-profiles-admin/notify-production/",
        PromotionalProfileAdminViewSet.as_view({'post': 'notify_production_lead'}),
        name='promotional-profiles-admin-notify-production'
    ),
    path(
        "events/<int:event_id>/promotional-profiles-admin/missing-assets/",
        PromotionalProfileAdminViewSet.as_view({'get': 'missing_assets_report'}),
        name='promotional-profiles-admin-missing-assets'
    ),
    path(
        "events/<int:event_id>/promotional-profiles-admin/export-production/",
        PromotionalProfileAdminViewSet.as_view({'post': 'export_production'}),
        name='promotional-profiles-admin-export-production'
    ),

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

    # --- Session Breaks ---
    path(
        "events/<int:event_id>/sessions/<int:session_pk>/breaks/",
        SessionBreakViewSet.as_view({'get': 'list', 'post': 'create'}),
        name='session-break-list'
    ),
    path(
        "events/<int:event_id>/sessions/<int:session_pk>/breaks/<int:pk>/",
        SessionBreakViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}),
        name='session-break-detail'
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

    # --- 1:1 Networking Meetings ---
    # Networking Settings
    path(
        "events/<int:event_id>/networking-settings/",
        EventNetworkingSettingsView.as_view(),
        name="networking-settings"
    ),

    # Networking Tables
    path(
        "events/<int:event_id>/networking-tables/",
        NetworkingTableViewSet.as_view({'get': 'list', 'post': 'create'}),
        name="networking-tables-list"
    ),
    path(
        "events/<int:event_id>/networking-tables/<int:pk>/",
        NetworkingTableViewSet.as_view({'get': 'retrieve', 'patch': 'partial_update', 'delete': 'destroy'}),
        name="networking-tables-detail"
    ),

    # Networking Meetings Availability
    path(
        "events/<int:event_id>/networking-meetings/availability/",
        NetworkingMeetingAvailabilityView.as_view(),
        name="networking-meetings-availability"
    ),

    # Networking Meetings List/Create
    path(
        "events/<int:event_id>/networking-meetings/",
        NetworkingMeetingListCreateView.as_view(),
        name="networking-meetings-list"
    ),

    # Networking Meetings My (user's meetings)
    path(
        "events/<int:event_id>/networking-meetings/my/",
        NetworkingMeetingMyView.as_view(),
        name="networking-meetings-my"
    ),

    # Mark meetings as seen
    path(
        "events/<int:event_id>/networking-meetings/mark-seen/",
        NetworkingMeetingMarkSeenView.as_view(),
        name="networking-meetings-mark-seen"
    ),

    # Networking Meeting Actions
    path(
        "networking-meetings/<int:meeting_id>/accept/",
        NetworkingMeetingAcceptView.as_view(),
        name="networking-meeting-accept"
    ),
    path(
        "networking-meetings/<int:meeting_id>/decline/",
        NetworkingMeetingDeclineView.as_view(),
        name="networking-meeting-decline"
    ),
    path(
        "networking-meetings/<int:meeting_id>/suggest/",
        NetworkingMeetingSuggestView.as_view(),
        name="networking-meeting-suggest"
    ),
    path(
        "networking-meetings/<int:meeting_id>/cancel/",
        NetworkingMeetingCancelView.as_view(),
        name="networking-meeting-cancel"
    ),
    path(
        "networking-meetings/<int:meeting_id>/reschedule/",
        NetworkingMeetingRescheduleView.as_view(),
        name="networking-meeting-reschedule"
    ),
    path(
        "events/<int:event_id>/sessions/",
        EventSessionViewSet.as_view({
            'get': 'list',
            'post': 'create',
        }),
        name="event-sessions-list"
    ),
    path(
        "events/<int:event_id>/sessions/<int:pk>/",
        EventSessionViewSet.as_view({
            'get': 'retrieve',
            'patch': 'partial_update',
            'delete': 'destroy',
        }),
        name="event-sessions-detail"
    ),
    path(
        "events/<int:event_id>/schedule/",
        EventScheduleView.as_view(),
        name="event-schedule"
    ),
    path(
        "events/<int:event_id>/schedule/<int:session_id>/bookmark/",
        SessionBookmarkToggleView.as_view(),
        name="session-bookmark-toggle"
    ),
]
