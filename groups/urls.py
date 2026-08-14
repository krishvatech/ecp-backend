from django.urls import path, include
from rest_framework.routers import DefaultRouter
from groups.views import (
    GroupViewSet,
    UsersLookupView,
    GroupNotificationViewSet,
    WordPressForumSourceSyncGroupView,
    WordPressForumSourceRefreshView,
    WordPressForumSourceListView,
    WordPressForumSourceImportContentView,
    WordPressGroupSourceListView,
    WordPressGroupSourceRefreshView,
    WordPressGroupSourceToggleView,
    WordPressGroupSourceSyncGroupView,
    WordPressGroupSourceSyncEnabledView,
    WordPressGroupSourceSyncMembersView,
    WordPressGroupSourceSyncEnabledMembersView,
    WordPressGroupSourceSyncEnabledFullContentView,
    WordPressGroupSourceSyncFullContentView,
    WordPressForumContentImportView,
    WordPressGroupSourceSyncCommentsView,
    WordPressGroupSourceSyncContentView,
    WordPressGroupSourceSyncEnabledCommentsView,
    WordPressGroupSourceSyncEnabledContentView,
    WordPressGroupSourceStatsView,
)

router = DefaultRouter()
router.register(r'groups', GroupViewSet, basename='group')
router.register(r'group-notifications', GroupNotificationViewSet, basename='group-notifications')

urlpatterns = [
    path('users-lookup/', UsersLookupView.as_view(), name='users-lookup'),
    path('groups/wordpress-sources/', WordPressGroupSourceListView.as_view(), name='wordpress-group-sources'),
    path('groups/wordpress-sources/refresh/', WordPressGroupSourceRefreshView.as_view(), name='wordpress-group-sources-refresh'),
    path('groups/wordpress-sources/stats/', WordPressGroupSourceStatsView.as_view(), name='wordpress-group-sources-stats'),
    path('groups/wordpress-forum-sources/', WordPressForumSourceListView.as_view(), name='wordpress-forum-sources'),
    path('groups/wordpress-forum-sources/refresh/', WordPressForumSourceRefreshView.as_view(), name='wordpress-forum-sources-refresh'),
    path('groups/wordpress-forum-sources/<int:wp_forum_id>/sync-group/', WordPressForumSourceSyncGroupView.as_view(), name='wordpress-forum-source-sync-group'),
    path('groups/wordpress-forum-sources/<int:wp_forum_id>/import-content/', WordPressForumSourceImportContentView.as_view(), name='wordpress-forum-source-import-content'),
    path('groups/wordpress-sources/sync-enabled-groups/', WordPressGroupSourceSyncEnabledView.as_view(), name='wordpress-group-sources-sync-enabled'),
    path('groups/wordpress-sources/sync-enabled-members/', WordPressGroupSourceSyncEnabledMembersView.as_view(), name='wordpress-group-sources-sync-enabled-members'),
    path('groups/wordpress-sources/sync-enabled-content/', WordPressGroupSourceSyncEnabledContentView.as_view(), name='wordpress-group-sources-sync-enabled-content'),
    path('groups/wordpress-sources/sync-enabled-comments/', WordPressGroupSourceSyncEnabledCommentsView.as_view(), name='wordpress-group-sources-sync-enabled-comments'),
    path('groups/wordpress-sources/sync-enabled-full-content/', WordPressGroupSourceSyncEnabledFullContentView.as_view(), name='wordpress-group-sources-sync-enabled-full-content'),
    path('groups/wordpress-sources/import-forum-content/', WordPressForumContentImportView.as_view(), name='wordpress-forum-content-import'),
    path('groups/wordpress-sources/<int:wp_group_id>/sync-group/', WordPressGroupSourceSyncGroupView.as_view(), name='wordpress-group-source-sync-group'),
    path('groups/wordpress-sources/<int:wp_group_id>/sync-members/', WordPressGroupSourceSyncMembersView.as_view(), name='wordpress-group-source-sync-members'),
    path('groups/wordpress-sources/<int:wp_group_id>/sync-content/', WordPressGroupSourceSyncContentView.as_view(), name='wordpress-group-source-sync-content'),
    path('groups/wordpress-sources/<int:wp_group_id>/sync-comments/', WordPressGroupSourceSyncCommentsView.as_view(), name='wordpress-group-source-sync-comments'),
    path('groups/wordpress-sources/<int:wp_group_id>/sync-full-content/', WordPressGroupSourceSyncFullContentView.as_view(), name='wordpress-group-source-sync-full-content'),
    path('groups/wordpress-sources/<int:wp_group_id>/', WordPressGroupSourceToggleView.as_view(), name='wordpress-group-source-toggle'),
    path('', include(router.urls)),
]
