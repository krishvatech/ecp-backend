from django.urls import path, include
from rest_framework.routers import DefaultRouter
from groups.views import (
    GroupViewSet,
    UsersLookupView,
    GroupNotificationViewSet,
    WordPressGroupSourceListView,
    WordPressGroupSourceRefreshView,
    WordPressGroupSourceToggleView,
)

router = DefaultRouter()
router.register(r'groups', GroupViewSet, basename='group')
router.register(r'group-notifications', GroupNotificationViewSet, basename='group-notifications')

urlpatterns = [
    path('users-lookup/', UsersLookupView.as_view(), name='users-lookup'),
    path('groups/wordpress-sources/', WordPressGroupSourceListView.as_view(), name='wordpress-group-sources'),
    path('groups/wordpress-sources/refresh/', WordPressGroupSourceRefreshView.as_view(), name='wordpress-group-sources-refresh'),
    path('groups/wordpress-sources/<int:wp_group_id>/', WordPressGroupSourceToggleView.as_view(), name='wordpress-group-source-toggle'),
    path('', include(router.urls)),
]
