from django.urls import path, include
from rest_framework.routers import DefaultRouter
from groups.views import GroupViewSet, UsersLookupView, GroupNotificationViewSet

router = DefaultRouter()
router.register(r'groups', GroupViewSet, basename='group')
router.register(r'group-notifications', GroupNotificationViewSet, basename='group-notifications')

urlpatterns = [
    path('users-lookup/', UsersLookupView.as_view(), name='users-lookup'),
    path('', include(router.urls)),
]
