from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import FriendshipViewSet, FriendRequestViewSet,NotificationViewSet

router = DefaultRouter()
router.register(r"friends", FriendshipViewSet, basename="friends")
router.register(r"friend-requests", FriendRequestViewSet, basename="friend-requests")
router.register(r"notifications", NotificationViewSet, basename="notifications") 

urlpatterns = [
    path("", include(router.urls)),
]
