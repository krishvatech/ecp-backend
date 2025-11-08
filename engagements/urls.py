from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CommentViewSet, ReactionViewSet, ShareViewSet

router = DefaultRouter()
router.register(r"comments", CommentViewSet, basename="engagement-comments")
router.register(r"reactions", ReactionViewSet, basename="engagement-reactions")
router.register(r"shares", ShareViewSet, basename="engagement-shares")

urlpatterns = [
    path("", include(router.urls)),
]
